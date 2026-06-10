"""
boltz_refund_api.py — detect failed/refundable swap-ins and broadcast refunds.

Ties together:
  - persisted swap records (boltz_swaps table / crud)
  - Boltz status (GET /v2/swap/submarine/{id})
  - the current chain height (mempool/esplora)
  - build_refund_tx() (the verified script-path refund builder)
  - broadcasting via mempool_url /api/tx (the path siLNt already uses)

A swap is REFUNDABLE when:
  - it has an on-chain lockup recorded (lockup_txid/vout/value set), AND
  - it has NOT completed (status != completed/refunded), AND
  - EITHER Boltz reports a failure status (invoice.failedToPay /
    transaction.lockupFailed / swap.expired), OR the chain height has reached
    the swap's timeout_block_height (script-path refund becomes valid).

Endpoints (mounted under /siLNt):
  GET  /api/v1/swap/refundable                 → list refundable swaps for the user
  POST /api/v1/swap/{id}/refund {address}      → build + broadcast the refund tx

Also exposes refund_due_swaps() for an optional background task that auto-refunds
after timeout (mirrors how the old Boltz extension retried refunds periodically).
"""

import json
from http import HTTPStatus
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from loguru import logger
from pydantic import BaseModel

from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key

# siLNt-local imports — adjust paths to your layout
from .crud import (
    get_blindbit_config,
    get_boltz_swap,
    update_boltz_swap,
    list_boltz_swaps_by_status,
)
from .boltz_refund import build_refund_tx
from .models import RefundRequest


FAILURE_STATES = {
    "invoice.failedToPay",
    "transaction.lockupFailed",
    "swap.expired",
}
TERMINAL_STATES = {"transaction.claimed", "invoice.settled"}  # swap succeeded


silnt_refund_router = APIRouter()


# ── helpers ───────────────────────────────────────────────────────────────────
async def _boltz_base() -> str:
    cfg = await get_blindbit_config()
    url = (getattr(cfg, "boltz_url", None) or "").rstrip("/")
    if not url:
        raise HTTPException(HTTPStatus.SERVICE_UNAVAILABLE, "Boltz URL not configured.")
    return url


async def _mempool_base() -> str:
    cfg = await get_blindbit_config()
    url = (getattr(cfg, "mempool_url", None) or "").rstrip("/")
    if not url:
        raise HTTPException(HTTPStatus.SERVICE_UNAVAILABLE, "Mempool URL not configured.")
    return url


async def _boltz_status(swap_id: str) -> Optional[str]:
    base = await _boltz_base()
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(f"{base}/v2/swap/submarine/{swap_id}")
        if r.status_code != 200:
            return None
        return r.json().get("status")


async def _chain_height() -> int:
    base = await _mempool_base()
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(f"{base}/api/blocks/tip/height")
        r.raise_for_status()
        return int(r.text.strip())


async def _broadcast(tx_hex: str) -> str:
    base = await _mempool_base()
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{base}/api/tx", content=tx_hex)
        if r.status_code != 200:
            raise HTTPException(HTTPStatus.BAD_GATEWAY, f"Broadcast rejected: {r.text}")
        return r.text.strip()  # txid


async def _is_refundable(rec, height: int) -> tuple:
    """
    Returns (refundable: bool, reason: str). A swap is refundable if it has a
    recorded lockup, isn't terminal, and is either failed at Boltz or past timeout.
    """
    if rec.status in ("refunded", "completed"):
        return False, rec.status
    if not (rec.lockup_txid and rec.lockup_vout is not None and rec.lockup_value):
        return False, "no lockup recorded (nothing was funded on-chain yet)"

    status = await _boltz_status(rec.id)
    if status in TERMINAL_STATES:
        return False, "swap already succeeded"
    if status in FAILURE_STATES:
        return True, f"boltz status {status}"
    if rec.timeout_block_height and height >= rec.timeout_block_height:
        return True, f"timeout reached ({height} >= {rec.timeout_block_height})"
    blocks_left = (rec.timeout_block_height or 0) - height
    return False, f"not yet refundable (status {status}, ~{blocks_left} blocks to timeout)"


# ── endpoints ─────────────────────────────────────────────────────────────────


@silnt_refund_router.get("/api/v1/swap/refundable")
async def api_list_refundable(key_info: WalletTypeInfo = Depends(require_admin_key)):
    """List the caller's swaps that are currently refundable + why."""
    height = await _chain_height()
    out = []
    # Pull candidate swaps in non-terminal states.
    for state in ("created", "funded", "failed"):
        for rec in await list_boltz_swaps_by_status(state):
            if rec.wallet_id != key_info.wallet.id and rec.silnt_wallet_id != key_info.wallet.id:
                continue
            ok, reason = await _is_refundable(rec, height)
            if ok:
                out.append({
                    "swap_id": rec.id,
                    "amount": rec.lockup_value,
                    "timeout_block_height": rec.timeout_block_height,
                    "reason": reason,
                })
    return {"refundable": out, "chain_height": height}


@silnt_refund_router.post("/api/v1/swap/{swap_id}/refund")
async def api_refund_swap(
    swap_id: str,
    data: RefundRequest,
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """Build + broadcast a script-path refund for a failed/timed-out swap-in."""
    rec = await get_boltz_swap(swap_id)
    if not rec:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Swap not found.")
    # ownership
    if rec.wallet_id != key_info.wallet.id and rec.silnt_wallet_id != key_info.wallet.id:
        raise HTTPException(HTTPStatus.FORBIDDEN, "Not your swap.")

    height = await _chain_height()
    ok, reason = await _is_refundable(rec, height)
    if not ok:
        raise HTTPException(HTTPStatus.BAD_REQUEST, f"Not refundable: {reason}")

    # Refund destination must be a plain on-chain address (not SP — Boltz lockup
    # is a normal Taproot output we spend to a normal address).
    if data.address.lower().startswith(("sp1", "tsp1")):
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Refund address must be a plain on-chain address, not SP.")

    network = getattr(await get_blindbit_config(), "network", None) or "regtest"

    try:
        tx_hex = build_refund_tx(
            refund_privkey_hex=rec.refund_privkey,
            claim_public_key_hex=rec.claim_public_key,
            swap_tree=rec.swap_tree,
            lockup_address=rec.address,            # the funded address — guardrail checks this
            lockup_txid=rec.lockup_txid,
            lockup_vout=rec.lockup_vout,
            lockup_value=rec.lockup_value,
            destination_address=data.address,
            timeout_block_height=rec.timeout_block_height,
            fee_sats=data.fee_sats,
            network=network,
        )
    except RuntimeError as exc:
        # The address-match guardrail or a build error. Do NOT broadcast.
        logger.error(f"refund build failed for {swap_id}: {exc}")
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, f"Could not build refund: {exc}")

    txid = await _broadcast(tx_hex)
    rec.status = "refunded"
    rec.refund_address = data.address
    await update_boltz_swap(rec)
    logger.info(f"Refund broadcast for swap {swap_id}: {txid}")
    return {"success": True, "txid": txid, "swap_id": swap_id, "refunded_to": data.address}


# ── optional: background auto-refund (call from a periodic task) ───────────────
async def refund_due_swaps(default_fee_sats: int = 300) -> list:
    """
    Auto-refund swaps that are refundable AND have a refund_address on record.
    Returns a list of {swap_id, txid|error}. Wire to a periodic task if you want
    the old extension's "retry every N minutes" behavior. Swaps without a stored
    refund_address are skipped (a destination is required).
    """
    results = []
    height = await _chain_height()
    network = getattr(await get_blindbit_config(), "network", None) or "regtest"
    for state in ("created", "funded", "failed"):
        for rec in await list_boltz_swaps_by_status(state):
            ok, _ = await _is_refundable(rec, height)
            if not ok or not rec.refund_address:
                continue
            try:
                tx_hex = build_refund_tx(
                    refund_privkey_hex=rec.refund_privkey,
                    claim_public_key_hex=rec.claim_public_key,
                    swap_tree=rec.swap_tree,
                    lockup_address=rec.address,
                    lockup_txid=rec.lockup_txid,
                    lockup_vout=rec.lockup_vout,
                    lockup_value=rec.lockup_value,
                    destination_address=rec.refund_address,
                    timeout_block_height=rec.timeout_block_height,
                    fee_sats=default_fee_sats,
                    network=network,
                )
                txid = await _broadcast(tx_hex)
                rec.status = "refunded"
                await update_boltz_swap(rec)
                results.append({"swap_id": rec.id, "txid": txid})
            except Exception as exc:
                logger.warning(f"auto-refund failed for {rec.id}: {exc}")
                results.append({"swap_id": rec.id, "error": str(exc)})
    return results