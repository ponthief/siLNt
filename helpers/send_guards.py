"""
The checks a send must pass, independent of who builds the transaction.

Extracted from views_api.api_build_transaction so that /tx/prepare — which
exists so the client can build and sign without sending its spend key — runs
exactly the same guards rather than a second copy of them. A security check
that exists twice is a security check that will eventually differ in one place,
and the one that would drift here decides whether a payment goes to the
recipient or to whoever altered a DNS record.

Neither function takes or returns key material.
"""

from __future__ import annotations

import json
from http import HTTPStatus

from fastapi import HTTPException
from loguru import logger

from ..crud import (
    create_admin_alert,
    get_cloudflare_config,
    get_eligible_utxos,
    get_issued_bitmail_sp_address,
    send_ntfy_notification,
)
from .address_resolver import bip353_resolve


async def validate_spendable_utxos(
    wallet_id: str, utxos: list, scanning: bool
) -> list[dict]:
    """Refuse anything frozen, already spent, or belonging to another wallet.

    Returns the eligible rows as the DATABASE has them. The caller passes
    outpoints and gets amounts and keys back, so a client cannot build against
    a stale amount it cached before a rescan.
    """
    if not utxos:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="No UTXOs provided for the transaction.",
        )

    def _txid(u):
        return u["txid"] if isinstance(u, dict) else u.txid

    def _vout(u):
        if isinstance(u, dict):
            return int(u.get("vout", 0))
        return int(getattr(u, "vout", 0) or 0)

    pairs = [(_txid(u), _vout(u)) for u in utxos]
    rows = await get_eligible_utxos(wallet_id=wallet_id, txid_vout_pairs=pairs)
    eligible = {(r["txid"], r["vout"]) for r in rows}

    rejected = [p for p in pairs if p not in eligible]
    if rejected:
        rejected_str = ", ".join(f"{t[:12]}…:{v}" for t, v in rejected)
        if scanning:
            detail = (
                f"Cannot spend these UTXOs ({rejected_str}) because a scan is "
                f"in progress and their state just changed. Refresh your UTXOs "
                f"and reselect, then try again."
            )
        else:
            detail = (
                f"Cannot spend these UTXOs ({rejected_str}). "
                f"They are either frozen, already spent, or don't belong "
                f"to this wallet. Unfreeze them or remove from selection."
            )
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=detail)

    return rows


async def resolve_recipient(recipient: str) -> str:
    """Resolve a BitMail to its Silent Payment address, refusing a tampered one.

    A plain sp1…/bc1… recipient comes back unchanged. A name@domain is resolved
    over DNSSEC, and if it is one WE issued on OUR configured domain the result
    must still match the address siLNt recorded for it. A mismatch means the TXT
    record was altered to redirect funds: the send is blocked, an admin alert is
    recorded and an urgent ntfy goes out.

    The alert and the notification are best-effort — neither failing may stop
    the block, which is the part that protects the money.
    """
    recipient = (recipient or "").strip()
    if "@" not in recipient:
        return recipient

    user, _, domain = recipient.partition("@")
    if not user or not domain:
        return recipient

    resolved = bip353_resolve(recipient)
    result = resolved["result"].replace("bitcoin:?sp=", "")
    if not result.startswith("sp1") and not result.startswith("tsp1"):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Address must resolve to Silent Payment address (sp1).",
        )

    try:
        cf = await get_cloudflare_config()
        our_domain = (getattr(cf, "domain", "") or "").strip().lower()
    except Exception:
        our_domain = ""

    if our_domain and domain.strip().lower() == our_domain:
        expected = await get_issued_bitmail_sp_address(user.strip())
        if expected and expected.strip().lower() != result.strip().lower():
            detail = (
                f"BitMail {user}@{domain} resolved to {result} but siLNt "
                f"issued it for {expected}. The DNS record may have been "
                f"tampered with to redirect funds. Send blocked."
            )
            try:
                await create_admin_alert(
                    kind="bitmail_tamper",
                    severity="critical",
                    title=f"BitMail tampering: {user}@{domain}",
                    detail=detail,
                    meta=json.dumps({
                        "bitmail": f"{user}@{domain}",
                        "resolved_sp": result,
                        "expected_sp": expected,
                    }),
                )
            except Exception as e:
                logger.error(f"could not record bitmail-tamper alert: {e}")
            try:
                await send_ntfy_notification(
                    title="⚠ BitMail tampering detected",
                    message=detail,
                    tags=["rotating_light"],
                    priority="urgent",
                )
            except Exception as e:
                logger.warning(f"ntfy (bitmail tamper) failed: {e}")
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    "This BitMail resolves to an address that does not match "
                    "what was registered. The send has been blocked and an "
                    "administrator has been alerted. Do not retry — verify the "
                    "recipient address out of band."
                ),
            )

    return result
