import json
from http import HTTPStatus
from base64 import b64encode
import httpx
import hashlib
from .helpers.wallet import (
    generate_silent_wallet_address,
    decrypt_mnemonic,
    decrypt_spend_key,
    decrypt_secret,
    build_transaction,
)
from .helpers.scan import scan_wallet, get_scan_progress, request_scan_stop
from .helpers.address_resolver import bip353_resolve
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key
from lnbits.helpers import urlsafe_short_hash
from loguru import logger

from .crud import (
    get_silnt_wallets,
    create_silnt_wallet,
    delete_silnt_wallet,
    delete_utxos_for_wallet,
    get_sp_address,
    get_hr_address,
    update_hr_address,
    update_last_height,
    update_title,
    update_balance,
    get_silnt_wallet,
    get_blindbit_config,
    update_blindbit_config,
    get_spend_key,
    get_utxos_for_wallet,
    insert_utxos_for_wallet,
)

from .models import (
    BlindbitConfig,
    CreateWallet,
    WalletAccount,
    BuildTxRequest,
    BroadcastTxRequest,
    Config,    
    ScanWalletRequest,
)


silnt_api_router = APIRouter()


# ── Wallets ──────────────────────────────────────────────────────────────────


@silnt_api_router.get("/api/v1/wallet", status_code=HTTPStatus.OK)
async def api_wallets_retrieve(
    network: str = Query("mainnet"),
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> list[WalletAccount]:
    return await get_silnt_wallets(key_info.wallet.user, network)


@silnt_api_router.get(
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_invoice_key)]
)
async def api_wallet_retrieve(wallet_id: str) -> WalletAccount:
    silnt_wallet = await get_silnt_wallet(wallet_id)
    if not silnt_wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    return silnt_wallet


@silnt_api_router.post("/api/v1/wallet", status_code=HTTPStatus.OK)
async def api_wallet_create(
    data: CreateWallet, key_info: WalletTypeInfo = Depends(require_invoice_key)
) -> str:
    try:
        new_wallet = WalletAccount(
            id=urlsafe_short_hash(),
            user=key_info.wallet.user,
            title=data.title,
            balance=0,
            hr_address=data.hr_address,
            network=data.network,
            last_height=int(data.last_height),
            sp_address="",
            spend_key="",
            scan_secret="",
        )
        (sp_address, scan_secret, spend_key) = await generate_silent_wallet_address(
            decrypt_mnemonic(data.mnemonic, str(data.last_height))
        )
        if not all([sp_address, scan_secret, spend_key]):
            raise ValueError(
                f"Wallet '{data.title}' cannot be created with given mnemonic!"
            )

        wallets = await get_silnt_wallets(key_info.wallet.user, data.network)
        existing_wallet = next(
            (
                ew
                for ew in wallets
                if ew.sp_address == sp_address and ew.network == new_wallet.network
            ),
            None,
        )
        if existing_wallet:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=f"Silent Payment Wallet already exists!",
            )
        if data.hr_address:
            try:
                resolved = bip353_resolve(data.hr_address)
                result = resolved.get("result", "")
                result = result.replace("bitcoin:?sp=", "").replace("sp=", "").strip()
                if result.lower() != sp_address.lower():
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST,
                        detail=f"BIP353 address resolves to a different SP address than the wallet's.",
                    )
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=f"BIP353 resolution failed for {data.hr_address}: {str(e)}",
                )
        new_wallet.scan_secret = scan_secret
        new_wallet.spend_key = spend_key
        new_wallet.sp_address = sp_address
        await create_silnt_wallet(new_wallet)
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
        ) from exc
    return ""


@silnt_api_router.put("/api/v1/wallet/{wallet_id}", status_code=HTTPStatus.OK)
async def api_wallet_update(
    wallet_id: str,
    data: CreateWallet,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> str:
    try:
        wallet = await get_silnt_wallet(wallet_id)
        if not wallet:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
            )
        if data.hr_address is not None and data.hr_address != wallet.hr_address:
            # Validate BIP353 resolves to this wallet's SP address            
            try:
                resolved = bip353_resolve(data.hr_address)
                result = resolved.get("result", "")
                result = (
                    result.replace("bitcoin:?sp=", "").replace("sp=", "").strip()
                )
                if result.lower() != wallet.sp_address.lower():
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST,
                        detail=f"BIP353 address resolves to a different SP address than this wallet's.",
                    )
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=f"BIP353 resolution failed for {data.hr_address}: {str(e)}",
                )
            await update_hr_address(wallet.id, data.hr_address)
        if data.last_height is not None and int(data.last_height) != wallet.last_height:
            await update_last_height(wallet.id, int(data.last_height))
        if data.title is not None and data.title != wallet.title:
            await update_title(wallet.id, data.title)
        if data.balance is not None and data.balance != wallet.balance:
            await update_balance(wallet.id, data.balance)
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
        ) from exc
    return ""


@silnt_api_router.delete(
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_invoice_key)]
)
async def api_wallet_delete(wallet_id: str):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    await delete_silnt_wallet(wallet_id)
    await delete_utxos_for_wallet(wallet_id)
    return "", HTTPStatus.NO_CONTENT


@silnt_api_router.get(
    "/api/v1/oracle/tip",
    dependencies=[Depends(require_invoice_key)],
)
async def api_get_chain_tip():
    blindbit = await get_blindbit_config()
    if not blindbit.blindbit_url:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="BlindBit Oracle URL not configured.",
        )
    headers = {}
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(
                f"{blindbit.blindbit_url.rstrip('/')}/block-height", headers=headers
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"Could not reach BlindBit Oracle: {str(e)}",
        )


# ── BlindBit config ───────────────────────────────────────────────────────────


@silnt_api_router.get("/api/v1/blindbit/config")
async def api_get_blindbit_config(
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> BlindbitConfig:
    """Any authenticated user can read the blindbit endpoint (needed to trigger scan).
    Credentials (user/pass) are included so the scan proxy can use them server-side."""
    return await get_blindbit_config()


@silnt_api_router.put("/api/v1/blindbit/config")
async def api_update_blindbit_config(
    data: BlindbitConfig, key_info: WalletTypeInfo = Depends(require_admin_key)
) -> BlindbitConfig:
    """Only admin can write blindbit connection settings."""
    return await update_blindbit_config(data)


# ── Scanning ──────────────────────────────────────────────────────────────────


@silnt_api_router.get(
    "/api/v1/utxos",
    description="Fetch UTXOs from blindbit",
    dependencies=[Depends(require_invoice_key)],
)
async def api_get_utxos(
    wallet_id: str = Query(...), key_info: WalletTypeInfo = Depends(require_invoice_key)
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    utxos = await get_utxos_for_wallet(wallet_id)
    return {
        "utxos": [u.dict() for u in utxos],
    }


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/scan")
async def api_scan_wallet(
    wallet_id: str,
    data: ScanWalletRequest,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    # Ownership guard: users may only scan wallets that belong to them.
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    try:
        result = await scan_wallet(
            wallet_id=wallet_id,
            from_height=data.from_height,
            to_height=data.to_height,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(e))


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/scan/stop")
async def api_stop_scan(
    wallet_id: str, key_info: WalletTypeInfo = Depends(require_invoice_key)
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    # Ownership guard: users may only stop scans for their own wallets.
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    request_scan_stop(wallet_id)
    return {"status": "stop requested"}


# BIP353
@silnt_api_router.get("/api/v1/bip353/resolve")
async def api_resolve_bip353(
    address: str = Query(
        ..., description="BIP353 address in email format, e.g. alice@domain.com"
    ),
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    return bip353_resolve(address=address)


# Transactions
@silnt_api_router.post("/api/v1/tx/build", dependencies=[Depends(require_admin_key)])
async def api_build_transaction(data: BuildTxRequest):
    try:
        # ── Load wallet ───────────────────────────────────────────────
        wallet = await get_silnt_wallet(data.wallet_id)
        if not wallet:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
            )

        # ── Decrypt keys ──────────────────────────────────────────────
        spend_key_encrypted = await get_spend_key(data.wallet_id)
        if not spend_key_encrypted:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="No spend key found for this wallet.",
            )

        scan_secret = await decrypt_secret(wallet.scan_secret)
        if not scan_secret:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Failed to decrypt scan secret.",
            )

        spend_key_hex = decrypt_spend_key(spend_key_encrypted, scan_secret)
        if not spend_key_hex:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Failed to decrypt spend key.",
            )
        if "@" in data.recipient:
            user, domain = data.recipient.strip().split("@")
            if user is not None and domain is not None:
                resolved = bip353_resolve(data.recipient)
                result = resolved["result"].replace("bitcoin:?sp=", "")
                if not result.startswith("sp1"):
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST,
                        detail="Address must resolve to SilenPayment address (sp1).",
                    )
                data.recipient = result
        # ── Build transaction ─────────────────────────────────────────
        result = build_transaction(
            spend_key_hex=spend_key_hex,
            recipient=data.recipient,
            amount=data.amount,
            fee_rate=data.fee_rate,
            utxos=data.utxos,
            network=wallet.network,
        )
        return result

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Transaction build failed: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Failed to build transaction: {str(exc)}",
        ) from exc


@silnt_api_router.post(
    "/api/v1/tx/broadcast", dependencies=[Depends(require_admin_key)]
)
async def api_broadcast_transaction(data: BroadcastTxRequest):
    try:
        config = Config()
        base = config.mempool_endpoint.rstrip("/")
        mempool_url = f"{base}/api/tx"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                mempool_url, content=data.tx_hex, headers={"Content-Type": "text/plain"}
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_GATEWAY,
                    detail=f"Broadcast failed: {resp.text}",
                )
            return {"txid": resp.text.strip()}

    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"Could not connect to {config.mempool_endpoint}",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=HTTPStatus.GATEWAY_TIMEOUT, detail="mempool.space timed out"
        )


@silnt_api_router.get("/api/v1/config")
async def api_get_config(
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    config = Config()
    return {
        "mempool_endpoint": config.mempool_endpoint,
        "sats_denominated": config.sats_denominated,
        "network": config.network,
    }


@silnt_api_router.get(
    "/api/v1/wallet/{wallet_id}/scan/progress",
    dependencies=[Depends(require_invoice_key)],
)
async def api_scan_progress(wallet_id: str):
    return get_scan_progress(wallet_id)
