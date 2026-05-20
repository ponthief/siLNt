import json
from http import HTTPStatus
from base64 import b64encode
import httpx
import hashlib
import re
from .helpers.wallet import (
    generate_silent_wallet_address,
    decrypt_mnemonic,
    build_transaction,
    generate_labeled_sp_address,
    get_spend_pub_from_secret,
)
from .helpers.scan import scan_wallet, get_scan_progress, request_scan_stop
from .helpers.address_resolver import bip353_resolve
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key
from lnbits.helpers import urlsafe_short_hash
from loguru import logger
from typing import Optional
from .helpers.bip353_cloudflare import (
    create_bip353_record,
    get_zone_domain,
    delete_bip353_record,
    CloudflareError,
)

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
    get_utxos_for_wallet,
    insert_utxos_for_wallet,
    update_unconfirmed_utxo,
    get_wallet_addresses,
    count_wallet_addresses,
    insert_wallet_address,
    delete_wallet_label_address,
    delete_wallet_label_addresses,
    get_cloudflare_config,
    update_cloudflare_config,
)

from .models import (
    BlindbitConfig,
    CreateWallet,
    WalletAccount,
    BuildTxRequest,
    BroadcastTxRequest,
    Config,
    ScanWalletRequest,
    SaveAddressRequest,
    PreviewAddressRequest,
    CloudflareConfig,
    SetupBip353Request,
)

MAX_ADDRESSES_PER_WALLET = 10

silnt_api_router = APIRouter()


# ── Wallets ──────────────────────────────────────────────────────────────────


@silnt_api_router.get("/api/v1/wallet", status_code=HTTPStatus.OK)
async def api_wallets_retrieve(
    network: Optional[str] = Query(None),
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
) -> dict:
    try:
        wallet_id = urlsafe_short_hash()
        new_wallet = WalletAccount(
            id=wallet_id,
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
        (
            sp_address,
            scan_secret_hex,
            spend_key_hex,
        ) = await generate_silent_wallet_address(
            decrypt_mnemonic(data.mnemonic, str(data.last_height)), network=data.network
        )
        if not all([sp_address, scan_secret_hex, spend_key_hex]):
            raise ValueError(
                f"Wallet '{data.title}' cannot be created with given mnemonic!"
            )

        wallets = await get_silnt_wallets(key_info.wallet.user, data.network)
        if any(w.sp_address == sp_address for w in wallets):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Silent Payment Wallet already exists!",
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
        new_wallet.sp_address = sp_address
        await create_silnt_wallet(new_wallet)
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
        ) from exc
    return {
        "wallet_id": wallet_id,
        "sp_address": sp_address,
        "scan_secret": scan_secret_hex,  # client must store this securely
        "spend_key": spend_key_hex,  # client must store this securely
    }


@silnt_api_router.put("/api/v1/wallet/{wallet_id}", status_code=HTTPStatus.OK)
async def api_wallet_update(
    wallet_id: str,
    data: CreateWallet,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
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
                result = result.replace("bitcoin:?sp=", "").replace("sp=", "").strip()
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
    return {}


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
    await delete_wallet_label_addresses(wallet_id)
    return "", HTTPStatus.NO_CONTENT


@silnt_api_router.get("/api/v1/wallet/{wallet_id}/addresses")
async def api_get_wallet_addresses(
    wallet_id: str, key_info: WalletTypeInfo = Depends(require_invoice_key)
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    addresses = await get_wallet_addresses(wallet_id)
    return {"addresses": addresses, "max": MAX_ADDRESSES_PER_WALLET}


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/addresses/preview")
async def api_preview_wallet_address(
    wallet_id: str,
    data: PreviewAddressRequest,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    spend_pub_hex = get_spend_pub_from_secret(data.spend_key)
    hrp = "sp" if wallet.network == "mainnet" else "tsp"

    try:
        sp_address = generate_labeled_sp_address(
            scan_secret_hex=data.scan_secret,
            spend_pub_hex=spend_pub_hex,
            m=data.label_index,
            hrp=hrp,
        )
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate address: {str(e)}",
        )

    return {
        "sp_address": sp_address,
        "label_index": data.label_index,
        "wallet_id": wallet_id,
    }


@silnt_api_router.delete("/api/v1/wallet/{wallet_id}/addresses/{address_id}")
async def api_delete_wallet_address(
    wallet_id: str,
    address_id: str,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    await delete_wallet_label_address(address_id, wallet_id)
    return "", HTTPStatus.NO_CONTENT


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/addresses")
async def api_save_generated_wallet_address(
    wallet_id: str,
    data: SaveAddressRequest,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    count = await count_wallet_addresses(wallet_id)
    if count >= MAX_ADDRESSES_PER_WALLET:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Maximum of {MAX_ADDRESSES_PER_WALLET} addresses per wallet reached.",
        )
    addr_id = urlsafe_short_hash()
    await insert_wallet_address(wallet_id, data.sp_address, data.label_index, addr_id)
    return {
        "sp_address": data.sp_address,
        "label_index": data.label_index,
        "wallet_id": wallet_id,
        "id": addr_id,
    }


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
                f"{blindbit.blindbit_url.rstrip('/')}/info", headers=headers
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
            scan_secret_hex=data.scan_secret,  # from client request
            spend_secret_hex=data.spend_key,
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
async def api_build_transaction(
    data: BuildTxRequest, key_info: WalletTypeInfo = Depends(require_admin_key)
):
    try:
        wallet = await get_silnt_wallet(data.wallet_id)
        if not wallet:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
            )
        if wallet.user != key_info.wallet.user:
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN, detail="Access denied."
            )

        if not data.spend_key:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST, detail="spend_key is required."
            )

        if "@" in data.recipient:
            user, domain = data.recipient.strip().split("@")
            if user and domain:
                resolved = bip353_resolve(data.recipient)
                result = resolved["result"].replace("bitcoin:?sp=", "")
                if not result.startswith("sp1"):
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST,
                        detail="Address must resolve to Silent Payment address (sp1).",
                    )
                data.recipient = result

        result = build_transaction(
            spend_key_hex=data.spend_key,
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
        blindbit = await get_blindbit_config()
        config = Config()
        base = (blindbit.mempool_url or "https://mempool.space").rstrip("/")
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
            txid = resp.text.strip()
            if data.spent_txids and data.wallet_id:
                for spent_txid in data.spent_txids:
                    await update_unconfirmed_utxo(data.wallet_id, spent_txid)
                logger.info(
                    f"Marked {len(data.spent_txids)} UTXOs as unconfirmed_spent after broadcast of {txid}"
                )
            return {"txid": txid}

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
    blindbit = await get_blindbit_config()
    config = Config()
    return {
        "mempool_endpoint": blindbit.mempool_url or "https://mempool.space",
        "sats_denominated": config.sats_denominated,
        "network": config.network,
    }


@silnt_api_router.get(
    "/api/v1/wallet/{wallet_id}/scan/progress",
    dependencies=[Depends(require_invoice_key)],
)
async def api_scan_progress(wallet_id: str):
    return get_scan_progress(wallet_id)


# ── GET Cloudflare config (admin only) ───────────────────────────────────────
@silnt_api_router.get("/api/v1/cloudflare/config")
async def api_get_cloudflare_config(
    key_info: WalletTypeInfo = Depends(require_admin_key),
) -> CloudflareConfig:
    cf = await get_cloudflare_config()
    # Backfill domain if credentials are present but domain is missing
    # (e.g. config saved before the domain field existed)
    if cf.api_token and cf.zone_id and not cf.domain:
        try:
            cf.domain = await get_zone_domain(cf.api_token, cf.zone_id)
            await update_cloudflare_config(cf)
        except Exception:
            pass
    return cf


# ── PUT Cloudflare config (admin only) ───────────────────────────────────────
@silnt_api_router.put("/api/v1/cloudflare/config")
async def api_update_cloudflare_config(
    data: CloudflareConfig,
    key_info: WalletTypeInfo = Depends(require_admin_key),
) -> CloudflareConfig:
    # Verify token + zone by fetching domain — also auto-populates data.domain
    if data.api_token and data.zone_id:
        try:
            data.domain = await get_zone_domain(data.api_token, data.zone_id)
        except Exception as e:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=f"Could not verify Cloudflare zone: {str(e)}",
            )
    else:
        data.domain = ""
    return await update_cloudflare_config(data)


# ── POST setup BIP-353 for a wallet via Cloudflare ───────────────────────────
@silnt_api_router.post("/api/v1/wallet/{wallet_id}/bip353/setup")
async def api_setup_bip353(
    wallet_id: str,
    data: SetupBip353Request,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    # Reject if wallet already has BIP-353 — users must remove first, then create
    if wallet.hr_address:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Wallet already has BIP-353 address: {wallet.hr_address}. "
            "Remove it first before creating a new one.",
        )
    # Validate username format
    if not re.match(r"^[a-zA-Z0-9._-]+$", data.username):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Username must contain only letters, numbers, dots, hyphens, underscores.",
        )

    cf = await get_cloudflare_config()
    if not cf.api_token or not cf.zone_id:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Cloudflare API not configured. Ask your administrator to set it up.",
        )

    try:
        result = await create_bip353_record(
            api_token=cf.api_token,
            zone_id=cf.zone_id,
            username=data.username.lower(),
            sp_address=wallet.sp_address,
            ttl=data.ttl,
        )
    except CloudflareError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(e))

    # Update wallet hr_address
    await update_hr_address(wallet_id, result["hr_address"])

    return {
        "hr_address": result["hr_address"],
        "record_name": result["record_name"],
        "action": result["action"],
        "sp_address": wallet.sp_address,
    }


# ── DELETE BIP-353 record for a wallet ───────────────────────────────────────
@silnt_api_router.delete("/api/v1/wallet/{wallet_id}/bip353")
async def api_delete_bip353(
    wallet_id: str,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    if not wallet.hr_address:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="No BIP-353 address set."
        )

    cf = await get_cloudflare_config()
    if not cf.api_token or not cf.zone_id:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Cloudflare API not configured."
        )

    try:
        username = wallet.hr_address.split("@")[0]
        deleted = await delete_bip353_record(cf.api_token, cf.zone_id, username)
    except CloudflareError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail=str(e))

    # Clear hr_address from wallet
    await update_hr_address(wallet_id, "")

    return {"deleted": deleted, "was": wallet.hr_address}
