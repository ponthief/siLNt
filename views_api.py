import json
from http import HTTPStatus
from base64 import b64encode
import httpx
import hashlib
import re
import secrets
import time
from .helpers.wallet import (
    generate_silent_wallet_address,
    decrypt_mnemonic,
    build_transaction,
    generate_labeled_sp_address,
    get_spend_pub_from_secret,
)
from .helpers.scan import scan_wallet, get_scan_progress, request_scan_stop
from .helpers.address_resolver import bip353_resolve
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, Cookie
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key
from lnbits.helpers import urlsafe_short_hash
from lnbits.settings import settings as lnbits_settings
from loguru import logger
from typing import Optional
from .helpers.bip353_cloudflare import (
    create_bip353_record,
    get_zone_domain,
    delete_bip353_record,
    CloudflareError,
)

from .helpers.email_verification import (
    RegistrationRequest, VerifyRegistrationRequest,
    start_registration, complete_registration,
)
from .helpers.scan_rate_limiter import check_scan_allowed, mark_scan_finished
from .helpers.forgot_password import request_password_reset
from .helpers.transactions import get_wallet_transaction_detail, list_wallet_transactions
from lnbits.core.crud import get_account
from lnbits.core.services.notifications import send_email_notification
from .helpers.device_auth import (
    require_trusted_device,
    require_trusted_device_admin,    
    make_device_confirm_token,
    verify_device_confirm_token,
    set_device_cookie,
    get_client_ip,
    DEVICE_COOKIE_NAME,
    MAX_TRUSTED_DEVICES_PER_USER
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
    save_wallet_address,
    get_wallet_addresses,
    count_wallet_addresses,
    insert_wallet_address,
    delete_wallet_label_address,
    delete_wallet_label_addresses,
    get_cloudflare_config,
    update_cloudflare_config,
    count_silnt_wallets,
    address_exists,
    update_utxo_label_by_txid,
    get_utxos_by_txid,
    get_next_label_index,
    label_index_taken,
    owner_check_dust,
    update_utxo_frozen,
    get_eligible_utxos,
    update_address_label,
    get_wallet_address,
    mark_utxos_spent_by_tx,
    set_utxo_freeze_manual,
    clear_utxo_freeze_manual,
    count_trusted_devices,
    list_trusted_devices,
    add_trusted_device,
    get_trusted_device,
    touch_trusted_device,
    revoke_trusted_device,
    revoke_all_other_devices
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
    RecoverKeysRequest,
    ForgotPasswordRequest,
    UpdateUtxoLabel,
    UpdateUtxoFrozenRequest,
    UpdateAddressLabelRequest,
    TrustedDevice,
    DeviceCheckResponse,
    DeviceConfirmResponse,
    DeviceListResponse
)

MAX_ADDRESSES_PER_WALLET = 10
BIP352_CHANGE_LABEL_INDEX = 1
silnt_api_router = APIRouter()


# ── Wallets ──────────────────────────────────────────────────────────────────


@silnt_api_router.get("/api/v1/wallet", status_code=HTTPStatus.OK)
async def api_wallets_retrieve(
    network: Optional[str] = Query(None),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> list[WalletAccount]:
    return await get_silnt_wallets(key_info.wallet.user, network)


@silnt_api_router.get(
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_trusted_device)]
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
    data: CreateWallet, key_info: WalletTypeInfo = Depends(require_trusted_device)
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
        # Clamp "Born at Height" to the configured minimum to prevent users
        # from creating wallets that would force expensive deep scans.
        blindbit_cfg = await get_blindbit_config()
        min_height   = blindbit_cfg.min_scan_height or 0
        if min_height > 0 and int(data.last_height) < min_height:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    f"Wallet birth height must be at least {min_height} on this server. "
                    f"You entered {data.last_height}."
                ),
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
        blindbit_cfg = await get_blindbit_config()
        max_wallets  = blindbit_cfg.max_wallets_per_user or 0
        if max_wallets > 0:
            current_count = await count_silnt_wallets(key_info.wallet.user)
            if current_count >= max_wallets:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=(
                        f"Wallet limit reached. You can have at most {max_wallets} wallet"
                        f"{'s' if max_wallets != 1 else ''} on this server. "
                        f"You currently have {current_count}."
                    ),
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
    key_info: WalletTypeInfo = Depends(require_trusted_device),
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
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_trusted_device)]
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
    wallet_id: str, key_info: WalletTypeInfo = Depends(require_trusted_device)
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
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    label_index = data.label_index
    if label_index is None or label_index <= 0:
        label_index = await get_next_label_index(wallet_id)
    elif label_index == BIP352_CHANGE_LABEL_INDEX:
        # m=1 is reserved per BIP-352 — silently bump to next free
        label_index = await get_next_label_index(wallet_id)
    elif await label_index_taken(wallet_id, label_index):
        label_index = await get_next_label_index(wallet_id)
    spend_pub_hex = get_spend_pub_from_secret(data.spend_key)
    hrp = "sp" if wallet.network == "mainnet" else "tsp"

    try:
        sp_address = generate_labeled_sp_address(
            scan_secret_hex=data.scan_secret,
            spend_pub_hex=spend_pub_hex,
            m=label_index,
            hrp=hrp,
        )
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate address: {str(e)}",
        )
    return {
        "sp_address":  sp_address,
        "label_index": label_index,
    }


@silnt_api_router.delete("/api/v1/wallet/{wallet_id}/addresses/{address_id}")
async def api_delete_wallet_address(
    wallet_id: str,
    address_id: str,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
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
    key_info: WalletTypeInfo = Depends(require_trusted_device),
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
    if await address_exists(wallet_id, data.sp_address):
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail="This address is already saved on this wallet. Generate a new one.",
        )
    # Determine the label_index — trust server, not stale client state
    label_index = data.label_index
    if label_index is None or label_index <= 0:
        label_index = await get_next_label_index(wallet_id)
    elif await label_index_taken(wallet_id, label_index):
        # Bump to next free instead of erroring
        label_index = await get_next_label_index(wallet_id)
    if label_index == BIP352_CHANGE_LABEL_INDEX:
      # m=1 is reserved for change — bump to next free
      label_index = await get_next_label_index(wallet_id)

    try:
        return await save_wallet_address(
            wallet_id   = wallet_id,
            sp_address  = data.sp_address,
            label       = data.label,
            label_index = label_index,
        )
    except Exception as e:
        logger.error(f"save_wallet_address failed: {e}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Could not save labeled address. Please contact your administrator.",
        )    


@silnt_api_router.get(
    "/api/v1/oracle/tip",
    dependencies=[Depends(require_trusted_device)],
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
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> BlindbitConfig:
    """Any authenticated user can read the blindbit endpoint (needed to trigger scan).
    Credentials (user/pass) are included so the scan proxy can use them server-side."""
    return await get_blindbit_config()


@silnt_api_router.put("/api/v1/blindbit/config")
async def api_update_blindbit_config(
    data: BlindbitConfig, key_info: WalletTypeInfo = Depends(require_trusted_device_admin)
) -> BlindbitConfig:
    """Only admin can write blindbit connection settings."""
    return await update_blindbit_config(data)


# ── Scanning ──────────────────────────────────────────────────────────────────


@silnt_api_router.get(
    "/api/v1/utxos",
    description="Fetch UTXOs from blindbit",
    dependencies=[Depends(require_trusted_device)],
)
async def api_get_utxos(
    wallet_id: str = Query(...), key_info: WalletTypeInfo = Depends(require_trusted_device)
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
    request: Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    # Enforce min scan height
    blindbit = await get_blindbit_config()
    min_height = blindbit.min_scan_height or 0

    requested_from = data.from_height if data.from_height is not None else wallet.last_height
    if min_height > 0 and requested_from < min_height:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                f"Scanning below block {min_height} is disabled on this server. "
                f"Requested start height was {requested_from}."
            ),
        )

    # Estimate block count for budget check
    # Use chain tip as fallback if to_height not given
    to_height_est = data.to_height
    if to_height_est is None:
        from .helpers.scan import BlindBitOracleClient
        oracle = BlindBitOracleClient(base_url=blindbit.blindbit_url)
        to_height_est = await oracle.get_chain_tip()
    estimated_blocks = max(1, to_height_est - requested_from)

    client_ip = request.client.host if request.client else "unknown"

    # Rate limit check (raises 429 if any limit exceeded)
    check_scan_allowed(
        user_id=key_info.wallet.user,
        wallet_id=wallet_id,
        ip=client_ip,
        estimated_blocks=estimated_blocks,
    )
    try:
        result = await scan_wallet(
            wallet_id=wallet_id,
            scan_secret_hex=data.scan_secret,
            spend_secret_hex=data.spend_key,
            from_height=data.from_height,
            to_height=data.to_height,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e))
    except RuntimeError as e:
        # Our scan code raises RuntimeError with user-friendly messages —
        # surface those without leaking implementation details
        logger.error(f"Scan runtime error for {wallet_id}: {e}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
    except Exception as e:
        # Catch-all for unexpected errors — generic message to the user,
        # full traceback in server logs
        logger.error(f"Scan unexpected error for {wallet_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during scanning. Please contact your administrator.",
        )

    finally:
        # ALWAYS release the concurrent-scan slot, even on error/exception
        mark_scan_finished(key_info.wallet.user, wallet_id)

@silnt_api_router.post("/api/v1/wallet/{wallet_id}/scan/stop")
async def api_stop_scan(
    wallet_id: str, key_info: WalletTypeInfo = Depends(require_trusted_device)
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
    mark_scan_finished(key_info.wallet.user, wallet_id)
    return {"status": "stop requested"}


# BIP353
@silnt_api_router.get("/api/v1/bip353/resolve")
async def api_resolve_bip353(
    address: str = Query(
        ..., description="BIP353 address in email format, e.g. alice@domain.com"
    ),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> dict:
    return bip353_resolve(address=address)


# Transactions
@silnt_api_router.post("/api/v1/tx/build", dependencies=[Depends(require_trusted_device_admin)])
async def api_build_transaction(
    data: BuildTxRequest, key_info: WalletTypeInfo = Depends(require_trusted_device_admin)
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
        if not data.scan_secret:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="scan_secret is required (used to derive change address).",
            )
        # ── Validate UTXOs against the DB: refuse frozen, refuse non-owned ──
        if not data.utxos:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="No UTXOs provided for the transaction.",
            )

        def _txid_of(u):
            return u["txid"] if isinstance(u, dict) else u.txid

        def _vout_of(u):
            if isinstance(u, dict):
                return int(u.get("vout", 0))
            return int(getattr(u, "vout", 0) or 0)
        
        passed_txids_vouts = [(_txid_of(u), _vout_of(u)) for u in data.utxos]
        eligible_rows = await get_eligible_utxos(
            wallet_id=data.wallet_id,
            txid_vout_pairs=passed_txids_vouts,
        )
        eligible_set = {(r["txid"], r["vout"]) for r in eligible_rows}

        # Anything passed but not in eligible_set is either frozen, not unspent,
        # or doesn't belong to this wallet
        rejected = [
            (_txid_of(u), _vout_of(u)) for u in data.utxos
            if (_txid_of(u), _vout_of(u)) not in eligible_set
        ]
        if rejected:
            rejected_str = ", ".join(f"{t[:12]}…:{v}" for t, v in rejected)
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    f"Cannot spend these UTXOs ({rejected_str}). "
                    f"They are either frozen, already spent, or don't belong "
                    f"to this wallet. Unfreeze them or remove from selection."
                ),
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
            scan_secret_hex = data.scan_secret,
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
    "/api/v1/tx/broadcast", dependencies=[Depends(require_trusted_device_admin)]
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
                input_outpoints = [(u_txid, u_vout) for u_txid, u_vout in data.spent_outpoints]
                await mark_utxos_spent_by_tx(
                    wallet_id=data.wallet_id,
                    input_outpoints=input_outpoints,
                    spending_txid=txid,
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


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/recover-keys")
async def api_recover_wallet_keys(
    wallet_id: str,
    data: RecoverKeysRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """
    Re-derive scan_secret and spend_key from mnemonic for an existing wallet.
    Verifies the derived sp_address matches the stored one — protects against
    re-importing the wrong mnemonic.
    Keys are NEVER stored on the server, only returned transiently.
    """
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    try:
        mnemonic_plain = decrypt_mnemonic(data.mnemonic, str(data.last_height))
        sp_address, scan_secret_hex, spend_key_hex = await generate_silent_wallet_address(
            mnemonic_plain,
            network=wallet.network,
        )
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Could not derive keys from mnemonic: {str(e)}",
        )

    # Verify derived address matches the stored one — wrong mnemonic = rejection
    if sp_address.lower() != wallet.sp_address.lower():
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                "The mnemonic you entered does not match this wallet. "
                "Derived SP address differs from the stored one."
            ),
        )

    # Return keys transiently — they are not stored anywhere on the server
    return {
        "wallet_id":   wallet_id,
        "scan_secret": scan_secret_hex,
        "spend_key":   spend_key_hex,
    }

@silnt_api_router.get("/api/v1/config")
async def api_get_config(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> dict:
    blindbit = await get_blindbit_config()
    config = Config()
    current  = await count_silnt_wallets(key_info.wallet.user)
    return {
        "mempool_endpoint": blindbit.mempool_url or "https://mempool.space",
        "sats_denominated": config.sats_denominated,
        "network": config.network,
        "min_scan_height":   blindbit.min_scan_height or 0,
        "wallet_count":         current,
        "dust_threshold_sats": blindbit.dust_threshold_sats or 5000
    }

@silnt_api_router.get(
    "/api/v1/wallet/{wallet_id}/scan/progress",
    dependencies=[Depends(require_trusted_device)],
)
async def api_scan_progress(wallet_id: str):
    return get_scan_progress(wallet_id)


# ── GET Cloudflare config (admin only) ───────────────────────────────────────
@silnt_api_router.get("/api/v1/cloudflare/config")
async def api_get_cloudflare_config(
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
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
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
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
    key_info: WalletTypeInfo = Depends(require_trusted_device),
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
    key_info: WalletTypeInfo = Depends(require_trusted_device),
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

@silnt_api_router.post("/api/v1/auth/register-start")
async def api_register_start(data: RegistrationRequest, request: Request) -> dict:
    return await start_registration(data, request)

@silnt_api_router.post("/api/v1/auth/register-verify")
async def api_register_verify(data: VerifyRegistrationRequest) -> dict:
    return await complete_registration(data.token)

@silnt_api_router.post("/api/v1/auth/forgot-password")
async def api_forgot_password(data: ForgotPasswordRequest, request: Request) -> dict:
    """
    User requests a password reset link by email.
    The link is emailed to them and contains a signed reset_key that can be
    submitted to LNbits's PUT /api/v1/auth/reset endpoint.
    """
    if not data.email or "@" not in data.email:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Valid email address required.",
        )
    return await request_password_reset(data.email.strip().lower(), request)

# UTXO Labels
@silnt_api_router.put("/api/v1/utxos/{txid}/label")
async def api_update_utxo_label(
    txid: str,
    data: UpdateUtxoLabel,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    utxos = await get_utxos_by_txid(txid)
     # Find the UTXO(s) by txid and verify ownership via their parent wallet
    utxos = await get_utxos_by_txid(txid)
    if not utxos:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="UTXO not found.")

    # All matching UTXOs should belong to a wallet the caller owns
    for utxo in utxos:
        wallet = await get_silnt_wallet(utxo.wallet_id)
        if not wallet or wallet.user != key_info.wallet.user:
            raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    updated = await update_utxo_label_by_txid(txid, data.label)
    return {"txid": txid, "label": data.label, "updated": updated}

@silnt_api_router.put("/api/v1/wallet/{wallet_id}/addresses/{addr_id}/label")
async def api_update_address_label(
    wallet_id: str,
    addr_id: str,
    data: UpdateAddressLabelRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    # Lookup the address to verify it belongs to this wallet AND grab its old label
    addr = await get_wallet_address(addr_id)
    if not addr:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Labeled address not found.")
    if addr.wallet_id != wallet_id:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Address does not belong to this wallet.")

    new_label = (data.label or "").strip() or None

    await update_address_label(addr_id, new_label)

    return {
        "id":          addr_id,
        "label":       new_label,
        "label_index": addr.label_index,
        "sp_address":  addr.sp_address,
    }

@silnt_api_router.put("/api/v1/utxos/{txid}/{vout}/frozen")
async def api_set_utxo_frozen(
    txid: str,
    vout: int,
    data: UpdateUtxoFrozenRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    utxos = await get_utxos_by_txid(txid)
    if not utxos:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="UTXO not found.")
    matching = next((u for u in utxos if u.vout == vout), None)
    if not matching:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="UTXO not found at that vout.")

    wallet = await get_silnt_wallet(matching.wallet_id)
    if not wallet or wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    if data.frozen:
        await set_utxo_freeze_manual(txid, vout)
    else:
        await clear_utxo_freeze_manual(txid, vout)

    return {"txid": txid, "vout": vout, "frozen": data.frozen}

@silnt_api_router.get("/api/v1/wallet/{wallet_id}/transactions")
async def api_list_wallet_transactions(
    wallet_id: str,
    limit:     int = 50,
    offset:    int = 0,
    key_info:  WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    txs = await list_wallet_transactions(wallet_id, limit=limit, offset=offset)
    return {"transactions": txs}


@silnt_api_router.get("/api/v1/wallet/{wallet_id}/transactions/{txid}")
async def api_get_wallet_transaction(
    wallet_id: str,
    txid:      str,
    key_info:  WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    return await get_wallet_transaction_detail(wallet_id, txid)

@silnt_api_router.post("/api/v1/auth/device-check")
async def api_device_check(
    request:  Request,
    response: Response,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    """
    Called by Thrilla after a successful login. If the device cookie is missing
    or unknown, send a confirmation email and return 'pending'. Otherwise
    refresh the cookie and return 'trusted'.
    """
    user_id  = key_info.wallet.user
    cookie   = request.cookies.get(DEVICE_COOKIE_NAME)
    ua       = request.headers.get("user-agent", "")[:512]
    ip       = get_client_ip(request)

    # Check if a cookie exists AND is in trusted set
    if cookie:
        existing = await get_trusted_device(user_id, cookie)
        if existing:
            # Already trusted — touch + return
            await touch_trusted_device(user_id, cookie)
            # Refresh cookie expiry
            set_device_cookie(response, cookie)
            return DeviceCheckResponse(
                status       = "trusted",
                device_count = await count_trusted_devices(user_id),
                cap          = MAX_TRUSTED_DEVICES_PER_USER,
            )

    # New device — generate a fresh device_id (server-issued)
    new_device_id = secrets.token_urlsafe(24)

    # Check the cap
    current_count = await count_trusted_devices(user_id)
    if current_count >= MAX_TRUSTED_DEVICES_PER_USER:
        # Still send email — but the confirmation step will reject
        # Better UX: tell the user up front
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                f"This account already has {MAX_TRUSTED_DEVICES_PER_USER} "
                f"trusted devices (the maximum). Sign in from a trusted device "
                f"and revoke one in Settings → Devices before continuing."
            ),
        )

    # Look up the user's email
    account = await get_account(user_id)
    if not account or not account.email:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="This account has no email address. Cannot send confirmation.",
        )

    # Build + send the confirmation email
    token = make_device_confirm_token(user_id, new_device_id, ua, ip)
    # NOTE: configure base URL appropriately for your deployment
    base_url = "https://signet.thrilla.me"
    confirm_url = f"{base_url.rstrip('/')}/confirm-device?token={token}"

    subject = "Confirm a new device on your wallet"
    body = (
        f"Hi {account.username or 'there'},\n\n"
        f"A new device tried to sign in to your wallet:\n\n"
        f"  Browser: {ua or 'unknown'}\n"
        f"  IP:      {ip or 'unknown'}\n"
        f"  Time:    {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n\n"
        f"If this was you, confirm the device here:\n\n"
        f"  {confirm_url}\n\n"
        f"This link expires in 1 hour.\n\n"
        f"If this WASN'T you, change your password immediately and ignore this email."
    )

    res = await send_email_notification(
        to_emails = [account.email],
        message   = body,
        subject   = subject,
    )
    if res.get("status") != "ok":
        logger.warning(f"Device confirmation email failed: {res}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Could not send confirmation email. Please contact your administrator.",
        )

    # Set the cookie now — but the device won't be trusted until confirmed.
    # Future requests will carry the cookie; the confirm endpoint reads it
    # from the URL token (more reliable than relying on the cookie at click-time).
    set_device_cookie(response, new_device_id)

    return DeviceCheckResponse(
        status       = "pending",
        device_count = current_count,
        cap          = MAX_TRUSTED_DEVICES_PER_USER,
    )


@silnt_api_router.get("/api/v1/auth/device-confirm")
async def api_device_confirm(
    request:  Request,
    response: Response,
    token:    str,
):
    """
    Called when the user clicks the link in the confirmation email.
    Validates the token + cap, then writes the device into trusted_devices.
    Also sets the cookie (in case the user opened the link in a different
    tab/window without the cookie present).
    """
    payload = verify_device_confirm_token(token)
    if not payload:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid or expired confirmation token.",
        )

    user_id   = payload["user_id"]
    device_id = payload["device_id"]
    ua        = payload.get("ua", "")
    ip        = payload.get("ip", "")

    # Hard cap re-check at confirm time (cap may have changed since email)
    current_count = await count_trusted_devices(user_id)
    if current_count >= MAX_TRUSTED_DEVICES_PER_USER:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                f"This account already has {MAX_TRUSTED_DEVICES_PER_USER} "
                f"trusted devices. Revoke one before adding another."
            ),
        )

    await add_trusted_device(
        user_id    = user_id,
        device_id  = device_id,
        user_agent = ua,
        ip         = ip,
    )

    # Ensure the cookie matches (in case user opened link in different browser)
    set_device_cookie(response, device_id)

    return DeviceConfirmResponse(
        confirmed    = True,
        device_count = current_count + 1,
        cap          = MAX_TRUSTED_DEVICES_PER_USER,
    )


@silnt_api_router.get("/api/v1/devices")
async def api_list_devices(
    request:  Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
    silnt_device_id: Optional[str] = Cookie(default=None),
):
    devices = await list_trusted_devices(key_info.wallet.user)
    return DeviceListResponse(
        devices        = devices,
        current_device = silnt_device_id,
        cap            = MAX_TRUSTED_DEVICES_PER_USER,
    )


@silnt_api_router.delete("/api/v1/devices/{device_row_id}")
async def api_revoke_device(
    device_row_id: str,
    request:  Request,
    response: Response,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
    silnt_device_id: Optional[str] = Cookie(default=None),
):
    devices = await list_trusted_devices(key_info.wallet.user)
    target  = next((d for d in devices if d.id == device_row_id), None)
    if not target:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Device not found.")

    deleted = await revoke_trusted_device(key_info.wallet.user, device_row_id)

    # If user revoked the CURRENT device, clear the cookie too
    if target.device_id == silnt_device_id:
        response.delete_cookie(DEVICE_COOKIE_NAME, path="/")

    return {"deleted": bool(deleted), "device_row_id": device_row_id}


@silnt_api_router.post("/api/v1/devices/sign-out-others")
async def api_sign_out_others(
    request:  Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
    silnt_device_id: Optional[str] = Cookie(default=None),
):
    if not silnt_device_id:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="No active device.")
    removed = await revoke_all_other_devices(key_info.wallet.user, silnt_device_id)
    return {"removed_count": removed}