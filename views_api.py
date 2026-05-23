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

from .helpers.email_verification import (
    RegistrationRequest, VerifyRegistrationRequest,
    start_registration, complete_registration,
)
from .helpers.scan_rate_limiter import check_scan_allowed, mark_scan_finished
from .helpers.forgot_password import request_password_reset
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
    count_silnt_wallets
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
    ForgotPasswordRequest
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
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(e))

    finally:
        # ALWAYS release the concurrent-scan slot, even on error/exception
        mark_scan_finished(key_info.wallet.user, wallet_id)

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
    mark_scan_finished(key_info.wallet.user, wallet_id)
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


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/recover-keys")
async def api_recover_wallet_keys(
    wallet_id: str,
    data: RecoverKeysRequest,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
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
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    blindbit = await get_blindbit_config()
    config = Config()
    current  = await count_silnt_wallets(key_info.wallet.user)
    return {
        "mempool_endpoint": blindbit.mempool_url or "https://mempool.space",
        "sats_denominated": config.sats_denominated,
        "network": config.network,
        "min_scan_height":   blindbit.min_scan_height or 0,
        "wallet_count":         current
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