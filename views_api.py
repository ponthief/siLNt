import json
from http import HTTPStatus
from base64 import b64encode
import httpx
import hashlib
import dns.resolver
from .helpers.curve import (
    decode, convertbits, pubkey_point_gen_from_int,
    int_from_bytes, point_add, point_mul, serP, ser256,
    has_even_y, G
)
from .helpers.wallet import (
    generate_silent_wallet_address,
    decrypt_mnemonic,
    decrypt_spend_key,
    decrypt_secret,
    build_transaction,
)
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
    get_spend_key
)

from .models import (
    BlindbitConfig,
    CreateWallet,
    WalletAccount,
    BuildTxRequest,
    BroadcastTxRequest
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
            sp_address='',
            spend_key='',
            scan_secret=''
        )
        (sp_address, scan_secret, spend_key) = await generate_silent_wallet_address(
            decrypt_mnemonic(data.mnemonic, str(data.last_height))
        )
        if not all([sp_address, scan_secret, spend_key]):
            raise ValueError(f"Wallet '{data.title}' cannot be created with given mnemonic!")

        wallets = await get_silnt_wallets(key_info.wallet.user, data.network)
        existing_wallet = next(
            (ew for ew in wallets if ew.sp_address == sp_address and ew.network == new_wallet.network),
            None,
        )
        if existing_wallet:           
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=f"Silent Payment Wallet already exists!")                       
        new_wallet.scan_secret = scan_secret
        new_wallet.spend_key = spend_key
        new_wallet.sp_address = sp_address
        await create_silnt_wallet(new_wallet)
    except Exception as exc:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)) from exc
    return ''


@silnt_api_router.put("/api/v1/wallet/{wallet_id}", status_code=HTTPStatus.OK)
async def api_wallet_update(
    wallet_id: str, data: CreateWallet, key_info: WalletTypeInfo = Depends(require_invoice_key)
) -> str:
    try:
        wallet = await get_silnt_wallet(wallet_id)
        if not wallet:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
        if data.hr_address is not None and data.hr_address != wallet.hr_address:
            await update_hr_address(wallet.id, data.hr_address)
        if data.last_height is not None and int(data.last_height) != wallet.last_height:
            await update_last_height(wallet.id, int(data.last_height))
        if data.title is not None and data.title != wallet.title:
            await update_title(wallet.id, data.title)
        if data.balance is not None and data.balance != wallet.balance:
            await update_balance(wallet.id, data.balance)
    except Exception as exc:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)) from exc
    return ''


@silnt_api_router.delete(
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_invoice_key)]
)
async def api_wallet_delete(wallet_id: str):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    await delete_silnt_wallet(wallet_id)
    await delete_utxos_for_wallet(wallet_id)
    return "", HTTPStatus.NO_CONTENT


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

@silnt_api_router.post(
    "/api/v1/scan",
    description="Proxy scan request to blindbit-scan using admin-configured credentials",
    dependencies=[Depends(require_invoice_key)],
)
async def api_scan_blockchain():
    blindbit = await get_blindbit_config()    
    if not blindbit.blindbit_url:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="BlindBit endpoint not configured. An admin must set it first.",
        )

    headers = {}
    if blindbit.blindbit_user and blindbit.blindbit_pass:
        credentials = b64encode(
            f"{blindbit.blindbit_user}:{blindbit.blindbit_pass}".encode()
        ).decode()
        headers["Authorization"] = f"Basic {credentials}"

    base_url = blindbit.blindbit_url.rstrip("/")    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            utxos_resp = await client.get(f"{base_url}/utxos", headers=headers)
            height_resp = await client.get(f"{base_url}/height", headers=headers)

            if utxos_resp.status_code != 200:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_GATEWAY,
                    detail=f"blindbit-scan /utxos returned {utxos_resp.status_code}",
                )

            return {
                "utxos": utxos_resp.json(),
                "height": height_resp.json() if height_resp.status_code == 200 else None,
            }

    except httpx.ConnectError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"Could not connect to blindbit-scan at {base_url}",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=HTTPStatus.GATEWAY_TIMEOUT,
            detail="blindbit-scan timed out",
        )


# BIP353
@silnt_api_router.get("/api/v1/bip353/resolve")
async def api_resolve_bip353(
    address: str = Query(..., description="BIP353 address in email format, e.g. alice@domain.com"),
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    try:
        user, domain = address.strip().split("@")
    except ValueError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid BIP353 address format. Expected user@domain.com"
        )
    try:        
        dns_domain = f"{user}.user._bitcoin-payment.{domain}"
        answers = dns.resolver.resolve(dns_domain, "TXT")
        result = ""
        for rdata in answers:
            result = "".join([a.decode() for a in rdata.strings])
            break
        if not result:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail=f"No TXT record found for {dns_domain}"
            )
        return {"address": address, "dns_domain": dns_domain, "result": result}
    except dns.resolver.NXDOMAIN:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Domain not found for {address}"
        )
    except dns.resolver.NoAnswer:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No TXT record found for {address}"
        )
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"DNS resolution failed: {str(exc)}"
        )
        
# Transactions
@silnt_api_router.post("/api/v1/tx/build", dependencies=[Depends(require_admin_key)])
async def api_build_transaction(data: BuildTxRequest):
    try:
        # ── Load wallet ───────────────────────────────────────────────
        wallet = await get_silnt_wallet(data.wallet_id)
        if not wallet:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail="Wallet does not exist."
            )

        # ── Decrypt keys ──────────────────────────────────────────────
        spend_key_encrypted = await get_spend_key(data.wallet_id)
        if not spend_key_encrypted:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="No spend key found for this wallet."
            )

        scan_secret = await decrypt_secret(wallet.scan_secret)
        if not scan_secret:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Failed to decrypt scan secret."
            )

        spend_key_hex = decrypt_spend_key(spend_key_encrypted, scan_secret)
        if not spend_key_hex:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Failed to decrypt spend key."
            )

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
            detail=f"Failed to build transaction: {str(exc)}"
        ) from exc


@silnt_api_router.post("/api/v1/tx/broadcast", dependencies=[Depends(require_admin_key)])
async def api_broadcast_transaction(data: BroadcastTxRequest):
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            blindbit = await get_blindbit_config()
            base_url = blindbit.blindbit_url.rstrip('/')
            headers = {}
            if blindbit.blindbit_user and blindbit.blindbit_pass:
                credentials = b64encode(
                    f"{blindbit.blindbit_user}:{blindbit.blindbit_pass}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {credentials}"
            resp = await client.post(
                f"{base_url}/tx/broadcast",
                json={"tx_hex": data.tx_hex},
                headers=headers
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_GATEWAY,
                    detail=f"Broadcast failed: {resp.text}"
                )
            return resp.json()
    except httpx.ConnectError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail="Could not connect to blindbit for broadcast"
        )

# ── Addresses ────────────────────────────────────────────────────────────────

@silnt_api_router.get("/api/v1/address/{wallet_id}")
async def api_get_address(
    wallet_id, key_info: WalletTypeInfo = Depends(require_invoice_key)
) -> str:
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    sp_address = await get_sp_address(wallet_id)
    assert sp_address, f"Silent Payment address doesn't exist for wallet: {wallet_id}"
    hr_address = await get_hr_address(wallet_id)
    return sp_address, hr_address