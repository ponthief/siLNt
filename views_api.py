import json
from http import HTTPStatus
from base64 import b64encode
import httpx
from embit import finalizer, script
from embit.ec import PublicKey
from embit.networks import NETWORKS
from .helpers.wallet import generate_silent_wallet_address, decrypt_mnemonic
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key
from lnbits.helpers import urlsafe_short_hash, decrypt_internal_message
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
    get_silnt_wallet,
    get_blindbit_config,
    update_blindbit_config,
)

from .models import (
    BlindbitConfig,
    CreateWallet,
    WalletAccount,
)

silnt_api_router = APIRouter()


# ── Wallets ──────────────────────────────────────────────────────────────────

@silnt_api_router.get("/api/v1/wallet", status_code=HTTPStatus.OK)
async def api_wallets_retrieve(
    network: str = Query("Mainnet"),
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
    data: CreateWallet, key_info: WalletTypeInfo = Depends(require_admin_key)
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
        (sp_address, scan_secret, spend_key) = generate_silent_wallet_address(
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
            if data.hr_address and data.hr_address != existing_wallet.hr_address:
                await update_hr_address(existing_wallet.id, data.hr_address)
            if data.last_height and data.last_height != existing_wallet.last_height:
                await update_last_height(existing_wallet.id, data.last_height)
            else:
                raise ValueError(f"Wallet '{data.title}' already exists!")
            return ''
        new_wallet.scan_secret = scan_secret
        new_wallet.spend_key = spend_key
        new_wallet.sp_address = sp_address
        await create_silnt_wallet(new_wallet)
    except Exception as exc:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)) from exc
    return ''


@silnt_api_router.post("/api/v1/wallet{wallet_id}", status_code=HTTPStatus.OK)
async def api_wallet_update(
    wallet_id: str, data: CreateWallet, key_info: WalletTypeInfo = Depends(require_admin_key)
) -> str:
    try:
        wallet = await get_silnt_wallet(wallet_id)
        if not wallet:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
        if data.hr_address and data.hr_address != wallet.hr_address:
            await update_hr_address(wallet.id, data.hr_address)
        if data.last_height and int(data.last_height) != wallet.last_height:
            await update_last_height(wallet.id, int(data.last_height))
    except Exception as exc:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)) from exc
    return ''


@silnt_api_router.delete(
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_admin_key)]
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

    if not blindbit.blindbit_endpoint:
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

    base_url = blindbit.blindbit_endpoint.rstrip("/")

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