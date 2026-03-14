import json
from http import HTTPStatus

import httpx
from embit import finalizer, script
from embit.ec import PublicKey
from embit.networks import NETWORKS
from .helpers.wallet import generate_silent_wallet_address, decrypt_mnemonic
# from embit.psbt import PSBT, DerivationPath
# from embit.transaction import Transaction, TransactionInput, TransactionOutput
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
    get_silnt_wallet
)

from .models import (
    # Address,
    Config,    
    CreateWallet,
    # ExtractPsbt,
    # ExtractTx,
    # SerializedTransaction,
    # SignedTransaction,
    WalletAccount,
)

silnt_api_router = APIRouter()


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
        (sp_address, scan_secret, spend_key) = generate_silent_wallet_address(data.mnemonic)
        if not all([sp_address,scan_secret,spend_key]):
            raise ValueError(
                    f"Wallet '{data.title}' cannot be created with given mnemonic!"
                )
        wallets = await get_silnt_wallets(key_info.wallet.user, data.network)        
        existing_wallet = next(
            (
                ew
                for ew in wallets
                if ew.sp_address == sp_address
                and ew.network == new_wallet.network                
            ),
            None,
        )
        logger.info(existing_wallet)            
        if existing_wallet:           
            if data.hr_address and data.hr_address != existing_wallet.hr_address:
                await update_hr_address(existing_wallet.id, data.hr_address)
            if data.last_height and data.last_height != existing_wallet.last_height:
                await update_last_height(existing_wallet.id, data.last_height)    
            else:
                raise ValueError(
                    f"Wallet '{data.title}' already exists!"
                )                                      
            return ''
        new_wallet.scan_secret = scan_secret
        new_wallet.spend_key = spend_key
        new_wallet.sp_address = sp_address
        # logger.info(new_wallet)
        wallet = await create_silnt_wallet(new_wallet)        
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
        ) from exc    
    return ''


@silnt_api_router.post("/api/v1/wallet{wallet_id}", status_code=HTTPStatus.OK)
async def api_wallet_update(
    wallet_id: str, data: CreateWallet, key_info: WalletTypeInfo = Depends(require_admin_key)
) -> str:
    try:        
        wallet = await get_silnt_wallet(wallet_id)
        if not wallet:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
            )                                             
        if data.hr_address and data.hr_address != wallet.hr_address:
            await update_hr_address(wallet.id, data.hr_address)
        if data.last_height and int(data.last_height) != wallet.last_height:
            await update_last_height(wallet.id, int(data.last_height))                                                                     
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
        ) from exc    
    return ''

@silnt_api_router.delete(
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_admin_key)]
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


#############################ADDRESSES##########################


# @silnt_api_router.get(
#     "/api/v1/address/{wallet_id}", dependencies=[Depends(require_invoice_key)]
# )
# async def api_fresh_address(wallet_id: str) -> Address:
#     address = await get_fresh_address(wallet_id)
#     assert address
#     return address


# @silnt_api_router.put(
#     "/api/v1/address/{address_id}", dependencies=[Depends(require_admin_key)]
# )
# async def api_update_address(address_id: str, req: Request):
#     address = await get_address_by_id(address_id)
#     if not address:
#         raise HTTPException(
#             status_code=HTTPStatus.NOT_FOUND, detail="Address does not exist."
#         )

#     body = await req.json()
#     # amount is only updated if the address has history
#     if "amount" in body:
#         address.amount = int(body["amount"])
#         address.has_activity = True

#     if "note" in body:
#         address.note = body["note"]

#     address = await update_address(address)

#     wallet = (
#         await get_watch_wallet(address.wallet)
#         if address.branch_index == 0 and address.amount != 0
#         else None
#     )

#     if wallet and wallet.address_no < address.address_index:
#         wallet.address_no = address.address_index
#         await update_watch_wallet(wallet)
#     return address


@silnt_api_router.get("/api/v1/address/{wallet_id}")
async def api_get_address(
    wallet_id, key_info: WalletTypeInfo = Depends(require_invoice_key)
) -> str:
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    sp_address = await get_sp_address(wallet_id)
    assert sp_address, f"Silent Payment address doesn't exist for wallet: {wallet_id}"
    hr_address = await get_hr_address(wallet_id)
    return sp_address,hr_address

    


# @silnt_api_router.post("/api/v1/psbt", dependencies=[Depends(require_admin_key)])
# async def api_psbt_create(data: CreatePsbt):
#     try:
#         vin = [
#             TransactionInput(bytes.fromhex(inp.tx_id), inp.vout) for inp in data.inputs
#         ]
#         vout = [
#             TransactionOutput(out.amount, script.address_to_scriptpubkey(out.address))
#             for out in data.outputs
#         ]

#         descriptors = {}
#         for _, masterpub in enumerate(data.masterpubs):
#             descriptors[masterpub.id] = parse_key(masterpub.public_key)

#         inputs_extra: list[dict] = []

#         for inp in data.inputs:
#             bip32_derivations = {}
#             descriptor = descriptors[inp.wallet][0]
#             d = descriptor.derive(inp.address_index, inp.branch_index)
#             for k in d.keys:
#                 bip32_derivations[PublicKey.parse(k.sec())] = DerivationPath(
#                     k.origin.fingerprint, k.origin.derivation
#                 )
#             inputs_extra.append(
#                 {
#                     "bip32_derivations": bip32_derivations,
#                     "non_witness_utxo": Transaction.from_string(inp.tx_hex),
#                 }
#             )

#         tx = Transaction(vin=vin, vout=vout)
#         psbt = PSBT(tx)

#         for i, inp_extra in enumerate(inputs_extra):
#             psbt.inputs[i].bip32_derivations = inp_extra["bip32_derivations"]
#             psbt.inputs[i].non_witness_utxo = inp_extra.get("non_witness_utxo", None)

#         outputs_extra = []
#         bip32_derivations = {}
#         for out in data.outputs:
#             if out.branch_index == 1:
#                 assert out.wallet
#                 descriptor = descriptors[out.wallet][0]
#                 d = descriptor.derive(out.address_index, out.branch_index)
#                 for k in d.keys:
#                     bip32_derivations[PublicKey.parse(k.sec())] = DerivationPath(
#                         k.origin.fingerprint, k.origin.derivation
#                     )
#                 outputs_extra.append({"bip32_derivations": bip32_derivations})

#         for i, out_extra in enumerate(outputs_extra):
#             psbt.outputs[i].bip32_derivations = out_extra["bip32_derivations"]

#         return psbt.to_string()

#     except Exception as exc:
#         raise HTTPException(
#             status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
#         ) from exc


# @silnt_api_router.put(
#     "/api/v1/psbt/utxos", dependencies=[Depends(require_admin_key)]
# )
# async def api_psbt_utxos_tx(req: Request):
#     """Extract previous unspent transaction outputs (tx_id, vout) from PSBT"""

#     body = await req.json()
#     try:
#         psbt = PSBT.from_base64(body["psbtBase64"])
#         res = []
#         for _, inp in enumerate(psbt.inputs):
#             res.append({"tx_id": inp.txid.hex(), "vout": inp.vout})

#         return res
#     except Exception as exc:
#         raise HTTPException(
#             status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
#         ) from exc


# @silnt_api_router.put(
#     "/api/v1/psbt/extract", dependencies=[Depends(require_admin_key)]
# )
# async def api_psbt_extract_tx(data: ExtractPsbt) -> SignedTransaction:
#     network = NETWORKS["main"] if data.network == "Mainnet" else NETWORKS["test"]
#     try:
#         psbt = PSBT.from_base64(data.psbt_base64)
#         for i, inp in enumerate(data.inputs):
#             psbt.inputs[i].non_witness_utxo = Transaction.from_string(inp.tx_hex)

#         final_psbt = finalizer.finalize_psbt(psbt)
#         if not final_psbt:
#             raise ValueError("PSBT cannot be finalized!")

#         tx_hex = final_psbt.to_string()
#         transaction = Transaction.from_string(tx_hex)
#         tx = {
#             "locktime": transaction.locktime,
#             "version": transaction.version,
#             "outputs": [],
#             "fee": psbt.fee(),
#         }

#         for out in transaction.vout:
#             tx["outputs"].append(
#                 {"amount": out.value, "address": out.script_pubkey.address(network)}
#             )
#         signed_tx = SignedTransaction(tx_hex=tx_hex, tx_json=json.dumps(tx))
#         return signed_tx
#     except Exception as exc:
#         raise HTTPException(
#             status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
#         ) from exc


# @silnt_api_router.put(
#     "/api/v1/tx/extract", dependencies=[Depends(require_admin_key)]
# )
# async def api_extract_tx(data: ExtractTx):
#     network = NETWORKS["main"] if data.network == "mainnet" else NETWORKS["test"]
#     try:
#         transaction = Transaction.from_string(data.tx_hex)
#         tx = {
#             "locktime": transaction.locktime,
#             "version": transaction.version,
#             "outputs": [],
#         }

#         for out in transaction.vout:
#             tx["outputs"].append(
#                 {"amount": out.value, "address": out.script_pubkey.address(network)}
#             )
#         return {"tx_json": tx}
#     except Exception as exc:
#         raise HTTPException(
#             status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
#         ) from exc


# @silnt_api_router.post("/api/v1/tx")
# async def api_tx_broadcast(
#     data: SerializedTransaction, key_info: WalletTypeInfo = Depends(require_admin_key)
# ):
#     try:
#         config = await get_config(key_info.wallet.user)
#         if not config:
#             raise ValueError(
#                 "Cannot broadcast transaction. Mempool endpoint not defined!"
#             )

#         endpoint = (
#             config.mempool_endpoint
#             if config.network == "mainnet"
#             else config.mempool_endpoint + "/testnet"
#         )
#         async with httpx.AsyncClient() as client:
#             r = await client.post(endpoint + "/api/tx", content=data.tx_hex)
#             r.raise_for_status()
#             tx_id = r.text
#             return tx_id
#     except Exception as exc:
#         raise HTTPException(
#             status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
#         ) from exc


# @silnt_api_router.put("/api/v1/config")
# async def api_update_config(
#     data: Config, key_info: WalletTypeInfo = Depends(require_admin_key)
# ) -> Config:
#     config = await update_config(data, user=key_info.wallet.user)
#     return config


# @silnt_api_router.get("/api/v1/config")
# async def api_get_config(
#     key_info: WalletTypeInfo = Depends(require_invoice_key),
# ) -> Config:
#     config = await get_config(key_info.wallet.user)
#     return config
