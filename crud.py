from typing import Optional, Tuple

from lnbits.db import Database
from lnbits.helpers import urlsafe_short_hash
from .models import Config, ConfigDb, WalletAccount

from embit.descriptor import Descriptor, Key
from embit.descriptor.arguments import AllowedDerivation
from embit.networks import NETWORKS

db = Database("ext_silnt")


async def create_silnt_wallet(wallet: WalletAccount) -> WalletAccount:
    await db.insert("silnt.wallets", wallet)
    return wallet


async def get_silnt_wallet(wallet_id: str) -> Optional[WalletAccount]:
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :id",
        {"id": wallet_id},
        WalletAccount,
    )


async def get_silnt_wallets(user: str, network: str) -> list[WalletAccount]:
    # title, id, sp_address, hr_address, balance, network, created_at, last_height
    return await db.fetchall(
        """
        SELECT * FROM silnt.wallets
        WHERE "user" = :user AND network = :network
        """,
        {"user": user, "network": network},
        WalletAccount,
    )


async def delete_silnt_wallet(wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.wallets WHERE id = :id",
        {"id": wallet_id},
    )

async def delete_utxos_for_wallet(wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.utxos WHERE wallet_id = :wallet_id",
        {"wallet_id": wallet_id},
    )

# async def get_fresh_address(wallet_id: str) -> Optional[Address]:
#     # todo: move logic to views_api after satspay refactoring
#     wallet = await get_silnt_wallet(wallet_id)

#     if not wallet:
#         return None

#     wallet_addresses = await get_addresses(wallet_id)
#     receive_addresses = list(
#         filter(
#             lambda addr: addr.branch_index == 0 and addr.has_activity, wallet_addresses
#         )
#     )
#     last_receive_index = (
#         receive_addresses.pop().address_index if receive_addresses else -1
#     )
#     address_index = (
#         last_receive_index
#         if last_receive_index > wallet.address_no
#         else wallet.address_no
#     )

#     address = await get_address_at_index(wallet_id, 0, address_index + 1)

#     if not address:
#         addresses = await create_fresh_addresses(
#             wallet_id, address_index + 1, address_index + 2
#         )
#         address = addresses.pop()

#     wallet.address_no = address_index + 1
#     await update_silnt_wallet(wallet)

#     return address
    

async def get_sp_address(wallet_id: str) -> str:
    return await db.fetchall(
        """
        SELECT sp_address FROM silnt.wallets WHERE wallet = :wallet        
        """,
        {"wallet": wallet_id},
        str,
    )

async def get_hr_address(wallet_id: str) -> str:
    return await db.fetchall(
        """
        SELECT hr_address FROM silnt.wallets WHERE wallet = :wallet        
        """,
        {"wallet": wallet_id},
        str,
    )


async def update_hr_address(wallet_id: str, hr_address: str) -> Optional[WalletAccount]:
     await db.execute(f"UPDATE silnt.wallets SET hr_address = :hra WHERE id = :wid", {"hra" : hr_address, "wid": wallet_id})
     return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid", {"wid": wallet_id},
        WalletAccount
    )
async def update_last_height(wallet_id: str, last_height: int) -> Optional[WalletAccount]:
     await db.execute(f"UPDATE silnt.wallets SET last_height = :lh WHERE id = :wid", {"lh" : last_height, "wid": wallet_id})
     return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid", {"wid": wallet_id},
        WalletAccount
    )
async def create_config(user: str) -> Config:
    config = Config()
    await db.insert("silnt.config", ConfigDb(user=user, json_data=config))
    return config


async def update_config(config: Config, user: str) -> Config:
    _config = ConfigDb(user=user, json_data=config)
    await db.update("silnt.config", _config, """WHERE "user" = :user""")
    return config


async def get_config(user: str) -> Config:
    _config = await db.fetchone(
        """SELECT * FROM silnt.config WHERE "user" = :user""",
        {"user": user},
        ConfigDb,
    )
    if not _config:
        return await create_config(user)
    return _config.json_data
