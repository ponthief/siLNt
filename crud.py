import json
from typing import Optional, Tuple
import secrets
from lnbits.db import Database
from lnbits.helpers import urlsafe_short_hash
from .models import Config, ConfigDb, BlindbitConfig, WalletAccount, UTXORecord

from embit.descriptor import Descriptor, Key
from embit.descriptor.arguments import AllowedDerivation
from embit.networks import NETWORKS

db = Database("ext_silnt")

# Singleton row ID for the global blindbit config
BLINDBIT_CONFIG_ID = "blindbit"
SILNT_SECRET_ID = "silnt_to_rule_them_all"


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


async def get_sp_address(wallet_id: str) -> str:
    return await db.fetchall(
        """
        SELECT sp_address FROM silnt.wallets WHERE id = :wallet_id        
        """,
        {"wallet_id": wallet_id},
        str,
    )


async def get_hr_address(wallet_id: str) -> str:
    return await db.fetchall(
        """
        SELECT hr_address FROM silnt.wallets WHERE id = :wallet_id        
        """,
        {"wallet_id": wallet_id},
        str,
    )


async def update_hr_address(wallet_id: str, hr_address: str) -> Optional[WalletAccount]:
    await db.execute(
        "UPDATE silnt.wallets SET hr_address = :hra WHERE id = :wid",
        {"hra": hr_address, "wid": wallet_id},
    )
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid",
        {"wid": wallet_id},
        WalletAccount,
    )


async def update_last_height(wallet_id: str, last_height: int) -> Optional[WalletAccount]:
    await db.execute(
        "UPDATE silnt.wallets SET last_height = :lh WHERE id = :wid",
        {"lh": last_height, "wid": wallet_id},
    )
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid",
        {"wid": wallet_id},
        WalletAccount,
    )

async def update_balance(wallet_id: str, balance: int) -> Optional[WalletAccount]:
    await db.execute(
        "UPDATE silnt.wallets SET balance = :bal WHERE id = :wid",
        {"bal": balance, "wid": wallet_id},
    )
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid",
        {"wid": wallet_id},
        WalletAccount,
    )

async def update_title(wallet_id: str, title: str) -> Optional[WalletAccount]:
    await db.execute(
        "UPDATE silnt.wallets SET title = :ttl WHERE id = :wid",
        {"ttl": title, "wid": wallet_id},
    )
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid",
        {"wid": wallet_id},
        WalletAccount,
    )

async def get_spend_key(wallet_id: str) -> Optional[str]:
    row = await db.fetchone(
        "SELECT spend_key FROM silnt.wallets WHERE id = :id",
        {"id": wallet_id},
    )
    return row["spend_key"] if row else None

async def get_or_create_server_secret() -> str:
    row = await db.fetchone(
        "SELECT json_data FROM silnt.blindbit_config WHERE id = :id",
        {"id": SILNT_SECRET_ID},
    )
    if row:
        return json.loads(row["json_data"])["secret"]
    
    # Generate new secret on first use    
    server_secret = secrets.token_hex(32)
    await db.execute(
        "INSERT INTO silnt.blindbit_config (id, json_data) VALUES (:id, :json_data)",
        {"id": SILNT_SECRET_ID, "json_data": json.dumps({"secret": server_secret})},
    )
    return server_secret

async def insert_utxos_for_wallet(wallet_id: str, utxos: [UTXORecord]) -> None:
    for utxo in utxos:        
        existing = await db.fetchone(
            "SELECT txid FROM silnt.utxos WHERE txid = :txid",
            {"txid": utxo.get('txid')},
        )
        if existing:
            await db.execute(
                "UPDATE silnt.utxos SET txid = :txid WHERE wallet_id = :wallet_id",
                {"txid": utxo.get('txid'), "wallet_id": wallet_id},
            )
        else:
            await db.execute(
                "INSERT INTO silnt.utxos (txid, vout, amount, priv_key_tweak, pub_key, timestamp, utxo_state, wallet_id) \
                VALUES (:txid, :vout, :amount, :priv_key_tweak,  :pub_key, :timestamp, :utxo_state, :wallet_id",
                {"txid": utxo.get('txid'), "vout": int(utxo.get('vout')), "amount": int(utxo.get('amount')),
                "priv_key_tweak": utxo.get('priv_key_tweak'), "pub_key": utxo.get('pub_key'),
                "timestamp": int(utxo.get('timestamp')), "utxo_state": utxo.get('utxo_state'), "wallet_id": wallet_id},
            )


# ── Global admin-only blindbit config ───────────────────────────────────────

async def get_blindbit_config() -> BlindbitConfig:
    row = await db.fetchone(
        "SELECT json_data FROM silnt.blindbit_config WHERE id = :id",
        {"id": BLINDBIT_CONFIG_ID},
    )
    if not row:
        return BlindbitConfig()
    return BlindbitConfig(**json.loads(row["json_data"]))


async def update_blindbit_config(config: BlindbitConfig) -> BlindbitConfig:
    json_data = config.json()
    existing = await db.fetchone(
        "SELECT id FROM silnt.blindbit_config WHERE id = :id",
        {"id": BLINDBIT_CONFIG_ID},
    )
    if existing:
        await db.execute(
            "UPDATE silnt.blindbit_config SET json_data = :json_data WHERE id = :id",
            {"json_data": json_data, "id": BLINDBIT_CONFIG_ID},
        )
    else:
        await db.execute(
            "INSERT INTO silnt.blindbit_config (id, json_data) VALUES (:id, :json_data)",
            {"id": BLINDBIT_CONFIG_ID, "json_data": json_data},
        )
    return config