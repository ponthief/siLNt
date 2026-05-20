import json
import time
from typing import Optional, Tuple
import secrets
from lnbits.db import Database
from lnbits.helpers import urlsafe_short_hash
from .models import (
    Config,
    BlindbitConfig,
    WalletAccount,
    UTXORecord,
    WalletAddress,
    CloudflareConfig,
)

from embit.descriptor import Descriptor, Key
from embit.descriptor.arguments import AllowedDerivation
from embit.networks import NETWORKS
from datetime import datetime

db = Database("ext_silnt")

# Singleton row ID for the global blindbit config
BLINDBIT_CONFIG_ID = "blindbit"
CF_CONFIG_ID = "cloudflare_config"


async def create_silnt_wallet(wallet: WalletAccount) -> WalletAccount:
    await db.insert("silnt.wallets", wallet)
    return wallet


async def get_silnt_wallet(wallet_id: str) -> Optional[WalletAccount]:
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :id",
        {"id": wallet_id},
        WalletAccount,
    )


async def get_silnt_wallets(
    user: str, network: Optional[str] = None
) -> list[WalletAccount]:
    if network:
        return await db.fetchall(
            'SELECT * FROM silnt.wallets WHERE "user" = :user AND network = :network ORDER BY network, title',
            {"user": user, "network": network},
            WalletAccount,
        )
    return await db.fetchall(
        'SELECT * FROM silnt.wallets WHERE "user" = :user ORDER BY network, title',
        {"user": user},
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


async def update_last_height(
    wallet_id: str, last_height: int
) -> Optional[WalletAccount]:
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


async def get_utxos_for_wallet(wallet_id: str) -> list[UTXORecord]:
    return await db.fetchall(
        "SELECT * FROM silnt.utxos WHERE wallet_id = :wallet_id ORDER BY timestamp DESC",
        {"wallet_id": wallet_id},
        UTXORecord,
    )


async def insert_utxos_for_wallet(wallet_id: str, utxos: list) -> None:
    for utxo in utxos:
        await db.execute(
            """INSERT INTO silnt.utxos (txid, vout, amount, priv_key_tweak, pub_key, utxo_state, timestamp, wallet_id)
            VALUES (:txid, :vout, :amount, :priv_key_tweak, :pub_key, :utxo_state, :timestamp, :wallet_id)
            ON CONFLICT (txid) DO UPDATE SET
                amount = EXCLUDED.amount,
                priv_key_tweak = EXCLUDED.priv_key_tweak,
                pub_key = EXCLUDED.pub_key,
                utxo_state = CASE
                    WHEN silnt.utxos.utxo_state IN ('spent', 'unconfirmed_spent')
                    THEN silnt.utxos.utxo_state
                    ELSE EXCLUDED.utxo_state
                END""",
            utxo.to_db_row(wallet_id),
        )


async def update_unconfirmed_utxo(wallet_id: str, txid: str):
    await db.execute(
        "UPDATE silnt.utxos SET utxo_state = 'unconfirmed_spent' WHERE txid = :txid AND wallet_id = :wallet_id",
        {"txid": txid, "wallet_id": wallet_id},
    )


async def get_wallet_addresses(wallet_id: str) -> list:
    return await db.fetchall(
        "SELECT * FROM silnt.wallet_addresses WHERE wallet_id = :wallet_id ORDER BY label_index ASC",
        {"wallet_id": wallet_id},
    )


async def count_wallet_addresses(wallet_id: str) -> int:
    row = await db.fetchone(
        "SELECT COUNT(*) as cnt FROM silnt.wallet_addresses WHERE wallet_id = :wallet_id",
        {"wallet_id": wallet_id},
    )
    return row["cnt"] if row else 0


async def insert_wallet_address(
    wallet_id: str, sp_address: str, label_index: int, address_id
) -> None:
    await db.execute(
        """INSERT INTO silnt.wallet_addresses (id, wallet_id, sp_address, label_index, created_at)
           VALUES (:id, :wallet_id, :sp_address, :label_index, :created_at)""",
        {
            "id": address_id,
            "wallet_id": wallet_id,
            "sp_address": sp_address,
            "label_index": label_index,
            "created_at": int(time.time()),
        },
    )


async def delete_wallet_label_addresses(wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.wallet_addresses WHERE wallet_id = :wallet_id",
        {"wallet_id": wallet_id},
    )


async def delete_wallet_label_address(address_id: str, wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.wallet_addresses WHERE id = :id AND wallet_id = :wallet_id",
        {"id": address_id, "wallet_id": wallet_id},
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


async def get_cloudflare_config() -> CloudflareConfig:
    row = await db.fetchone(
        "SELECT json_data FROM silnt.blindbit_config WHERE id = :id",
        {"id": CF_CONFIG_ID},
    )
    if not row:
        return CloudflareConfig()
    return CloudflareConfig(**json.loads(row["json_data"]))


async def update_cloudflare_config(config: CloudflareConfig) -> CloudflareConfig:
    json_data = config.json()
    existing = await db.fetchone(
        "SELECT id FROM silnt.blindbit_config WHERE id = :id",
        {"id": CF_CONFIG_ID},
    )
    if existing:
        await db.execute(
            "UPDATE silnt.blindbit_config SET json_data = :json_data WHERE id = :id",
            {"json_data": json_data, "id": CF_CONFIG_ID},
        )
    else:
        await db.execute(
            "INSERT INTO silnt.blindbit_config (id, json_data) VALUES (:id, :json_data)",
            {"id": CF_CONFIG_ID, "json_data": json_data},
        )
    return config
