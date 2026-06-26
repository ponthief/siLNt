import json
import time
import secrets
import os
from typing import Optional, Tuple, List
from lnbits.db import Database
from lnbits.helpers import urlsafe_short_hash
from .models import (
    Config,
    BlindbitConfig,
    WalletAccount,
    UTXORecord,
    WalletAddress,
    CloudflareConfig,
    UpdateUtxoLabel,
    TrustedDevice,
    UserPrefs,
    Bip353Request,
    BoltzSwapRecord
)

from .models import PayjoinDescriptor, PayjoinRequest
from embit.descriptor import Descriptor, Key
from embit.descriptor.arguments import AllowedDerivation
from embit.networks import NETWORKS
from datetime import datetime, timedelta, timezone

db = Database("ext_silnt")

# Singleton row ID for the global blindbit config
BLINDBIT_CONFIG_ID = "blindbit"
CF_CONFIG_ID = "cloudflare_config"
BIP352_CHANGE_LABEL_INDEX = 1

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
            """INSERT INTO silnt.utxos
                 (txid, vout, amount, priv_key_tweak, pub_key, utxo_state, timestamp, wallet_id, label)
               VALUES
                 (:txid, :vout, :amount, :priv_key_tweak, :pub_key, :utxo_state, :timestamp, :wallet_id, :label)
               ON CONFLICT (txid, vout, wallet_id) DO UPDATE SET
                 amount         = EXCLUDED.amount,
                 priv_key_tweak = EXCLUDED.priv_key_tweak,
                 pub_key        = EXCLUDED.pub_key,
                 utxo_state     = CASE
                     WHEN silnt.utxos.utxo_state IN ('spent', 'unconfirmed_spent')
                     THEN silnt.utxos.utxo_state
                     ELSE EXCLUDED.utxo_state
                 END,
                 label = COALESCE(silnt.utxos.label, EXCLUDED.label)
            """,
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

async def get_wallet_address(id: str) -> Optional[WalletAddress]:
    return await db.fetchone(
        "SELECT * FROM silnt.wallet_addresses WHERE id = :id",
        {"id": id},
        WalletAddress
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
    cfg = CloudflareConfig(**json.loads(row["json_data"])) if row else CloudflareConfig()
    # BitMail/DNS domain is deployment config, not an admin-editable field.
    # Source it from SILNT_BITMAIL_DOMAIN when set; otherwise keep whatever is
    # stored (back-compat). Strip a leading dot in case someone reuses the
    # cookie-domain form (".thrilla.me" → "thrilla.me").
    env_domain = os.environ.get("SILNT_BITMAIL_DOMAIN", "").strip().lstrip(".")
    if env_domain:
        cfg.domain = env_domain
    return cfg


async def update_cloudflare_config(config: CloudflareConfig) -> CloudflareConfig:
    # Domain is not admin-editable — force it from the env var (or keep the
    # currently-effective value), ignoring whatever the client sent.
    env_domain = os.environ.get("SILNT_BITMAIL_DOMAIN", "").strip().lstrip(".")
    if env_domain:
        config.domain = env_domain
    else:
        # No env override: preserve the existing stored domain rather than let
        # the client change it.
        existing = await db.fetchone(
            "SELECT json_data FROM silnt.blindbit_config WHERE id = :id",
            {"id": CF_CONFIG_ID},
        )
        if existing:
            try:
                config.domain = CloudflareConfig(**json.loads(existing["json_data"])).domain
            except Exception:
                pass
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

async def count_silnt_wallets(user: str, network: Optional[str] = None) -> int:
    if network:
        row = await db.fetchone(
            'SELECT COUNT(*) AS c FROM silnt.wallets WHERE "user" = :user AND network = :network',
            {"user": user, "network": network},
        )
    else:
        row = await db.fetchone(
            'SELECT COUNT(*) AS c FROM silnt.wallets WHERE "user" = :user',
            {"user": user},
        )
    return row["c"] if row else 0

async def update_utxo_label_by_txid(
    txid: str, label: Optional[str], wallet_id: Optional[str]
) -> int:
    """
    Set or clear the label on UTXO(s) matching the given txid.
    Returns the number of rows updated. Empty string label is treated as NULL.
    Optionally scoped to a specific wallet_id for safety.
    """
    label_value = (label or "").strip() or None
    if wallet_id:
        result = await db.execute(
            """UPDATE silnt.utxos SET label = :label
               WHERE txid = :txid AND wallet_id = :wallet_id""",
            {"label": label_value, "txid": txid, "wallet_id": wallet_id},
        )
    else:
        result = await db.execute(
            "UPDATE silnt.utxos SET label = :label WHERE txid = :txid",
            {"label": label_value, "txid": txid},
        )
    return getattr(result, "rowcount", 0) or 0


async def get_utxos_by_txid(txid: str) -> list:
    """Return all UTXO rows for a given txid (may have multiple vouts)."""
    rows = await db.fetchall(
        "SELECT * FROM silnt.utxos WHERE txid = :txid", {"txid": txid}
    )
    return [UTXORecord(**dict(r)) for r in rows]

async def get_next_label_index(wallet_id: str) -> int:
    row = await db.fetchone(
        """SELECT COALESCE(MAX(label_index), 0) AS max_idx
           FROM silnt.wallet_addresses
           WHERE wallet_id = :wid""",
        {"wid": wallet_id},
    )
    next_idx = int((row["max_idx"] or 0)) + 1
    # Skip the BIP-352 change label
    if next_idx <= BIP352_CHANGE_LABEL_INDEX:
        next_idx = BIP352_CHANGE_LABEL_INDEX + 1   # → 2
    return next_idx


async def address_exists(wallet_id: str, sp_address: str) -> bool:
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallet_addresses
           WHERE wallet_id = :wid AND sp_address = :addr""",
        {"wid": wallet_id, "addr": sp_address},
    )
    return row is not None

async def label_index_taken(wallet_id: str, label_index: int) -> bool:
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallet_addresses
           WHERE wallet_id = :wid AND label_index = :idx""",
        {"wid": wallet_id, "idx": label_index},
    )
    return row is not None

async def save_wallet_address(
    wallet_id: str,
    sp_address: str,
    label: Optional[str],
    label_index: int,
) -> dict:
    addr_id = secrets.token_urlsafe(16)
    now     = int(time.time())
    await db.execute(
        """INSERT INTO silnt.wallet_addresses
              (id, wallet_id, sp_address, label, label_index, created_at)
           VALUES (:id, :wid, :addr, :label, :idx, :ts)""",
        {
            "id":    addr_id,
            "wid":   wallet_id,
            "addr":  sp_address,
            "label": (label or "").strip() or None,
            "idx":   label_index,
            "ts":    now,
        },
    )
    return {
        "id":          addr_id,
        "wallet_id":   wallet_id,
        "sp_address":  sp_address,
        "label":       label,
        "label_index": label_index,
        "created_at":  now,
    }

async def get_unspent_dust_check(wallet_id: str) -> list[dict]:
    rows = await db.fetchall(
        """SELECT txid, vout, amount, suspected_dust FROM silnt.utxos
           WHERE wallet_id = :wid AND utxo_state = 'unspent'""",
        {"wid": wallet_id}        
    )
    return [dict(r) for r in rows]

async def update_utxo_dust_flag(txid: str, vout: int, flag: bool) -> None:
    await db.execute(
        """UPDATE silnt.utxos SET suspected_dust = :flag
           WHERE txid = :txid AND vout = :vout""",
        {"flag": flag, "txid": txid, "vout": vout},
    )


async def update_utxo_frozen(txid: str, vout: int, frozen: bool) -> None:
    await db.execute(
        """UPDATE silnt.utxos SET frozen = :frozen
           WHERE txid = :txid AND vout = :vout""",
        {"frozen": frozen, "txid": txid, "vout": vout},
    )

async def owner_check_dust(txid: str, vout: int):
    return await db.fetchone(
        "SELECT wallet_id FROM silnt.utxos WHERE txid = :txid AND vout = :vout",
        {"txid": txid, "vout": vout},
    )

async def get_eligible_utxos(
    wallet_id: str,
    txid_vout_pairs: list[tuple[str, int]],
) -> list[dict]:
    """
    Return rows from silnt.utxos that are:
      - belong to wallet_id
      - state = 'unspent'
      - NOT frozen
      - match one of the (txid, vout) pairs supplied
    """
    if not txid_vout_pairs:
        return []

    # Build a parameterized IN-clause using row tuples
    placeholders = []
    params = {"wid": wallet_id}
    for i, (txid, vout) in enumerate(txid_vout_pairs):
        placeholders.append(f"(:t{i}, :v{i})")
        params[f"t{i}"] = txid
        params[f"v{i}"] = vout

    sql = f"""
        SELECT txid, vout, amount FROM silnt.utxos
        WHERE wallet_id = :wid
          AND utxo_state = 'unspent'
          AND COALESCE(frozen, FALSE) = FALSE
          AND (txid, vout) IN ({", ".join(placeholders)})
    """
    rows = await db.fetchall(sql, params)
    return [dict(r) for r in rows]

async def update_address_label(addr_id: str, label: Optional[str]) -> int:
    """
    Update only the label string on a labeled address. Returns rows affected.
    Empty string is stored as NULL.
    """
    label_value = (label or "").strip() or None
    result = await db.execute(
        "UPDATE silnt.wallet_addresses SET label = :label WHERE id = :id",
        {"label": label_value, "id": addr_id},
    )
    return getattr(result, "rowcount", 0) or 0

async def get_wallet_unspent_utxos_for_dust_check(wallet_id: str) -> list[dict]:
    rows = await db.fetchall(
        """SELECT txid, vout, amount, suspected_dust
           FROM silnt.utxos
           WHERE wallet_id = :wid AND utxo_state = 'unspent'""",
        {"wid": wallet_id},
    )
    return [dict(r) for r in rows]


async def get_wallet_owned_txids(wallet_id: str) -> set[str]:
    rows = await db.fetchall(
        "SELECT txid FROM silnt.utxos WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    return {r["txid"] for r in rows}


async def mark_utxos_spent_by_tx(
    wallet_id:       str,
    input_outpoints: list[tuple[str, int]],
    spending_txid:   str,
) -> int:
    """Mark UTXOs as spent by a tx we broadcast — also records spent_at timestamp."""
    if not input_outpoints:
        return 0    
    now = int(time.time())

    placeholders = []
    params = {
        "wid":           wallet_id,
        "spending_txid": spending_txid,
        "spent_at":      now,
    }
    for i, (in_txid, in_vout) in enumerate(input_outpoints):
        placeholders.append(f"(:t{i}, :v{i})")
        params[f"t{i}"] = in_txid
        params[f"v{i}"] = in_vout

    sql = f"""
        UPDATE silnt.utxos
        SET utxo_state    = 'unconfirmed_spent',
            spent_in_txid = :spending_txid,
            spent_at      = :spent_at
        WHERE wallet_id = :wid
          AND (txid, vout) IN ({", ".join(placeholders)})
    """
    result = await db.execute(sql, params)
    return getattr(result, "rowcount", 0) or 0

async def mark_utxos_spent_by_outpoints(
    wallet_id:     str,
    outpoints:     list[tuple[str, int]],   # [(txid, vout), ...]
    spending_txid: str,
) -> int:
    if not outpoints:
        return 0
    now = int(time.time())
    affected = 0
    for (in_txid, in_vout) in outpoints:
        result = await db.execute(
            """UPDATE silnt.utxos
                  SET utxo_state    = 'unconfirmed_spent',
                      spent_in_txid = :stxid,
                      spent_at      = :ts
                WHERE wallet_id = :wid
                  AND txid      = :txid
                  AND vout      = :vout
                  AND utxo_state IN ('unspent', 'unconfirmed')""",
            {"wid": wallet_id, "txid": in_txid, "vout": int(in_vout),
             "stxid": spending_txid, "ts": now},
        )
        affected += getattr(result, "rowcount", 0) or 0
    return affected

async def is_own_sent_tx(wallet_id: str, txid: str) -> bool:
    """
    Check if this wallet has broadcast a transaction with this txid.
    A row exists with spent_in_txid = txid iff we broadcast it.
    """
    row = await db.fetchone(
        """SELECT 1 FROM silnt.utxos
           WHERE wallet_id = :wid AND spent_in_txid = :txid
           LIMIT 1""",
        {"wid": wallet_id, "txid": txid},
    )
    return row is not None

async def get_wallet_owned_outpoints(wallet_id: str) -> set[tuple[str, int]]:
    """
    All (txid, vout) outpoints this wallet has ever owned, regardless of state.
    Used to classify funding-tx inputs as self-send vs external.
    """
    rows = await db.fetchall(
        "SELECT txid, vout FROM silnt.utxos WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    return {(r["txid"], int(r["vout"])) for r in rows}

async def get_utxo_freeze_reason(txid: str, vout: int) -> Optional[str]:
    """Return current freeze_reason ('auto'|'manual'|None) for a UTXO."""
    row = await db.fetchone(
        "SELECT freeze_reason FROM silnt.utxos WHERE txid = :txid AND vout = :vout",
        {"txid": txid, "vout": vout},
    )
    return row["freeze_reason"] if row else None

async def set_utxo_freeze_auto(txid: str, vout: int) -> None:
    """
    Mark a UTXO as auto-frozen (dust eval owns this lock). Only acts on UTXOs that
    are not user-owned: freeze_reason NULL or already 'auto'. A 'manual' freeze or
    a 'manual_unfrozen' override is left untouched.
    """
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = TRUE, freeze_reason = 'auto'
           WHERE txid = :txid AND vout = :vout
             AND (freeze_reason IS NULL OR freeze_reason = 'auto')
        """,
        {"txid": txid, "vout": vout},
    )

async def set_utxo_freeze_manual(txid: str, vout: int) -> None:
    """Mark a UTXO as manually frozen (user owns this lock)."""
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = TRUE, freeze_reason = 'manual'
           WHERE txid = :txid AND vout = :vout""",
        {"txid": txid, "vout": vout},
    )
    
async def clear_utxo_freeze_manual(txid: str, vout: int) -> None:
    """
    User-initiated unfreeze. Clears the frozen flag regardless of who set it, and
    records freeze_reason = 'manual_unfrozen' so the dust evaluator knows this was
    a deliberate user override and must NOT auto-re-freeze it.
    """
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = FALSE, freeze_reason = 'manual_unfrozen'
           WHERE txid = :txid AND vout = :vout""",
        {"txid": txid, "vout": vout},
    )


async def clear_utxo_freeze_auto(txid: str, vout: int) -> None:
    """
    Clear an auto-freeze. NO-OP if the UTXO was manually frozen — only the
    user (via the unfreeze endpoint) can clear those.
    """
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = FALSE, freeze_reason = NULL
           WHERE txid = :txid AND vout = :vout AND freeze_reason = 'auto'""",
        {"txid": txid, "vout": vout},
    )


async def clear_utxo_freeze_manual(txid: str, vout: int) -> None:
    """User-initiated unfreeze — clears regardless of who set it."""
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = FALSE, freeze_reason = NULL
           WHERE txid = :txid AND vout = :vout""",
        {"txid": txid, "vout": vout},
    )

async def normalize_unfrozen_override(txid: str, vout: int) -> None:
    """Once a UTXO is no longer dust, drop a lingering 'manual_unfrozen' marker."""
    await db.execute(
        """UPDATE silnt.utxos SET freeze_reason = NULL
           WHERE txid = :txid AND vout = :vout AND freeze_reason = 'manual_unfrozen'""",
        {"txid": txid, "vout": vout},
    )

async def get_wallet_receives(wallet_id: str) -> list[dict]:
    """
    Group all owned UTXOs by funding txid. Each row = one tx where we received.
    Returns: [{txid, timestamp, output_sum, output_count, labels[]}, ...]
    """
    rows = await db.fetchall(
        """
        SELECT
            txid,
            MIN(timestamp)             AS timestamp,
            SUM(amount)                AS output_sum,
            COUNT(*)                   AS output_count,
            ARRAY_REMOVE(ARRAY_AGG(DISTINCT label), NULL) AS labels
        FROM silnt.utxos
        WHERE wallet_id = :wid
        GROUP BY txid
        """,
        {"wid": wallet_id},
    )
    return [
        {
            "txid":         r["txid"],
            "timestamp":    int(r["timestamp"] or 0),
            "output_sum":   int(r["output_sum"] or 0),
            "output_count": int(r["output_count"] or 0),
            "labels":       list(r["labels"] or []),
        }
        for r in rows
    ]


async def get_wallet_sends(wallet_id: str) -> list[dict]:
    """
    Group all UTXOs we've spent by spent_in_txid. Each row = one tx we sent.
    Returns: [{txid, spent_at, input_sum, input_count}, ...]
    """
    rows = await db.fetchall(
        """
        SELECT
            spent_in_txid              AS txid,
            MIN(spent_at)              AS spent_at,
            SUM(amount)                AS input_sum,
            COUNT(*)                   AS input_count
        FROM silnt.utxos
        WHERE wallet_id = :wid AND spent_in_txid IS NOT NULL
        GROUP BY spent_in_txid
        """,
        {"wid": wallet_id},
    )
    return [
        {
            "txid":        r["txid"],
            "spent_at":    int(r["spent_at"] or 0),
            "input_sum":   int(r["input_sum"] or 0),
            "input_count": int(r["input_count"] or 0),
        }
        for r in rows
    ]


async def get_utxos_for_txid(wallet_id: str, txid: str) -> list[dict]:
    """All UTXOs we own at a given funding txid (for the detail view)."""
    rows = await db.fetchall(
        """SELECT txid, vout, amount, label, label_index, utxo_state, timestamp
           FROM silnt.utxos
           WHERE wallet_id = :wid AND txid = :txid
           ORDER BY vout""",
        {"wid": wallet_id, "txid": txid},
    )
    return [dict(r) for r in rows]


async def get_utxos_spent_in_tx(wallet_id: str, txid: str) -> list[dict]:
    """All UTXOs we spent in a given tx (for the detail view's input list)."""
    rows = await db.fetchall(
        """SELECT txid, vout, amount, label, label_index, utxo_state, timestamp, spent_at
           FROM silnt.utxos
           WHERE wallet_id = :wid AND spent_in_txid = :txid
           ORDER BY timestamp""",
        {"wid": wallet_id, "txid": txid},
    )
    return [dict(r) for r in rows]


async def get_owned_pubkeys(wallet_id: str) -> set[str]:
    """All x-only output pubkeys this wallet has ever owned — used to filter
    out own change from a send tx's outputs (anything not in this set is
    treated as a recipient)."""
    rows = await db.fetchall(
        "SELECT pub_key FROM silnt.utxos WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    return {r["pub_key"] for r in rows if r["pub_key"]}

async def add_trusted_device(
    user_id:    str,
    device_id:  str,
    user_agent: Optional[str],
    ip:         Optional[str],
    label:      Optional[str] = None,
) -> dict:
    now = int(time.time())
    row_id = secrets.token_urlsafe(16)
    await db.execute(
        """INSERT INTO silnt.trusted_devices
              (id, user_id, device_id, user_agent, ip, label, confirmed_at, last_seen_at)
           VALUES (:id, :uid, :did, :ua, :ip, :label, :ts, :ts)
           ON CONFLICT (user_id, device_id) DO UPDATE
              SET last_seen_at = EXCLUDED.last_seen_at,
                  user_agent   = EXCLUDED.user_agent,
                  ip           = EXCLUDED.ip""",
        {
            "id":    row_id,
            "uid":   user_id,
            "did":   device_id,
            "ua":    (user_agent or "")[:512],
            "ip":    (ip or "")[:64],
            "label": label,
            "ts":    now,
        },
    )
    return {"id": row_id, "device_id": device_id, "confirmed_at": now}


async def get_trusted_device(user_id: str, device_id: str) -> Optional[TrustedDevice]:
    row = await db.fetchone(
        """SELECT * FROM silnt.trusted_devices
           WHERE user_id = :uid AND device_id = :did""",
        {"uid": user_id, "did": device_id},
    )
    return TrustedDevice(**dict(row)) if row else None


async def list_trusted_devices(user_id: str) -> List[TrustedDevice]:
    rows = await db.fetchall(
        """SELECT * FROM silnt.trusted_devices
           WHERE user_id = :uid
           ORDER BY confirmed_at DESC""",
        {"uid": user_id},
    )
    return [TrustedDevice(**dict(r)) for r in rows]


async def count_trusted_devices(user_id: str) -> int:
    row = await db.fetchone(
        "SELECT COUNT(*) AS c FROM silnt.trusted_devices WHERE user_id = :uid",
        {"uid": user_id},
    )
    return int(row["c"] or 0)


async def revoke_trusted_device(user_id: str, device_row_id: str) -> int:
    result = await db.execute(
        """DELETE FROM silnt.trusted_devices
           WHERE user_id = :uid AND id = :id""",
        {"uid": user_id, "id": device_row_id},
    )
    return getattr(result, "rowcount", 0) or 0


async def revoke_all_other_devices(user_id: str, keep_device_id: str) -> int:
    result = await db.execute(
        """DELETE FROM silnt.trusted_devices
           WHERE user_id = :uid AND device_id != :keep""",
        {"uid": user_id, "keep": keep_device_id},
    )
    return getattr(result, "rowcount", 0) or 0


async def touch_trusted_device(user_id: str, device_id: str) -> None:
    """Update last_seen_at when the device makes a request."""
    await db.execute(
        """UPDATE silnt.trusted_devices
           SET last_seen_at = :ts
           WHERE user_id = :uid AND device_id = :did""",
        {"uid": user_id, "did": device_id, "ts": int(time.time())},
    )

async def get_user_prefs(user_id: str) -> Optional[UserPrefs]:
    row = await db.fetchone(
        "SELECT * FROM silnt.user_prefs WHERE user_id = :uid",
        {"uid": user_id},
    )
    return UserPrefs(**dict(row)) if row else None


async def upsert_user_prefs(
    user_id:             str,
    dust_threshold_sats: Optional[int],
) -> UserPrefs:
    now = int(time.time())
    await db.execute(
        """INSERT INTO silnt.user_prefs (user_id, dust_threshold_sats, updated_at)
           VALUES (:uid, :dts, :ts)
           ON CONFLICT (user_id) DO UPDATE
             SET dust_threshold_sats = EXCLUDED.dust_threshold_sats,
                 updated_at          = EXCLUDED.updated_at""",
        {"uid": user_id, "dts": dust_threshold_sats, "ts": now},
    )
    return UserPrefs(
        user_id             = user_id,
        dust_threshold_sats = dust_threshold_sats,
        updated_at          = now,
    )


async def get_effective_dust_threshold(user_id: str) -> int:
    """
    Resolve the dust threshold for a user.
    Priority:
      1. User's own prefs.dust_threshold_sats (if non-NULL and > 0)
      2. Admin's BlindbitConfig.dust_threshold_sats (if non-zero)
      3. Hard fallback: 5000 sats
    """
    prefs = await get_user_prefs(user_id)
    if prefs and prefs.dust_threshold_sats and prefs.dust_threshold_sats > 0:
        return int(prefs.dust_threshold_sats)
    blindbit = await get_blindbit_config()
    return int(blindbit.dust_threshold_sats or 5000)

async def create_bip353_request(
    user_id:            str,
    wallet_id:          str,
    sp_address:         str,    
    requested_username: str,
    message:            Optional[str],
    address_id:         Optional[str] = None,
) -> Bip353Request:
    row_id = secrets.token_urlsafe(16)
    now    = int(time.time())
    await db.execute(
        """INSERT INTO silnt.bip353_requests
              (id, user_id, wallet_id, address_id, sp_address, requested_username, message,
               status, created_at)
           VALUES (:id, :uid, :wid, :aid, :sp, :uname, :msg, 'pending', :ts)""",
        {
            "id":    row_id,
            "uid":   user_id,
            "wid":   wallet_id,
            "aid":   address_id,
            "sp":    sp_address,
            "uname": requested_username,
            "msg":   message,
            "ts":    now,
        },
    )
    return Bip353Request(
        id=row_id, user_id=user_id, wallet_id=wallet_id, address_id=address_id,
        sp_address=sp_address, requested_username=requested_username, message=message,
        status="pending", created_at=now,
    )

async def address_has_approved_bitmail(wallet_id: str, address_id: Optional[str]) -> bool:
    """
    True if this specific SP address (base = NULL address_id, or a labeled
    address row) has EVER had an approved BitMail. Enforces 'assign once' per
    address — the slot stays burned even after removal.
    """
    if address_id is None:
        row = await db.fetchone(
            """SELECT 1 FROM silnt.bip353_requests
               WHERE wallet_id = :wid AND address_id IS NULL AND status = 'approved'
               LIMIT 1""",
            {"wid": wallet_id},
        )
    else:
        row = await db.fetchone(
            """SELECT 1 FROM silnt.bip353_requests
               WHERE wallet_id = :wid AND address_id = :aid AND status = 'approved'
               LIMIT 1""",
            {"wid": wallet_id, "aid": address_id},
        )
    return row is not None

async def update_label_hr_address(address_id: str, hr_address: str) -> None:
    await db.execute(
        "UPDATE silnt.wallet_addresses SET hr_address = :hra WHERE id = :id",
        {"hra": hr_address, "id": address_id},
    )

async def clear_label_hr_address(address_id: str) -> None:
    await db.execute(
        "UPDATE silnt.wallet_addresses SET hr_address = NULL WHERE id = :id",
        {"id": address_id},
    )
# Also check the existing wallets.hr_address column (base addresses)
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallets
           WHERE LOWER(hr_address) LIKE LOWER(:pat)""",
        {"pat": f"{username}@%"},
    )
    if row:
        return True
    # And labeled-address BitMails (wallet_addresses.hr_address)
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallet_addresses
           WHERE LOWER(hr_address) LIKE LOWER(:pat)""",
        {"pat": f"{username}@%"},
    )
    return row is not None

async def get_user_hr_addresses(user_id: str) -> list[str]:
    rows = await db.fetchall(
        'SELECT hr_address FROM silnt.wallets '
        'WHERE "user" = :uid AND hr_address IS NOT NULL AND hr_address <> \'\'',
        {"uid": user_id},
    )
    out = [r["hr_address"] for r in rows if r["hr_address"]]
    # Labeled-address BitMails belonging to this user's wallets, too.
    label_rows = await db.fetchall(
        '''SELECT wa.hr_address FROM silnt.wallet_addresses wa
           JOIN silnt.wallets w ON w.id = wa.wallet_id
           WHERE w."user" = :uid AND wa.hr_address IS NOT NULL AND wa.hr_address <> \'\'''',
        {"uid": user_id},
    )
    out.extend(r["hr_address"] for r in label_rows if r["hr_address"])
    return out

async def get_bip353_request(req_id: str) -> Optional[Bip353Request]:
    row = await db.fetchone(
        "SELECT * FROM silnt.bip353_requests WHERE id = :id",
        {"id": req_id},
    )
    return Bip353Request(**dict(row)) if row else None


async def list_user_bip353_requests(user_id: str) -> List[Bip353Request]:
    rows = await db.fetchall(
        """SELECT * FROM silnt.bip353_requests
           WHERE user_id = :uid
           ORDER BY created_at DESC""",
        {"uid": user_id},
    )
    return [Bip353Request(**dict(r)) for r in rows]


async def list_pending_bip353_requests() -> List[Bip353Request]:
    rows = await db.fetchall(
        """SELECT * FROM silnt.bip353_requests
           WHERE status = 'pending'
           ORDER BY created_at ASC"""
    )
    return [Bip353Request(**dict(r)) for r in rows]


async def is_username_taken(username: str) -> bool:
    """Check if username is already approved + active for someone."""
    row = await db.fetchone(
        """SELECT 1 FROM silnt.bip353_requests
           WHERE LOWER(final_username) = LOWER(:uname)
             AND status = 'approved'""",
        {"uname": username},
    )
    if row:
        return True
    # Also check the existing wallets.hr_address column (legacy addresses)
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallets
           WHERE LOWER(hr_address) LIKE LOWER(:pat)""",
        {"pat": f"{username}@%"},
    )
    return row is not None


async def update_bip353_request_status(
    req_id:        str,
    status:        str,
    processed_by:  str,
    final_username: Optional[str] = None,
    reject_reason:  Optional[str] = None,
) -> int:
    now = int(time.time())
    result = await db.execute(
        """UPDATE silnt.bip353_requests
           SET status         = :status,
               final_username = :final_username,
               reject_reason  = :reject_reason,
               processed_at   = :ts,
               processed_by   = :by
           WHERE id = :id""",
        {
            "id":             req_id,
            "status":         status,
            "final_username": final_username,
            "reject_reason":  reject_reason,
            "ts":             now,
            "by":             processed_by,
        },
    )
    return getattr(result, "rowcount", 0) or 0


async def cancel_user_request(req_id: str, user_id: str) -> int:
    """User cancels their own pending request."""
    result = await db.execute(
        """UPDATE silnt.bip353_requests
           SET status = 'cancelled', processed_at = :ts
           WHERE id = :id AND user_id = :uid AND status = 'pending'""",
        {"id": req_id, "uid": user_id, "ts": int(time.time())},
    )
    return getattr(result, "rowcount", 0) or 0

async def get_wallet_active_request(wallet_id: str) -> Optional[Bip353Request]:
    """Return the currently pending request for THIS wallet, if any."""
    row = await db.fetchone(
        """SELECT * FROM silnt.bip353_requests
           WHERE wallet_id = :wid AND status = 'pending'
           ORDER BY created_at DESC LIMIT 1""",
        {"wid": wallet_id},
    )
    return Bip353Request(**dict(row)) if row else None


async def get_wallet_last_rejected_request(wallet_id: str) -> Optional[Bip353Request]:
    """Last rejection for THIS wallet — used for per-wallet cooldown."""
    row = await db.fetchone(
        """SELECT * FROM silnt.bip353_requests
           WHERE wallet_id = :wid AND status = 'rejected'
           ORDER BY processed_at DESC LIMIT 1""",
        {"wid": wallet_id},
    )
    return Bip353Request(**dict(row)) if row else None

async def get_utxo(wallet_id: str, txid: str, vout: int) -> Optional[dict]:
    """
    Fetch a single UTXO by (wallet_id, txid, vout).
    Returns a dict with txid, vout, spent_in_txid, utxo_state — or None if absent.
    """
    rows = await db.fetchall(
        """SELECT txid, vout, spent_in_txid, utxo_state
             FROM silnt.utxos
            WHERE wallet_id = :wid AND txid = :txid AND vout = :vout""",
        {"wid": wallet_id, "txid": txid, "vout": vout},
    )
    return rows[0] if rows else None


async def restore_utxo_to_unspent(wallet_id: str, txid: str, vout: int) -> int:
    """
    Restore an unconfirmed_spent UTXO back to unspent (clears spend metadata).
    Only affects rows currently in 'unconfirmed_spent' state. Returns rowcount.
    """
    result = await db.execute(
        """UPDATE silnt.utxos
              SET utxo_state = 'unspent', spent_in_txid = NULL, spent_at = NULL
            WHERE wallet_id = :wid AND txid = :txid AND vout = :vout
              AND utxo_state = 'unconfirmed_spent'""",
        {"wid": wallet_id, "txid": txid, "vout": vout},
    )
    return getattr(result, "rowcount", 0) or 0


async def get_wallet_unspent_balance(wallet_id: str) -> int:
    """Sum of all 'unspent' UTXO amounts for a wallet."""
    rows = await db.fetchall(
        "SELECT amount FROM silnt.utxos WHERE wallet_id = :wid AND utxo_state = 'unspent'",
        {"wid": wallet_id},
    )
    return sum(r["amount"] for r in rows)

async def delete_all_silnt_data_for_user(user_id: str) -> dict:
    """
    Remove every siLNt artifact belonging to a user across ALL networks: UTXOs,
    addresses, and wallet rows. Network-agnostic — selects the user's wallets
    directly so it doesn't depend on enumerating networks. Returns counts.
    """
    wallet_rows = await db.fetchall(
        'SELECT id FROM silnt.wallets WHERE "user" = :uid',
        {"uid": user_id},
    )
    wallet_ids = [r["id"] for r in wallet_rows]
    if not wallet_ids:
        return {"wallets_deleted": 0}

    for wid in wallet_ids:
        await db.execute("DELETE FROM silnt.utxos WHERE wallet_id = :wid", {"wid": wid})
        await db.execute("DELETE FROM silnt.wallet_addresses WHERE wallet_id = :wid", {"wid": wid})
        await db.execute("DELETE FROM silnt.wallets WHERE id = :wid", {"wid": wid})
        await db.execute("DELETE FROM silnt.wallets WHERE id = :wid", {"wid": wid})

    # Per-user data (keyed by user_id, not wallet_id) — these must be cleaned even
    # if the user somehow had no wallets, so do them unconditionally.
    await db.execute("DELETE FROM silnt.bip353_requests WHERE user_id = :uid", {"uid": user_id})
    await db.execute("DELETE FROM silnt.trusted_devices  WHERE user_id = :uid", {"uid": user_id})
    await db.execute("DELETE FROM silnt.user_prefs        WHERE user_id = :uid", {"uid": user_id})

    return {"wallets_deleted": len(wallet_ids), "wallet_ids": wallet_ids}

async def clear_wallet_hr_address(wallet_id: str) -> None:
    """Blank a wallet's hr_address after its BitMail DNS record is removed."""
    await db.execute(
        "UPDATE silnt.wallets SET hr_address = '' WHERE id = :wid",
        {"wid": wallet_id},
    )

async def count_approved_bip353_for_wallet(wallet_id: str) -> int:
    """How many times this wallet has been granted a BitMail address (approved)."""
    row = await db.fetchone(
        "SELECT COUNT(*) AS c FROM silnt.bip353_requests "
        "WHERE wallet_id = :wid AND status = 'approved'",
        {"wid": wallet_id},
    )
    # db.fetchone shape may be a mapping or a Row; handle both.
    if row is None:
        return 0
    try:
        return int(row["c"])
    except (KeyError, TypeError):
        return int(row[0])

async def create_boltz_swap(rec: BoltzSwapRecord) -> BoltzSwapRecord:
    await db.execute(
        """
        INSERT INTO silnt.boltz_swaps
            (id, wallet_id, silnt_wallet_id, status, timeout_block_height, json_data)
        VALUES (:id, :wallet_id, :silnt_wallet_id, :status, :timeout, :json_data)
        """,
        {
            "id": rec.id,
            "wallet_id": rec.wallet_id,
            "silnt_wallet_id": rec.silnt_wallet_id,
            "status": rec.status,
            "timeout": rec.timeout_block_height,
            "json_data": rec.json(),
        },
    )
    return rec

async def get_boltz_swap(swap_id: str) -> Optional[BoltzSwapRecord]:
    row = await db.fetchone(
        "SELECT json_data FROM silnt.boltz_swaps WHERE id = :id", {"id": swap_id}
    )
    return BoltzSwapRecord(**json.loads(row["json_data"])) if row else None

async def update_boltz_swap(rec: BoltzSwapRecord) -> BoltzSwapRecord:
    await db.execute(
        """
        UPDATE silnt.boltz_swaps
        SET status = :status, timeout_block_height = :timeout,
            updated_at = now(), json_data = :json_data
        WHERE id = :id
        """,
        {"status": rec.status, "timeout": rec.timeout_block_height,
         "json_data": rec.json(), "id": rec.id},
    )
    return rec

async def list_boltz_swaps_by_status(status: str) -> list[BoltzSwapRecord]:
    rows = await db.fetchall(
        "SELECT json_data FROM silnt.boltz_swaps WHERE status = :status",
        {"status": status},
    )
    return [BoltzSwapRecord(**json.loads(r["json_data"])) for r in rows]

async def list_boltz_swaps_for_wallet(
    wallet_id: str, silnt_wallet_id: str | None = None
) -> list[BoltzSwapRecord]:
    rows = await db.fetchall(
        """
        SELECT json_data FROM silnt.boltz_swaps
        WHERE wallet_id = :w OR silnt_wallet_id = :s
        ORDER BY created_at DESC
        """,
        {"w": wallet_id, "s": silnt_wallet_id or wallet_id},
    )
    return [BoltzSwapRecord(**json.loads(r["json_data"])) for r in rows]


async def delete_boltz_swap(swap_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.boltz_swaps WHERE id = :id",
        {"id": swap_id},
    )

async def mark_utxos_confirmed_spent_by_tx(wallet_id: str, spending_txid: str) -> int:
    """
    Finalize a confirmed send: move this wallet's inputs spent in `spending_txid`
    from 'unconfirmed_spent' to 'spent'. Returns rows affected. Idempotent —
    re-running on an already-'spent' tx changes nothing.
    """
    result = await db.execute(
        """UPDATE silnt.utxos
              SET utxo_state = 'spent'
            WHERE wallet_id = :wid
              AND spent_in_txid = :txid
              AND utxo_state = 'unconfirmed_spent'""",
        {"wid": wallet_id, "txid": spending_txid},
    )
    return getattr(result, "rowcount", 0) or 0

async def cancel_pending_request_for_address(wallet_id: str, address_id: Optional[str]) -> int:
    """Cancel any PENDING BitMail request bound to a specific address (a label,
    or the wallet base when address_id is None). Used when the address/wallet is
    deleted so the request doesn't linger in the admin queue. Approved rows are
    left intact (they preserve the wallet's lifetime cap and keep the username
    reserved)."""
    if address_id is None:
        result = await db.execute(
            """UPDATE silnt.bip353_requests
               SET status = 'cancelled', processed_at = :ts
               WHERE wallet_id = :wid AND address_id IS NULL AND status = 'pending'""",
            {"wid": wallet_id, "ts": int(time.time())},
        )
    else:
        result = await db.execute(
            """UPDATE silnt.bip353_requests
               SET status = 'cancelled', processed_at = :ts
               WHERE wallet_id = :wid AND address_id = :aid AND status = 'pending'""",
            {"wid": wallet_id, "aid": address_id, "ts": int(time.time())},
        )
    return getattr(result, "rowcount", 0) or 0


async def cancel_all_pending_requests_for_wallet(wallet_id: str) -> int:
    """Cancel ALL pending BitMail requests for a wallet (any address). Used when
    the whole wallet is deleted."""
    result = await db.execute(
        """UPDATE silnt.bip353_requests
           SET status = 'cancelled', processed_at = :ts
           WHERE wallet_id = :wid AND status = 'pending'""",
        {"wid": wallet_id, "ts": int(time.time())},
    )
    return getattr(result, "rowcount", 0) or 0

async def list_all_bip353_requests(limit: int = 13, offset: int = 0) -> list[Bip353Request]:
    """All BitMail requests (any status), newest first, paginated. Admin history."""
    rows = await db.fetchall(
        """SELECT * FROM silnt.bip353_requests
           ORDER BY created_at DESC
           LIMIT :limit OFFSET :offset""",
        {"limit": limit, "offset": offset},
    )
    return [Bip353Request(**r) for r in rows]

async def delete_bip353_request_if_terminal(req_id: str) -> int:
    """Delete a single request ONLY if it is rejected or cancelled. Approved and
    pending rows are protected (approved = burned-slot/username record; pending =
    still in the queue). Returns rows deleted (0 if not terminal / not found)."""
    result = await db.execute(
        """DELETE FROM silnt.bip353_requests
           WHERE id = :id AND status IN ('rejected', 'cancelled')""",
        {"id": req_id},
    )
    return getattr(result, "rowcount", 0) or 0


async def delete_terminal_bip353_requests() -> int:
    """Bulk-delete ALL rejected/cancelled requests. Approved/pending untouched."""
    result = await db.execute(
        """DELETE FROM silnt.bip353_requests
           WHERE status IN ('rejected', 'cancelled')"""
    )
    return getattr(result, "rowcount", 0) or 0

# ── descriptor parsing ────────────────────────────────────────────────────────
def _embit_net(network: str):
    n = network.lower()
    if n == "mainnet":
        return NETWORKS["main"]
    if n == "regtest":
        return NETWORKS["regtest"]
    return NETWORKS["test"]


def _fmt_path(derivation: list[int]) -> str:
    """[84',1',0'] ints -> '84h/1h/0h'."""
    H = 0x80000000
    parts = []
    for i in derivation:
        if i >= H:
            parts.append(f"{i - H}h")
        else:
            parts.append(str(i))
    return "/".join(parts)


def _strip_checksum(descriptor: str) -> str:
    """Remove BIP-380 '#checksum' so a Sparrow export pasted verbatim parses.
    Checksum is a trailing '#'+8 chars; xpubs/paths never contain '#'."""
    s = (descriptor or "").strip()
    if "#" in s:
        s = s[: s.rindex("#")].strip()
    return s

def _normalize_multipath(descriptor: str) -> str:
    """
    Repair the key-path branch spec so embit can parse it and so BOTH the receive
    (0) and change (1) chains are covered.

    Some clients mangle the literal '<0;1>' (it contains '<' '>') into an empty
    branch, e.g. '...xpub//*'. Others export a single chain '.../0/*'. Normalize
    all of these to the canonical multipath '.../<0;1>/*'.

    Operates on the checksum-stripped string. Only touches the key-path tail
    (after the xpub); never alters the xpub or the [origin] prefix.
    """
    s = _strip_checksum(descriptor)
    # The tail we care about is the '/.../*' after the xpub, before the closing ')'.
    # Repair the two known bad/!canonical forms:
    #   //*        (empty branch  -> the <0;1> was eaten)
    #   /<0;1>/*   (already canonical -> leave)
    #   /0/*       (single receive chain -> expand to multipath)
    if "//*" in s:
        s = s.replace("//*", "/<0;1>/*")
    elif "/<0;1>/*" in s:
        pass  # canonical
    elif "/0/*" in s and "/<0;1>/*" not in s:
        s = s.replace("/0/*", "/<0;1>/*")
    return s

def _prepare_descriptor(descriptor: str) -> str:
    """Checksum-stripped + multipath-normalized string for embit parsing."""
    return _normalize_multipath(descriptor)

def parse_descriptor(descriptor: str) -> dict:
    """
    Parse + validate a BIP-84 output descriptor (Sparrow export).
    Returns {xpub, master_fp, account_path, script_type}. Raises ValueError on
    anything that isn't a single-key wpkh descriptor.
    """
    try:
        d = Descriptor.from_string(_prepare_descriptor(descriptor))
    except Exception as e:
        raise ValueError(f"Could not parse descriptor: {e}")
    if not d.wpkh:
        raise ValueError("Only BIP-84 native SegWit (wpkh) descriptors are supported.")
    if len(d.keys) != 1:
        raise ValueError("Only single-key descriptors are supported.")
    k = d.keys[0]
    if k.origin is None:
        raise ValueError("Descriptor is missing key origin ([fingerprint/path]).")
    return {
        "xpub": str(k.key).split("/")[0],          # strip any /<0;1>/* suffix
        "master_fp": k.origin.fingerprint.hex(),
        "account_path": _fmt_path(k.origin.derivation),
        "script_type": "wpkh",
    }

def derive_descriptor_address(descriptor: str, network: str, chain: int, index: int) -> str:
    """Derive a concrete address from the descriptor: chain 0=receive,1=change."""
    d = Descriptor.from_string(_prepare_descriptor(descriptor))
    return d.derive(index, branch_index=chain).address(_embit_net(network))

# ── descriptors CRUD ──────────────────────────────────────────────────────────
async def create_payjoin_descriptor(
    user_id: str, descriptor: str, network: str, label: Optional[str] = None
) -> PayjoinDescriptor:
    parsed = parse_descriptor(descriptor)
    # Prevent duplicate imports: same user + same account xpub (covers re-pasting
    # the same descriptor, with or without a trailing checksum / whitespace diff).
    existing = await db.fetchall(
        "SELECT id FROM silnt.payjoin_descriptors WHERE user_id = :uid AND xpub = :xpub",
        {"uid": user_id, "xpub": parsed["xpub"]},
    )
    if existing:
        raise ValueError("This wallet (xpub) is already imported.")
    did = urlsafe_short_hash()
    await db.execute(
        """
        INSERT INTO silnt.payjoin_descriptors
            (id, user_id, label, descriptor, xpub, master_fp, account_path,
             script_type, network)
        VALUES
            (:id, :user_id, :label, :descriptor, :xpub, :master_fp, :account_path,
             :script_type, :network)
        """,
        {
            "id": did, "user_id": user_id, "label": label,
            "descriptor": descriptor.strip(), "xpub": parsed["xpub"],
            "master_fp": parsed["master_fp"], "account_path": parsed["account_path"],
            "script_type": parsed["script_type"], "network": network,
        },
    )
    return await get_payjoin_descriptor(did)


async def get_payjoin_descriptor(did: str) -> Optional[PayjoinDescriptor]:
    row = await db.fetchone(
        "SELECT * FROM silnt.payjoin_descriptors WHERE id = :id", {"id": did}
    )
    return PayjoinDescriptor(**row) if row else None


async def list_payjoin_descriptors(user_id: str) -> list[PayjoinDescriptor]:
    rows = await db.fetchall(
        "SELECT * FROM silnt.payjoin_descriptors WHERE user_id = :uid ORDER BY created_at DESC",
        {"uid": user_id},
    )
    return [PayjoinDescriptor(**r) for r in rows]

async def list_payjoin_descriptor_user_ids(exclude_user_id: Optional[str] = None) -> list[str]:
    """Distinct user_ids that have imported at least one PayJoin descriptor
    (i.e. can actually receive a PayJoin). Optionally exclude the caller."""
    rows = await db.fetchall(
        "SELECT DISTINCT user_id FROM silnt.payjoin_descriptors", {}
    )
    ids = [r["user_id"] for r in rows]
    if exclude_user_id:
        ids = [i for i in ids if i != exclude_user_id]
    return ids

async def delete_payjoin_descriptor(did: str, user_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.payjoin_descriptors WHERE id = :id AND user_id = :uid",
        {"id": did, "uid": user_id},
    )


async def get_reserved_outpoints(user_id: str) -> set:
    """
    Outpoints (txid:vout) reserved by this user's PENDING PayJoins — as sender
    (sender_inputs) or receiver (receiver_input). 'Pending' = not terminal
    (BROADCAST/CANCELLED). Used to soft-lock UTXOs so they can't be double-
    selected in another siLNt PayJoin. (Watch-only: this is siLNt-scope only;
    it can't stop the user spending the coins directly in their own wallet.)
    """
    rows = await db.fetchall(
        """
        SELECT sender_inputs, receiver_input FROM silnt.payjoin_requests
        WHERE (sender_user_id = :uid OR receiver_user_id = :uid)
          AND status IN ('PROPOSED','ACCEPTED','CONTRIBUTED','FINALIZING')
        """,
        {"uid": user_id},
    )
    reserved = set()
    for r in rows:
        for col in ("sender_inputs", "receiver_input"):
            raw = r[col]
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except Exception:
                continue
            items = data if isinstance(data, list) else [data]
            for u in items:
                if isinstance(u, dict) and "txid" in u and "vout" in u:
                    reserved.add(f"{u['txid']}:{u['vout']}")
    return reserved

# ── requests CRUD ─────────────────────────────────────────────────────────────
async def create_payjoin_request(
    sender_user_id: str, sender_username: str, sender_descriptor_id: str,
    receiver_username: str, amount_sats: int, fee_rate: float,
    payment_address: str, sender_inputs: list[dict],
    receiver_user_id: Optional[str] = None, expiry_seconds: int = 3600,
) -> PayjoinRequest:
    rid = urlsafe_short_hash()
    # expires_at as a real datetime (TIMESTAMP column). Match however your other
    # CRUD writes datetimes — if they pass datetime objects, this is correct; if
    # they use db.timestamp_now + interval SQL, adapt accordingly.    
    expires_at = int(time.time()) + expiry_seconds
    await db.execute(
        """
        INSERT INTO silnt.payjoin_requests
            (id, status, sender_user_id, sender_username, sender_descriptor_id,
             receiver_user_id, receiver_username, amount_sats, fee_rate,
             payment_address, sender_inputs, expires_at)
        VALUES
            (:id, 'PROPOSED', :suid, :suser, :sdid, :ruid, :ruser, :amount,
             :fee_rate, :pay_addr, :sinputs, :expires)
        """,
        {
            "id": rid, "suid": sender_user_id, "suser": sender_username,
            "sdid": sender_descriptor_id, "ruid": receiver_user_id,
            "ruser": receiver_username, "amount": amount_sats, "fee_rate": fee_rate,
            "pay_addr": payment_address, "sinputs": json.dumps(sender_inputs),
            "expires": expires_at,
        },
    )
    return await get_payjoin_request(rid)


async def get_payjoin_request(rid: str) -> Optional[PayjoinRequest]:
    row = await db.fetchone(
        "SELECT * FROM silnt.payjoin_requests WHERE id = :id", {"id": rid}
    )
    return PayjoinRequest(**row) if row else None


async def list_payjoin_requests_for_receiver(
    receiver_user_id: str, status: Optional[str] = None
) -> list[PayjoinRequest]:
    if status:
        rows = await db.fetchall(
            "SELECT * FROM silnt.payjoin_requests WHERE receiver_user_id = :uid "
            "AND status = :st ORDER BY created_at DESC",
            {"uid": receiver_user_id, "st": status},
        )
    else:
        rows = await db.fetchall(
            "SELECT * FROM silnt.payjoin_requests WHERE receiver_user_id = :uid "
            "ORDER BY created_at DESC",
            {"uid": receiver_user_id},
        )
    return [PayjoinRequest(**r) for r in rows]


async def list_payjoin_requests_for_sender(sender_user_id: str) -> list[PayjoinRequest]:
    rows = await db.fetchall(
        "SELECT * FROM silnt.payjoin_requests WHERE sender_user_id = :uid "
        "ORDER BY created_at DESC",
        {"uid": sender_user_id},
    )
    return [PayjoinRequest(**r) for r in rows]


async def update_payjoin_request(rid: str, **fields) -> Optional[PayjoinRequest]:
    """
    Generic field updater. Always bumps updated_at. Pass only columns that exist.
    e.g. update_payjoin_request(rid, status='CONTRIBUTED', psbt=..., fee_sats=...)
    """
    if not fields:
        return await get_payjoin_request(rid)
    fields_sql = ", ".join(f"{k} = :{k}" for k in fields)
    params = {**fields, "id": rid}
    await db.execute(
        f"UPDATE silnt.payjoin_requests SET {fields_sql}, "
        f"updated_at = {db.timestamp_now} WHERE id = :id",
        params,
    )
    return await get_payjoin_request(rid)

async def list_expired_payjoin_requests(now_ts: Optional[int] = None) -> list[PayjoinRequest]:
    """Non-terminal requests past their expiry — for the sweep. expires_at is
    Unix seconds (int)."""
    now_ts = now_ts if now_ts is not None else int(time.time())
    rows = await db.fetchall(
        "SELECT * FROM silnt.payjoin_requests "
        "WHERE status IN ('PROPOSED','CONTRIBUTED') AND expires_at IS NOT NULL "
        "AND expires_at < :now",
        {"now": now_ts},
    )
    return [PayjoinRequest(**r) for r in rows]