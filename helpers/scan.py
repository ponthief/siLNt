"""
scan.py — Silent Payments blockchain scanner for the silnt LNbits extension.

Connects to a BlindBit Oracle (https://localhost:8001) and scans for UTXOs
belonging to the wallet's Silent Payment address.

Oracle endpoints used:
  GET /tweaks/{height}?dustLimit={dust}   — per-block tweaks
  GET /utxos/{height}                     — per-block UTXOs
  GET /filter/spent/{height}              — spent outpoints filter (GCS)

Mirrors the logic in blindbit-scan/pkg/daemon/scan.go.
"""
from __future__ import annotations
import asyncio
import coincurve
import hashlib
import json
import ssl
import struct
from binascii import hexlify, unhexlify
from typing import Optional

import httpx
from loguru import logger

from ..crud import (
    db,
    get_silnt_wallets,
    get_blindbit_config,
    insert_utxos_for_wallet,
    update_balance,
    get_or_create_server_secret,
    get_silnt_wallet
)
from .wallet import decrypt_secret, decrypt_spend_key

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

from coincurve import PublicKey, PrivateKey  

# In-memory progress store — keyed by wallet_id
_scan_progress: dict[str, dict] = {}

# ── Constants ──────────────────────────────────────────────────────────────────
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DUST_LIMIT = 100

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class Label:
    pub_key: bytes   # 33-byte compressed pubkey
    tweak: bytes     # 32-byte scalar
    address: str = ""
    m: int = 0


@dataclass
class FoundOutput:
    output: bytes        # 32-byte x-only pubkey
    sec_key_tweak: bytes # 32-byte scalar
    label: Optional[Label] = None


@dataclass
class UTXOServed:
    txid: bytes          # 32 bytes (little-endian as stored)
    vout: int
    amount: int          # sats
    script_pubkey: bytes # full scriptpubkey (34 bytes for P2TR: OP_1 OP_PUSH32 <32>)
    spent: bool = False
    timestamp: int = 0


@dataclass
class OwnedUTXO:
    txid: bytes
    vout: int
    amount: int
    priv_key_tweak: bytes
    pub_key: bytes       # 32-byte x-only
    utxo_state: str      # "unspent" | "spent" | "unconfirmed_spent"
    timestamp: int = 0
    label: Optional[Label] = None

    def to_db_row(self, wallet_id: str) -> dict:
        """Returns dict ready for DB insert."""
        return {
            "txid": self.txid.hex(),
            "vout": self.vout,
            "amount": self.amount,
            "priv_key_tweak": self.priv_key_tweak.hex(),
            "pub_key": self.pub_key.hex(),
            "utxo_state": self.utxo_state,
            "timestamp": self.timestamp,
            "wallet_id": wallet_id,
        }


# ---------------------------------------------------------------------------
# Elliptic curve helpers (secp256k1 via coincurve)
# ---------------------------------------------------------------------------

def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _ser_u32(k: int) -> bytes:
    """Serialize uint32 as big-endian 4 bytes, matching Go's binary.BigEndian."""
    return struct.pack(">I", k)


def create_shared_secret(
    public_component: bytes,          # 33-byte compressed pubkey (tweak or A_sum)
    scan_key: bytes,                  # 32-byte secret scalar
    input_hash: Optional[bytes] = None,
) -> bytes:
    """
    shared_secret = scan_key * public_component  (optionally * input_hash first)
    Mirrors Go: btcec.S256().ScalarMult(pubKey.X(), pubKey.Y(), secretComponent[:])
    """
    if input_hash is not None:
        # secretComponent = MultPrivateKeys(scan_key, input_hash)
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        scalar = (int.from_bytes(scan_key, "big") * int.from_bytes(input_hash, "big")) % n
        effective_key = scalar.to_bytes(32, "big")
    else:
        effective_key = scan_key
    return PublicKey(public_component).multiply(effective_key).format(compressed=True)


def create_output_pub_key_and_tweak(
    shared_secret: bytes,   # 33-byte compressed
    spend_pub_key: bytes,   # 33-byte compressed
    k: int,
) -> tuple[bytes, bytes]:
    """
    t_k  = TaggedHash("BIP0352/SharedSecret", shared_secret || ser_u32(k))
    P_k  = B_spend + t_k*G   (x-only returned)
    """
    t_k = _tagged_hash("BIP0352/SharedSecret", shared_secret + _ser_u32(k))
    # t_k * G
    tk_point = PublicKey.from_secret(t_k)
    # P_k = B_spend + t_k*G
    p_k = PublicKey(spend_pub_key).combine([tk_point]).format(compressed=True)
    return p_k[1:], t_k  # (32-byte x-only, 32-byte tweak)

def add_public_keys(pk1: bytes, pk2: bytes) -> bytes:
    """Add two 33-byte compressed pubkeys. Returns 33-byte result."""
    if isinstance(pk1, PublicKey):
        pk1 = pk1.format(compressed=True)
    if isinstance(pk2, PublicKey):
        pk2 = pk2.format(compressed=True)
    return PublicKey(pk1).combine([PublicKey(pk2)]).format(compressed=True)


def negate_public_key(pk: bytes) -> bytes:
    """Return the negated 33-byte compressed pubkey."""
    # Flip parity byte 0x02 <-> 0x03
    parity = 0x02 if pk[0] == 0x03 else 0x03
    return bytes([parity]) + pk[1:]


def add_private_keys(sk1: bytes, sk2: bytes) -> bytes:
    """Add two 32-byte scalars mod n. Returns 32-byte result."""
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    result = (int.from_bytes(sk1, "big") + int.from_bytes(sk2, "big")) % n
    return result.to_bytes(32, "big")
    

def create_label(scan_key: bytes, m: int) -> Label:
    """
    label_tweak = TaggedHash("BIP0352/Label", scan_key || ser_u32(m))
    label_pub   = label_tweak * G
    Mirrors Go: bip352.CreateLabel(scanSecKey, m)
    """
    tweak = _tagged_hash("BIP0352/Label", scan_key + _ser_u32(m))
    pub_key = PublicKey.from_secret(tweak).format(compressed=True)
    return Label(pub_key=pub_key, tweak=tweak, m=m)

def create_labels(scan_key: bytes, count: int = 21) -> list[Label]:
    """
    Create `count` labels starting from m=0 (change label).
    Mirrors BlindBit's labelCount config.
    """
    return [create_label(scan_key, m) for m in range(count)]

# ---------------------------------------------------------------------------
# Label matching
# ---------------------------------------------------------------------------

def match_labels(
    tx_output_33: bytes,     # 33-byte compressed
    pk_33: bytes,            # 33-byte derived output pubkey
    labels: list[Label],
) -> Optional[Label]:
    """
    Computes tx_output - pk (i.e. tx_output + (-pk)) and checks against labels.
    """
    pk_neg = negate_public_key(pk_33)
    try:
        diff = add_public_keys(tx_output_33, pk_neg)
    except Exception:
        return None

    for label in labels:
        if diff[1:] == label.pub_key[1:]:
            return label
    return None
# ---------------------------------------------------------------------------
# Core scanning: mirrors ReceiverScanTransactionWithSharedSecret
# ---------------------------------------------------------------------------

def receiver_scan_transaction_with_shared_secret(
    scan_key: bytes,            # 32-byte
    spend_pub_key: bytes,       # 33-byte compressed
    labels: list[Label],
    tx_outputs: list[bytes],    # list of 32-byte x-only pubkeys
    shared_secret: bytes,       # 33-byte compressed
) -> list[FoundOutput]:
    found_outputs: list[FoundOutput] = []
    remaining = list(tx_outputs)  # copy so we can remove matched outputs
    k = 0

    while True:
        output_pub_key, tweak = create_output_pub_key_and_tweak(shared_secret, spend_pub_key, k)        
        found = False
        for i, tx_output in enumerate(remaining):
            # --- Direct match ---
            if output_pub_key == tx_output:
                found_outputs.append(FoundOutput(
                    output=tx_output,
                    sec_key_tweak=tweak,
                    label=None,
                ))
                remaining.pop(i)
                found = True
                k += 1
                break

            if not labels:
                continue

            # --- Label matching ---
            tx_out_33 = b"\x02" + tx_output
            out_pk_33 = b"\x02" + output_pub_key

            # Try normal output against labels
            found_label = match_labels(tx_out_33, out_pk_33, labels)
            if found_label is not None:
                sec_key_tweak = add_private_keys(tweak, found_label.tweak)
                found_outputs.append(FoundOutput(
                    output=tx_output,
                    sec_key_tweak=sec_key_tweak,
                    label=found_label,
                ))
                remaining.pop(i)
                found = True
                k += 1
                break

            # Try negated tx_output against labels
            tx_out_33_neg = negate_public_key(tx_out_33)
            found_label = match_labels(tx_out_33_neg, out_pk_33, labels)
            if found_label is not None:
                sec_key_tweak = add_private_keys(tweak, found_label.tweak)
                found_outputs.append(FoundOutput(
                    output=tx_out_33_neg[1:],  # x-only of negated point
                    sec_key_tweak=sec_key_tweak,
                    label=found_label,
                ))
                remaining.pop(i)
                found = True
                k += 1
                break

        if not found:
            break

    return found_outputs


def receiver_scan_transaction(
    scan_key: bytes,
    spend_pub_key: bytes,
    labels: list[Label],
    tx_outputs: list[bytes],
    public_component: bytes,       # 33-byte tweak or A_sum
    input_hash: Optional[bytes],   # None if public_component already includes it
) -> list[FoundOutput]:
    shared_secret = create_shared_secret(public_component, scan_key, input_hash)
    return receiver_scan_transaction_with_shared_secret(
        scan_key, spend_pub_key, labels, tx_outputs, shared_secret
    )
# ---------------------------------------------------------------------------
# Block-level scan: mirrors syncBlock
# ---------------------------------------------------------------------------

def sync_block(
    tweaks: list[bytes | str],  # list of 33-byte tweaks, bytes or hex strings
    utxos: list[dict],       # raw dicts: {txid, vout, value, scriptpubkey, timestamp, spent, ...}
    scan_key: bytes,         # 32-byte secret scan key
    spend_pub_key: bytes,    # 33-byte compressed spend pubkey
    labels: list[Label],
) -> list[OwnedUTXO]:
    # Step 1 & 2: precompute potential output pubkeys for every tweak
    tweak_script_map: dict[bytes, tuple[bytes, bytes]] = {}
   
    tweak = bytes.fromhex(tweaks[0]) if isinstance(tweaks[0], str) else tweaks[0]    
    shared = create_shared_secret(tweak, scan_key, None)    
    t_k, _ = create_output_pub_key_and_tweak(shared, spend_pub_key, 0)      
    for raw_tweak in tweaks:
        tweak = bytes.fromhex(raw_tweak) if isinstance(raw_tweak, str) else raw_tweak
        shared_secret = create_shared_secret(tweak, scan_key, input_hash=None)
        output_pub_key, _ = create_output_pub_key_and_tweak(shared_secret, spend_pub_key, 0)
        tweak_script_map[output_pub_key] = (tweak, output_pub_key)

        out_pk_33 = b"\x02" + output_pub_key
        for label in labels:            
            try:
                label_out_33 = add_public_keys(out_pk_33, label.pub_key)
                tweak_script_map[label_out_33[1:]] = (tweak, label_out_33[1:])
            except Exception:
                pass
            try:
                neg_label_pub = negate_public_key(label.pub_key)
                label_out_neg_33 = add_public_keys(out_pk_33, neg_label_pub)
                tweak_script_map[label_out_neg_33[1:]] = (tweak, label_out_neg_33[1:])
            except Exception:
                pass        
    if not tweak_script_map:        
        return []    

    # Step 3: group UTXOs by txid, build helper map: x-only -> txid bytes
    txid_groups: dict[bytes, list[dict]] = {}
    helper_mapping: dict[bytes, bytes] = {}

    for utxo in utxos:
        txid_b = bytes.fromhex(utxo["txid"])
        x_only = bytes.fromhex(utxo["scriptpubkey"])[2:]
        txid_groups.setdefault(txid_b, []).append(utxo)
        helper_mapping[x_only] = txid_b    

    # Step 4: collect tx groups that contain a precomputed candidate output
    tweaks_outputs_to_check: dict[bytes, list[dict]] = {}

    for x_only, (tweak, _) in tweak_script_map.items():
        if x_only in helper_mapping:
            tweaks_outputs_to_check[tweak] = txid_groups[helper_mapping[x_only]]    
    
    owned_utxos: list[OwnedUTXO] = []

    for tweak, relevant_utxos in tweaks_outputs_to_check.items():
        tx_outputs = [bytes.fromhex(u["scriptpubkey"])[2:] for u in relevant_utxos]

        found = receiver_scan_transaction(
            scan_key=scan_key,
            spend_pub_key=spend_pub_key,
            labels=labels,
            tx_outputs=tx_outputs,
            public_component=tweak,
            input_hash=None,
        )

        for fo in found:
            for utxo in relevant_utxos:
                if fo.output == bytes.fromhex(utxo["scriptpubkey"])[2:]:
                    owned_utxos.append(OwnedUTXO(
                        txid=bytes.fromhex(utxo["txid"]),
                        vout=utxo["vout"],
                        amount=utxo["value"],
                        priv_key_tweak=fo.sec_key_tweak,
                        pub_key=fo.output,                        
                        utxo_state="spent" if utxo.get("spent") else "unspent",
                        timestamp=utxo.get("timestamp"),
                        label=fo.label,
                    ))
                    break

    return owned_utxos

# ── BlindBit Oracle client ─────────────────────────────────────────────────────

class BlindBitOracleClient:
    """HTTP client for the BlindBit Oracle."""

    def __init__(self, base_url: str, user: str = "", password: str = ""):
        self.base_url = base_url.rstrip("/")        

    def _client(self) -> httpx.AsyncClient:
        kwargs = {"timeout": 30.0, "verify": False}       
        return httpx.AsyncClient(**kwargs)

    async def get_chain_tip(self) -> int:
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/block-height")
            resp.raise_for_status()
            return resp.json()["block_height"]

    async def get_tweaks(self, height: int, dust_limit: int = DUST_LIMIT) -> list[bytes]:
        """Returns list of 33-byte compressed pubkey tweaks for the block."""
        async with self._client() as client:
            resp = await client.get(
                f"{self.base_url}/tweaks/{height}",
                params={"dustLimit": dust_limit}
            )
            resp.raise_for_status()
            data = resp.json()
            tweaks = []           
            # for t in data.get("tweaks", []):
            for t in data:
                tweaks.append(bytes.fromhex(t))
            return tweaks

    async def get_utxos(self, height: int) -> list[dict]:
        """Returns list of UTXOs served at this block height."""
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/utxos/{height}")
            resp.raise_for_status()
            return resp.json()

    async def get_spent_filter(self, height: int) -> Optional[dict]:
        """Returns the spent outpoints GCS filter for the block."""
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/filter/spent/{height}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()


# ── Block scanner ──────────────────────────────────────────────────────────────

async def scan_block(
    height: int,
    client: BlindBitOracleClient,
    scan_secret_bytes: bytes,
    spend_pub_bytes: bytes,
    spend_secret_bytes: bytes,
) -> list[dict]:
    """
    Scan a single block for UTXOs belonging to this wallet.
    Returns list of owned UTXO dicts ready for DB insertion.
    """ 
    # Plug in real keys, tweaks, and UTXOs from your BlindBit client
    # scan_key = bytes.fromhex("your_32_byte_scan_secret_key_hex")
    # spend_pub_key = bytes.fromhex("your_33_byte_spend_pubkey_hex")
    tweaks = await client.get_tweaks(height, DUST_LIMIT)
    labels: list[Label] = []  # populate with your wallet's labels
    utxos = await client.get_utxos(height)
    if not utxos:
        return []
    # tweaks: list[bytes] = []  # from BlindBit GetTweaks(blockHeight, dustLimit)
    # utxos: list[UTXOServed] = []  # from BlindBit GetUTXOs(blockHeight) 
    
    labels = create_labels(scan_secret_bytes,count=21)
    owned = sync_block(tweaks, utxos, scan_secret_bytes, spend_pub_bytes, labels)

    return owned


async def mark_spent_utxos(
    height: int,
    client: BlindBitOracleClient,
    wallet_id: str,
) -> None:
    """
    Check spent filter and mark UTXOs as spent in the DB.
    """
    try:
        filter_data = await client.get_spent_filter(height)
        if not filter_data:
            return

        # Get current unspent UTXOs from DB
        rows = await db.fetchall(
            "SELECT txid, vout FROM silnt.utxos WHERE wallet_id = :wallet_id AND utxo_state = 'unspent'",
            {"wallet_id": wallet_id},
        )
        if not rows:
            return

        # The filter data contains spent outpoint hashes
        # We compare our UTXOs against the spent index
        spent_index = filter_data.get("data", [])
        block_hash = bytes.fromhex(filter_data.get("block_hash", ""))

        for row in rows:
            txid_bytes = bytes.fromhex(row["txid"])[::-1]  # internal byte order
            vout_bytes = struct.pack("<I", row["vout"])
            outpoint = txid_bytes + vout_bytes
            outpoint_hash_full = hashlib.sha256(outpoint + block_hash[::-1]).digest()
            short_hash = outpoint_hash_full[:8].hex()

            if short_hash in spent_index:
                await db.execute(
                    "UPDATE silnt.utxos SET utxo_state = 'spent' WHERE txid = :txid AND vout = :vout AND wallet_id = :wallet_id",
                    {"txid": row["txid"], "vout": row["vout"], "wallet_id": wallet_id}
                )
                logger.info(f"Marked UTXO {row['txid']}:{row['vout']} as spent at block {height}")

    except Exception as e:
        logger.warning(f"Block {height}: could not check spent filter: {e}")


# ── Last scan height ───────────────────────────────────────────────────────────

async def set_last_scan_height(wallet_id: str, height: int) -> None:
    await db.execute(
        "UPDATE silnt.wallets SET last_scan_height = :height WHERE id = :id",
        {"height": height, "id": wallet_id},
    )


# ── Main scan entry points ─────────────────────────────────────────────────────

async def scan_wallet(
    wallet_id: str,
    from_height: Optional[int] = None,
    to_height: Optional[int] = None,
) -> dict:
    """
    Scan blockchain for UTXOs belonging to a wallet.
    Stores found UTXOs in the DB and updates balance.

    Args:
        wallet_id: The silnt wallet ID
        from_height: Start scanning from this block (default: wallet birth height)
        to_height: Stop at this block (default: chain tip)

    Returns:
        dict with utxos_found, blocks_scanned, final_height
    """        
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise ValueError(f"Wallet {wallet_id} not found")

    blindbit = await get_blindbit_config()
    if not blindbit.blindbit_url:
        raise ValueError("BlindBit Oracle URL not configured")

    # ── Decrypt keys ──────────────────────────────────────────────────────────
    scan_secret_encrypted = wallet.scan_secret
    scan_secret_hex = await decrypt_secret(scan_secret_encrypted)    
    scan_secret_bytes = bytes.fromhex(scan_secret_hex)    
    
    # Get spend key
    row = await db.fetchone(
        "SELECT spend_key FROM silnt.wallets WHERE id = :id",
        {"id": wallet_id}
    )
    if not row or not row["spend_key"]:
        raise ValueError(f"No spend key found for wallet {wallet_id}")
    
    spend_secret_hex = decrypt_spend_key(row["spend_key"], scan_secret_hex)    
    spend_secret_bytes = bytes.fromhex(spend_secret_hex)
    spend_pub_bytes = coincurve.PublicKey.from_secret(spend_secret_bytes).format(compressed=True) 
     
    # ── Setup oracle client ───────────────────────────────────────────────────
    oracle = BlindBitOracleClient(
        base_url=blindbit.blindbit_url        
    )
    
    # ── Determine scan range ──────────────────────────────────────────────────
    start = from_height if from_height is not None else wallet.last_height
    if start < 1:
        start = 1
    
    chain_tip = await oracle.get_chain_tip()
    end = to_height if to_height is not None else chain_tip

    logger.info(f"Scanning wallet {wallet_id} from block {start} to {end}")

    # ── Scan blocks ───────────────────────────────────────────────────────────
    total_found = 0
    blocks_scanned = 0
    total_blocks = end - start + 1
    set_scan_progress(wallet_id, 0, total_blocks, 0)
    for height in range(start, end + 1):
        try:
            # Check spent UTXOs first
            await mark_spent_utxos(height, oracle, wallet_id)

            # Scan for new UTXOs
            owned_utxos = await scan_block(
                height=height,
                client=oracle,
                scan_secret_bytes=scan_secret_bytes,
                spend_pub_bytes=spend_pub_bytes,
                spend_secret_bytes=spend_secret_bytes,
            )

            if owned_utxos:                
                await insert_utxos_for_wallet(wallet_id, owned_utxos)
                total_found += len(owned_utxos)
                logger.info(f"Block {height}: stored {len(owned_utxos)} UTXOs")

            blocks_scanned += 1
            set_scan_progress(wallet_id, blocks_scanned, total_blocks, total_found)

            # Save progress every 100 blocks
            if blocks_scanned % 100 == 0:
                await set_last_scan_height(wallet_id, height)
                logger.debug(f"Progress saved at block {height}")            
        except Exception as e:
            logger.error(f"Error scanning block {height}: {e}")
            continue

    # ── Final update ──────────────────────────────────────────────────────────
    await set_last_scan_height(wallet_id, end)

    # Recalculate balance from unspent UTXOs
    unspent_rows = await db.fetchall(
        "SELECT amount FROM silnt.utxos WHERE wallet_id = :wallet_id AND utxo_state = 'unspent'",
        {"wallet_id": wallet_id},
    )
    balance = sum(row["amount"] for row in unspent_rows)
    await update_balance(wallet_id, balance)

    logger.info(f"Scan complete: {blocks_scanned} blocks, {total_found} UTXOs found, balance={balance} sats")
    set_scan_progress(wallet_id, total_blocks, total_blocks, total_found, active=False)
    return {
        "utxos_found": total_found,
        "blocks_scanned": blocks_scanned,
        "final_height": end,
        "balance": balance,
    }


async def scan_all_wallets(user: str, network: str = "mainnet") -> list[dict]:
    """Scan all wallets for a given user."""
    wallets = await get_silnt_wallets(user, network)
    results = []
    for wallet in wallets:
        try:
            result = await scan_wallet(wallet.id)
            result["wallet_id"] = wallet.id
            results.append(result)
        except Exception as e:
            logger.error(f"Failed to scan wallet {wallet.id}: {e}")
            results.append({"wallet_id": wallet.id, "error": str(e)})
    return results

def get_scan_progress(wallet_id: str) -> dict:
    return _scan_progress.get(wallet_id, {
        "active": False, "current": 0, "total": 0, "found": 0
    })

def set_scan_progress(wallet_id: str, current: int, total: int, found: int, active: bool = True):
    _scan_progress[wallet_id] = {
        "active": active,
        "current": current,
        "total": total,
        "found": found,
    }