"""
scan.py — Silent Payments blockchain scanner for the silnt LNbits extension.

Connects to a BlindBit Oracle (https://localhost:8001) and scans for UTXOs
belonging to the wallet's Silent Payment address.

Oracle endpoints used:
  GET /tweaks/{height}                    — per-block tweaks
  GET /utxos/{height}                     — per-block UTXOs
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
    get_silnt_wallet,
    get_wallet_addresses
)
from .wallet import decrypt_secret, decrypt_spend_key

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

from coincurve import PublicKey, PrivateKey

# In-memory progress store — keyed by wallet_id
_scan_progress: dict[str, dict] = {}

_scan_stop: dict[str, bool] = {}

# ── Constants ──────────────────────────────────────────────────────────────────
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DUST_LIMIT = 100

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass
class Label:
    pub_key: bytes  # 33-byte compressed pubkey
    tweak: bytes  # 32-byte scalar
    address: str = ""
    m: int = 0


@dataclass
class FoundOutput:
    output: bytes  # 32-byte x-only pubkey
    sec_key_tweak: bytes  # 32-byte scalar
    label: Optional[Label] = None


@dataclass
class UTXOServed:
    txid: bytes  # 32 bytes (little-endian as stored)
    vout: int
    amount: int  # sats
    script_pubkey: bytes  # full scriptpubkey (34 bytes for P2TR: OP_1 OP_PUSH32 <32>)
    spent: bool = False
    timestamp: int = 0


@dataclass
class OwnedUTXO:
    txid: bytes
    vout: int
    amount: int
    priv_key_tweak: bytes
    pub_key: bytes  # 32-byte x-only
    utxo_state: str  # "unspent" | "spent" | "unconfirmed_spent"
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


def request_scan_stop(wallet_id: str):
    _scan_stop[wallet_id] = True


def should_stop(wallet_id: str) -> bool:
    return _scan_stop.get(wallet_id, False)


def clear_scan_stop(wallet_id: str):
    _scan_stop.pop(wallet_id, None)


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
    public_component: bytes,  # 33-byte compressed pubkey (tweak or A_sum)
    scan_key: bytes,  # 32-byte secret scalar
    input_hash: Optional[bytes] = None,
) -> bytes:
    """
    shared_secret = scan_key * public_component  (optionally * input_hash first)
    Mirrors Go: btcec.S256().ScalarMult(pubKey.X(), pubKey.Y(), secretComponent[:])
    """
    if input_hash is not None:
        # secretComponent = MultPrivateKeys(scan_key, input_hash)
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        scalar = (
            int.from_bytes(scan_key, "big") * int.from_bytes(input_hash, "big")
        ) % n
        effective_key = scalar.to_bytes(32, "big")
    else:
        effective_key = scan_key
    return PublicKey(public_component).multiply(effective_key).format(compressed=True)


def create_output_pub_key_and_tweak(
    shared_secret: bytes,  # 33-byte compressed
    spend_pub_key: bytes,  # 33-byte compressed
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


def create_labels(scan_key: bytes, indices: list[int]) -> list[Label]:
    """
    Create `count` labels starting from m=0 (change label).
    Mirrors BlindBit's labelCount config.
    """    
    return [create_label(scan_key, m) for m in indices]


# ---------------------------------------------------------------------------
# Label matching
# ---------------------------------------------------------------------------


def match_labels(
    tx_output_33: bytes,  # 33-byte compressed
    pk_33: bytes,  # 33-byte derived output pubkey
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
    scan_key: bytes,  # 32-byte
    spend_pub_key: bytes,  # 33-byte compressed
    labels: list[Label],
    tx_outputs: list[bytes],  # list of 32-byte x-only pubkeys
    shared_secret: bytes,  # 33-byte compressed
) -> list[FoundOutput]:
    found_outputs: list[FoundOutput] = []
    remaining = list(tx_outputs)  # copy so we can remove matched outputs
    k = 0

    while True:
        output_pub_key, tweak = create_output_pub_key_and_tweak(
            shared_secret, spend_pub_key, k
        )
        found = False
        for i, tx_output in enumerate(remaining):
            # --- Direct match ---
            if output_pub_key == tx_output:
                found_outputs.append(
                    FoundOutput(
                        output=tx_output,
                        sec_key_tweak=tweak,
                        label=None,
                    )
                )
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
                found_outputs.append(
                    FoundOutput(
                        output=tx_output,
                        sec_key_tweak=sec_key_tweak,
                        label=found_label,
                    )
                )
                remaining.pop(i)
                found = True
                k += 1
                break

            # Try negated tx_output against labels
            tx_out_33_neg = negate_public_key(tx_out_33)
            found_label = match_labels(tx_out_33_neg, out_pk_33, labels)
            if found_label is not None:
                sec_key_tweak = add_private_keys(tweak, found_label.tweak)
                found_outputs.append(
                    FoundOutput(
                        output=tx_out_33_neg[1:],  # x-only of negated point
                        sec_key_tweak=sec_key_tweak,
                        label=found_label,
                    )
                )
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
    public_component: bytes,  # 33-byte tweak or A_sum
    input_hash: Optional[bytes],  # None if public_component already includes it
) -> list[FoundOutput]:
    shared_secret = create_shared_secret(public_component, scan_key, input_hash)
    return receiver_scan_transaction_with_shared_secret(
        scan_key, spend_pub_key, labels, tx_outputs, shared_secret
    )


# ---------------------------------------------------------------------------
# Block-level scan: mirrors syncBlock
# ---------------------------------------------------------------------------


def sync_block_from_compute_index(
    index: list[dict],
    scan_key: bytes,
    spend_pub_key: bytes,
    labels: list[Label],
) -> list[OwnedUTXO]:
    """
    Process Compute Index response.
    Each entry has: {txid, tweak, outputs: [x-only-hex, ...]}
    """
    owned_utxos: list[OwnedUTXO] = []

    for entry in index:
        tweak_hex = entry.get("tweak", "")
        txid = entry.get("txid", "")
        outputs_hex = entry.get("outputs", [])

        if not tweak_hex or not outputs_hex:
            continue

        try:
            tweak_bytes = bytes.fromhex(tweak_hex)
            # outputs are shortened (8 bytes / 16 hex chars) — can only use for
            # matching, not for full pubkey recovery. Use receiver_scan_transaction
            # with the full tweak to derive expected outputs and match.
            shared_secret = create_shared_secret(tweak_bytes, scan_key, input_hash=None)

            # Derive expected x-only outputs for k=0,1,2...
            # outputs in compute index are shortened — 8 bytes each
            # Build set for fast lookup
            short_outputs = set(outputs_hex)

            # Check if any of our derived outputs match
            k = 0
            while True:
                output_pub_key, t_k = create_output_pub_key_and_tweak(
                    shared_secret, spend_pub_key, k
                )
                short = output_pub_key.hex()[:16]  # first 8 bytes

                matched = False

                # Direct match
                if short in short_outputs:
                    owned_utxos.append(OwnedUTXO(
                        txid=bytes.fromhex(txid),
                        vout=k,  # vout not available in compute index
                        amount=0,  # amount not available — fetch separately if needed
                        priv_key_tweak=t_k,
                        pub_key=output_pub_key,
                        utxo_state="unspent",
                        timestamp=0,
                        label=None,
                    ))
                    matched = True

                # Label match
                if labels:
                    out_pk_33 = b"\x02" + output_pub_key
                    for label in labels:
                        try:
                            label_out = add_public_keys(out_pk_33, label.pub_key)
                            label_short = label_out[1:].hex()[:16]
                            if label_short in short_outputs:
                                sec_key_tweak = add_private_keys(t_k, label.tweak)
                                owned_utxos.append(OwnedUTXO(
                                    txid=bytes.fromhex(txid),
                                    vout=k,
                                    amount=0,
                                    priv_key_tweak=sec_key_tweak,
                                    pub_key=label_out[1:],
                                    utxo_state="unspent",
                                    timestamp=0,
                                    label=label,
                                ))
                                matched = True
                        except Exception:
                            pass

                if not matched:
                    break
                k += 1

        except Exception as e:
            logger.warning(f"compute_index entry error for txid {txid}: {e}")
            continue

    return owned_utxos

def sync_block(
    tweaks: list[bytes | str],  # list of 33-byte tweaks, bytes or hex strings
    utxos: list[
        dict
    ],  # raw dicts: {txid, vout, value, scriptpubkey, timestamp, spent, ...}
    scan_key: bytes,  # 32-byte secret scan key
    spend_pub_key: bytes,  # 33-byte compressed spend pubkey
    labels: list[Label],
) -> list[OwnedUTXO]:
    # Step 1 & 2: precompute potential output pubkeys for every tweak
    tweak_script_map: dict[bytes, tuple[bytes, bytes]] = {}

    # tweak = bytes.fromhex(tweaks[0]) if isinstance(tweaks[0], str) else tweaks[0]
    # shared = create_shared_secret(tweak, scan_key, None)
    # t_k, _ = create_output_pub_key_and_tweak(shared, spend_pub_key, 0)
    for raw_tweak in tweaks:
        tweak = bytes.fromhex(raw_tweak) if isinstance(raw_tweak, str) else raw_tweak
        shared_secret = create_shared_secret(tweak, scan_key, input_hash=None)
        output_pub_key, _ = create_output_pub_key_and_tweak(
            shared_secret, spend_pub_key, 0
        )
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
        x_only = bytes.fromhex(utxo["pubkey"])
        txid_groups.setdefault(txid_b, []).append(utxo)
        helper_mapping[x_only] = txid_b

    # Step 4: collect tx groups that contain a precomputed candidate output
    tweaks_outputs_to_check: dict[bytes, list[dict]] = {}

    for x_only, (tweak, _) in tweak_script_map.items():
        if x_only in helper_mapping:
            tweaks_outputs_to_check[tweak] = txid_groups[helper_mapping[x_only]]

    owned_utxos: list[OwnedUTXO] = []

    for tweak, relevant_utxos in tweaks_outputs_to_check.items():
        tx_outputs = [bytes.fromhex(u["pubkey"]) for u in relevant_utxos]

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
                if fo.output == bytes.fromhex(utxo["pubkey"]):
                    owned_utxos.append(
                        OwnedUTXO(
                            txid=bytes.fromhex(utxo["txid"]),
                            vout=utxo["vout"],
                            amount=utxo["amount"],
                            priv_key_tweak=fo.sec_key_tweak,
                            pub_key=fo.output,
                            utxo_state="unspent",
                            timestamp=utxo.get("timestamp", 0),
                            label=fo.label,
                        )
                    )
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
            resp = await client.get(f"{self.base_url}/info")
            resp.raise_for_status()
            return resp.json()["height"]

    async def get_tweaks(
        self, height: int
    ) -> list[bytes]:
        """Returns list of 33-byte compressed pubkey tweaks for the block."""
        async with self._client() as client:
            resp = await client.get(
                f"{self.base_url}/tweaks/{height}"
            )
            resp.raise_for_status()
            data = resp.json()["index"]
            tweaks = []
            for t in data:
                tweaks.append(bytes.fromhex(t))
            return tweaks

    async def get_utxos(self, height: int) -> list[dict]:
        """Returns list of UTXOs served at this block height."""
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/utxos/{height}")
            resp.raise_for_status()
            return resp.json()["index"]

    # async def get_spent_filter(self, height: int) -> Optional[dict]:
    #     """Returns the spent outpoints GCS filter for the block."""
    #     async with self._client() as client:
    #         resp = await client.get(f"{self.base_url}/filter/spent/{height}")
    #         if resp.status_code == 404:
    #             return None
    #         resp.raise_for_status()
    #         return resp.json()

    # async def get_spent_index(self, height: int) -> Optional[dict]:
    #     async with self._client() as client:
    #         resp = await client.get(f"{self.base_url}/spent-outputs/{height}")
    #         if resp.status_code == 404:
    #             return None
    #         resp.raise_for_status()
    #         return resp.json()

    async def get_spent_outputs(self, height: int) -> Optional[dict]:
        """
        Spent Outputs (Shortened) — first 8 bytes of x-only pubkeys of spent outputs.
        Replaces deprecated spent-index endpoint.
        """
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/spent-outputs/{height}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()

    async def get_compute_index(self, height: int) -> Optional[dict]:
        """
        Compute Index — combined tweak + output info per transaction.
        Can replace separate tweaks + utxos calls.
        """
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/compute-index/{height}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()

    async def get_block_hash(self, height: int) -> Optional[dict]:
        """Returns the hash for the block."""
        async with self._client() as client:
            resp = await client.get(f"{self.base_url}/blockhash/{height}")
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
    labels: list[Label],          # ← pre-computed, passed in
) -> list[OwnedUTXO]:
    """Scan a single block. Labels are pre-computed outside the loop."""

    # Try Compute Index first
    compute_data = await client.get_compute_index(height)
    if compute_data:
        matches = sync_block_from_compute_index(
            compute_data["index"],
            scan_secret_bytes,
            spend_pub_bytes,
            labels
        )
        if matches:
            # Only fetch full utxos if we have matches
            full_utxos = await client.get_utxos(height)
            utxo_lookup = {u["pubkey"]: u for u in full_utxos if "pubkey" in u}
            for owned in matches:
                pub_hex = owned.pub_key.hex()
                full = utxo_lookup.get(pub_hex)
                if not full:
                    # fallback: match by short prefix
                    short = pub_hex[:16]
                    full = next(
                        (u for u in full_utxos if u.get("pubkey", "")[:16] == short),
                        None
                    )
                if full:
                    owned.vout = full.get("vout", owned.vout)
                    owned.amount = full.get("amount", owned.amount)
                    owned.timestamp = full.get("timestamp", owned.timestamp)
                    owned.utxo_state = "spent" if full.get("spent") else "unspent"
                    owned.pub_key = bytes.fromhex(full["pubkey"])
        return matches

    # Fallback: separate tweaks + utxos
    tweaks = await client.get_tweaks(height)
    if not tweaks:
        return []
    utxos = await client.get_utxos(height)
    if not utxos:
        return []
    return sync_block(tweaks, utxos, scan_secret_bytes, spend_pub_bytes, labels)


async def mark_spent_utxos_batch(
    heights: list[int],
    client: BlindBitOracleClient,
    wallet_id: str,
    owned_utxos_lookup: dict[str, dict],  # txid:vout -> row — pre-fetched
) -> None:
    """
    Check spent outputs for a batch of heights.
    owned_utxos_lookup is pre-fetched once per scan batch.
    """
    if not owned_utxos_lookup:
        return

    async def check_height(height: int):
        try:
            spent_data = await client.get_spent_outputs(height)
            if not spent_data:
                return

            spent_set = set(spent_data.get("index", []))
            if not spent_set:
                return

            block_utxos = await client.get_utxos(height)
            utxo_pub_lookup = {
                f"{u['txid']}:{u['vout']}": u.get("pubkey", "")[:16]
                for u in block_utxos
            }

            for lookup_key, row in owned_utxos_lookup.items():
                short_pub = utxo_pub_lookup.get(lookup_key, "")
                if short_pub and short_pub in spent_set:
                    await db.execute(
                        """UPDATE silnt.utxos SET utxo_state = 'spent'
                           WHERE txid = :txid AND vout = :vout
                           AND wallet_id = :wallet_id""",
                        {
                            "txid": row["txid"],
                            "vout": row["vout"],
                            "wallet_id": wallet_id,
                        },
                    )
                    logger.info(
                        f"Marked UTXO {row['txid']}:{row['vout']} as spent at block {height}"
                    )
        except Exception as e:
            logger.warning(f"mark_spent_utxos error at block {height}: {e}")

    await asyncio.gather(*[check_height(h) for h in heights])


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
        "SELECT spend_key FROM silnt.wallets WHERE id = :id", {"id": wallet_id}
    )
    if not row or not row["spend_key"]:
        raise ValueError(f"No spend key found for wallet {wallet_id}")

    spend_secret_hex = decrypt_spend_key(row["spend_key"], scan_secret_hex)
    spend_secret_bytes = bytes.fromhex(spend_secret_hex)
    spend_pub_bytes = coincurve.PublicKey.from_secret(spend_secret_bytes).format(
        compressed=True
    )

    # ── Setup oracle client ───────────────────────────────────────────────────
    oracle = BlindBitOracleClient(base_url=blindbit.blindbit_url)

    # ── Determine scan range ──────────────────────────────────────────────────
    start = from_height if from_height is not None else wallet.last_height
    if start < 1:
        start = 1

    chain_tip = await oracle.get_chain_tip()
    end = to_height if to_height is not None else chain_tip

    logger.info(f"Scanning wallet {wallet_id} from block {start} to {end}")

    # ── Pre-compute labels ONCE ───────────────────────────────────────────────
    saved_addresses = await get_wallet_addresses(wallet_id)
    labels = create_labels(
        scan_secret_bytes,
        indices=[addr.label_index for addr in saved_addresses]
    )
    logger.debug(f"Scanning with {len(labels)} label(s) for wallet {wallet_id}")

    # ── Scan blocks ───────────────────────────────────────────────────────────
    total_found = 0
    blocks_scanned = 0
    last_scanned_height = start
    total_blocks = end - start + 1
    clear_scan_stop(wallet_id)  # ← clear any previous stop request
    set_scan_progress(wallet_id, 0, total_blocks, 0)

    # ── Batch size for concurrent scanning ────────────────────────────────────
    BATCH_SIZE = 10

    heights = list(range(start, end + 1))

    for batch_start in range(0, len(heights), BATCH_SIZE):
        if should_stop(wallet_id):
            logger.info(f"Scan stopped by user at block {last_scanned_height}")
            await set_last_scan_height(wallet_id, last_scanned_height)
            set_scan_progress(wallet_id, blocks_scanned, total_blocks, total_found, active=False)
            clear_scan_stop(wallet_id)
            break

        batch = heights[batch_start:batch_start + BATCH_SIZE]

        # ── Fetch pre-owned UTXOs for spent check (once per batch) ───────────
        owned_rows = await db.fetchall(
            """SELECT txid, vout FROM silnt.utxos
               WHERE wallet_id = :wallet_id
               AND utxo_state IN ('unspent', 'unconfirmed_spent')""",
            {"wallet_id": wallet_id},
        )
        owned_utxos_lookup = {
            f"{r['txid']}:{r['vout']}": r for r in owned_rows
        }

        # ── Concurrent scan + spent check for batch ───────────────────────────
        scan_tasks = [
            scan_block(
                height=h,
                client=oracle,
                scan_secret_bytes=scan_secret_bytes,
                spend_pub_bytes=spend_pub_bytes,
                spend_secret_bytes=spend_secret_bytes,
                labels=labels,
            )
            for h in batch
        ]

        batch_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        # Check spent UTXOs for the batch concurrently
        await mark_spent_utxos_batch(batch, oracle, wallet_id, owned_utxos_lookup)

        # ── Process results ───────────────────────────────────────────────────
        for h, result in zip(batch, batch_results):
            if isinstance(result, Exception):
                logger.error(f"Error scanning block {h}: {result}")
                continue

            if result:
                await insert_utxos_for_wallet(wallet_id, result)
                total_found += len(result)
                logger.info(f"Block {h}: stored {len(result)} UTXOs")

            blocks_scanned += 1
            last_scanned_height = h

        set_scan_progress(wallet_id, blocks_scanned, total_blocks, total_found)

        # Save progress every batch
        await set_last_scan_height(wallet_id, last_scanned_height)
    

    # ── Final update ──────────────────────────────────────────────────────────
    await set_last_scan_height(wallet_id, last_scanned_height)
    set_scan_progress(
        wallet_id, blocks_scanned, total_blocks, total_found, active=False
    )

    # Recalculate balance from unspent UTXOs
    unspent_rows = await db.fetchall(
        "SELECT amount FROM silnt.utxos WHERE wallet_id = :wallet_id AND utxo_state = 'unspent'",
        {"wallet_id": wallet_id},
    )
    balance = sum(row["amount"] for row in unspent_rows)
    await update_balance(wallet_id, balance)

    logger.info(
        f"Scan complete: {blocks_scanned} blocks, {total_found} Unspent UTXOs found, balance={balance} sats"
    )
    set_scan_progress(wallet_id, total_blocks, total_blocks, total_found, active=False)
    return {
        "utxos_found": total_found,
        "blocks_scanned": blocks_scanned,
        "final_height": last_scanned_height,
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
    return _scan_progress.get(
        wallet_id, {"active": False, "current": 0, "total": 0, "found": 0}
    )


def set_scan_progress(
    wallet_id: str, current: int, total: int, found: int, active: bool = True
):
    _scan_progress[wallet_id] = {
        "active": active,
        "current": current,
        "total": total,
        "found": found,
    }
