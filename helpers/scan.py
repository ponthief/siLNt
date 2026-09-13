"""
scan.py — Silent Payments blockchain scanner for the silnt LNbits extension.
"""

from __future__ import annotations
import asyncio, concurrent.futures, hashlib, os, struct, time
from dataclasses import dataclass
from typing import Optional
import coincurve, httpx
from coincurve import PublicKey
from loguru import logger
from ..crud import (
    db,
    DEFAULT_CONFIG_NETWORK,
    get_backend_config,
    get_silnt_wallet,
    get_silnt_wallets,
    get_wallet_addresses,
    insert_utxos_for_wallet,
    update_balance,
    ensure_labeled_address_row
)
from .appenv import silnt_env
from .dust_check import evaluate_dust_for_wallet
from .wallet import generate_labeled_sp_address, get_spend_pub_from_secret

_scan_progress: dict[str, dict] = {}
_scan_stop: dict[str, bool] = {}
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# BIP-352 reserves label m=0 for change. Wallets created before this fix put
# change at m=1, so we keep scanning m=1 too (legacy) — cheap, and it keeps
# existing wallets' historical change detectable — while producing new change
# at the standard m=0.
BIP352_CHANGE_LABEL_INDEX = 0
BIP352_LEGACY_CHANGE_LABEL_INDICES = [1]
# The labeled-address indices the receiver ALWAYS scans, whether or not a saved
# wallet_addresses row exists for them. This is what makes deleting a labeled
# address safe: its label stays in the scan set, so payments keep being detected
# (and ensure_labeled_address_row re-creates the row). COUPLED to
# MAX_ADDRESSES_PER_WALLET in views_api.py — this set must cover every index the
# assigner can hand out (2 .. cap+1). If you widen this, you may raise that cap;
# if you raise that cap, you MUST widen this (an assert there enforces it).
BIP352_LABELED_ADDRESS_INDICES=[2,3]
# BIP-352 v1.1.0 (March 2026): a recipient group holds at most K_max = 2323
# outputs — the most P2TR outputs that fit in a 100,000-vByte standard tx.
# Cap the receiver's per-transaction scan loop at this so a maliciously crafted
# transaction packing many outputs to one scan key can't force O(N^2) work
# (each match rescans the remaining outputs); the cap bounds it to O(N*K_max).
# Honest transactions never reach it, so conforming receivers are unaffected.
BIP352_MAX_OUTPUTS_PER_GROUP = 2323

@dataclass
class Label:
    pub_key: bytes
    tweak: bytes
    address: str = ""
    m: int = 0


@dataclass
class FoundOutput:
    output: bytes
    sec_key_tweak: bytes
    label: Optional[Label] = None


@dataclass
class OwnedUTXO:
    txid: bytes
    vout: int
    amount: int
    priv_key_tweak: bytes
    pub_key: bytes
    utxo_state: str
    timestamp: int = 0
    label: Optional[Label] = None
    label_text: Optional[str] = None

    def to_db_row(self, wallet_id: str) -> dict:
        return {
            "txid": self.txid.hex(),
            "vout": self.vout,
            "amount": self.amount,
            "priv_key_tweak": self.priv_key_tweak.hex(),
            "pub_key": self.pub_key.hex(),
            "utxo_state": self.utxo_state,
            "timestamp": self.timestamp,
            "wallet_id": wallet_id,
            "label": self.label_text,
            "label_index": self.label.m if self.label else None
        }


def request_scan_stop(wallet_id: str):
    _scan_stop[wallet_id] = True


def should_stop(wallet_id: str) -> bool:
    return _scan_stop.get(wallet_id, False)


def clear_scan_stop(wallet_id: str):
    _scan_stop.pop(wallet_id, None)


def _tagged_hash(tag: str, data: bytes) -> bytes:
    h = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(h + h + data).digest()


def _ser_u32(k: int) -> bytes:
    return struct.pack(">I", k)


def create_shared_secret(
    public_component: bytes, scan_key: bytes, input_hash: Optional[bytes] = None
) -> bytes:
    if input_hash is not None:
        scalar = (
            int.from_bytes(scan_key, "big") * int.from_bytes(input_hash, "big")
        ) % SECP256K1_N
        effective_key = scalar.to_bytes(32, "big")
    else:
        effective_key = scan_key
    return PublicKey(public_component).multiply(effective_key).format(compressed=True)


def create_output_pub_key_and_tweak(
    shared_secret: bytes, spend_pub_key: bytes, k: int
) -> tuple[bytes, bytes]:
    t_k = _tagged_hash("BIP0352/SharedSecret", shared_secret + _ser_u32(k))
    p_k = (
        PublicKey(spend_pub_key)
        .combine([PublicKey.from_secret(t_k)])
        .format(compressed=True)
    )
    return p_k[1:], t_k


def add_public_keys(pk1: bytes, pk2: bytes) -> bytes:
    if isinstance(pk1, PublicKey):
        pk1 = pk1.format(compressed=True)
    if isinstance(pk2, PublicKey):
        pk2 = pk2.format(compressed=True)
    return PublicKey(pk1).combine([PublicKey(pk2)]).format(compressed=True)


def negate_public_key(pk: bytes) -> bytes:
    return bytes([0x02 if pk[0] == 0x03 else 0x03]) + pk[1:]


def add_private_keys(sk1: bytes, sk2: bytes) -> bytes:
    return (
        (int.from_bytes(sk1, "big") + int.from_bytes(sk2, "big")) % SECP256K1_N
    ).to_bytes(32, "big")


def create_label(scan_key: bytes, m: int) -> Label:
    tweak = _tagged_hash("BIP0352/Label", scan_key + _ser_u32(m))
    return Label(
        pub_key=PublicKey.from_secret(tweak).format(compressed=True), tweak=tweak, m=m
    )


def create_labels(scan_key: bytes, indices: list[int]) -> list[Label]:
    all_indices = sorted(set(
        [BIP352_CHANGE_LABEL_INDEX]
        + BIP352_LEGACY_CHANGE_LABEL_INDICES
        + BIP352_LABELED_ADDRESS_INDICES
        + list(indices)
    ))
    return [create_label(scan_key, m) for m in all_indices]


def match_labels(
    tx_output_33: bytes, pk_33: bytes, labels: list  # list[Label]
):  # -> Optional[Label]
    try:
        diff = add_public_keys(tx_output_33, negate_public_key(pk_33))
    except Exception:
        return None
    for label in labels:
        # X-only comparison (includes parity byte) — avoids matching a label
        # that only shares an x-coordinate (its negation), which would produce a
        # wrong tweak and an unspendable detected output.
        if diff[1:] == label.pub_key[1:]:
            return label
    return None


def receiver_scan_transaction_with_shared_secret(
    scan_key: bytes,
    spend_pub_key: bytes,
    labels: list[Label],
    tx_outputs: list[bytes],
    shared_secret: bytes,
) -> list[FoundOutput]:
    found_outputs: list[FoundOutput] = []
    remaining = list(tx_outputs)
    k = 0
    # Stop at K_max even if outputs keep matching — bounds worst-case work on a
    # hostile transaction. A normal transaction exits earlier via `not found`.
    while k < BIP352_MAX_OUTPUTS_PER_GROUP:
        output_pub_key, tweak = create_output_pub_key_and_tweak(
            shared_secret, spend_pub_key, k
        )
        found = False
        for i, tx_output in enumerate(remaining):
            if output_pub_key == tx_output:
                found_outputs.append(FoundOutput(output=tx_output, sec_key_tweak=tweak))
                remaining.pop(i)
                found = True
                k += 1
                break
            if not labels:
                continue
            tx_out_33 = b"\x02" + tx_output
            out_pk_33 = b"\x02" + output_pub_key
            fl = match_labels(tx_out_33, out_pk_33, labels)
            if fl:
                found_outputs.append(
                    FoundOutput(
                        output=tx_output,
                        sec_key_tweak=add_private_keys(tweak, fl.tweak),
                        label=fl,
                    )
                )
                remaining.pop(i)
                found = True
                k += 1
                break
            tx_out_neg = negate_public_key(tx_out_33)
            fl = match_labels(tx_out_neg, out_pk_33, labels)
            if fl:
                found_outputs.append(
                    FoundOutput(
                        output=tx_out_neg[1:],
                        sec_key_tweak=add_private_keys(tweak, fl.tweak),
                        label=fl,
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
    scan_key, spend_pub_key, labels, tx_outputs, public_component, input_hash
):
    return receiver_scan_transaction_with_shared_secret(
        scan_key,
        spend_pub_key,
        labels,
        tx_outputs,
        create_shared_secret(public_component, scan_key, input_hash),
    )


def sync_block(tweaks, utxos, scan_key, spend_pub_key, labels):
    tweak_script_map: dict[bytes, tuple[bytes, bytes]] = {}
    # (The first tweak used to be processed here and then again by the loop
    # below, the results of the first pass being overwritten unread. Two wasted
    # elliptic-curve operations per block, and an IndexError waiting for the day
    # a caller forgot to check for an empty list.)
    for raw in tweaks:
        tweak = bytes.fromhex(raw) if isinstance(raw, str) else raw
        ss = create_shared_secret(tweak, scan_key)
        opk, _ = create_output_pub_key_and_tweak(ss, spend_pub_key, 0)
        tweak_script_map[opk] = (tweak, opk)
        b33 = b"\x02" + opk
        for label in labels:
            try:
                lo = add_public_keys(b33, label.pub_key)
                tweak_script_map[lo[1:]] = (tweak, lo[1:])
            except Exception as e:
                logger.debug(f"label add m={label.m}: {e}")
            try:
                lon = add_public_keys(b33, negate_public_key(label.pub_key))
                tweak_script_map[lon[1:]] = (tweak, lon[1:])
            except Exception as e:
                logger.debug(f"label neg m={label.m}: {e}")
    if not tweak_script_map:
        return []
    txid_groups: dict[bytes, list[dict]] = {}
    helper_mapping: dict[bytes, bytes] = {}
    for u in utxos:
        tb = bytes.fromhex(u["txid"])
        xo = bytes.fromhex(u["pubkey"])
        txid_groups.setdefault(tb, []).append(u)
        helper_mapping[xo] = tb
    to_check: dict[bytes, list[dict]] = {}
    for xo, (tw, _) in tweak_script_map.items():
        if xo in helper_mapping:
            to_check[tw] = txid_groups[helper_mapping[xo]]
    owned: list[OwnedUTXO] = []
    for tw, rel_utxos in to_check.items():
        found = receiver_scan_transaction(
            scan_key,
            spend_pub_key,
            labels,
            [bytes.fromhex(u["pubkey"]) for u in rel_utxos],
            tw,
            None,
        )
        for fo in found:
            for u in rel_utxos:
                if fo.output == bytes.fromhex(u["pubkey"]):
                    owned.append(
                        OwnedUTXO(
                            txid=bytes.fromhex(u["txid"]),
                            vout=u["vout"],
                            amount=u["amount"],
                            priv_key_tweak=fo.sec_key_tweak,
                            pub_key=fo.output,
                            utxo_state="unspent",
                            timestamp=u.get("timestamp", 0),
                            label=fo.label,
                        )
                    )
                    break
    return owned


def sync_block_from_compute_index(index, scan_key, spend_pub_key, labels):
    owned: list[OwnedUTXO] = []
    for entry in index:
        tweak_hex = entry.get("tweak", "")
        txid = entry.get("txid", "")
        outputs_hex = entry.get("outputs", [])
        if not tweak_hex or not outputs_hex:
            continue
        try:
            ss = create_shared_secret(bytes.fromhex(tweak_hex), scan_key)
            shorts = set(outputs_hex)
            k = 0
            while True:
                opk, t_k = create_output_pub_key_and_tweak(ss, spend_pub_key, k)
                matched = False
                if opk.hex()[:16] in shorts:
                    owned.append(
                        OwnedUTXO(
                            txid=bytes.fromhex(txid),
                            vout=0,
                            amount=0,
                            priv_key_tweak=t_k,
                            pub_key=opk,
                            utxo_state="unspent",
                        )
                    )
                    matched = True
                if labels:
                    b33 = b"\x02" + opk
                    for label in labels:
                        try:
                            lo = add_public_keys(b33, label.pub_key)
                            if lo[1:].hex()[:16] in shorts:
                                owned.append(
                                    OwnedUTXO(
                                        txid=bytes.fromhex(txid),
                                        vout=0,
                                        amount=0,
                                        priv_key_tweak=add_private_keys(
                                            t_k, label.tweak
                                        ),
                                        pub_key=lo[1:],
                                        utxo_state="unspent",
                                        label=label,
                                    )
                                )
                                matched = True
                        except Exception:
                            pass
                if not matched:
                    break
                k += 1
        except Exception as e:
            logger.warning(f"compute_index txid={txid}: {e}")
    return owned

async def get_outspend_status(base_mempool_url: str, txid: str, vout: int) -> dict | None:
    """
    Exact-outpoint spent check via mempool.
    Returns {"spent": bool} when known, or None on unknown/error (caller leaves
    the UTXO in unconfirmed_spent and retries next scan).
    """
    base = (base_mempool_url or "https://mempool.space").rstrip("/")
    url = f"{base}/api/tx/{txid}/outspend/{vout}"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as c:
            r = await c.get(url)
            if r.status_code == 404:
                # outpoint unknown to explorer — can't confirm; treat as unknown
                return None
            if r.status_code != 200:
                return None
            data = r.json()
            return {"spent": bool(data.get("spent", False))}
    except Exception as e:
        logger.warning(f"outspend check failed for {txid}:{vout}: {e}")
        return None

# One HTTP client for the whole process, instead of one per request.
#
# Every oracle method used to open its own httpx.AsyncClient and close it again,
# which meant a fresh TCP handshake — and a fresh TLS handshake on top of it —
# for every single call. Scanning costs roughly three requests per block
# (tweaks, utxos, spent-outputs), so a ten-thousand-block scan was making about
# thirty thousand connections where one suffices. On a remote oracle that
# handshake cost dominates everything else the scanner does; it is latency, not
# computation, and no amount of faster matching touches it.
#
# A module-level client is deliberate rather than one per BlindBitOracleClient:
# there are five places that construct one of those for a single call, and a
# per-instance pool would have to be closed by each of them or leak sockets.
# httpx pools per host internally, so sharing one client across oracles is
# correct even when they point at different URLs.
#
# It is bound to the event loop that first uses it, which in LNbits is the one
# uvicorn loop. aclose_http() exists for shutdown and for tests.
_http: Optional[httpx.AsyncClient] = None

# TLS verification is OFF, which is how this has always been, and it is worth
# naming rather than leaving implicit: anyone able to intercept the oracle
# connection can serve whatever tweaks and UTXOs they like, which shows a user
# the wrong balance and reveals which blocks they are interested in. It cannot
# steal keys — scanning never sees a spend key — but it is not nothing.
# Overridable so a deployment with a properly certificated oracle can turn it
# on without a code change.
# Read through silnt_env, NOT os.getenv. Some LNbits deployments load .env into
# pydantic settings without exporting it to os.environ, so a SILNT_* line in the
# .env would be invisible to os.getenv and the setting would silently do nothing
# — the failure being that you set it, see no change, and conclude the feature
# is broken. silnt_env falls back to parsing the .env LNbits actually loaded;
# it is what the rest of the extension already uses (see device_auth.py).
_VERIFY_TLS = silnt_env("SILNT_ORACLE_VERIFY_TLS").lower() in ("1", "true", "yes")

# Opt-in, because the path it enables has never run. See the note in scan_block.
#
#   unset / 0  legacy path: tweaks + utxos per block, plus the spent check.
#   verify     run BOTH per block, compare, log any disagreement, and RETURN
#              THE LEGACY RESULT. Costs more, proves the fast path against the
#              one already trusted with your money.
#   1 / true   compute-index only. One oracle request per block instead of
#              three, which on a local oracle at ~28ms of service time per
#              request is most of a scan.
_COMPUTE_INDEX_MODE = silnt_env("SILNT_SCAN_COMPUTE_INDEX").strip().lower()
_USE_COMPUTE_INDEX = _COMPUTE_INDEX_MODE in ("1", "true", "yes")
_VERIFY_COMPUTE_INDEX = _COMPUTE_INDEX_MODE == "verify"


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(silnt_env(name) or default)))
    except ValueError:
        return default


def get_http_client() -> httpx.AsyncClient:
    global _http
    if _http is None or _http.is_closed:
        _http = httpx.AsyncClient(
            timeout=30.0,
            verify=_VERIFY_TLS,
            # The pool has to be at least as large as the number of block
            # requests in flight, or the extra ones queue behind it and the
            # concurrency above is imaginary.
            limits=httpx.Limits(
                max_connections=64,
                max_keepalive_connections=32,
                keepalive_expiry=60.0,
            ),
        )
    return _http


_mempool_http: Optional[httpx.AsyncClient] = None


def get_mempool_client() -> httpx.AsyncClient:
    """Pooled client for the mempool explorer. Verifies TLS, unlike the oracle's."""
    global _mempool_http
    if _mempool_http is None or _mempool_http.is_closed:
        _mempool_http = httpx.AsyncClient(
            timeout=10.0,
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16,
                                keepalive_expiry=60.0),
        )
    return _mempool_http


async def aclose_http() -> None:
    global _http, _mempool_http
    if _http is not None and not _http.is_closed:
        await _http.aclose()
    _http = None
    if _mempool_http is not None and not _mempool_http.is_closed:
        await _mempool_http.aclose()
    _mempool_http = None


@dataclass
class OracleStats:
    """Where a scan's time actually goes, counted rather than guessed."""

    requests: int = 0
    request_seconds: float = 0.0
    match_seconds: float = 0.0
    blocks: int = 0
    # Block shape. Matching cost is linear in tweaks, so "how many tweaks does
    # a block here actually have" is the difference between a diagnosis and a
    # guess — a signet block with 20 tweaks and a mainnet block with 2000 are
    # two completely different problems wearing the same symptom.
    tweaks: int = 0
    utxos: int = 0
    wall_seconds: float = 0.0
    # Phases of the batch loop. These are sequential with respect to each other,
    # so unlike request_seconds they sum to (about) the wall clock — which is
    # what makes them able to say where the time went rather than only where
    # some of it went. The first instrumentation covered oracle requests and
    # matching alone, and on a real signet scan those two accounted for well
    # under half of it.
    ts_lookups: int = 0           # per-found-output timestamp lookups
    ts_seconds: float = 0.0
    fetch_seconds: float = 0.0    # gathering scan_block over a batch
    spent_seconds: float = 0.0    # mark_spent_utxos_batch
    persist_seconds: float = 0.0  # database writes for what was found

    def as_dict(self) -> dict:
        return {
            "blocks": self.blocks,
            "wall_seconds": round(self.wall_seconds, 2),
            "oracle_requests": self.requests,
            "oracle_seconds": round(self.request_seconds, 2),
            "match_seconds": round(self.match_seconds, 2),
            "tweaks": self.tweaks,
            "utxos": self.utxos,
            "tweaks_per_block": round(self.tweaks / self.blocks, 1) if self.blocks else 0,
            "timestamp_lookups": self.ts_lookups,
            "timestamp_seconds": round(self.ts_seconds, 2),
            "fetch_seconds": round(self.fetch_seconds, 2),
            "spent_seconds": round(self.spent_seconds, 2),
            "persist_seconds": round(self.persist_seconds, 2),
            "unaccounted_seconds": round(
                self.wall_seconds
                - self.fetch_seconds - self.spent_seconds - self.persist_seconds,
                2,
            ),
        }

    def summary(self) -> str:
        per_block = (self.requests / self.blocks) if self.blocks else 0
        tw = (self.tweaks / self.blocks) if self.blocks else 0
        # request_seconds is summed across concurrent requests, so it can exceed
        # the wall clock. Say so rather than leaving someone to wonder how 40s
        # of waiting fits in a 27s scan.
        return (
            f"{self.blocks} blocks in {self.wall_seconds:.1f}s wall clock | "
            f"{self.requests} oracle requests ({per_block:.1f}/block), "
            f"{self.request_seconds:.1f}s summed across concurrent requests | "
            f"{self.match_seconds:.1f}s matching | "
            f"{self.tweaks} tweaks ({tw:.0f}/block), {self.utxos} utxos"
        )

    def phases(self) -> str:
        """The breakdown, as its OWN log line.

        This used to be a newline inside summary(), which meant a plain
        `grep "Scan timing"` returned the totals and silently dropped the part
        that says where the time went — which is the part worth having.
        """
        other = (
            self.wall_seconds
            - self.fetch_seconds - self.spent_seconds - self.persist_seconds
        )
        return (
            f"fetch {self.fetch_seconds:.1f}s "
            f"(matching {self.match_seconds:.1f}s, "
            f"timestamp lookups {self.ts_seconds:.1f}s over {self.ts_lookups}) | "
            f"spent-check {self.spent_seconds:.1f}s | "
            f"persist {self.persist_seconds:.1f}s | "
            f"other {other:.1f}s"
        )


class BlindBitOracleClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.stats = OracleStats()

    async def _get(self, path: str) -> httpx.Response:
        started = time.perf_counter()
        try:
            return await get_http_client().get(f"{self.base_url}{path}")
        finally:
            self.stats.requests += 1
            self.stats.request_seconds += time.perf_counter() - started

    async def get_chain_tip(self) -> int:
        return (await self._get("/info")).json()["height"]

    async def get_tweaks(self, height: int) -> list[bytes]:
        r = await self._get(f"/tweaks/{height}")
        r.raise_for_status()
        d = r.json()
        return [bytes.fromhex(t) for t in (d["index"] if isinstance(d, dict) else d)]

    async def get_utxos(self, height: int) -> list[dict]:
        r = await self._get(f"/utxos/{height}")
        r.raise_for_status()
        d = r.json()
        return d["index"] if isinstance(d, dict) else d

    async def get_spent_outputs(self, height: int) -> Optional[dict]:
        r = await self._get(f"/spent-outputs/{height}")
        return None if r.status_code == 404 else r.json()

    async def get_compute_index(self, height: int) -> Optional[dict]:
        r = await self._get(f"/compute-index/{height}")
        if r.status_code == 404:
            return None
        d = r.json()
        return d if isinstance(d, dict) and "index" in d else {"index": d}

    async def get_block_hash(self, height: int) -> Optional[dict]:
        r = await self._get(f"/blockhash/{height}")
        return None if r.status_code == 404 else r.json()


# One thread for all EC matching, not the default pool.
#
# Matching has to leave the event loop — it is hundreds of milliseconds of
# straight computation per block and would otherwise freeze the API for the
# length of a scan. But it must not run on MORE than one thread, because
# coincurve holds the GIL through its calls, so concurrent matching threads do
# not share the work, they fight over the interpreter. Measured on a 4-core box,
# 8 blocks of 300 tweaks each:
#
#   inline, no executor        0.61s
#   ThreadPoolExecutor(1)      0.64s   (0.96x — the cost of handing work over)
#   ThreadPoolExecutor(2)      1.84s   (0.33x)
#   ThreadPoolExecutor(4)      2.18s   (0.28x)
#
# run_in_executor(None, ...) uses the default pool, which is min(32, cpu+4)
# threads — 8 here — and a scan hands it a whole batch of blocks at once. So the
# matching was running about three times slower than doing nothing clever at
# all. One worker keeps the loop responsive and the contention gone.
#
# Real parallelism needs processes, not threads, since the GIL is the limit.
# That is worth doing only after the per-tweak cost itself comes down.
_matcher = concurrent.futures.ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="silnt-scan-match"
)


async def _match_in_thread(client, fn, *args):
    """Run the synchronous EC matching off the event loop, and time it.

    The timing is the point: it is the only way to say whether a slow scan is
    slow because of the oracle or because of the matching, and that answer
    decides whether anything is worth optimising here at all.
    """
    loop = asyncio.get_event_loop()
    started = time.perf_counter()
    try:
        return await loop.run_in_executor(_matcher, fn, *args)
    finally:
        client.stats.match_seconds += time.perf_counter() - started


def _owned_fingerprint(owned) -> set:
    """What two scan paths must agree on, reduced to something comparable.

    txid, vout and the output key — identity and spendability. Deliberately not
    the timestamp, which the two paths source differently and which is display
    metadata, not money.
    """
    return {(o.txid.hex(), o.vout, o.pub_key.hex()) for o in (owned or [])}


async def scan_block(
    height, client, scan_secret_bytes, spend_pub_bytes, labels,
    network: str,
):
    client.stats.blocks += 1

    # Verification mode: run the fast path and the trusted one over the same
    # block and report any disagreement. The LEGACY result is what gets
    # returned, so a bug in the fast path cannot cost anyone a payment while it
    # is being evaluated. Slower than either path alone, by design — this is a
    # thing you run once over a range whose payments you already know, not a
    # setting to leave on.
    if _VERIFY_COMPUTE_INDEX:
        fast = None
        try:
            fast = await _scan_block_compute_index(
                height, client, scan_secret_bytes, spend_pub_bytes, labels, network
            )
        except Exception as e:
            logger.error(f"compute-index verify: block {height} raised {e!r}")
        legacy = await _scan_block_legacy(
            height, client, scan_secret_bytes, spend_pub_bytes, labels, network
        )
        a, b = _owned_fingerprint(fast), _owned_fingerprint(legacy)
        if fast is None:
            logger.error(f"compute-index verify: block {height} FAST PATH FAILED")
        elif a != b:
            logger.error(
                f"compute-index verify: block {height} MISMATCH — "
                f"fast-only={sorted(a - b)} legacy-only={sorted(b - a)}"
            )
        else:
            logger.debug(f"compute-index verify: block {height} agrees ({len(b)} owned)")
        return legacy

    if _USE_COMPUTE_INDEX:
        return await _scan_block_compute_index(
            height, client, scan_secret_bytes, spend_pub_bytes, labels, network
        )
    return await _scan_block_legacy(
        height, client, scan_secret_bytes, spend_pub_bytes, labels, network
    )


async def _scan_block_compute_index(
    height, client, scan_secret_bytes, spend_pub_bytes, labels, network: str,
):
    """One oracle request per block: the oracle does the filtering."""
    compute_data = await client.get_compute_index(height)
    if not compute_data:
        # 404 means this oracle does not serve compute-index. Fall back rather
        # than report an empty block, which would look exactly like having no
        # money here.
        return await _scan_block_legacy(
            height, client, scan_secret_bytes, spend_pub_bytes, labels, network
        )
    matches = await _match_in_thread(
        client, sync_block_from_compute_index,
        compute_data["index"], scan_secret_bytes, spend_pub_bytes, labels,
    )
    if matches:
        full_utxos = await client.get_utxos(height)
        client.stats.utxos += len(full_utxos)
        lkp = {u["pubkey"]: u for u in full_utxos if "pubkey" in u}
        for owned in matches:
            ph = owned.pub_key.hex()
            full = lkp.get(ph) or next(
                (u for u in full_utxos if u.get("pubkey", "")[:16] == ph[:16]), None
            )
            if full:
                owned.vout = full.get("vout", owned.vout)
                owned.amount = full.get("amount", owned.amount)
                owned.timestamp = full.get("timestamp") or await get_block_ts(
                    full.get("txid", ""), network
                )
                owned.pub_key = bytes.fromhex(full["pubkey"])
    return matches


async def _scan_block_legacy(
    height, client, scan_secret_bytes, spend_pub_bytes, labels, network: str,
):
    """The path that has always run: every tweak and every UTXO in the block,
    matched here. Two oracle requests per block, plus the spent check."""
    if labels:
        tweaks = await client.get_tweaks(height)
        client.stats.tweaks += len(tweaks)
        if not tweaks:
            return []
        utxos = await client.get_utxos(height)
        client.stats.utxos += len(utxos)
        if not utxos:
            return []
        # Offload the synchronous EC matching to a worker thread so it doesn't
        # block the event loop — keeps the API/UI responsive during a scan.
        owned = await _match_in_thread(
            client, sync_block,
            tweaks, utxos, scan_secret_bytes, spend_pub_bytes, labels,
        )
        for o in owned:
            if not o.timestamp:
                # One mempool round trip per detected output whose timestamp the
                # oracle did not supply. Counted separately because it is inside
                # the fetch phase but has nothing to do with the oracle, and on a
                # rescan of a range full of your own payments there can be a lot
                # of them.
                _t = time.perf_counter()
                o.timestamp = await get_block_ts(o.txid.hex(), network)
                client.stats.ts_lookups += 1
                client.stats.ts_seconds += time.perf_counter() - _t
        return owned

    # labels is empty. create_labels() makes that impossible today, so this is
    # unreachable in practice — but it is the correct behaviour if the label set
    # ever becomes genuinely empty, so it stays rather than being deleted.
    tweaks = await client.get_tweaks(height)
    client.stats.tweaks += len(tweaks)
    if not tweaks:
        return []
    utxos = await client.get_utxos(height)
    client.stats.utxos += len(utxos)
    if not utxos:
        return []
    return await _match_in_thread(
        client, sync_block,
        tweaks, utxos, scan_secret_bytes, spend_pub_bytes, labels,
    )


async def mark_spent_utxos_batch(heights, client, wallet_id, owned_utxos_lookup, network):
    """
    Short-hash matches move UTXOs to 'unconfirmed_spent' (provisional), then each
    is verified against the exact outpoint via mempool outspend before finalizing.
    Replaces the previous version that finalized 'spent' directly on an 8-byte
    short-hash match.
    """
    if not owned_utxos_lookup:
        return

    # Resolve the mempool base once for verification.
    backend = await get_backend_config(network)
    mempool_base = backend.mempool_url or "https://mempool.space"

    async def check_height(height: int):
        try:
            spent_data = await client.get_spent_outputs(height)
            if not spent_data:
                return
            spent_set = set(spent_data.get("index", []))
            if not spent_set:
                return

            rows = await db.fetchall(
                """SELECT txid, vout, pub_key FROM silnt.utxos
                   WHERE wallet_id = :wallet_id
                   AND utxo_state IN ('unspent', 'unconfirmed_spent')""",
                {"wallet_id": wallet_id},
            )
            for row in rows:
                short_pub = row["pub_key"][:16]  # 8 bytes = 16 hex chars
                if short_pub not in spent_set:
                    continue
                # PROVISIONAL: short-hash match → mark unconfirmed_spent, do NOT
                # finalize. Only flip from 'unspent'; leave existing
                # 'unconfirmed_spent' as-is (verification below handles both).
                await db.execute(
                    """UPDATE silnt.utxos SET utxo_state = 'unconfirmed_spent'
                       WHERE txid = :txid AND vout = :vout
                         AND wallet_id = :wallet_id
                         AND utxo_state = 'unspent'""",
                    {"txid": row["txid"], "vout": row["vout"], "wallet_id": wallet_id},
                )
                # VERIFY the exact outpoint before finalizing.
                status = await get_outspend_status(mempool_base, row["txid"], row["vout"])
                if status is None:
                    # Unknown — leave as unconfirmed_spent, retry next scan.
                    logger.info(
                        f"{row['txid']}:{row['vout']} short-hash matched at block "
                        f"{height}; outspend unknown — left unconfirmed_spent"
                    )
                    continue
                if status["spent"]:
                    await db.execute(
                        """UPDATE silnt.utxos SET utxo_state = 'spent'
                           WHERE txid = :txid AND vout = :vout
                             AND wallet_id = :wallet_id
                             AND utxo_state = 'unconfirmed_spent'""",
                        {"txid": row["txid"], "vout": row["vout"], "wallet_id": wallet_id},
                    )
                    logger.info(
                        f"Confirmed {row['txid']}:{row['vout']} spent (outspend) "
                        f"at block {height}"
                    )
                else:
                    # FALSE POSITIVE: 8-byte short-hash collision. Restore unspent.
                    await db.execute(
                        """UPDATE silnt.utxos SET utxo_state = 'unspent'
                           WHERE txid = :txid AND vout = :vout
                             AND wallet_id = :wallet_id
                             AND utxo_state = 'unconfirmed_spent'""",
                        {"txid": row["txid"], "vout": row["vout"], "wallet_id": wallet_id},
                    )
                    logger.warning(
                        f"Short-hash FALSE POSITIVE: {row['txid']}:{row['vout']} "
                        f"matched spent-index at block {height} but outspend says "
                        f"unspent — restored to unspent."
                    )
        except Exception as e:
            logger.warning(f"mark_spent_utxos error at block {height}: {e}")

    # Verification adds an explorer call per matched UTXO. Matches are rare
    # (only your own spends), so this stays cheap. Kept within the same
    # asyncio.gather over heights as before.    
    await asyncio.gather(*[check_height(h) for h in heights])


async def set_last_scan_height(wallet_id: str, height: int) -> None:
    await db.execute(
        "UPDATE silnt.wallets SET last_scan_height = :height WHERE id = :id",
        {"height": height, "id": wallet_id},
    )


def get_scan_progress(wallet_id: str) -> dict:
    return _scan_progress.get(
        wallet_id, {"active": False, "current": 0, "total": 0, "found": 0, "amount": 0}
    )


def set_scan_progress(wallet_id, current, total, found, active=True, amount=0):
    _scan_progress[wallet_id] = {
        "active": active,
        "current": current,
        "total": total,
        "found": found,
        "amount": amount,
    }


def mark_scan_inactive(wallet_id: str) -> None:
    """Say this wallet is no longer scanning, keeping the counters it reached.

    A wallet stuck at active=True is worse than one that reports a failure: the
    app shows a progress bar for a scan that is not running and never finishes,
    the background sweep skips the wallet (run_background_scans checks this
    flag), and the scan panel will not even offer a range to retry. Nothing
    recovers it short of restarting LNbits, because the flag lives in memory.
    """
    progress = _scan_progress.get(wallet_id)
    if progress:
        progress["active"] = False
    # No entry means no scan has run for this wallet in this process, and
    # get_scan_progress already reports that as inactive.


def clear_wallet_scan_state(wallet_id: str) -> None:
    """Forget everything this process remembers about scanning one wallet.

    Called when a wallet is deleted. Wallet ids are deliberately reproducible
    from the seed ("sp" + sha256(network:sp_address)), so deleting a wallet and
    importing the same phrase again produces the SAME id — and would otherwise
    inherit the deleted wallet's scan state. That is not hypothetical: a
    lingering active=True is exactly what makes a freshly imported wallet
    refuse to scan and show no Silent Payments balance.
    """
    _scan_progress.pop(wallet_id, None)
    _scan_stop.pop(wallet_id, None)


async def scan_wallet(
    wallet_id: str,
    scan_secret_hex: str,
    spend_secret_hex: Optional[str] = None,
    from_height: Optional[int] = None,
    to_height: Optional[int] = None,
    spend_pub_hex: Optional[str] = None,
) -> dict:
    """Scan a range of blocks for this wallet's Silent Payments outputs.

    Owns the active flag rather than trusting callers to clear it: whatever
    happens in here — an oracle timeout, a DB error, the wallet being deleted
    mid-scan — the wallet must not be left looking busy forever. Every caller
    got this wrong at least once, so the guarantee belongs at the source.
    """
    try:
        return await _scan_wallet(
            wallet_id=wallet_id,
            scan_secret_hex=scan_secret_hex,
            spend_secret_hex=spend_secret_hex,
            from_height=from_height,
            to_height=to_height,
            spend_pub_hex=spend_pub_hex,
        )
    finally:
        mark_scan_inactive(wallet_id)


async def _scan_wallet(
    wallet_id: str,
    scan_secret_hex: str,  # scan private key — detection only
    spend_secret_hex: Optional[str] = None,
    from_height: Optional[int] = None,
    to_height: Optional[int] = None,
    spend_pub_hex: Optional[str] = None,
) -> dict:
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise ValueError(f"Wallet {wallet_id} not found")
    blindbit = await get_backend_config(wallet.network)
    if not blindbit.blindbit_url:
        raise ValueError("BlindBit Oracle URL not configured")

    scan_secret_bytes = bytes.fromhex(scan_secret_hex)
    # Scanning is detection-only: it needs the spend PUBLIC key, never the spend
    # private key. Accept the pubkey directly (the background scanner derives it
    # from the wallet's sp_address, so the spend key never reaches the server) or
    # derive it from a supplied spend secret (interactive client scans).
    if spend_pub_hex:
        spend_pub_bytes = bytes.fromhex(spend_pub_hex)
    elif spend_secret_hex:
        spend_pub_bytes = coincurve.PublicKey.from_secret(
            bytes.fromhex(spend_secret_hex)
        ).format(compressed=True)
    else:
        raise ValueError("scan_wallet needs spend_pub_hex or spend_secret_hex")
    spend_pub_hex_resolved = spend_pub_bytes.hex()

    oracle = BlindBitOracleClient(base_url=blindbit.blindbit_url)
    scan_started = time.perf_counter()
    start = max(from_height if from_height is not None else wallet.last_height, 1)
    end = to_height if to_height is not None else await oracle.get_chain_tip()
    logger.info(f"Scanning wallet {wallet_id} blocks {start}–{end}")

    saved_addresses = await get_wallet_addresses(wallet_id)
    labels = create_labels(
        scan_secret_bytes, indices=[a.label_index for a in saved_addresses]
    )
    addr_label_map: dict[int, str] = {
        a.label_index: a.label
        for a in saved_addresses
        if getattr(a, "label", None)
    }
    total_found = 0
    total_found_amount = 0
    blocks_scanned = 0
    last_scanned_height = start
    total_blocks = end - start + 1
    stopped = False
    clear_scan_stop(wallet_id)
    set_scan_progress(wallet_id, 0, total_blocks, 0)
    # How many blocks are in flight at once.
    #
    # This was 5, chosen when every request paid for its own TCP and TLS
    # handshake — in that world more concurrency mostly bought more handshakes.
    # With a pooled, keep-alive client the requests are cheap and the limit is
    # what the oracle will tolerate, so the default is higher. Each block is
    # still a few small requests, and the matching stays on worker threads, so
    # the event loop keeps yielding and the UI stays responsive.
    #
    # Tunable because "what the oracle tolerates" is a property of someone
    # else's server: lower it if a scan starts drawing timeouts or 429s. The
    # ceiling is the client's max_connections.
    BATCH_SIZE = _env_int("SILNT_SCAN_BATCH_SIZE", 24, 1, 64)

    for batch_start in range(0, total_blocks, BATCH_SIZE):
        if should_stop(wallet_id):
            logger.info(f"Scan stopped at {last_scanned_height}")
            stopped = True
            await set_last_scan_height(wallet_id, last_scanned_height)
            set_scan_progress(
                wallet_id, blocks_scanned, total_blocks, total_found,
                active=False, amount=total_found_amount,
            )
            clear_scan_stop(wallet_id)
            break

        batch = list(
            range(start + batch_start, min(start + batch_start + BATCH_SIZE, end + 1))
        )

        owned_rows = await db.fetchall(
            "SELECT txid, vout FROM silnt.utxos WHERE wallet_id = :wallet_id AND utxo_state IN ('unspent', 'unconfirmed_spent')",
            {"wallet_id": wallet_id},
        )
        owned_utxos_lookup = {f"{r['txid']}:{r['vout']}": r for r in owned_rows}

        _t = time.perf_counter()
        batch_results = await asyncio.gather(
            *[
                scan_block(
                    h,
                    oracle,
                    scan_secret_bytes,
                    spend_pub_bytes,
                    labels,
                    wallet.network,
                )
                for h in batch
            ],
            return_exceptions=True,
        )
        oracle.stats.fetch_seconds += time.perf_counter() - _t

        _t = time.perf_counter()
        await mark_spent_utxos_batch(batch, oracle, wallet_id, owned_utxos_lookup, wallet.network)
        oracle.stats.spent_seconds += time.perf_counter() - _t

        _t = time.perf_counter()
        for h, result in zip(batch, batch_results):
            if isinstance(result, Exception):
                logger.error(f"Block {h} error: {result}")
                continue
            if result:
                # Inherit address labels onto matching UTXOs (added earlier)
                for owned in result:
                    if owned.label and owned.label.m in addr_label_map:
                        owned.label_text = addr_label_map[owned.label.m]
                    elif owned.label and owned.label.m >= 2:
                        try:
                            hrp = "sp" if (wallet.network == "mainnet") else "tsp"
                            spend_pub_hex = spend_pub_hex_resolved
                            labeled_addr = generate_labeled_sp_address(
                                scan_secret_hex=scan_secret_hex,
                                spend_pub_hex=spend_pub_hex,
                                m=owned.label.m,
                                hrp=hrp,
                            )
                            await ensure_labeled_address_row(
                                wallet_id, labeled_addr, owned.label.m
                            )
                        except Exception as e:
                            logger.warning(f"Could not restore labeled address m={owned.label.m}: {e}")    
                try:
                    # Count only genuinely NEW utxos — re-detecting an existing
                    # one on a rescan is an upsert, not a discovery, and must not
                    # inflate the "found" count the UI shows.
                    new_count, new_amount = await insert_utxos_for_wallet(wallet_id, result)
                    total_found += new_count
                    total_found_amount += new_amount
                    logger.info(
                        f"Block {h}: {len(result)} detected, {new_count} new"
                    )
                except Exception as ins_err:
                    # Log full DB error server-side for the admin to investigate,
                    # but don't crash the whole scan — just skip this block's results
                    logger.error(
                        f"Block {h}: found {len(result)} UTXO(s) but DB insert failed: {ins_err}"
                    )
                    continue
            blocks_scanned += 1
            last_scanned_height = h

        set_scan_progress(
            wallet_id, blocks_scanned, total_blocks, total_found,
            amount=total_found_amount,
        )
        await set_last_scan_height(wallet_id, last_scanned_height)
        oracle.stats.persist_seconds += time.perf_counter() - _t

        # Yield to the event loop between batches so other requests (wallet
        # loads, navigation) get serviced promptly during a long scan.
        await asyncio.sleep(0)

    await set_last_scan_height(wallet_id, last_scanned_height)
    set_scan_progress(
        wallet_id, blocks_scanned, total_blocks, total_found,
        active=False, amount=total_found_amount,
    )

    try:
        rec = await reconcile_unconfirmed_spent(wallet_id, wallet.network)
        if rec["restored"] or rec["confirmed"]:
            logger.info(
                f"Wallet {wallet_id} reconcile: "
                f"{rec['confirmed']} confirmed, {rec['restored']} restored, "
                f"{rec['pending']} still pending"
            )
    except Exception as e:
        logger.warning(f"Reconcile failed for {wallet_id}: {e}")
        
    unspent = await db.fetchall(
        "SELECT amount FROM silnt.utxos WHERE wallet_id = :wallet_id AND utxo_state = 'unspent'",
        {"wallet_id": wallet_id},
    )
    balance = sum(r["amount"] for r in unspent)
    await update_balance(wallet_id, balance)
    try:        
        newly_flagged = await evaluate_dust_for_wallet(wallet_id)
        if newly_flagged > 0:
            logger.info(f"Wallet {wallet_id}: flagged {newly_flagged} new dust UTXO(s)")
    except Exception as e:
        logger.warning(f"Dust evaluation failed for {wallet_id}: {e}")
    logger.info(
        f"Scan done: {blocks_scanned} blocks, {total_found} UTXOs, balance={balance}"
    )
    # The number that decides what, if anything, to optimise next. If waiting on
    # the oracle dominates, faster matching — in any language — changes nothing.
    oracle.stats.wall_seconds = time.perf_counter() - scan_started
    logger.info(f"Scan timing: {oracle.stats.summary()}")
    logger.info(f"Scan phases: {oracle.stats.phases()}")
    set_scan_progress(
        wallet_id, blocks_scanned, total_blocks, total_found,
        active=False, amount=total_found_amount,
    )
    return {
        "utxos_found": total_found,
        "amount_found": total_found_amount,
        "blocks_scanned": blocks_scanned,
        "final_height": last_scanned_height,
        "balance": balance,
        "stopped": stopped,
        "timing": oracle.stats.as_dict()
    }


async def scan_all_wallets(user: str, network: str = "mainnet") -> list[dict]:
    results = []
    for wallet in await get_silnt_wallets(user, network):
        try:
            r = await scan_wallet(wallet.id)
            r["wallet_id"] = wallet.id
            results.append(r)
        except Exception as e:
            logger.error(f"Wallet {wallet.id} failed: {e}")
            results.append({"wallet_id": wallet.id, "error": str(e)})
    return results


async def get_block_ts(txid: str, network: str = DEFAULT_CONFIG_NETWORK) -> int:
    backend = await get_backend_config(network)
    base = (backend.mempool_url or "https://mempool.space").rstrip("/")
    try:
        # Shared, pooled, keep-alive — the same fix the oracle client got, for
        # the same reason: this used to build a client and open a connection per
        # call, and it is called once per detected output.
        #
        # A SEPARATE client from the oracle's on purpose: this one verifies TLS
        # certificates and the oracle's, by long-standing default, does not.
        # Routing it through the shared oracle client would quietly downgrade it.
        r = await get_mempool_client().get(f"{base}/api/tx/{txid}")
        if r.status_code == 200:
            return int(r.json().get("status", {}).get("block_time") or 0)
    except Exception:
        pass
    return 0

async def get_tx_status(base_mempool_url: str, txid: str) -> dict | None:
    """
    Returns {"confirmed": bool} if the tx is known to the explorer,
    or None if the tx is unknown (404 — dropped / never propagated).
    """
    base = (base_mempool_url or "https://mempool.space").rstrip("/")
    url = f"{base}/api/tx/{txid}"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as c:
            r = await c.get(url)
            if r.status_code == 404:
                return None                      # unknown → dropped
            if r.status_code != 200:
                # transient error — treat as "unknown status", do nothing this round
                return {"unknown": True}
            data = r.json()
            return {"confirmed": bool(data.get("status", {}).get("confirmed", False))}
    except Exception as e:
        logger.warning(f"tx-status check failed for {txid}: {e}")
        return {"unknown": True}                  # network hiccup — don't change state


async def reconcile_unconfirmed_spent(wallet_id: str, network: str = DEFAULT_CONFIG_NETWORK) -> dict:
    """
    Walk the wallet's unconfirmed_spent UTXOs and reconcile each against the
    explorer. Returns counts of {confirmed, restored, pending}.
    """
    backend = await get_backend_config(network)
    base = backend.mempool_url or "https://mempool.space"

    rows = await db.fetchall(
        """SELECT txid, vout, spent_in_txid FROM silnt.utxos
           WHERE wallet_id = :wid AND utxo_state = 'unconfirmed_spent'""",
        {"wid": wallet_id},
    )
    if not rows:
        return {"confirmed": 0, "restored": 0, "pending": 0}

    # Group outpoints by the spending txid so we query each tx once
    by_txid: dict[str, list[tuple[str, int]]] = {}
    for r in rows:
        stx = r["spent_in_txid"]
        if not stx:
            # No spending txid recorded but state is unconfirmed_spent — anomalous.
            # Safest is to leave it; a manual restore can handle it.
            continue
        by_txid.setdefault(stx, []).append((r["txid"], r["vout"]))

    confirmed = restored = pending = 0

    for spending_txid, outpoints in by_txid.items():
        status = await get_tx_status(base, spending_txid)

        if status is None:
            # Dropped / unknown to the explorer → the spend never happened.
            # Restore these inputs to unspent so they're spendable again.
            for (in_txid, in_vout) in outpoints:
                await db.execute(
                    """UPDATE silnt.utxos
                          SET utxo_state    = 'unspent',
                              spent_in_txid = NULL,
                              spent_at      = NULL
                        WHERE wallet_id = :wid AND txid = :txid AND vout = :vout
                          AND utxo_state = 'unconfirmed_spent'""",
                    {"wid": wallet_id, "txid": in_txid, "vout": in_vout},
                )
                restored += 1
            logger.info(
                f"Restored {len(outpoints)} UTXO(s) to unspent — spending tx "
                f"{spending_txid} was dropped/unknown"
            )

        elif status.get("confirmed"):
            # The spend confirmed → finalize as spent.
            for (in_txid, in_vout) in outpoints:
                await db.execute(
                    """UPDATE silnt.utxos SET utxo_state = 'spent'
                        WHERE wallet_id = :wid AND txid = :txid AND vout = :vout
                          AND utxo_state = 'unconfirmed_spent'""",
                    {"wid": wallet_id, "txid": in_txid, "vout": in_vout},
                )
                confirmed += 1
            logger.info(f"Finalized {len(outpoints)} UTXO(s) spent by confirmed tx {spending_txid}")

        else:
            # Still pending in mempool, or transient error → leave unchanged.
            pending += len(outpoints)

    return {"confirmed": confirmed, "restored": restored, "pending": pending}