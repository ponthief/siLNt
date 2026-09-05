"""
Standalone checks for the sweep path (helpers/sweep.py), in the same spirit as
_curve_equivalence_check.py: no pytest, no DB, run it directly.

    python3 helpers/_sweep_check.py        # from the siLNt directory

Covers the parts where a mistake loses money rather than throwing:

  1. BIP-84 derivation against the canonical vectors, so the sweep address is
     the one the user's other wallets would show for the same seed.
  2. The Silent Payments output for a normal taproot spend, frozen — the sweep
     work refactored that derivation, and any drift changes where every existing
     send goes.
  3. A full round trip: build a sweep, then find its output with the RECEIVER
     scanner in helpers/scan.py. That is the property that matters — an output
     the scanner cannot find is an output whose coins are gone.
  4. Every P2WPKH witness verifies against its own BIP-143 sighash.
  5. That the is_taproot flag is load-bearing: negating a P2WPKH input key, the
     one plausible way to get this wrong, yields an output the receiver misses.
"""

from __future__ import annotations

import hashlib
import sys
import types
from io import BytesIO


def _bootstrap():
    """Import helpers/ without dragging in LNbits or the DB layer."""
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    sys.path.insert(0, os.path.dirname(root))

    pkg = types.ModuleType(os.path.basename(root))
    pkg.__path__ = [root]
    sys.modules[os.path.basename(root)] = pkg

    class _Any(types.ModuleType):
        def __getattr__(self, name):
            return None

    sys.modules[f"{os.path.basename(root)}.crud"] = _Any(f"{os.path.basename(root)}.crud")

    lnbits = types.ModuleType("lnbits")
    utils = types.ModuleType("lnbits.utils")
    crypto = types.ModuleType("lnbits.utils.crypto")

    class AESCipher:
        def __init__(self, key=None):
            pass

    crypto.AESCipher = AESCipher
    utils.crypto = crypto
    lnbits.utils = utils
    sys.modules.setdefault("lnbits", lnbits)
    sys.modules.setdefault("lnbits.utils", utils)
    sys.modules.setdefault("lnbits.utils.crypto", crypto)
    return os.path.basename(root)


PKG = _bootstrap()

import coincurve  # noqa: E402
from embit import bip32, bip39, ec, script  # noqa: E402
from embit.networks import NETWORKS  # noqa: E402
from embit.transaction import SIGHASH, Transaction  # noqa: E402

_w = __import__(f"{PKG}.helpers.wallet", fromlist=["*"])
_s = __import__(f"{PKG}.helpers.sweep", fromlist=["*"])
_c = __import__(f"{PKG}.helpers.curve", fromlist=["*"])
_sc = __import__(f"{PKG}.helpers.scan", fromlist=["*"])

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FAILED: list[str] = []


def ok(name: str, cond: bool, detail: str = ""):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        if detail:
            print("         " + detail)
        FAILED.append(name)


def tagged(tag: str, data: bytes) -> bytes:
    h = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(h + h + data).digest()


# ── 1. BIP-84 ────────────────────────────────────────────────────────────────
print("\n1. BIP-84 canonical vectors")
MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(MNEMONIC, password=""))
k00 = root.derive("m/84'/0'/0'/0/0").key
ok(
    "m/84'/0'/0'/0/0 is bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    script.p2wpkh(k00.get_public_key()).address(NETWORKS["main"])
    == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
)
ok(
    "sweep_address_for_key derives the same address",
    _s.sweep_address_for_key(k00.secret.hex(), "mainnet")
    == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
)

# ── 2. taproot SP output, frozen ─────────────────────────────────────────────
print("\n2. Silent Payments output for a taproot spend (frozen)")
SPEND = bytes.fromhex("11" * 32)
SCAN = bytes.fromhex("22" * 32)
SPEND_PUB = coincurve.PublicKey.from_secret(SPEND).format(True)
SCAN_PUB = coincurve.PublicKey.from_secret(SCAN).format(True)
SP_ADDR = _c.bech32_encode(
    "tsp", [0] + _c.convertbits(SCAN_PUB + SPEND_PUB, 8, 5), _c.Encoding.BECH32M
)
frozen = _w.derive_sp_scriptpubkey(
    SP_ADDR,
    SPEND,
    [
        {"txid": "aa" * 32, "vout": 1, "amount": 100_000, "priv_key_tweak": "33" * 32},
        {"txid": "bb" * 32, "vout": 0, "amount": 50_000, "priv_key_tweak": "44" * 32},
    ],
).hex()
EXPECTED = "5120b0e1e857769fc909eb0515a8965ae827d7f99c9c97cb2b35a1bf6e71722f8006"
ok("output unchanged", frozen == EXPECTED, f"got {frozen}")

# ── 3. sweep round trip ──────────────────────────────────────────────────────
# Two DIFFERENT addresses on the chain, because rotating the receive address
# means a sweep routinely spans more than one — and a single-key sum would still
# pass a same-key test while being wrong here.
print("\n3. sweep round trip across two chain indices")
keys = [root.derive(f"m/84'/1'/0'/0/{i}").key for i in (0, 1)]
addrs = [script.p2wpkh(k.get_public_key()).address(NETWORKS["test"]) for k in keys]
ok("the two indices give different addresses", addrs[0] != addrs[1])

utxos = [
    {"address": addrs[0], "txid": "cc" * 32, "vout": 0, "amount": 40_000, "height": 100},
    {"address": addrs[1], "txid": "dd" * 32, "vout": 3, "amount": 60_000, "height": 101},
]
built = _s.build_sweep_transaction(
    [k.secret.hex() for k in keys], SP_ADDR, utxos, 5.0, "signet"
)
tx = Transaction.read_from(BytesIO(bytes.fromhex(built["tx_hex"])))

ok("fee accounting balances", built["amount"] + built["fee"] == built["total_input"])
ok("exactly one output", len(tx.vout) == 1)
ok("output is P2TR", tx.vout[0].script_pubkey.data[:2] == bytes([0x51, 0x20]))
ok("both addresses reported swept", len(built["swept_addresses"]) == 2)

# Rebuild the per-transaction tweak the way the BlindBit indexer would, then
# hand it to the receiver scanner — a code path entirely separate from the
# sender's.
ordered = sorted(utxos, key=lambda u: (u["txid"], int(u["vout"])))
by_address = {a: k for a, k in zip(addrs, keys)}
outpoints = [bytes(reversed(v.txid)) + v.vout.to_bytes(4, "little") for v in tx.vin]
a_sum = sum(int.from_bytes(by_address[u["address"]].secret, "big") for u in ordered) % N
A_sum = coincurve.PublicKey.from_secret(a_sum.to_bytes(32, "big")).format(True)
input_hash = tagged("BIP0352/Inputs", min(outpoints) + A_sum)

found = _sc.receiver_scan_transaction(
    SCAN, SPEND_PUB, [], [tx.vout[0].script_pubkey.data[2:]], A_sum, input_hash
)
ok("scanner finds the swept output", len(found) == 1)

# A key for an address that holds coins must never be silently skipped: a
# partial sweep leaves money behind while reporting the addresses emptied.
try:
    _s.build_sweep_transaction([keys[0].secret.hex()], SP_ADDR, utxos, 5.0, "signet")
    ok("a missing key is refused, not skipped", False)
except ValueError:
    ok("a missing key is refused, not skipped", True)

# ── 4. signatures ────────────────────────────────────────────────────────────
print("\n4. BIP-143 signatures")
valid = True
for i, u in enumerate(ordered):
    key = by_address[u["address"]]
    items = tx.vin[i].witness.items
    if len(items) != 2 or items[0][-1] != SIGHASH.ALL:
        valid = False
        break
    script_code = script.p2pkh_from_p2wpkh(script.p2wpkh(key.get_public_key()))
    h = tx.sighash_segwit(i, script_code, u["amount"], SIGHASH.ALL)
    if not key.get_public_key().verify(ec.Signature.parse(items[0][:-1]), h):
        valid = False
    # Each input must carry ITS OWN key, not whichever was first in the list.
    if items[1] != key.get_public_key().sec():
        valid = False
ok("each witness is [sig|SIGHASH_ALL, pubkey] for its own input's key", valid)

# ── 5. the taproot flag ──────────────────────────────────────────────────────
print("\n5. is_taproot is load-bearing")
wrong_inputs = [
    (N - int.from_bytes(by_address[u["address"]].secret, "big"), op, False)
    for u, op in zip(ordered, outpoints)
]
wrong = _w.sp_scriptpubkey_from_inputs(SP_ADDR, wrong_inputs)
wrong_found = _sc.receiver_scan_transaction(
    SCAN, SPEND_PUB, [], [wrong[2:]], A_sum, input_hash
)
ok(
    "negating a P2WPKH key produces an output the receiver cannot find",
    wrong != tx.vout[0].script_pubkey.data and not wrong_found,
)

print()
if FAILED:
    print(f"{len(FAILED)} FAILED: " + ", ".join(FAILED))
    sys.exit(1)
print("all checks passed")
