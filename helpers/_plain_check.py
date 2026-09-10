"""
Standalone checks for the plain-address chain (helpers/plain.py), in the same
spirit as _curve_equivalence_check.py: no pytest, no DB, run it directly.

    python3 helpers/_plain_check.py        # from the siLNt directory

Covers the parts where a mistake loses money rather than throwing:

  1. BIP-84 derivation against the canonical vectors, so a plain address is the
     one the user's other wallets would show for the same seed.
  2. The Silent Payments output for a normal taproot spend, frozen — this work
     refactored that derivation, and any drift changes where every existing send
     goes.
  3. Paying a Silent Payments address from the plain chain, round-tripped: build
     it, then find the output with the RECEIVER scanner in helpers/scan.py. That
     is the property that matters — an output the scanner cannot find is an
     output whose coins are gone. It is also the only path where the two key
     types have to agree.
  4. Every P2WPKH witness verifies against its own BIP-143 sighash.
  5. That the is_taproot flag is load-bearing: negating a P2WPKH input key, the
     one plausible way to get this wrong, yields an output the receiver misses.
  6. Paying an ordinary address: change, fees per output type, and that nothing
     in the transaction belongs to the Silent Payments wallet.
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
_s = __import__(f"{PKG}.helpers.plain", fromlist=["*"])
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
    "plain_address_for_key derives the same address",
    _s.plain_address_for_key(k00.secret.hex(), "mainnet")
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
print("\n3. paying a Silent Payments address from two chain indices")
keys = [root.derive(f"m/84'/1'/0'/0/{i}").key for i in (0, 1)]
addrs = [script.p2wpkh(k.get_public_key()).address(NETWORKS["test"]) for k in keys]
ok("the two indices give different addresses", addrs[0] != addrs[1])

utxos = [
    {"address": addrs[0], "txid": "cc" * 32, "vout": 0, "amount": 40_000, "height": 100},
    {"address": addrs[1], "txid": "dd" * 32, "vout": 3, "amount": 60_000, "height": 101},
]
built = _s.build_plain_transaction(
    keys=[k.secret.hex() for k in keys],
    destination=SP_ADDR,
    utxos=utxos,
    fee_rate=5.0,
    network="signet",
)
tx = Transaction.read_from(BytesIO(bytes.fromhex(built["tx_hex"])))

ok("fee accounting balances", built["amount"] + built["fee"] == built["total_input"])
ok("exactly one output", len(tx.vout) == 1)
ok("output is P2TR", tx.vout[0].script_pubkey.data[:2] == bytes([0x51, 0x20]))
ok("both addresses reported spent", len(built["swept_addresses"]) == 2)

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
ok("scanner finds the output", len(found) == 1)

# A key for an address that holds coins must never be silently skipped: a
# partial spend leaves money behind while reporting the addresses emptied.
try:
    _s.build_plain_transaction(
        keys=[keys[0].secret.hex()], destination=SP_ADDR, utxos=utxos,
        fee_rate=5.0, network="signet",
    )
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

# ── 6. paying out of the pool ────────────────────────────────────────────────
print("\n6. paying an ordinary address (no Silent Payments involved)")
# Derived rather than pasted, so the checksums are right by construction.
DEST = script.p2wpkh(root.derive("m/84'/1'/9'/0/0").key.get_public_key()).address(
    NETWORKS["test"]
)
DEST_TR = script.p2tr(root.derive("m/86'/1'/0'/0/0").key.get_public_key()).address(
    NETWORKS["test"]
)
change_addr = script.p2wpkh(root.derive("m/84'/1'/0'/0/9").key.get_public_key()).address(
    NETWORKS["test"]
)

paid = _s.build_plain_transaction(
    keys=[keys[0].secret.hex()],
    destination=DEST,
    utxos=[utxos[0]],
    fee_rate=2.0,
    network="signet",
    amount=10_000,
    change_address=change_addr,
)
ptx = Transaction.read_from(BytesIO(bytes.fromhex(paid["tx_hex"])))
ok("pays the requested amount", paid["amount"] == 10_000)
ok(
    "value is conserved",
    paid["amount"] + paid["change"] + paid["fee"] == paid["total_input"],
)
ok("two outputs: destination and change", len(ptx.vout) == 2)
dest_spk = script.address_to_scriptpubkey(DEST).data
change_spk = script.address_to_scriptpubkey(change_addr).data
spks = [o.script_pubkey.data for o in ptx.vout]
ok("destination output present", dest_spk in spks)
ok("change returns to the plain chain", change_spk in spks)
ok(
    "change value matches",
    next(o.value for o in ptx.vout if o.script_pubkey.data == change_spk)
    == paid["change"],
)
# The whole point: no output belongs to the Silent Payments wallet.
found_sp = _sc.receiver_scan_transaction(
    SCAN, SPEND_PUB, [], [o.script_pubkey.data[2:] for o in ptx.vout if len(o.script_pubkey.data) == 34], A_sum, input_hash
)
ok("nothing in it belongs to the SP wallet", not found_sp)

# Fee must reflect the real size, including the change output.
import math as _math  # noqa: E402
expected_vsize = _math.ceil(
    _s.OVERHEAD_VBYTES + _s.INPUT_VBYTES + 31 + _s.CHANGE_VBYTES
)  # 1 input, P2WPKH destination, P2WPKH change
ok(
    "vsize counts one input, the destination and the change output",
    paid["vsize"] == expected_vsize,
    f"got {paid['vsize']}, expected {expected_vsize}",
)
ok("fee is vsize x rate", paid["fee"] == 2 * paid["vsize"])

# A taproot destination is a bigger output and must cost more.
paid_tr = _s.build_plain_transaction(
    keys=[keys[0].secret.hex()], destination=DEST_TR, utxos=[utxos[0]],
    fee_rate=2.0, network="signet", amount=10_000, change_address=change_addr,
)
ok("a taproot destination costs more vbytes", paid_tr["vsize"] > paid["vsize"])

# Dust change is given to the miner rather than made into an unspendable output.
dusty = _s.build_plain_transaction(
    keys=[keys[0].secret.hex()], destination=DEST, utxos=[utxos[0]],
    fee_rate=1.0, network="signet",
    amount=utxos[0]["amount"] - 200, change_address=change_addr,
)
ok("dust change is absorbed into the fee, not created",
   dusty["change"] == 0 and len(Transaction.read_from(BytesIO(bytes.fromhex(dusty["tx_hex"]))).vout) == 1)

# Change must not be routable off this chain.
try:
    _s.build_plain_transaction(
        keys=[keys[0].secret.hex()], destination=DEST, utxos=[utxos[0]],
        fee_rate=2.0, network="signet", amount=10_000, change_address=DEST_TR,
    )
    ok("change off the plain chain is refused", False)
except ValueError:
    ok("change off the plain chain is refused", True)

# Signatures still verify with two outputs in play.
sc = script.p2pkh_from_p2wpkh(script.p2wpkh(keys[0].get_public_key()))
h = ptx.sighash_segwit(0, sc, utxos[0]["amount"], SIGHASH.ALL)
items = ptx.vin[0].witness.items
ok(
    "the pay-out signature verifies",
    keys[0].get_public_key().verify(ec.Signature.parse(items[0][:-1]), h),
)

# ── batched vs sequential walk ───────────────────────────────────────────────
# Batching turned twenty-plus round trips into two, which is the difference
# between a receive address appearing at once and after a visible wait. The risk
# is that the two paths disagree: pairing a batch response to the wrong address
# would attribute one address's coins to another, and the wallet would sign with
# the wrong key. So both paths run over the same fake server and must produce
# byte-identical results.
def _check_batched_walk():
    _scan_batched = _s._scan_batched
    _scan_one = _s._scan_one

    # Three addresses: unused, used-with-coins, used-and-emptied. The last is
    # the one that matters — no unspent outputs, but must still read as used.
    #
    # DERIVED, not written out: a hand-typed bech32 string fails its checksum
    # and the check dies on setup rather than testing anything.
    addrs = [
        _s.plain_address_for_key(f"{n:064x}", "signet") for n in (11, 12, 13)
    ]
    HISTORY = {0: [], 1: [{"tx_hash": "aa", "height": 100}], 2: [{"tx_hash": "bb", "height": 90}]}
    UNSPENT = {
        1: [
            {"tx_hash": "aa", "tx_pos": 0, "height": 100, "value": 50_000},
            {"tx_hash": "cc", "tx_pos": 1, "height": 0, "value": 7_000},
        ],
        2: [],
    }

    class FakeClient:
        """Stands in for ElectrumClient at the call_batch boundary.

        Answers in the order asked, because that is call_batch's contract —
        it has already paired responses to requests by id. Whether it does
        that correctly is tested separately below, against a socket that
        deliberately replies out of order.
        """

        def __init__(self):
            self.round_trips = 0
            self._sh_to_idx = {}

        def _idx(self, sh):
            return self._sh_to_idx[sh]

        def call_batch(self, calls):
            self.round_trips += 1
            out = []
            for n, (method, params) in enumerate(calls):
                i = self._idx(params[0])
                result = HISTORY[i] if "get_history" in method else UNSPENT.get(i, [])
                out.append({"id": n, "result": result})
            return out

        def get_history(self, sh):
            self.round_trips += 1
            return HISTORY[self._idx(sh)]

        def list_unspent(self, sh):
            self.round_trips += 1
            return UNSPENT.get(self._idx(sh), [])

    electrum_scripthash = __import__(
        f"{PKG}.helpers.electrum_client", fromlist=["*"]
    ).electrum_scripthash

    fake = FakeClient()
    for i, a in enumerate(addrs):
        fake._sh_to_idx[electrum_scripthash(a)] = i

    batched = _scan_batched(fake, addrs)
    batch_trips = fake.round_trips

    fake.round_trips = 0
    sequential = [_scan_one(fake, a) for a in addrs]
    seq_trips = fake.round_trips

    ok("batched and sequential walks agree exactly", batched == sequential,
          f"\n  batched={batched}\n  sequential={sequential}")
    ok("an emptied address still reads as used",
          batched[2]["used"] and batched[2]["utxos"] == [], str(batched[2]))
    ok("confirmed and unconfirmed stay apart",
          batched[1]["confirmed_sats"] == 50_000
          and batched[1]["unconfirmed_sats"] == 7_000
          and batched[1]["unconfirmed_count"] == 1, str(batched[1]))
    ok("unused addresses cost no second call", batch_trips == 2, f"{batch_trips} round trips")
    ok(f"batching cut {seq_trips} round trips to {batch_trips}", batch_trips < seq_trips)


_check_batched_walk()


# ── call_batch pairs by id, not position ────────────────────────────────────
# The one place a batch can corrupt a wallet: if responses were matched to
# requests by position and the server replied in a different order, one
# address's history would be attributed to another. The client would then hand
# out an address it believes unused, or sign for coins with the wrong key. The
# Electrum spec does not promise order, so this is tested against a socket that
# replies backwards.
def _check_batch_pairing():
    ElectrumClient = __import__(
        f"{PKG}.helpers.electrum_client", fromlist=["*"]
    ).ElectrumClient

    import json as _json

    class ReversingSocket:
        """Answers a JSON-RPC batch with the results in reverse order."""

        def __init__(self):
            self.sent = None

        def sendall(self, data):
            self.sent = _json.loads(data.decode())

        def recv(self, _n):
            # Echo each request's id back with a result naming it, reversed.
            out = [{"id": r["id"], "result": f"result-for-{r['params'][0]}"} for r in self.sent]
            out.reverse()
            return (_json.dumps(out) + "\n").encode()

    c = ElectrumClient("fake", 0)
    c._sock = ReversingSocket()
    c._buf = b""

    got = c.call_batch(
        [("blockchain.scripthash.get_history", [f"sh{i}"]) for i in range(4)]
    )
    expected = [f"result-for-sh{i}" for i in range(4)]
    ok(
        "a batch answered in reverse is still paired correctly",
        [r["result"] for r in got] == expected,
        f"{[r['result'] for r in got]}",
    )
    ok("every request is answered", len(got) == 4, str(len(got)))

    # An empty batch must not touch the socket at all.
    c2 = ElectrumClient("fake", 0)
    c2._sock = ReversingSocket()
    c2._buf = b""
    ok("an empty batch sends nothing", c2.call_batch([]) == [] and c2._sock.sent is None)


_check_batch_pairing()


# ── spend watch ─────────────────────────────────────────────────────────────
# The alert says "your wallet may be compromised". Getting that wrong in either
# direction is bad in a way most bugs are not: a false alarm teaches people to
# ignore the one that matters, and a miss is the whole point of the feature.
#
# So both directions are checked against a fake indexer, plus the script
# construction — watching the wrong scriptPubKey would silently watch nothing.
def _check_spend_watch():
    sw = __import__(f"{PKG}.helpers.spend_watch", fromlist=["*"])

    # The output key is x-only, and the script is what wallet.py builds when it
    # verifies an input: 0x51 0x20 || key.
    key = "ab" * 32
    spk = sw.scriptpubkey_for_output_key(key)
    ok("P2TR script is 0x51 0x20 || the 32-byte output key",
       spk == bytes([0x51, 0x20]) + bytes.fromhex(key) and len(spk) == 34,
       spk.hex())
    try:
        sw.scriptpubkey_for_output_key("ab" * 33)
        ok("a wrong-length key is refused", False, "it was accepted")
    except ValueError:
        ok("a wrong-length key is refused", True)

    FUNDING = "f" * 64
    SPEND = "e" * 64
    utxos = [
        {"txid": FUNDING, "vout": 0, "amount": 1000, "pub_key": "11" * 32},
        {"txid": FUNDING, "vout": 1, "amount": 2000, "pub_key": "22" * 32},
    ]

    class FakeIndexer:
        """Answers get_history per scripthash. Coin 0 is spent, coin 1 is not."""

        def __init__(self, spent_first=True):
            self.spent_first = spent_first
            self.order = []

        def call_batch(self, calls):
            out = []
            for n, (_m, params) in enumerate(calls):
                self.order.append(params[0])
                first = n == 0
                hist = [{"tx_hash": FUNDING, "height": 100}]
                if first and self.spent_first:
                    hist.append({"tx_hash": SPEND, "height": 0})
                out.append({"id": n, "result": hist})
            return out

        def get_history(self, sh):
            raise AssertionError("batch path should have been used")

    spent = sw.find_spending_txids(FakeIndexer(), utxos)
    ok("a spent coin is detected, with the spending txid",
       spent == {f"{FUNDING}:0": SPEND}, str(spent))
    ok("an unspent coin is not reported", f"{FUNDING}:1" not in spent)

    # The funding transaction is in the history of EVERY coin. Treating it as a
    # spend would report every wallet in existence as compromised.
    quiet = sw.find_spending_txids(FakeIndexer(spent_first=False), utxos)
    ok("the funding tx is never mistaken for a spend", quiet == {}, str(quiet))

    ok("no coins means no indexer calls", sw.find_spending_txids(FakeIndexer(), []) == {})

    # A coin whose key cannot be parsed is skipped, not reported — a data
    # problem must not surface as a compromise warning.
    mixed = [{"txid": FUNDING, "vout": 0, "amount": 1, "pub_key": "zz"}] + utxos[1:]
    ok("an unparseable key is skipped, not alarmed about",
       sw.find_spending_txids(FakeIndexer(spent_first=False), mixed) == {})


_check_spend_watch()


print()
if FAILED:
    print(f"{len(FAILED)} FAILED: " + ", ".join(FAILED))
    sys.exit(1)
print("all checks passed")
