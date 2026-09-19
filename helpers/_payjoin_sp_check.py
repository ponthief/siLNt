"""
SPIKE — can a two-party PayJoin pay a Silent Payments address?

    python3 helpers/_payjoin_sp_check.py        # from the siLNt directory

The existing PayJoin (helpers/payjoin_merge.py) is a descriptor/P2WPKH affair:
both sides import an output descriptor, siLNt builds a PSBT, Sparrow signs. It
never touches Silent Payments. The question this answers is whether the same
two-party transaction can pay an sp1 address, and what it costs to do it.

THE APPARENT BLOCKER. BIP-352's sender derivation is

    shared_secret = input_hash · a_sum · B_scan

and a_sum sums the PRIVATE keys of every eligible input. In a PayJoin the
inputs belong to two people, so neither side can compute a_sum. That looks
fatal, and check 2 below demonstrates that it really is fatal if you ignore it:
a sender who derives from its own inputs alone produces an output the receiver
will never find.

WHY IT IS NOT FATAL. The same secret has a second form,

    shared_secret = input_hash · A_sum · b_scan

where A_sum is the sum of the input PUBLIC keys and input_hash is the smallest
outpoint with A_sum — both public once the inputs are agreed. So whoever holds
a scan key can derive their own output from data everybody already has. The
receiver is the payee and holds b_scan; the sender's change goes to the
sender's own address and the sender holds theirs. Each side derives its own
outputs. No multi-party computation, no new cryptography.

What this script proves, in order:

  1. The public-side derivation agrees with the production sender-side one on a
     single-party transaction. If these two disagree the rest means nothing.
  2. Sender-side derivation over only the sender's inputs — today's
     build_transaction, dropped into a PayJoin unchanged — produces an output
     the receiver's scanner misses. The blocker, made concrete.
  3. A real two-party PayJoin: one input each, receiver derives the payment,
     sender derives its own change, and the PRODUCTION scanner in
     helpers/scan.py finds each party exactly its own output and nothing else.
  4. Both found outputs are spendable: b_spend + priv_key_tweak reproduces the
     key the scanner recorded, checked with the spend secrets the scanner never
     sees.
  5. Mixed input types work — P2WPKH beside P2TR — and the taproot negation
     rule is load-bearing across the party boundary: get the flag wrong on the
     OTHER party's input and the payment is lost.
  6. Adding an input after the outputs are derived invalidates them, which is
     what forces inputs-first ordering on any protocol built from this.
"""

from __future__ import annotations

import hashlib
import sys
import types


def _bootstrap():
    """Import helpers/ without dragging in LNbits or the DB layer."""
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    sys.path.insert(0, os.path.dirname(root))

    name = os.path.basename(root)
    pkg = types.ModuleType(name)
    pkg.__path__ = [root]
    sys.modules[name] = pkg

    class _Any(types.ModuleType):
        def __getattr__(self, attr):
            return None

    sys.modules[f"{name}.crud"] = _Any(f"{name}.crud")

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
    return name


PKG = _bootstrap()

import coincurve  # noqa: E402

_w = __import__(f"{PKG}.helpers.wallet", fromlist=["*"])
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


# ── the piece that does not exist in the codebase yet ────────────────────────

def sp_output_point_from_public_inputs(
    scan_secret: bytes,
    spend_pub: bytes,
    inputs: list[tuple[bytes, bytes, bool]],
    k: int = 0,
):
    """BIP-352 output derived WITHOUT any input private key. Returns P_k as a
    POINT, not an x-only key.

    Returning the point rather than the script matters and cost this spike a
    round. A labelled output is (P_k + label), and that addition happens on the
    curve, so it needs P_k's real Y parity. Hand back only the x-only key and
    the caller has to guess a parity: half the time it builds an output whose
    private key nobody holds — and the scanner still FINDS it, because the
    scanner tests both label signs, so the mistake surfaces as coins that are
    detected and unspendable rather than as anything that throws.

    `inputs` is one (pubkey_bytes, outpoint_bytes, is_taproot) per input, where
    outpoint_bytes is reversed_txid || vout_LE. pubkey_bytes is the 33-byte
    compressed key for a P2WPKH input and the 32-byte x-only key for a P2TR one.

    This mirrors wallet.py::sp_scriptpubkey_from_inputs step for step, with
    a_sum · B_scan replaced by A_sum · b_scan. The taproot rule survives the
    swap: a P2TR key is x-only, which IS the even-Y point, so lifting it with
    an 0x02 prefix is the public-side counterpart of negating an odd-Y private
    key. A P2WPKH key is used exactly as given.

    This is the whole of what a PayJoin needs and the whole of what is missing:
    ~30 lines beside a function the wallet already has.
    """
    A_points = []
    for pub, _outpoint, is_taproot in inputs:
        if is_taproot:
            if len(pub) != 32:
                raise ValueError("a taproot input contributes its 32-byte x-only key")
            pub = bytes([0x02]) + pub        # x-only is even-Y by definition
        A_points.append(_w.compressed_pubkey_to_point(pub))

    A_sum_point = A_points[0]
    for pt in A_points[1:]:
        A_sum_point = _w.point_add(A_sum_point, pt)
    A_sum_bytes = bytes([0x02 + (A_sum_point[1] % 2)]) + _c.ser256(A_sum_point[0])

    outpointL = min(outpoint for _pub, outpoint, _tr in inputs)
    input_hash = int.from_bytes(
        _w.tagged_hash("BIP0352/Inputs", outpointL + A_sum_bytes), "big"
    )

    b_scan = int.from_bytes(scan_secret, "big") % N
    ecdh_point = _w.point_mul(A_sum_point, (b_scan * input_hash) % N)
    ecdh_compressed = bytes([0x02 + (ecdh_point[1] % 2)]) + _c.ser256(ecdh_point[0])

    t_k = int.from_bytes(
        _w.tagged_hash("BIP0352/SharedSecret", ecdh_compressed + k.to_bytes(4, "big")),
        "big",
    )
    return _w.point_add(
        _w.compressed_pubkey_to_point(spend_pub), _w.pubkey_point_gen_from_int(t_k)
    )


def spk(point) -> bytes:
    """A taproot scriptPubKey from a point: OP_1 <32-byte x-only>."""
    return bytes([0x51, 0x20]) + _c.ser256(point[0])


def sp_scriptpubkey_from_public_inputs(scan_secret, spend_pub, inputs, k=0) -> bytes:
    return spk(sp_output_point_from_public_inputs(scan_secret, spend_pub, inputs, k))


def oracle_tweak(inputs: list[tuple[bytes, bytes, bool]]) -> bytes:
    """What BlindBit publishes for a transaction: input_hash · A_sum, a point.

    Built here from the same public data, so the scanner in check 3 is driven by
    a tweak computed the way the real oracle computes it rather than one faked
    to make the test pass.
    """
    A_points = []
    for pub, _o, is_taproot in inputs:
        if is_taproot:
            pub = bytes([0x02]) + pub
        A_points.append(_w.compressed_pubkey_to_point(pub))
    A_sum_point = A_points[0]
    for pt in A_points[1:]:
        A_sum_point = _w.point_add(A_sum_point, pt)
    A_sum_bytes = bytes([0x02 + (A_sum_point[1] % 2)]) + _c.ser256(A_sum_point[0])
    outpointL = min(o for _p, o, _t in inputs)
    input_hash = int.from_bytes(
        _w.tagged_hash("BIP0352/Inputs", outpointL + A_sum_bytes), "big"
    )
    tweak_point = _w.point_mul(A_sum_point, input_hash)
    return bytes([0x02 + (tweak_point[1] % 2)]) + _c.ser256(tweak_point[0])


# ── two parties ──────────────────────────────────────────────────────────────

class Party:
    def __init__(self, tag: str, seed: int):
        self.tag = tag
        self.scan_secret = bytes([seed]) * 32
        self.spend_secret = bytes([seed + 1]) * 32
        self.scan_pub = coincurve.PublicKey.from_secret(self.scan_secret).format()
        self.spend_pub = coincurve.PublicKey.from_secret(self.spend_secret).format()
        # The UTXO this party brings: an ordinary taproot key it controls.
        self.utxo_secret = bytes([seed + 2]) * 32
        self.utxo_priv = int.from_bytes(self.utxo_secret, "big")

    @property
    def sp_address(self) -> str:
        # encode_silent_payment_address takes POINTS, not compressed bytes.
        return _w.encode_silent_payment_address(
            _w.pubkey_point_gen_from_int(int.from_bytes(self.scan_secret, "big")),
            _w.pubkey_point_gen_from_int(int.from_bytes(self.spend_secret, "big")),
            "tsp",
        )

    def utxo_xonly(self) -> bytes:
        """The x-only key as it appears on chain, after BIP-340 even-Y."""
        priv = self.utxo_priv
        if _w.pubkey_point_gen_from_int(priv)[1] % 2 == 1:
            priv = N - priv
        return coincurve.PublicKey.from_secret(priv.to_bytes(32, "big")).format()[1:]

    def utxo_signing_priv(self) -> int:
        """The private key as BIP-352 wants it contributed: even-Y."""
        priv = self.utxo_priv
        if _w.pubkey_point_gen_from_int(priv)[1] % 2 == 1:
            priv = N - priv
        return priv


def outpoint(txid_hex: str, vout: int) -> bytes:
    return bytes.fromhex(txid_hex)[::-1] + vout.to_bytes(4, "little")


def scan_for(party: Party, tweak: bytes, outputs: list[bytes], amount: int = 10_000):
    """Run the PRODUCTION matcher for one party over a transaction's outputs."""
    labels = _sc.create_labels(party.scan_secret, indices=[])
    utxos = [
        {"txid": "11" * 32, "vout": i, "amount": amount, "pubkey": o.hex(),
         "timestamp": 1}
        for i, o in enumerate(outputs)
    ]
    return _sc.sync_block([tweak.hex()], utxos, party.scan_secret,
                          party.spend_pub, labels)


def spendable(party: Party, owned) -> bool:
    """b_spend + priv_key_tweak must reproduce the key the scanner recorded."""
    full = _sc.add_private_keys(party.spend_secret, owned.priv_key_tweak)
    return coincurve.PublicKey.from_secret(full).format()[1:] == owned.pub_key


SENDER = Party("sender", 0x11)
RECEIVER = Party("receiver", 0x41)

S_IN = (SENDER.utxo_xonly(), outpoint("aa" * 32, 0), True)
R_IN = (RECEIVER.utxo_xonly(), outpoint("bb" * 32, 1), True)
BOTH = [S_IN, R_IN]


# ── 1. the new derivation agrees with the production one ─────────────────────

print("\n1. public-side derivation vs. the production sender-side one")

single = [S_IN]
from_private = _w.sp_scriptpubkey_from_inputs(
    RECEIVER.sp_address,
    [(SENDER.utxo_signing_priv(), S_IN[1], True)],
)
from_public = sp_scriptpubkey_from_public_inputs(
    RECEIVER.scan_secret, RECEIVER.spend_pub, single
)
ok("one party: A_sum·b_scan == a_sum·B_scan", from_private == from_public,
   f"private {from_private.hex()[:24]} public {from_public.hex()[:24]}")

two_private = _w.sp_scriptpubkey_from_inputs(
    RECEIVER.sp_address,
    [(SENDER.utxo_signing_priv(), S_IN[1], True),
     (RECEIVER.utxo_signing_priv(), R_IN[1], True)],
)
two_public = sp_scriptpubkey_from_public_inputs(
    RECEIVER.scan_secret, RECEIVER.spend_pub, BOTH
)
ok("two parties: the two forms still agree", two_private == two_public)
ok("...and an added input changes the output", two_private != from_private)


# ── 2. the blocker, made concrete ────────────────────────────────────────────

print("\n2. today's sender-side derivation dropped into a PayJoin unchanged")

naive = _w.sp_scriptpubkey_from_inputs(
    RECEIVER.sp_address,
    [(SENDER.utxo_signing_priv(), S_IN[1], True)],   # sender's inputs only
)
tweak_both = oracle_tweak(BOTH)
found = scan_for(RECEIVER, tweak_both, [naive[2:]])
ok("the receiver's scanner does NOT find it", found == [],
   f"unexpectedly found {len(found)} output(s)")
ok("the naive script differs from the correct one", naive != two_private)


# ── 3. a real two-party PayJoin ──────────────────────────────────────────────

print("\n3. two-party PayJoin: each side derives its own output")

# The receiver is the payee and holds b_scan, so it derives the payment output.
payment_spk = sp_scriptpubkey_from_public_inputs(
    RECEIVER.scan_secret, RECEIVER.spend_pub, BOTH
)
# The sender's change goes to the sender's own m=0 address, and the sender
# holds its own b_scan, so it derives that the same way.
m0 = [lab for lab in _sc.create_labels(SENDER.scan_secret, indices=[]) if lab.m == 0][0]
change_P0 = sp_output_point_from_public_inputs(
    SENDER.scan_secret, SENDER.spend_pub, BOTH
)
# P_0 + label, on the curve, with P_0's real parity — see the note on
# sp_output_point_from_public_inputs for what using the x-only key costs here.
change_spk = spk(
    _w.point_add(change_P0, _w.compressed_pubkey_to_point(m0.pub_key))
)

outputs = [payment_spk[2:], change_spk[2:]]

r_found = scan_for(RECEIVER, tweak_both, outputs)
s_found = scan_for(SENDER, tweak_both, outputs)

ok("receiver finds exactly one output", len(r_found) == 1, f"found {len(r_found)}")
ok("receiver found the payment, not the change",
   bool(r_found) and r_found[0].pub_key == payment_spk[2:])
ok("sender finds exactly one output", len(s_found) == 1, f"found {len(s_found)}")
ok("sender found its own change", bool(s_found) and s_found[0].pub_key == change_spk[2:])
ok("the change is labelled m=0",
   bool(s_found) and getattr(s_found[0], "label", None) is not None)
ok("neither party sees the other's output",
   bool(r_found) and bool(s_found) and r_found[0].pub_key != s_found[0].pub_key)


# ── 4. both are spendable ────────────────────────────────────────────────────

print("\n4. spendability, checked with the spend secrets the scanner never sees")

ok("the receiver can spend the payment", bool(r_found) and spendable(RECEIVER, r_found[0]))
ok("the sender can spend its change", bool(s_found) and spendable(SENDER, s_found[0]))


# ── 5. mixed input types, and the negation flag across the party boundary ────

print("\n5. a P2WPKH input beside a P2TR one")

wpkh_secret = bytes([0x77]) * 32
wpkh_priv = int.from_bytes(wpkh_secret, "big")
wpkh_pub = coincurve.PublicKey.from_secret(wpkh_secret).format()     # 33 bytes, as-is
W_IN = (wpkh_pub, outpoint("cc" * 32, 2), False)
MIXED = [S_IN, R_IN, W_IN]

mixed_private = _w.sp_scriptpubkey_from_inputs(
    RECEIVER.sp_address,
    [(SENDER.utxo_signing_priv(), S_IN[1], True),
     (RECEIVER.utxo_signing_priv(), R_IN[1], True),
     (wpkh_priv, W_IN[1], False)],
)
mixed_public = sp_scriptpubkey_from_public_inputs(
    RECEIVER.scan_secret, RECEIVER.spend_pub, MIXED
)
ok("mixed P2TR + P2WPKH: the two forms agree", mixed_private == mixed_public)

mixed_found = scan_for(RECEIVER, oracle_tweak(MIXED), [mixed_public[2:]])
ok("the production scanner finds the mixed-input payment", len(mixed_found) == 1)
ok("...and it is spendable", bool(mixed_found) and spendable(RECEIVER, mixed_found[0]))

# The trap: treating the P2WPKH key as taproot. On the private side that negates
# a key it must not negate; on the public side it drops the 0x02 and lifts the
# wrong point. Either way the payment is gone, silently.
wrong = _w.sp_scriptpubkey_from_inputs(
    RECEIVER.sp_address,
    [(SENDER.utxo_signing_priv(), S_IN[1], True),
     (RECEIVER.utxo_signing_priv(), R_IN[1], True),
     (wpkh_priv, W_IN[1], True)],        # <- wrong flag
)
ok("a wrong is_taproot flag yields a different output", wrong != mixed_private)
ok("...which the receiver never finds",
   scan_for(RECEIVER, oracle_tweak(MIXED), [wrong[2:]]) == [])


# ── 6. why the protocol has to freeze inputs first ───────────────────────────

print("\n6. ordering")

late = sp_scriptpubkey_from_public_inputs(
    RECEIVER.scan_secret, RECEIVER.spend_pub, MIXED
)
ok("adding an input after derivation changes the output", late != payment_spk)
ok("the old output is unfindable under the new input set",
   scan_for(RECEIVER, oracle_tweak(MIXED), [payment_spk[2:]]) == [])
ok("...and the new one is findable",
   len(scan_for(RECEIVER, oracle_tweak(MIXED), [late[2:]])) == 1)


print()
if FAILED:
    print(f"{len(FAILED)} FAILED: " + ", ".join(FAILED))
    sys.exit(1)
print("all checks passed — a two-party PayJoin can pay a Silent Payments address")
