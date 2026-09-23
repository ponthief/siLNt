"""
Silent Payments PayJoin — the two-party pieces, siLNt to siLNt.

helpers/payjoin_merge.py builds the OTHER PayJoin: imported descriptors,
P2WPKH, a PSBT that Sparrow signs. That one cannot carry Silent Payments,
because PSBT BIP32_DERIVATION is how the external signer recognises its inputs
and an SP UTXO has no derivation path — its key is a one-off from a tweak. So
this is a second implementation rather than a mode of the first, and both
parties are siLNt wallets.

WHY THIS IS POSSIBLE AT ALL. BIP-352's sender derivation is

    shared_secret = input_hash · a_sum · B_scan

summing the PRIVATE keys of every eligible input. In a PayJoin the inputs
belong to two people and neither can compute a_sum, which looks fatal and is:
derive from one party's inputs alone and the other's scanner never finds the
output. But the same secret is also

    shared_secret = input_hash · A_sum · b_scan

with A_sum the sum of the input PUBLIC keys — public once the inputs are
agreed. So each party derives its OWN outputs from its own scan key and a
public input set. No multi-party computation, no new cryptography.

helpers/_payjoin_sp_check.py is the spike that established this, including that
the production matcher in scan.py finds what this module builds.

WHAT THAT COSTS THE PROTOCOL. Every output depends on the whole input set, so
inputs must be frozen before any output is derived, and outputs must all exist
before anyone signs (a taproot key-path signature commits to every output).
That forces the order: commit inputs → both parties derive → both parties sign.
Adding an input afterwards invalidates every output in the transaction.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Optional

import coincurve
from embit import ec
from embit.script import Script
from embit.transaction import (
    Transaction,
    TransactionInput,
    TransactionOutput,
    Witness,
)
from loguru import logger

from .curve import ser256
from .curve_native import point_add, point_mul, pubkey_point_gen_from_int
from .txsize import TAPROOT_OUTPUT_VBYTES, estimate_vsize, fee_for
from .wallet import (
    DUST_SATS,
    compressed_pubkey_to_point,
    tagged_hash,
    taproot_sighash,
)

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Sizes come from helpers/txsize.py, which is also what wallet.py uses, so the
# two builders cannot quote different fees for the same shape. This module had
# its own copies and inherited the P2WPKH-output bug along with them.


@dataclass
class PayjoinInput:
    """One contributed UTXO.

    `pub_key` is the 32-byte x-only key as it sits on chain, and is all that is
    needed to take part in the shared input set. `priv_key_tweak` is present
    only for inputs the caller can sign — the counterparty's tweak never leaves
    their side.
    """

    txid: str
    vout: int
    amount: int
    pub_key: bytes
    priv_key_tweak: Optional[bytes] = None

    @property
    def outpoint(self) -> bytes:
        """reversed_txid || vout_LE, the form BIP-352 orders and hashes."""
        return bytes.fromhex(self.txid)[::-1] + int(self.vout).to_bytes(4, "little")

    @property
    def script(self) -> bytes:
        return bytes([0x51, 0x20]) + self.pub_key


def canonical(inputs: list[PayjoinInput]) -> list[PayjoinInput]:
    """BIP-69 input order.

    Both parties must agree on one order before deriving anything, because the
    transaction they each sign has to be the same transaction. BIP-69 gives
    that without a negotiation round: it is a function of the outpoints, which
    both sides already know.
    """
    return sorted(inputs, key=lambda i: (i.txid, int(i.vout)))


def input_digest(inputs: list[PayjoinInput]) -> tuple[tuple[int, int], int]:
    """(A_sum point, input_hash) for a frozen input set — all public.

    Every input here is P2TR, so each contributes its x-only key lifted to even
    Y. That lift is the public-side counterpart of negating an odd-Y private
    key on the sender side (wallet.py::sp_scriptpubkey_from_inputs), and the
    two must agree or the output is one nobody can find. A P2WPKH input would
    contribute its 33-byte key unchanged; this module does not accept one,
    because an SP wallet has no P2WPKH coins to contribute.
    """
    if not inputs:
        raise ValueError("A PayJoin needs inputs from both parties.")

    points = []
    for i in inputs:
        if len(i.pub_key) != 32:
            raise ValueError(
                f"{i.txid}:{i.vout} is not a 32-byte x-only key — only taproot "
                f"inputs take part in this input set."
            )
        points.append(compressed_pubkey_to_point(bytes([0x02]) + i.pub_key))

    a_sum = points[0]
    for p in points[1:]:
        a_sum = point_add(a_sum, p)
    a_sum_bytes = bytes([0x02 + (a_sum[1] % 2)]) + ser256(a_sum[0])

    outpoint_l = min(i.outpoint for i in inputs)
    input_hash = int.from_bytes(
        tagged_hash("BIP0352/Inputs", outpoint_l + a_sum_bytes), "big"
    )
    return a_sum, input_hash


def own_output_point(
    scan_secret: bytes,
    spend_pub: bytes,
    inputs: list[PayjoinInput],
    k: int = 0,
):
    """P_k for an output paying the holder of `scan_secret`, from public inputs.

    Returns a POINT rather than a script, and that is deliberate. A labelled
    output is P_k + label, added on the curve, so it needs P_k's real Y parity.
    Hand back only the x-only key and a caller has to guess: half the time it
    builds an output nobody can spend, and the scanner STILL finds it, because
    the scanner tests both label signs. Detected-and-unspendable is the worst
    failure available, so the parity does not get thrown away here — and
    `change_script` below avoids the addition entirely instead.
    """
    a_sum, input_hash = input_digest(inputs)
    b_scan = int.from_bytes(scan_secret, "big") % SECP256K1_N

    ecdh = point_mul(a_sum, (b_scan * input_hash) % SECP256K1_N)
    ecdh_compressed = bytes([0x02 + (ecdh[1] % 2)]) + ser256(ecdh[0])
    t_k = int.from_bytes(
        tagged_hash("BIP0352/SharedSecret", ecdh_compressed + k.to_bytes(4, "big")),
        "big",
    )
    return point_add(
        compressed_pubkey_to_point(spend_pub), pubkey_point_gen_from_int(t_k)
    )


def _spk(point) -> bytes:
    return bytes([0x51, 0x20]) + ser256(point[0])


def payment_script(
    scan_secret: bytes, spend_pub: bytes, inputs: list[PayjoinInput]
) -> bytes:
    """The payee's output. Derived by the PAYEE, who is the only party with the
    scan key it needs; the payer cannot compute it and cannot check it."""
    return _spk(own_output_point(scan_secret, spend_pub, inputs))


def change_script(
    scan_secret: bytes,
    spend_pub: bytes,
    label_pub: bytes,
    inputs: list[PayjoinInput],
) -> bytes:
    """The payer's change, to their own m=0 labelled address.

    The label is folded into B_spend BEFORE deriving, which is what
    wallet.py::_derive_change_script does via generate_labeled_sp_address. Doing
    it that way round means (B_spend + label) + t_k·G is one point addition on
    full points, with no x-only key in the middle and no parity to get wrong.
    """
    labelled = coincurve.PublicKey(spend_pub).combine(
        [coincurve.PublicKey(label_pub)]
    ).format(compressed=True)
    return _spk(own_output_point(scan_secret, labelled, inputs))


def estimate_fee(n_inputs: int, n_outputs: int, fee_rate: float) -> tuple[int, int]:
    """(vsize, fee). Every input and every output in a PayJoin is P2TR."""
    vsize = estimate_vsize(n_inputs, [TAPROOT_OUTPUT_VBYTES] * n_outputs)
    return vsize, fee_for(vsize, fee_rate)


def plan(
    payer_inputs: list[PayjoinInput],
    payee_inputs: list[PayjoinInput],
    amount: int,
    fee_rate: float,
) -> dict:
    """Amounts for a sender-pays-fee PayJoin, before any derivation.

    The payee's contributed input comes straight back out in the payment, so
    the payee is no worse off for taking part and the payer pays only `amount`
    plus the fee — the same model as payjoin_merge.py.
    """
    if amount < DUST_SATS:
        raise ValueError(
            f"{amount} sats is below the {DUST_SATS} sat dust limit."
        )
    payer_total = sum(i.amount for i in payer_inputs)
    payee_total = sum(i.amount for i in payee_inputs)
    if not payer_inputs or not payee_inputs:
        raise ValueError("A PayJoin needs inputs from both parties.")

    n_in = len(payer_inputs) + len(payee_inputs)
    _vsize, fee = estimate_fee(n_in, 2, fee_rate)
    change = payer_total - amount - fee

    if change < 0:
        spendable = payer_total - fee
        if spendable < DUST_SATS:
            raise ValueError(
                f"Your coins total {payer_total} sats, which leaves {spendable} "
                f"after a {fee} sat fee — below the {DUST_SATS} sat dust limit."
            )
        raise ValueError(
            f"Not enough to cover {amount} sats plus a {fee} sat fee — your "
            f"selected coins total {payer_total} sats, and the most they can "
            f"send is {spendable} sats."
        )

    if change < DUST_SATS:
        # Uneconomic to create, so it goes to the miner — and the transaction
        # drops to one output, which is cheaper than the estimate assumed.
        _vsize, fee = estimate_fee(n_in, 1, fee_rate)
        fee += max(0, payer_total - amount - fee)
        change = 0

    return {
        "payer_in": payer_total,
        "payee_in": payee_total,
        "payment": amount + payee_total,
        "amount": amount,
        "fee": fee,
        "change": change,
        "vsize": estimate_fee(n_in, 2 if change else 1, fee_rate)[0],
    }


def outputs_for(amounts: dict, payment_spk: bytes, change_spk: Optional[bytes]):
    """Transaction outputs in BIP-69 order, from the two derived scripts."""
    outs = [TransactionOutput(amounts["payment"], Script(payment_spk))]
    if amounts["change"]:
        if change_spk is None:
            raise ValueError("change is non-zero but no change script was derived")
        outs.append(TransactionOutput(amounts["change"], Script(change_spk)))
    outs.sort(key=lambda o: (o.value, bytes(o.script_pubkey.data)))
    return outs


def signing_key(spend_secret: bytes, priv_key_tweak: bytes, pub_key: bytes) -> ec.PrivateKey:
    """The full key for one of your own SP inputs: b_spend + tweak, negated if
    the resulting point has odd Y.

    Same rule as wallet.py::_prepare_inputs. It is repeated rather than shared
    because that function also builds embit Scripts and sorts, and the one line
    that matters here is the negation — which, got wrong, produces a signature
    that verifies against a key nobody expects and a transaction the network
    rejects.
    """
    total = (
        int.from_bytes(spend_secret, "big") + int.from_bytes(priv_key_tweak, "big")
    ) % SECP256K1_N
    if total == 0:
        raise ValueError("degenerate signing key for input")
    point = pubkey_point_gen_from_int(total)
    if point[1] % 2 == 1:
        total = SECP256K1_N - total
        point = pubkey_point_gen_from_int(total)
    derived = ser256(point[0])
    if derived != pub_key:
        raise ValueError(
            "b_spend + tweak does not reproduce this input's key — wrong wallet, "
            "or the stored tweak belongs to another output"
        )
    return ec.PrivateKey(total.to_bytes(32, "big"))


# ── assembly and witness handling: the server's half, and it needs no keys ───
#
# Everything below runs on the coordinator. None of it takes a scan key, a
# spend key or a private tweak — it works from outpoints, x-only PUBLIC keys,
# amounts and the two scriptPubKeys the parties derived on their own devices.
# That is the whole reason this module can be split this way: the transaction
# is assembled from public data, each party signs its own inputs at home, and
# the coordinator checks the signatures it is handed against the public keys
# already in the input set.


def assemble(inputs: list[PayjoinInput], amounts: dict, payment_spk: bytes,
             change_spk: Optional[bytes]) -> Transaction:
    """The unsigned transaction, from the frozen input set and the two scripts.

    Inputs go in `canonical` order and outputs in BIP-69, so both parties
    reproduce this byte for byte from the same inputs. They have to: a
    key-path signature commits to every prevout, amount, scriptPubKey and
    output, so a coordinator that ordered things differently from the client
    would produce signatures that verify against nothing.
    """
    ordered = canonical(inputs)
    vin = [
        TransactionInput(bytes.fromhex(i.txid)[::-1], i.vout) for i in ordered
    ]
    tx = Transaction(vin=vin, vout=outputs_for(amounts, payment_spk, change_spk))
    return tx


def sighashes(tx: Transaction, inputs: list[PayjoinInput]) -> list[bytes]:
    """The BIP-341 key-path sighash for every input, SIGHASH_DEFAULT.

    One per input and in the same order as tx.vin, which is `canonical` order.
    """
    ordered = canonical(inputs)
    scripts = [Script(i.script) for i in ordered]
    amounts = [i.amount for i in ordered]
    return [
        taproot_sighash(tx, n, scripts, amounts, sighash_type=0)
        for n in range(len(ordered))
    ]


def owner_indices(
    inputs: list[PayjoinInput], owned: list[PayjoinInput]
) -> set[int]:
    """Which positions in the frozen, canonically ordered set belong to one
    party. The coordinator needs this to know which witnesses a caller is
    entitled to supply, and to refuse one for an input that is not theirs."""
    ordered = canonical(inputs)
    mine = {(i.txid.lower(), i.vout) for i in owned}
    return {n for n, i in enumerate(ordered) if (i.txid.lower(), i.vout) in mine}


def verify_witnesses(
    tx: Transaction,
    inputs: list[PayjoinInput],
    witnesses: dict,
    allowed: set[int],
) -> dict:
    """Check a party's witnesses and return them normalised to {index: bytes}.

    Every signature is verified against the x-only key already sitting in the
    frozen input set, so a party cannot sign for an input it does not own, and
    a malformed or mis-signed witness is refused here rather than by the
    network — where the whole PayJoin would fail with nothing to point at.

    Raises ValueError with something a user can act on. Nothing in here is a
    secret: a signature and a public key are both on-chain data.
    """
    ordered = canonical(inputs)
    digests = sighashes(tx, inputs)
    out: dict = {}
    for key, value in witnesses.items():
        try:
            n = int(key)
        except (TypeError, ValueError):
            raise ValueError(f"{key!r} is not an input index.")
        if n not in allowed:
            raise ValueError(
                f"Input {n} is not yours to sign in this PayJoin."
            )
        try:
            sig = bytes.fromhex(str(value))
        except ValueError:
            raise ValueError(f"The witness for input {n} is not hex.")
        # 65 bytes is a signature with an explicit sighash byte appended. Only
        # SIGHASH_DEFAULT is used here, and a 64-byte signature IS default, so
        # an explicit 0x00 is invalid per BIP-341 and anything else is a
        # sighash this flow does not build for.
        if len(sig) != 64:
            raise ValueError(
                f"The witness for input {n} is {len(sig)} bytes; a taproot "
                f"key-path signature for SIGHASH_DEFAULT is 64."
            )
        if not coincurve.PublicKeyXOnly(ordered[n].pub_key).verify(
            sig, digests[n]
        ):
            raise ValueError(
                f"The signature for input {n} does not match that input's key "
                f"and this transaction. Both parties must sign the same frozen "
                f"input set and the same outputs."
            )
        out[n] = sig
    missing = sorted(allowed - set(out))
    if missing:
        raise ValueError(
            f"No witness for input(s) {', '.join(map(str, missing))}."
        )
    return out


def finalize(tx: Transaction, witnesses: dict) -> str:
    """Put both parties' witnesses on the transaction and serialise it.

    `witnesses` is {index: 64-byte signature} covering every input; a gap means
    an unsigned input, which is not a transaction worth handing to the network.
    """
    for n in range(len(tx.vin)):
        sig = witnesses.get(n)
        if sig is None:
            raise ValueError(f"Input {n} has no signature.")
        tx.vin[n].witness = Witness([sig])
    return tx.serialize().hex()


# ── whose turn it is ─────────────────────────────────────────────────────────

# The states, in the order a PayJoin passes through them. CONTRIBUTED exists
# here and not in the PSBT flow because a key-path signature commits to every
# output and every SP output depends on the whole input set: inputs must freeze
# before anything is derived, and every output must exist before anyone signs.
PROPOSED = "PROPOSED"
CONTRIBUTED = "CONTRIBUTED"
PAYER_SIGNED = "PAYER_SIGNED"
BROADCAST = "BROADCAST"
CANCELLED = "CANCELLED"

# The advertised flow's two extra states, for a PayJoin the PAYEE starts.
#
# It needs them because of the same constraint everything else here bends
# around: every SP output is derived from the WHOLE input set. When the payer
# starts, the payee learns the complete set at the moment it contributes and
# derives in that same call. When the payee starts, it posts before a payer
# exists, so it can derive nothing and must come back once someone claims.
OPEN = "OPEN"          # advertised, no payer yet
CLAIMED = "CLAIMED"    # a contact added their inputs; the set is now frozen

TERMINAL = (BROADCAST, CANCELLED)

# Who acts next, per state. One table rather than an `if` in each handler:
# spread across four endpoints these conditions drift, and the failure is a
# party signing out of turn — which produces a signature over a transaction
# that is about to change, so it verifies against nothing and the PayJoin dies
# with nobody able to say why.
_TURN = {
    # Payer-initiated.
    PROPOSED: "payee",       # contribute inputs and the derived payment script
    # Payee-initiated. OPEN is the one state with no single party waited on —
    # any contact may claim it — so it is handled separately below rather than
    # answered with a role that would be a lie.
    CLAIMED: "payee",        # derive the payment script, now the set is frozen
    # Both, from here on. The two flows converge at CONTRIBUTED and share
    # every endpoint after it.
    CONTRIBUTED: "payer",    # derive change, then sign
    PAYER_SIGNED: "payee",   # sign, which completes and broadcasts it
}


def whose_turn(status: str) -> Optional[str]:
    """'payer', 'payee', or None when no ONE party is waited on.

    None covers two different situations and callers have to keep them apart:
    a terminal PayJoin, where nobody acts again, and an OPEN offer, where
    anybody among the payee's contacts may act. `is_open` tells them apart.
    """
    return _TURN.get(status)


def is_open(status: str) -> bool:
    """An advertised offer nobody has claimed. Not anyone's 'turn': it is on
    the board until a contact takes it or the payee withdraws it."""
    return status == OPEN


def require_turn(status: str, role: str) -> None:
    """Raise unless it is this party's turn to act, with something a person can
    read. Cancelling is not covered here — either party may walk away at any
    point before broadcast, which is a different rule."""
    if role not in ("payer", "payee"):
        raise ValueError(f"{role!r} is not a party to a PayJoin.")
    if is_open(status):
        # Claiming is not taking a turn — see api_payjoin_sp_claim, which owns
        # that transition and the race between two claimants.
        raise ValueError(
            "This PayJoin is still open for someone to take, not waiting on a "
            "signature."
        )
    turn = whose_turn(status)
    if turn == role:
        return
    if status in TERMINAL:
        raise ValueError(f"This PayJoin is already {status.lower()}.")
    if turn is None:
        raise ValueError(f"This PayJoin is {status.lower()} and cannot go on.")
    raise ValueError(
        f"This PayJoin is waiting on the {turn}, not on you."
    )


def can_cancel(status: str) -> bool:
    """Either party, right up until it is broadcast. After that there is
    nothing to cancel — the transaction belongs to the network."""
    return status not in TERMINAL


# ── wire shapes ──────────────────────────────────────────────────────────────
#
# These were Field(pattern=...) constraints on the request models until an
# LNbits on Pydantic v1 refused to import the extension over the neighbouring
# min_length. The regex spellings differ between v1 and v2 too (regex vs
# pattern), and under v1 `pattern=` is not a keyword at all: it lands in the
# schema extras and enforces nothing. Silently absent validation on the
# endpoints that decide where money goes is worse than none, so the checks
# moved here, where they run the same under either version and can be tested.

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_P2TR_SPK = re.compile(r"^5120[0-9a-fA-F]{64}$")


def validate_wire_input(i: dict, where: str = "input") -> None:
    """One contributed UTXO as it arrived over the wire.

    Shape only — that these are real, spendable, unreserved coins of the
    caller's wallet is views_api.py's job, and it needs the database. This is
    the check that stops a malformed value reaching the curve code, where a
    64-character string that is not hex becomes an exception halfway through a
    derivation rather than a 400 with a reason.
    """
    txid = str(i.get("txid", ""))
    if not _HEX64.match(txid):
        raise ValueError(f"{where}: txid must be 64 hex characters.")
    try:
        vout = int(i.get("vout"))
    except (TypeError, ValueError):
        raise ValueError(f"{where}: vout must be a whole number.")
    if vout < 0:
        raise ValueError(f"{where}: vout cannot be negative.")
    if not _HEX64.match(str(i.get("pub_key", ""))):
        raise ValueError(
            f"{where}: pub_key must be a 32-byte x-only key, 64 hex "
            f"characters. Only taproot inputs can join this input set."
        )
    try:
        amount = int(i.get("amount"))
    except (TypeError, ValueError):
        raise ValueError(f"{where}: amount must be a whole number of sats.")
    if amount <= 0:
        raise ValueError(f"{where}: amount must be more than zero.")


def validate_wire_inputs(rows: list, where: str = "inputs") -> None:
    """A party's whole contribution: at least one input, each well formed, and
    no outpoint named twice.

    The duplicate check is not cosmetic. The same outpoint twice would be the
    same coin spent twice in one transaction, which the network rejects — and
    it would sail past the per-input checks, because each copy is individually
    fine.
    """
    if not rows:
        raise ValueError(f"{where}: a PayJoin needs at least one coin from you.")
    for n, i in enumerate(rows):
        validate_wire_input(i, f"{where}[{n}]")
    seen = [(str(i["txid"]).lower(), int(i["vout"])) for i in rows]
    if len(set(seen)) != len(seen):
        raise ValueError(f"{where}: the same coin is listed twice.")


def validate_spk(spk: str, where: str = "script") -> None:
    """A P2TR scriptPubKey, hex: OP_1 <32-byte key>.

    Every output in a PayJoin is P2TR, on both sides, so anything else is
    either a bug in the client's derivation or an attempt to redirect an
    output — and neither should be written to the row the other party will
    sign over.
    """
    if not _P2TR_SPK.match(str(spk or "")):
        raise ValueError(
            f"{where}: must be a P2TR scriptPubKey — 5120 followed by 64 hex "
            f"characters."
        )


def explain_mismatch(ours: Transaction, theirs_hex: str) -> Optional[str]:
    """Why two assemblies of one PayJoin differ, in words.

    Both parties and the coordinator build the transaction independently from
    the same row. They must agree byte for byte, because a key-path signature
    commits to every prevout, amount, scriptPubKey and output. When they do
    not, the only thing signature verification can report is that it failed —
    which is true, and tells nobody what to fix.

    Returns None when they agree, or a sentence naming the first real
    difference. Everything compared here is public.
    """
    if not theirs_hex:
        return None
    mine_hex = ours.serialize().hex()
    if mine_hex == theirs_hex:
        return None
    try:
        theirs = Transaction.from_string(theirs_hex)
    except Exception:
        return "The transaction you signed is not a transaction we can parse."

    if len(theirs.vin) != len(ours.vin):
        return (
            f"You signed a transaction with {len(theirs.vin)} inputs; this "
            f"PayJoin has {len(ours.vin)}."
        )
    mine_in = [(v.txid[::-1].hex(), v.vout) for v in ours.vin]
    their_in = [(v.txid[::-1].hex(), v.vout) for v in theirs.vin]
    if mine_in != their_in:
        if sorted(mine_in) == sorted(their_in):
            return (
                "You signed the same inputs in a different order. Both sides "
                "must use BIP-69 order over the outpoints."
            )
        return (
            f"You signed different inputs: {their_in} against {mine_in}."
        )

    if len(theirs.vout) != len(ours.vout):
        return (
            f"You signed {len(theirs.vout)} outputs; this PayJoin has "
            f"{len(ours.vout)}. A change output absorbed into the fee is the "
            f"usual cause."
        )
    for n, (a, b) in enumerate(zip(ours.vout, theirs.vout)):
        if a.value != b.value:
            return (
                f"Output {n}: you signed {b.value} sats where this PayJoin "
                f"pays {a.value}."
            )
        if bytes(a.script_pubkey.data) != bytes(b.script_pubkey.data):
            return (
                f"Output {n}: you signed a different destination than this "
                f"PayJoin has."
            )

    if theirs.version != ours.version:
        return f"You signed version {theirs.version}; this is version {ours.version}."
    if theirs.locktime != ours.locktime:
        return f"You signed locktime {theirs.locktime}; this is {ours.locktime}."
    seq_mine = [v.sequence for v in ours.vin]
    seq_theirs = [v.sequence for v in theirs.vin]
    if seq_mine != seq_theirs:
        return f"You signed sequences {seq_theirs}; this PayJoin uses {seq_mine}."

    return (
        "The transaction you signed differs from this one in a way this check "
        "does not name. Yours: " + theirs_hex[:120] + "…"
    )
