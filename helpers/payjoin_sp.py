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

TERMINAL = (BROADCAST, CANCELLED)

# Who acts next, per state. One table rather than an `if` in each handler:
# spread across four endpoints these conditions drift, and the failure is a
# party signing out of turn — which produces a signature over a transaction
# that is about to change, so it verifies against nothing and the PayJoin dies
# with nobody able to say why.
_TURN = {
    PROPOSED: "payee",       # contribute inputs and the derived payment script
    CONTRIBUTED: "payer",    # derive change, then sign
    PAYER_SIGNED: "payee",   # sign, which completes and broadcasts it
}


def whose_turn(status: str) -> Optional[str]:
    """'payer', 'payee', or None when nobody is waited on."""
    return _TURN.get(status)


def require_turn(status: str, role: str) -> None:
    """Raise unless it is this party's turn to act, with something a person can
    read. Cancelling is not covered here — either party may walk away at any
    point before broadcast, which is a different rule."""
    if role not in ("payer", "payee"):
        raise ValueError(f"{role!r} is not a party to a PayJoin.")
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
