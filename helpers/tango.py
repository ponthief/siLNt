"""
Tango — a two-party equal-output mix.

NOT a PayJoin, and the difference is the whole point. A PayJoin moves money:
one party pays another, the outputs differ, and what it hides is that the
inputs had two owners. Tango moves nothing. Both parties put in the same
amount and both take the same amount back out, so the two mixed outputs are
IDENTICAL — same value, same script shape, same freshness — and an observer
who can see the transaction cannot say which output belongs to which input.

    A: 25,000 in  ─┐         ┌─ 25,000 out   (one of these is A's,
    B: 25,000 in  ─┴─ Tango ─┤                one is B's, and nothing
                             └─ 25,000 out    on chain says which)

That is an anonymity set of two. Small, and real, and it compounds: mix again
with a different partner and the set squares.

WHAT CARRIES OVER FROM payjoin_sp. All of the cryptography. BIP-352's shared
secret is input_hash · A_sum · b_scan over the input PUBLIC keys, so each party
derives its own outputs from its own scan key and a public input set, exactly
as in a PayJoin — with two parties or twenty. This module imports that rather
than restating it, along with the sighash, witness and finalisation machinery,
which care about inputs and outputs and not about who is paying whom.

WHAT DOES NOT CARRY OVER. The amounts. payjoin_sp.plan computes a payment and
one change; Tango computes a fixed denomination for each side plus up to two
changes, and splits the fee. That is this file.

THE HONEST LIMITS, because a privacy feature that oversells itself is worse
than none:

  * CHANGE LEAKS. Coins rarely total the denomination plus a fee share
    exactly, so the excess becomes change — and change plus mixed output is
    that party's input total. With two inputs an observer can often solve
    which is which by arithmetic. A Tango with no change on either side is a
    clean mix; one with change is weaker, and how much weaker depends on the
    numbers. The clients say so, and the change output carries the BIP-352
    m=0 label so the owner's own wallet knows it for what it is.
  * THE COORDINATOR SEES EVERYTHING. Both parties post their derived scripts
    to the same server that knows both their identities. Tango hides the
    mapping from chain analysis. It hides nothing from this instance.
  * TWO IS TWO. An anonymity set of two is a coin flip, not anonymity.
"""

from __future__ import annotations

from typing import Optional

from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput

# The parts that do not care what the transaction means. Imported rather than
# copied: a second implementation of a sighash is how two of them end up
# disagreeing, and the signature that verifies against nothing is the symptom.
from .payjoin_sp import (  # noqa: F401  (re-exported for the endpoints)
    PayjoinInput,
    canonical,
    change_script,
    explain_mismatch,
    finalize,
    input_digest,
    owner_indices,
    payment_script,
    sighashes,
    verify_witnesses,
)
from .txsize import TAPROOT_OUTPUT_VBYTES, estimate_vsize, fee_for
from .wallet import DUST_SATS

# The states a round passes through. The shape mirrors the advertised PayJoin
# because the constraint is the same: every SP output is derived from the whole
# input set, so nothing can be derived until both sides' coins are in, and
# every output must exist before anyone signs.
PROPOSED = "PROPOSED"          # A named a denomination and picked its coins
ACCEPTED = "ACCEPTED"          # B matched it; the input set is frozen
A_SIGNED = "A_SIGNED"          # A derived its outputs and signed
BROADCAST = "BROADCAST"
CANCELLED = "CANCELLED"

TERMINAL = (BROADCAST, CANCELLED)

_TURN = {
    PROPOSED: "b",   # match the denomination, contribute coins, derive
    ACCEPTED: "a",   # derive, then sign
    A_SIGNED: "b",   # sign, which completes and broadcasts
}


def whose_turn(status: str) -> Optional[str]:
    """'a', 'b', or None when nobody is waited on."""
    return _TURN.get(status)


def require_turn(status: str, role: str) -> None:
    if role not in ("a", "b"):
        raise ValueError(f"{role!r} is not a party to a Tango.")
    turn = whose_turn(status)
    if turn == role:
        return
    if status in TERMINAL:
        raise ValueError(f"This Tango is already {status.lower()}.")
    if turn is None:
        raise ValueError(f"This Tango is {status.lower()} and cannot go on.")
    raise ValueError("This Tango is waiting on the other side, not on you.")


def can_cancel(status: str) -> bool:
    return status not in TERMINAL


def estimate(n_inputs: int, n_outputs: int, fee_rate: float) -> tuple[int, int]:
    """(vsize, fee). Every input and output in a Tango is P2TR."""
    vsize = estimate_vsize(n_inputs, [TAPROOT_OUTPUT_VBYTES] * n_outputs)
    return vsize, fee_for(vsize, fee_rate)


def split_fee(fee: int) -> tuple[int, int]:
    """(A's share, B's share). An odd sat goes to the initiator.

    Someone has to pay it and a rule nobody can predict is worse than a rule
    that is slightly unfair by one satoshi. The initiator chose the
    denomination and the fee rate, so it is theirs.
    """
    half = fee // 2
    return fee - half, half


def plan(
    a_inputs: list[PayjoinInput],
    b_inputs: list[PayjoinInput],
    denom: int,
    fee_rate: float,
) -> dict:
    """What each side puts in, takes out, and pays.

    Both sides receive exactly `denom`. That is not negotiable and it is the
    entire privacy claim: two outputs of different sizes are two outputs an
    observer can tell apart, at which point this is a slow, expensive PayJoin
    with nobody being paid.

    The fee depends on how many change outputs there are, and whether there is
    change depends on the fee. Resolved the same way payjoin_sp.plan does it:
    price the largest shape, then drop any change too small to be worth
    creating and reprice. A dropped change is absorbed into the fee by the
    party whose excess it was, so the other side never pays for it.
    """
    if denom < DUST_SATS:
        raise ValueError(
            f"{denom} sats is below the {DUST_SATS} sat dust limit, so neither "
            f"side could spend what they got back."
        )
    if not a_inputs or not b_inputs:
        raise ValueError("A Tango needs coins from both sides.")

    a_in = sum(i.amount for i in a_inputs)
    b_in = sum(i.amount for i in b_inputs)
    n_in = len(a_inputs) + len(b_inputs)

    def shares(n_out: int) -> tuple[int, int, int, int]:
        vsize, fee = estimate(n_in, n_out, fee_rate)
        a_fee, b_fee = split_fee(fee)
        return vsize, fee, a_fee, b_fee

    # Start by assuming both sides need change: four outputs, the dearest case.
    vsize, fee, a_fee, b_fee = shares(4)
    a_change = a_in - denom - a_fee
    b_change = b_in - denom - b_fee

    for label, total, change, share in (
        ("Your", a_in, a_change, a_fee),
        ("Their", b_in, b_change, b_fee),
    ):
        if change < 0:
            raise ValueError(
                f"{label} coins total {total} sats, which does not cover "
                f"{denom} plus a {share} sat share of the fee. Pick more, or "
                f"agree a smaller amount."
            )

    # Now drop the changes that are not worth creating and reprice. Iterated
    # rather than solved: dropping one change shrinks the transaction, which
    # lowers the fee, which can lift the OTHER change back above dust. Two
    # passes settle it, because there are only two changes to drop.
    for _ in range(2):
        n_out = 2 + (1 if a_change >= DUST_SATS else 0) + (
            1 if b_change >= DUST_SATS else 0
        )
        vsize, fee, a_fee, b_fee = shares(n_out)
        new_a = a_in - denom - a_fee
        new_b = b_in - denom - b_fee
        if new_a < 0 or new_b < 0:
            raise ValueError(
                "The fee moved above what one side's coins can cover. Pick "
                "more coins, or agree a smaller amount."
            )
        a_change, b_change = new_a, new_b

    # Anything left below the dust limit goes to the miner, charged to whoever
    # it belonged to.
    if 0 <= a_change < DUST_SATS:
        a_fee += a_change
        a_change = 0
    if 0 <= b_change < DUST_SATS:
        b_fee += b_change
        b_change = 0

    return {
        "denom": denom,
        "a_in": a_in,
        "b_in": b_in,
        "a_change": a_change,
        "b_change": b_change,
        "a_fee": a_fee,
        "b_fee": b_fee,
        "fee": a_fee + b_fee,
        "vsize": vsize,
        # Said plainly so the clients do not have to work it out, and so the
        # warning they show cannot drift from the arithmetic that caused it.
        "clean": a_change == 0 and b_change == 0,
    }


def outputs_for(
    amounts: dict,
    a_mix_spk: bytes,
    b_mix_spk: bytes,
    a_change_spk: Optional[bytes],
    b_change_spk: Optional[bytes],
) -> list:
    """The outputs, in BIP-69 order.

    The two mixed outputs have the SAME value, so BIP-69 breaks the tie on the
    script bytes — which are two unrelated fresh taproot keys. Neither position
    says anything about who derived it, and neither party can influence it,
    which is what stops "the initiator's output is always first" becoming the
    thing that identifies them.
    """
    outs = [
        TransactionOutput(amounts["denom"], Script(a_mix_spk)),
        TransactionOutput(amounts["denom"], Script(b_mix_spk)),
    ]
    if amounts["a_change"]:
        if a_change_spk is None:
            raise ValueError("A has change but no change script was derived")
        outs.append(TransactionOutput(amounts["a_change"], Script(a_change_spk)))
    if amounts["b_change"]:
        if b_change_spk is None:
            raise ValueError("B has change but no change script was derived")
        outs.append(TransactionOutput(amounts["b_change"], Script(b_change_spk)))
    outs.sort(key=lambda o: (o.value, bytes(o.script_pubkey.data)))
    return outs


def assemble(
    inputs: list[PayjoinInput],
    amounts: dict,
    a_mix_spk: bytes,
    b_mix_spk: bytes,
    a_change_spk: Optional[bytes] = None,
    b_change_spk: Optional[bytes] = None,
) -> Transaction:
    """The unsigned transaction. Inputs canonical, outputs BIP-69.

    No [::-1] on the txid: embit takes it in display order and reverses when it
    serialises. Reversing here does it twice and puts every input on the wire
    backwards — which happened in payjoin_sp, survived every test because the
    fixture txids were palindromes, and was only found by a real transaction
    failing to verify.
    """
    ordered = canonical(inputs)
    vin = [TransactionInput(bytes.fromhex(i.txid), i.vout) for i in ordered]
    vout = outputs_for(amounts, a_mix_spk, b_mix_spk, a_change_spk, b_change_spk)
    return Transaction(vin=vin, vout=vout)
