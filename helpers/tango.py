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
# The label vocabulary, re-exported so tango.* remains the one import every
# caller and test already uses. It lives in its own module because it needs
# none of the above — see tangolabels.py.
from .tangolabels import (  # noqa: F401
    CHANGE_LABEL,
    MIX_LABEL,
    _MARKERS,
    _named,
    _party,
    _strip_marker,
    change_label,
    coin_labels,
    day_marker,
    mix_label,
    undoes_a_round,
    wrote_label,
)
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


# Why a round ended, as reject_reason. Three of the four are already sentences;
# a cancellation is the one that needs to name somebody, and the name depends on
# who is reading. So the column keeps the SIDE and each client turns it into
# "You cancelled it" or "alice cancelled it" — which is what it always meant,
# and what the web was printing raw as "cancelled by a".
#
# The wording below is unchanged from what shipped, deliberately: rounds
# cancelled before this are in the database now, and the clients read them with
# the same parser as the ones cancelled after it.
EXPIRED = "expired"
CONNECTION_REMOVED = "connection removed"
_CANCELLED_BY = "cancelled by "


def cancelled_by(role: str) -> str:
    """The reject_reason for a round somebody stopped."""
    if role not in ("a", "b"):
        raise ValueError(f"{role!r} is not a party to a Tango.")
    return f"{_CANCELLED_BY}{role}"


def who_cancelled(reason: Optional[str]) -> Optional[str]:
    """'a', 'b', or None when this reason is not a cancellation by a person.

    The clients have their own copy of this (tangoTurns.ts) because they are
    the ones doing the rendering; this one is here so the format has a single
    definition on the side that writes it, and a test that reads it back.
    """
    text = (reason or "").strip().lower()
    if not text.startswith(_CANCELLED_BY):
        return None
    role = text[len(_CANCELLED_BY):].strip()
    return role if role in ("a", "b") else None


def dust_to_fee(
    my_fee: Optional[int],
    my_change: Optional[int],
    vsize: Optional[int],
    fee_rate: Optional[float],
    i_am_the_initiator: bool,
) -> int:
    """How much of this side's change was too small to keep, and so went to the
    miner instead of back to the wallet.

    WHY THIS HAS TO BE SAYABLE. `plan` drops a change below the dust limit and
    charges it to whoever's excess it was. The result is a side that put in
    13,749, got one 13,000 coin back, and paid 749 — while the other side, in
    the same transaction, paid 427. Nothing on chain or in the wallet explains
    the difference, and the coin the owner expects to see simply is not there.
    The honest reading is "322 sats was below the 546 sat dust limit", and
    without this the wallet cannot say it.

    Recovered rather than stored, because the round records the fee AFTER
    absorption. The planned share is recomputable exactly: `vsize` is the final
    shape's size and `fee_rate` is what the initiator chose, so fee_for and
    split_fee retrace the two lines of plan() that ran just before the
    absorption.

    Returns 0 whenever there is real change (nothing was dropped), and whenever
    a field needed for the arithmetic is missing — an unknown is not a claim.
    """
    if my_fee is None or vsize is None or fee_rate is None:
        return 0
    if my_change:
        return 0
    a_share, b_share = split_fee(fee_for(int(vsize), float(fee_rate)))
    planned = a_share if i_am_the_initiator else b_share
    return max(0, int(my_fee) - planned)


def is_expired(status: str, expires_at: Optional[int], now: int) -> bool:
    """Whether a round has run out of time and should be closed.

    WHY THIS MATTERS MORE HERE THAN IN MOST PLACES. A round that is not
    terminal holds a claim on both sides' coins: get_reserved_tango_outpoints
    lists them, and /propose and /accept refuse anything already claimed. So an
    abandoned round does not merely sit there — it takes those coins out of
    circulation, for this feature, until something closes it. Nobody is going
    to: the whole reason it is abandoned is that one side stopped. The sweeper
    is what closes it, and this decides what it closes.

    A terminal round is never expired. BROADCAST has already spent the coins
    and CANCELLED has already freed them, so re-closing either would only
    rewrite history.

    A round with no expires_at never expires, which is the honest reading of a
    missing value rather than a reason to cancel someone's coins.
    """
    if status in TERMINAL:
        return False
    if not expires_at:
        return False
    return int(expires_at) <= int(now)


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
