"""Tango: a two-party equal-output mix.

The privacy claim rests on one property — both mixed outputs are the same size
— and on one honest caveat: change gives an observer arithmetic to work with.
These tests hold the first and measure the second, because a mix that quietly
produces unequal outputs is not a weaker mix, it is a PayJoin that nobody is
being paid in.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

import coincurve
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name


def _load(module: str):
    name = f"{PKG}.helpers._{module}_for_tango_tests"
    if name in sys.modules:
        return sys.modules[name]
    for m in ("lnbits", "lnbits.utils", "lnbits.utils.crypto"):
        sys.modules.setdefault(m, types.ModuleType(m))
    if not hasattr(sys.modules["lnbits.utils.crypto"], "AESCipher"):
        sys.modules["lnbits.utils.crypto"].AESCipher = object
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "helpers" / f"{module}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


wallet = _load("wallet")
sys.modules[f"{PKG}.helpers.wallet"] = wallet
pjsp = _load("payjoin_sp")
sys.modules[f"{PKG}.helpers.payjoin_sp"] = pjsp
tango = _load("tango")

DUST = wallet.DUST_SATS
N = pjsp.SECP256K1_N


def txid_for(seed: int) -> str:
    """Not a palindrome. See test_payjoin_sp_assembly — a repeated-byte txid is
    its own reverse, and that is how a byte-order bug lived undetected."""
    return f"{seed:02x}" + "11" * 30 + f"{(seed ^ 0xFF):02x}"


def xonly(secret: bytes) -> bytes:
    return coincurve.PrivateKey(secret).public_key.format(compressed=True)[1:]


A_SECRET = bytes([0xA1]) * 32
B_SECRET = bytes([0xB2]) * 32

A_MIX = bytes([0x51, 0x20]) + bytes([0x01]) * 32
B_MIX = bytes([0x51, 0x20]) + bytes([0x02]) * 32
A_CHG = bytes([0x51, 0x20]) + bytes([0x03]) * 32
B_CHG = bytes([0x51, 0x20]) + bytes([0x04]) * 32


def coin(seed: int, amount: int, secret: bytes):
    return pjsp.PayjoinInput(
        txid=txid_for(seed), vout=0, amount=amount, pub_key=xonly(secret)
    )


def plan(a_amt, b_amt, denom=25_000, rate=2):
    return tango.plan([coin(0xA0, a_amt, A_SECRET)],
                      [coin(0xB0, b_amt, B_SECRET)], denom, rate)


# ── the property the whole thing rests on ────────────────────────────────────


def test_both_sides_get_exactly_the_same_amount():
    a = plan(40_000, 90_000)
    assert a["denom"] == 25_000
    tx = tango.assemble(
        [coin(0xA0, 40_000, A_SECRET), coin(0xB0, 90_000, B_SECRET)],
        a, A_MIX, B_MIX, A_CHG, B_CHG,
    )
    mixed = [o.value for o in tx.vout if o.value == a["denom"]]
    assert len(mixed) == 2, [o.value for o in tx.vout]


def test_the_two_mixed_outputs_are_indistinguishable_by_shape():
    """Same value, same length, both P2TR. If either differed, an observer
    would not need arithmetic."""
    a = plan(40_000, 90_000)
    tx = tango.assemble(
        [coin(0xA0, 40_000, A_SECRET), coin(0xB0, 90_000, B_SECRET)],
        a, A_MIX, B_MIX, A_CHG, B_CHG,
    )
    mixed = [o for o in tx.vout if o.value == a["denom"]]
    shapes = {(len(bytes(o.script_pubkey.data)),
               bytes(o.script_pubkey.data)[:2]) for o in mixed}
    assert shapes == {(34, bytes([0x51, 0x20]))}


def test_output_order_does_not_reveal_who_initiated():
    """Both mixed outputs have one value, so BIP-69 breaks the tie on script
    bytes — two unrelated fresh keys. Swapping who is A and who is B must not
    reorder anything, or position identifies the initiator."""
    a = plan(40_000, 40_000)
    ins = [coin(0xA0, 40_000, A_SECRET), coin(0xB0, 40_000, B_SECRET)]
    one = tango.assemble(ins, a, A_MIX, B_MIX, A_CHG, B_CHG)
    # Same round, roles labelled the other way round.
    b = plan(40_000, 40_000)
    two = tango.assemble(ins, b, B_MIX, A_MIX, B_CHG, A_CHG)
    assert [o.value for o in one.vout] == [o.value for o in two.vout]
    assert {bytes(o.script_pubkey.data) for o in one.vout} == {
        bytes(o.script_pubkey.data) for o in two.vout
    }


# ── the fee ──────────────────────────────────────────────────────────────────


def test_the_fee_is_split_and_an_odd_sat_goes_to_the_initiator():
    assert tango.split_fee(100) == (50, 50)
    assert tango.split_fee(101) == (51, 50)
    a = plan(40_000, 90_000)
    assert a["a_fee"] + a["b_fee"] == a["fee"]
    assert a["a_fee"] >= a["b_fee"]
    assert a["a_fee"] - a["b_fee"] <= 1


def test_each_side_pays_only_for_itself():
    """A's excess must not cost B anything. Same denomination, same fee rate,
    A's input much larger — B's share must not move."""
    small = plan(40_000, 40_000)
    large = plan(900_000, 40_000)
    assert large["b_fee"] == small["b_fee"], (large["b_fee"], small["b_fee"])
    assert large["b_change"] == small["b_change"]


def test_the_arithmetic_balances():
    a = plan(40_000, 90_000)
    total_in = a["a_in"] + a["b_in"]
    total_out = 2 * a["denom"] + a["a_change"] + a["b_change"]
    assert total_in - total_out == a["fee"]


# ── change, which is where it leaks ──────────────────────────────────────────


def test_a_round_with_no_change_is_reported_clean():
    """Both sides spending exactly the denomination plus their share: two
    inputs, two identical outputs, nothing for an observer to solve."""
    rough = plan(40_000, 40_000)
    exact_a = rough["denom"] + rough["a_fee"]
    exact_b = rough["denom"] + rough["b_fee"]
    a = plan(exact_a, exact_b)
    assert a["a_change"] == 0 and a["b_change"] == 0
    assert a["clean"] is True


def test_a_round_with_change_is_not_reported_clean():
    a = plan(400_000, 400_000)
    assert a["a_change"] > 0 and a["b_change"] > 0
    assert a["clean"] is False


def test_dust_change_is_absorbed_by_whoever_it_belonged_to():
    """Not shared. It is one party's excess, and charging the other for it
    would make the fee split depend on the other side's coin sizes."""
    rough = plan(40_000, 400_000)
    a_exact = rough["denom"] + rough["a_fee"] + (DUST - 1)
    a = plan(a_exact, 400_000)
    assert a["a_change"] == 0
    assert a["a_fee"] > a["b_fee"]


def test_change_below_dust_never_becomes_an_output():
    rough = plan(40_000, 40_000)
    a_exact = rough["denom"] + rough["a_fee"] + 10
    a = plan(a_exact, 400_000)
    tx = tango.assemble(
        [coin(0xA0, a_exact, A_SECRET), coin(0xB0, 400_000, B_SECRET)],
        a, A_MIX, B_MIX, None, B_CHG,
    )
    assert all(o.value >= DUST for o in tx.vout)


# ── refusals ─────────────────────────────────────────────────────────────────


def test_a_side_that_cannot_cover_its_share_is_refused():
    with pytest.raises(ValueError, match="does not cover"):
        plan(25_000, 400_000)


def test_a_denomination_below_dust_is_refused():
    with pytest.raises(ValueError, match="dust limit"):
        plan(400_000, 400_000, denom=DUST - 1)


def test_a_tango_needs_both_sides():
    with pytest.raises(ValueError, match="both sides"):
        tango.plan([], [coin(0xB0, 40_000, B_SECRET)], 25_000, 2)


def test_assemble_refuses_change_with_no_script():
    a = plan(400_000, 400_000)
    assert a["a_change"] > 0
    with pytest.raises(ValueError, match="A has change"):
        tango.assemble(
            [coin(0xA0, 400_000, A_SECRET), coin(0xB0, 400_000, B_SECRET)],
            a, A_MIX, B_MIX, None, B_CHG,
        )


# ── byte order, the bug that already happened once ───────────────────────────


def test_the_txid_goes_onto_the_wire_reversed():
    a = plan(400_000, 400_000)
    ins = [coin(0xA0, 400_000, A_SECRET), coin(0xB0, 400_000, B_SECRET)]
    raw = tango.assemble(ins, a, A_MIX, B_MIX, A_CHG, B_CHG).serialize().hex()
    first = pjsp.canonical(ins)[0].txid
    assert raw[10:10 + 64] == bytes.fromhex(first)[::-1].hex()


def test_no_txid_here_is_its_own_reverse():
    for seed in (0xA0, 0xB0):
        t = txid_for(seed)
        assert bytes.fromhex(t)[::-1].hex() != t


# ── turn taking ──────────────────────────────────────────────────────────────


def test_the_turn_order_is_b_then_a_then_b():
    assert tango.whose_turn(tango.PROPOSED) == "b"
    assert tango.whose_turn(tango.ACCEPTED) == "a"
    assert tango.whose_turn(tango.A_SIGNED) == "b"
    assert tango.whose_turn(tango.BROADCAST) is None


@pytest.mark.parametrize("status,role", [
    (tango.PROPOSED, "a"), (tango.ACCEPTED, "b"), (tango.A_SIGNED, "a"),
])
def test_acting_out_of_turn_is_refused(status, role):
    with pytest.raises(ValueError, match="waiting on the other side"):
        tango.require_turn(status, role)


def test_nobody_acts_on_a_finished_round():
    for status in (tango.BROADCAST, tango.CANCELLED):
        for role in ("a", "b"):
            with pytest.raises(ValueError, match="already"):
                tango.require_turn(status, role)


def test_either_side_may_walk_away_until_it_is_broadcast():
    """Also the set that removing a connection cancels: everything still
    holding coins. BROADCAST is on chain and CANCELLED is already done."""
    for s in (tango.PROPOSED, tango.ACCEPTED, tango.A_SIGNED):
        assert tango.can_cancel(s)
    assert not tango.can_cancel(tango.BROADCAST)
    assert not tango.can_cancel(tango.CANCELLED)


# ── a whole round, signed by both sides ──────────────────────────────────────
#
# The arithmetic tests above say the plan is right. This says the transaction
# built from it is one the network would accept: real derivations from real
# scan keys, real BIP-341 signatures, verified the way the endpoint verifies
# them. It is the closest thing to a live round that runs without a database.


def even_secret(secret: bytes) -> bytes:
    key = coincurve.PrivateKey(secret)
    if key.public_key.format(compressed=True)[0] == 0x02:
        return secret
    return ((N - int.from_bytes(secret, "big")) % N).to_bytes(32, "big")


def spend_pub(secret: bytes) -> bytes:
    return coincurve.PrivateKey(secret).public_key.format(compressed=True)


def label_pub(scan: bytes, m: int = 0) -> bytes:
    tweak = int.from_bytes(
        wallet.tagged_hash("BIP0352/Label", scan + m.to_bytes(4, "big")), "big"
    ) % N
    return coincurve.PublicKey.from_secret(tweak.to_bytes(32, "big")).format(True)


A_SCAN, A_SPEND = bytes([0x11]) * 32, bytes([0x12]) * 32
B_SCAN, B_SPEND = bytes([0x21]) * 32, bytes([0x22]) * 32


def test_a_full_round_signs_verifies_and_finalises():
    a_in = [coin(0xA1, 400_000, A_SECRET)]
    b_in = [coin(0xB1, 300_000, B_SECRET)]
    all_in = a_in + b_in
    amounts = tango.plan(a_in, b_in, 25_000, 2)
    assert not amounts["clean"], "this case is meant to exercise change"

    # Each side derives its OWN two outputs, from its own scan key and the
    # shared public input set. Neither could compute the other's.
    a_mix = tango.payment_script(A_SCAN, spend_pub(A_SPEND), all_in)
    b_mix = tango.payment_script(B_SCAN, spend_pub(B_SPEND), all_in)
    a_chg = tango.change_script(A_SCAN, spend_pub(A_SPEND), label_pub(A_SCAN), all_in)
    b_chg = tango.change_script(B_SCAN, spend_pub(B_SPEND), label_pub(B_SCAN), all_in)
    assert len({a_mix, b_mix, a_chg, b_chg}) == 4

    tx = tango.assemble(all_in, amounts, a_mix, b_mix, a_chg, b_chg)
    digests = tango.sighashes(tx, all_in)

    def sign(secret, indices):
        key = coincurve.PrivateKey(even_secret(secret))
        return {str(n): key.sign_schnorr(digests[n]).rjust(64, b"\x00").hex()
                for n in indices}

    a_idx = tango.owner_indices(all_in, a_in)
    b_idx = tango.owner_indices(all_in, b_in)
    a_w = tango.verify_witnesses(tx, all_in, sign(A_SECRET, a_idx), a_idx)
    b_w = tango.verify_witnesses(tx, all_in, sign(B_SECRET, b_idx), b_idx)

    tx_hex = tango.finalize(tx, {**a_w, **b_w})
    from embit.transaction import Transaction

    parsed = Transaction.from_string(tx_hex)
    assert all(len(v.witness.items) == 1 for v in parsed.vin)
    # Two outputs at the denomination, and they are the only equal pair.
    values = sorted(o.value for o in parsed.vout)
    assert values.count(amounts["denom"]) == 2


def test_a_clean_round_has_exactly_two_outputs():
    """No change on either side: two inputs, two identical outputs, nothing for
    an observer to solve. This is the shape Tango is actually for."""
    rough = tango.plan([coin(0xA1, 400_000, A_SECRET)],
                       [coin(0xB1, 300_000, B_SECRET)], 25_000, 2)
    a_in = [coin(0xA1, 25_000 + rough["a_fee"], A_SECRET)]
    b_in = [coin(0xB1, 25_000 + rough["b_fee"], B_SECRET)]
    amounts = tango.plan(a_in, b_in, 25_000, 2)
    assert amounts["clean"], amounts

    all_in = a_in + b_in
    a_mix = tango.payment_script(A_SCAN, spend_pub(A_SPEND), all_in)
    b_mix = tango.payment_script(B_SCAN, spend_pub(B_SPEND), all_in)
    tx = tango.assemble(all_in, amounts, a_mix, b_mix)
    assert len(tx.vout) == 2
    assert {o.value for o in tx.vout} == {amounts["denom"]}


def test_neither_side_can_derive_the_others_output():
    """The property the mix depends on. If A could compute B's output, A would
    know which of the two is B's — and the anonymity set would be one."""
    all_in = [coin(0xA1, 400_000, A_SECRET), coin(0xB1, 300_000, B_SECRET)]
    b_mix = tango.payment_script(B_SCAN, spend_pub(B_SPEND), all_in)
    forged = tango.payment_script(A_SCAN, spend_pub(B_SPEND), all_in)
    assert forged != b_mix


# ── expiry ───────────────────────────────────────────────────────────────────
# A live round holds a claim on both sides' coins. That is the whole reason
# expiry has to be enforced rather than displayed: the side who would close an
# abandoned round is the side that stopped, so without a sweeper those coins
# are held out of the next Tango for good.


def test_a_round_past_its_time_is_expired():
    assert tango.is_expired(tango.PROPOSED, 1_000, 1_001)
    assert tango.is_expired(tango.ACCEPTED, 1_000, 1_001)
    assert tango.is_expired(tango.A_SIGNED, 1_000, 1_001)


def test_the_boundary_second_counts_as_expired():
    """<= rather than <: a round whose deadline is this second has had all the
    time it was given, and the sweeper and the endpoints must agree on which
    side of it they are."""
    assert tango.is_expired(tango.PROPOSED, 1_000, 1_000)
    assert not tango.is_expired(tango.PROPOSED, 1_000, 999)


def test_a_broadcast_round_never_expires():
    """Its coins are spent on chain. Cancelling it would rewrite a finished
    round, and the sweeper would do it on every pass forever."""
    assert not tango.is_expired(tango.BROADCAST, 1_000, 99_999)


def test_a_cancelled_round_never_expires():
    assert not tango.is_expired(tango.CANCELLED, 1_000, 99_999)


def test_a_round_with_no_deadline_never_expires():
    """The honest reading of a missing value. Treating it as 'expired long ago'
    would cancel rounds nobody agreed to time-limit."""
    assert not tango.is_expired(tango.PROPOSED, None, 99_999)
    assert not tango.is_expired(tango.PROPOSED, 0, 99_999)


# ── the label pair, and what it is for ───────────────────────────────────────
# A round's change and its mixed share add up to what that side put in. Spend
# them together and the coin flip between the two identical outputs becomes a
# certainty — retroactively, and no later mix puts it back. The labels exist so
# a client can refuse that combination, so the format is load-bearing.


def test_both_coins_are_named_after_the_counterparty():
    assert tango.mix_label("alice") == "Tango mix - alice"
    assert tango.change_label("alice") == "Tango change - alice"


def test_a_missing_username_still_names_the_coin():
    """Better an unattributed "Tango mix" than "Tango mix - ", which looks like
    the wallet lost something."""
    for f, bare in (
        (tango.mix_label, "Tango mix"),
        (tango.change_label, "Tango change"),
    ):
        assert f(None) == bare
        assert f("") == bare
        assert f("   ") == bare


def test_a_share_with_its_own_change_is_refused():
    assert tango.undoes_a_round(
        ["Tango mix - alice", "Tango change - alice"]
    ) == "alice"


def test_a_share_with_someone_elses_change_is_refused_too():
    """Two rounds with the same person are still one person. Pairing across
    them links coins whose whole purpose was to be unlinkable, so the name is
    the unit to refuse on rather than the round."""
    assert tango.undoes_a_round(
        ["Tango mix - alice", "Tango change - alice", "rent"]
    ) == "alice"


def test_two_shares_together_are_not_this_failure():
    """Spending two mixed shares links them, which the generic multi-input
    caution already says. It does not hand anyone the arithmetic."""
    assert tango.undoes_a_round(["Tango mix - alice", "Tango mix - bob"]) is None


def test_two_changes_together_are_not_this_failure():
    assert tango.undoes_a_round(
        ["Tango change - alice", "Tango change - bob"]
    ) is None


def test_a_share_with_another_rounds_change_is_refused_too():
    """This assertion used to say the opposite, on the reasoning that alice's
    share and bob's change do not add up to anything. They do not — and it is
    still the same failure.

    A Tango change coin is attributable by construction: its value plus a share
    equals an input total, so an observer can tie it to the coins its owner
    brought. A share is the coin that history was cut off from. One transaction
    holding both repairs the cut, and it does not matter which round the change
    came from.
    """
    assert tango.undoes_a_round(
        ["Tango mix - alice", "Tango change - bob"]
    ) == "alice"


def test_the_share_at_risk_is_the_one_named():
    """The share is what loses its protection, so that is whose round the
    warning is about — not the change coin's."""
    assert tango.undoes_a_round(
        ["Tango mix - alice", "Tango mix - bob", "Tango change - carol"]
    ) == "alice and bob"


def test_unnamed_tango_coins_still_pair():
    """Labelled before the username was carried, or by a wallet that had no
    name to use. Still the same two coins."""
    assert tango.undoes_a_round(["Tango mix", "Tango change"]) == "someone"


def test_ordinary_coins_are_left_alone():
    assert tango.undoes_a_round([]) is None
    assert tango.undoes_a_round(["", None, "salary", "Tango"]) is None


def test_a_label_that_merely_mentions_tango_is_not_one():
    """Substring matching here would refuse a coin the user named themselves."""
    assert tango.undoes_a_round(
        ["my Tango mix - alice", "Tango change - alice"]
    ) is None


# ── telling two rounds apart ─────────────────────────────────────────────────
# Two rounds with the same person produced two coins with identical labels — a
# wallet showing "Tango change - alice" twice, with nothing to say which round
# either came from. The marker is for the person reading the list; the refusal
# above does not use it, because the refusal is by kind.


def test_the_marker_is_the_day():
    from datetime import date, datetime

    assert tango.change_label("alice", date(2026, 9, 24)) == (
        "Tango change - alice · 2026-09-24"
    )
    assert tango.mix_label("alice", datetime(2026, 9, 24, 13, 5)) == (
        "Tango mix - alice · 2026-09-24"
    )


def test_a_date_already_a_string_is_taken_as_written():
    """Some rows come back as text rather than a datetime, depending on the
    driver. Both have to produce the same label or two coins from one round
    would disagree."""
    assert tango.change_label("alice", "2026-09-24") == (
        "Tango change - alice · 2026-09-24"
    )
    assert tango.change_label("alice", "2026-09-24T13:05:00Z") == (
        "Tango change - alice · 2026-09-24"
    )


def test_two_days_distinguish_two_rounds():
    from datetime import date

    a = tango.change_label("alice", date(2026, 9, 24))
    b = tango.change_label("alice", date(2026, 10, 1))
    assert a != b


def test_the_marker_is_optional():
    """Callers without a date, and every coin labelled before the marker
    existed, still get a usable name."""
    assert tango.change_label("alice") == "Tango change - alice"
    assert tango.mix_label("alice", "") == "Tango mix - alice"
    assert tango.mix_label(None, None) == "Tango mix"


def test_a_marker_without_a_name_still_reads():
    assert tango.mix_label("", "2026-09-24") == "Tango mix · 2026-09-24"


def test_every_shape_this_has_ever_written_is_recognised():
    """Coins labelled by the earlier versions are the ones most likely to be
    sitting in a wallet right now — including the round-id marker the date
    replaced. If the rule stopped recognising them it would stop refusing
    them, silently."""
    for mix in ("Tango mix", "Tango mix #7c2e", "Tango mix · 2026-09-24",
                "Tango mix - alice", "Tango mix - alice #7c2e",
                "Tango mix - alice · 2026-09-24"):
        for change in ("Tango change", "Tango change #3f9a",
                       "Tango change · 2026-09-24",
                       "Tango change - bob", "Tango change - bob #3f9a",
                       "Tango change - bob · 2026-10-01"):
            assert tango.undoes_a_round([mix, change]), f"{mix!r} + {change!r}"


def test_a_coin_the_user_named_is_left_alone():
    """Only separators this module writes count. Anything else after the
    prefix is the user's own words."""
    assert tango.undoes_a_round(
        ["my Tango mix - alice", "Tango change - alice"]
    ) is None
    assert tango.undoes_a_round(
        ["Tango mixer fund", "Tango change - alice"]
    ) is None
    assert tango.undoes_a_round(
        ["Tango mix money for alice", "Tango change - alice"]
    ) is None


# ── which coin is which, read off the chain ──────────────────────────────────
# The label decides whether the send guard refuses a selection, so a label on
# the wrong coin is worse than none: it would refuse the safe pair and allow
# the dangerous one while reading plausibly throughout. a_mix_spk says which
# scripts belong to which side; only the transaction says what they received.

MIX_A = "51" + "20" + "aa" * 32
CHG_A = "51" + "20" + "bb" * 32
MIX_B = "51" + "20" + "cc" * 32
CHG_B = "51" + "20" + "dd" * 32

# The real shape: two shares at the denomination, two unequal changes.
OUTS = {MIX_A: 4000, MIX_B: 4000, CHG_A: 1702, CHG_B: 4024}


def test_the_share_is_the_output_worth_the_denomination():
    got = tango.coin_labels(OUTS, 4000, [MIX_A, CHG_A], "bob", "2026-09-24")
    assert got[MIX_A] == "Tango mix - bob · 2026-09-24"
    assert got[CHG_A] == "Tango change - bob · 2026-09-24"


def test_swapped_columns_still_produce_the_right_labels():
    """The case this was written for. Whatever order the caller passes the two
    scripts in, the values decide — so a client or a column that had them the
    wrong way round cannot make the wallet call a change coin a share."""
    got = tango.coin_labels(OUTS, 4000, [CHG_A, MIX_A], "bob", "2026-09-24")
    assert got[MIX_A] == "Tango mix - bob · 2026-09-24"
    assert got[CHG_A] == "Tango change - bob · 2026-09-24"


def test_a_clean_round_has_only_a_share_to_name():
    got = tango.coin_labels(
        {MIX_A: 4000, MIX_B: 4000}, 4000, [MIX_A], "bob", "2026-09-24"
    )
    assert got == {MIX_A: "Tango mix - bob · 2026-09-24"}


def test_a_script_that_is_not_an_output_is_left_out():
    """The caller counts what it asked for, so a missing one is reported rather
    than guessed at. A label written past this would be fiction."""
    got = tango.coin_labels(OUTS, 4000, [MIX_A, "51" + "20" + "ee" * 32],
                            "bob", "2026-09-24")
    assert list(got) == [MIX_A]


def test_case_and_padding_do_not_matter():
    got = tango.coin_labels(
        {MIX_A.upper(): 4000}, 4000, ["  " + MIX_A.upper() + " "], "bob",
        "2026-09-24",
    )
    assert got[MIX_A] == "Tango mix - bob · 2026-09-24"


def test_change_that_happens_to_equal_the_denomination_reads_as_a_share():
    """An honest limit of deciding by value, and harmless. A change output of
    exactly denom means that side put in 2*denom plus its fee share, and the
    coin is then indistinguishable from a share on chain too — so calling it
    one is not a lie, and the guard still refuses it beside a change coin."""
    outs = {MIX_A: 4000, CHG_A: 4000}
    got = tango.coin_labels(outs, 4000, [MIX_A, CHG_A], "bob", "2026-09-24")
    assert got[CHG_A] == "Tango mix - bob · 2026-09-24"


# ── the round that was labelled wrongly, as it happened ──────────────────────
# Signet ddec1aeafefbd146737eba3e60982e8265072e20164b1c19108caab2cf0a8b22:
# 8322 + 6000 in, 4000 + 4000 + 1702 + 4024 out at 2 sat/vB. The initiator put
# in 6000 and took a 4000 share plus 1702 change; the wallet showed that 1702
# labelled as a SHARE, which is the label that makes the send guard refuse the
# safe selection and allow the one that undoes the round.

REAL_OUTS = {
    "512085f3628e9f18b3ac4ba72937163585127ab38d0718e31a69d2b84cf948572bda": 1702,
    "51201a08dea43d883e55dc81d941a9cb7608981475cadf917b7604be4ae6892c2ed2": 4000,
    "51205f11824a325d0059d003d0497b4f02167a00fa042ee82286bca784bf9b0f6216": 4000,
    "51203a8874d97eb8254b1a2b1fe012f6ffc4df6dc97a5feabdd3b9d7fea1887acbd5": 4024,
}
REAL_A_MIX = "51201a08dea43d883e55dc81d941a9cb7608981475cadf917b7604be4ae6892c2ed2"
REAL_A_CHANGE = "512085f3628e9f18b3ac4ba72937163585127ab38d0718e31a69d2b84cf948572bda"


def test_the_real_round_labels_its_1702_as_change():
    got = tango.coin_labels(
        REAL_OUTS, 4000, [REAL_A_MIX, REAL_A_CHANGE], "bob", "2026-09-24"
    )
    assert got[REAL_A_CHANGE] == "Tango change - bob · 2026-09-24"
    assert got[REAL_A_MIX] == "Tango mix - bob · 2026-09-24"


def test_and_still_does_with_the_scripts_the_wrong_way_round():
    """Whatever put a share's name on that 1702, the value decides now."""
    got = tango.coin_labels(
        REAL_OUTS, 4000, [REAL_A_CHANGE, REAL_A_MIX], "bob", "2026-09-24"
    )
    assert got[REAL_A_CHANGE] == "Tango change - bob · 2026-09-24"
    assert got[REAL_A_MIX] == "Tango mix - bob · 2026-09-24"


def test_the_two_coins_of_that_round_are_refused_together():
    """Which is the point of getting the labels right."""
    got = tango.coin_labels(
        REAL_OUTS, 4000, [REAL_A_MIX, REAL_A_CHANGE], "bob", "2026-09-24"
    )
    assert tango.undoes_a_round(list(got.values())) == "bob"


# ── severing a connection takes its unfinished rounds ────────────────────────
# A round that is not terminal holds both sides' coins, and /accept and /sign
# do not re-check the connection — only proposing does. So removing a
# connection has to reach the rounds, or it leaves one live: the coins stay
# reserved until it expires, and the other side can still carry it through to a
# broadcast with somebody who has just cut them off.


def test_removal_cancels_rounds_before_deleting_the_connection():
    """Order matters and there is no database here to prove it on. The other
    way round could sever the connection and leave the round it was supposed to
    take with it — which is the state this was written to prevent."""
    src = (ROOT / "views_api.py").read_text()
    body = src[src.index("async def api_payjoin_contact_remove"):]
    body = body[: body.index("@silnt_api_router")]
    assert "list_live_tango_rounds_between(" in body
    assert "delete_payjoin_contact(" in body
    assert body.index("list_live_tango_rounds_between(") < body.index(
        "delete_payjoin_contact("
    ), "the connection is deleted before its rounds are cancelled"
    # And the other side is told, since their coins come back too.
    assert "_notify_tango(" in body


def test_the_query_leaves_broadcast_rounds_alone():
    """Cancelling a broadcast round would rewrite a finished one, and its coins
    are spent rather than reserved."""
    src = (ROOT / "crud.py").read_text()
    body = src[src.index("async def list_live_tango_rounds_between"):]
    body = body[: body.index("async def get_reserved_tango_outpoints")]
    assert 's != "BROADCAST"' in body
    assert "TANGO_LIVE" in body


# ── the round whose missing change looked like a bug ─────────────────────────
# Signet 61511d8a53fc2ed4f5c33848547306638d63804feb19a8df917cb68591f6d27a:
# five inputs (8000 + 1749 + 5000 + 11500 + 4000 = 30,249) and only THREE
# outputs — 3073, 13,000, 13,000 — for a fee of 1176 over 427 vB.
#
# The side that put in 13,749 got one 13,000 coin and no change at all, and its
# row read "-749" while the other side's read "-427" for the same transaction.
# Both numbers are right and neither explains itself: 13,749 - 13,000 - 427 is
# 322, which is under the 546 sat dust limit, so plan() dropped it and charged
# it to the side whose excess it was. These hold that arithmetic, because the
# alternative reading — that the wallet lost a coin — is the one a user reaches
# for first, and it was wrong.

REAL_DENOM = 13_000
REAL_RATE = 2
REAL_A_IN = 11_500 + 5_000        # the initiator
REAL_B_IN = 8_000 + 4_000 + 1_749


def real_round():
    return tango.plan(
        [coin(0xA0, 11_500, A_SECRET), coin(0xA1, 5_000, A_SECRET)],
        [coin(0xB0, 8_000, B_SECRET), coin(0xB1, 4_000, B_SECRET),
         coin(0xB2, 1_749, B_SECRET)],
        REAL_DENOM, REAL_RATE,
    )


def test_the_planner_reproduces_that_transaction_exactly():
    """Every number on chain, from the two sides' coins alone."""
    p = real_round()
    assert p["vsize"] == 427
    assert p["a_change"] == 3073
    assert p["b_change"] == 0
    assert p["a_fee"] == 427
    assert p["b_fee"] == 749
    assert p["fee"] == 1176
    # And it balances: what went in, less what came out, is the fee.
    outs = REAL_DENOM * 2 + p["a_change"] + p["b_change"]
    assert REAL_A_IN + REAL_B_IN - outs == 1176


def test_the_side_with_no_change_paid_its_dust():
    """749 is not a fee anyone chose. It is 427 of a real fee share plus 322 of
    change too small to be worth an output."""
    p = real_round()
    assert p["b_fee"] - 427 == 322
    assert REAL_B_IN - REAL_DENOM - 427 == 322
    assert 322 < 546, "if this ever stops being dust the round gains an output"


def test_dust_to_fee_recovers_the_322():
    """What the wallet needs in order to say where the coin went. The round
    stores the fee AFTER absorption, so this has to retrace it."""
    p = real_round()
    assert tango.dust_to_fee(
        p["b_fee"], p["b_change"], p["vsize"], REAL_RATE, i_am_the_initiator=False
    ) == 322


def test_the_side_that_kept_its_change_absorbed_nothing():
    p = real_round()
    assert tango.dust_to_fee(
        p["a_fee"], p["a_change"], p["vsize"], REAL_RATE, i_am_the_initiator=True
    ) == 0


def test_a_round_where_both_sides_keep_change_absorbs_nothing():
    p = tango.plan(
        [coin(0xA0, 14_000, A_SECRET)],
        [coin(0xB0, 14_000, B_SECRET)],
        REAL_DENOM, REAL_RATE,
    )
    assert p["a_change"] == p["b_change"] == 702
    for fee, change, is_a in ((p["a_fee"], p["a_change"], True),
                              (p["b_fee"], p["b_change"], False)):
        assert tango.dust_to_fee(fee, change, p["vsize"], REAL_RATE, is_a) == 0


def test_clean_does_not_mean_nothing_was_absorbed():
    """A trap for anyone reading `clean` as "the coins covered it exactly".

    It means only that no change OUTPUT exists, which is the privacy property
    it was named for. Both sides here put in 86 sats more than the fee, kept
    nothing, and paid it to the miner — a clean round in which each side
    absorbed dust. So a wallet cannot use `clean` to decide whether to explain
    a missing change coin; that is what dust_to_fee is for.
    """
    p = tango.plan(
        [coin(0xA0, 13_298, A_SECRET)],
        [coin(0xB0, 13_298, B_SECRET)],
        REAL_DENOM, REAL_RATE,
    )
    assert p["clean"] and p["a_change"] == 0
    assert tango.dust_to_fee(p["a_fee"], 0, p["vsize"], REAL_RATE, True) == 86
    assert 13_298 - REAL_DENOM - 212 == 86


def test_dust_to_fee_claims_nothing_when_a_field_is_missing():
    """An old round predating these columns must not report a dust absorption
    it cannot know about."""
    assert tango.dust_to_fee(749, 0, None, 2, False) == 0
    assert tango.dust_to_fee(749, 0, 427, None, False) == 0
    assert tango.dust_to_fee(None, 0, 427, 2, False) == 0


# ── which labels the transaction row may drop ────────────────────────────────


def test_our_own_coin_labels_are_recognised():
    assert tango.wrote_label("Tango mix - bob · 2026-09-25")
    assert tango.wrote_label("Tango change - bob · 2026-09-25")
    assert tango.wrote_label("Tango mix - bob #fagk")     # the old marker
    assert tango.wrote_label("Tango change")             # bare, no counterparty


def test_a_label_the_user_wrote_is_not_ours_to_drop():
    """The row drops what this module wrote. Dropping the user's text because
    it begins with the same word would lose the only note they kept."""
    assert not tango.wrote_label("Tango mix money")
    assert not tango.wrote_label("my Tango mix - bob · 2026-09-25")
    assert not tango.wrote_label("rent")
    assert not tango.wrote_label("")


def test_the_real_rounds_labels_are_both_droppable():
    """Both of the three badges that row carried, so one is left."""
    got = tango.coin_labels(
        REAL_OUTS, 4000, [REAL_A_MIX, REAL_A_CHANGE], "bob", "2026-09-24"
    )
    assert all(tango.wrote_label(v) for v in got.values())


# ── the label vocabulary stands on its own ───────────────────────────────────
# It moved out of this module so the transaction list could ask "is this label
# one of ours?" without importing the signing stack to find out. That is only
# true while it stays import-free, and nothing about editing it would say so.


def test_the_label_vocabulary_imports_nothing_of_its_own():
    """No curve, no embit, no wallet — it is string work.

    Checked on the import statements rather than the text, because the module's
    own docstring names the things it is avoiding.
    """
    import ast

    tree = ast.parse((ROOT / "helpers" / "tangolabels.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    # json is stdlib and pure: the scripts a side derived are stored as an
    # array and something has to read it. The rule this test exists for is
    # about the SIGNING stack — curve, embit, wallet — not about whether the
    # module may parse a list.
    assert imported <= {"__future__", "typing", "json"}, sorted(imported)


def test_tango_still_re_exports_all_of_it():
    """Every caller and test reaches these through tango.*, and the split was
    supposed to be invisible to them."""
    for name in (
        "MIX_LABEL", "CHANGE_LABEL", "mix_label", "change_label",
        "coin_labels", "undoes_a_round", "day_marker", "wrote_label",
        "_party", "_strip_marker", "_MARKERS", "_named",
    ):
        assert hasattr(tango, name), name


# ── why a round ended ────────────────────────────────────────────────────────
# reject_reason is read by two clients and shown to a person, so the wording is
# a contract. A cancellation keeps the SIDE rather than a name, because the name
# depends on who is reading — and for a while the web printed the raw value, so
# a stopped round read "Cancelled · cancelled by a".


def test_a_cancellation_records_which_side_stopped_it():
    assert tango.cancelled_by("a") == "cancelled by a"
    assert tango.cancelled_by("b") == "cancelled by b"


def test_only_a_party_can_be_recorded_as_cancelling():
    for role in ("c", "", "A ", "alice", None):
        with pytest.raises(ValueError):
            tango.cancelled_by(role)


def test_the_reason_reads_back_as_the_side_that_wrote_it():
    for role in ("a", "b"):
        assert tango.who_cancelled(tango.cancelled_by(role)) == role


def test_rounds_cancelled_before_this_existed_still_read():
    """The wording is unchanged on purpose: the endpoint has been writing this
    exact string, and those rows are in the database now. Changing it would
    leave every past cancellation unattributable."""
    assert tango.who_cancelled("cancelled by a") == "a"
    assert tango.who_cancelled("cancelled by b") == "b"


def test_the_other_endings_are_nobody_cancelling():
    """An expiry is not a refusal — the time ran out and the coins went back —
    and a severed connection is the app closing the round, not a person."""
    assert tango.who_cancelled(tango.EXPIRED) is None
    assert tango.who_cancelled(tango.CONNECTION_REMOVED) is None


def test_a_reason_that_is_not_one_of_ours_names_nobody():
    for reason in ("cancelled by carol", "cancelled by", "cancelled", "", None):
        assert tango.who_cancelled(reason) is None, reason


def test_case_and_padding_do_not_hide_the_side():
    assert tango.who_cancelled("  Cancelled By A  ") == "a"


# ── a coin a live round is holding ───────────────────────────────────────────
# The reservation guarded /rounds and /accept only, so a second Tango could not
# take a committed coin but an ORDINARY SEND could. The round then went all the
# way to its last step, both people signed, and the node refused the finished
# transaction with "bad-txns-inputs-missingorspent" — as a 502, naming no coin,
# to whichever side happened to sign second.


def test_the_two_spellings_of_an_outpoint_are_one():
    """The reserved set was built from the txid as stored and looked up with it
    lowercased. A miss there is a coin let into a second round, not a wasted
    lookup."""
    assert tango.outpoint_key("AB" * 32, 1) == tango.outpoint_key("ab" * 32, 1)
    assert tango.outpoint_key("  ab  ", "2") == "ab:2"


def test_a_held_coin_is_found_whatever_case_it_was_stored_in():
    reserved = {tango.outpoint_key("AB" * 32, 0)}
    rows = [{"txid": "ab" * 32, "vout": 0}]
    assert tango.clashing_outpoints(rows, reserved) == [f"{'ab' * 32}:0"]


def test_the_clash_is_quoted_back_as_it_was_asked_for():
    """Not normalised: the user has never seen the normalised form."""
    reserved = {tango.outpoint_key("ab" * 32, 3)}
    assert tango.clashing_outpoints([{"txid": "AB" * 32, "vout": 3}], reserved) == [
        f"{'AB' * 32}:3"
    ]


def test_every_shape_a_caller_sends_is_checked():
    """Dicts from a send, stored round rows, and (txid, vout) pairs all reach
    this. A shape it skipped would pass the coin straight through."""
    reserved = {tango.outpoint_key("cd" * 32, 7)}

    class Row:
        txid = "cd" * 32
        vout = 7

    for rows in (
        [{"txid": "cd" * 32, "vout": 7}],
        [("cd" * 32, 7)],
        [Row()],
    ):
        assert tango.clashing_outpoints(rows, reserved), rows


def test_free_coins_clash_with_nothing():
    reserved = {tango.outpoint_key("cd" * 32, 7)}
    assert tango.clashing_outpoints([{"txid": "ef" * 32, "vout": 7}], reserved) == []
    assert tango.clashing_outpoints([{"txid": "cd" * 32, "vout": 8}], reserved) == []
    assert tango.clashing_outpoints([], reserved) == []
    assert tango.clashing_outpoints([{"txid": "cd" * 32, "vout": 7}], set()) == []


def test_a_row_with_no_outpoint_is_skipped_not_guessed():
    assert tango.clashing_outpoints([{"vout": 0}], {"none:0"}) == []


def test_the_refusal_says_where_the_coins_went_and_how_to_get_them_back():
    one = tango.reserved_refusal(["abc:0"])
    assert "Tango" in one and "Cancel" in one
    assert one.startswith("That coin is")
    assert tango.reserved_refusal(["abc:0", "abc:1"]).startswith("Those coins are")
    assert tango.reserved_refusal([]) == ""


def test_a_round_whose_coins_are_gone_says_so_in_words():
    """Replacing a 502 carrying the node's "bad-txns-inputs-missingorspent",
    which names no coin and says nothing to do."""
    msg = tango.spent_input_refusal(["deadbeef:0"])
    assert "deadbeef:0" in msg
    assert "cancel it" in msg
    assert msg.startswith("A coin")
    # The record is corrected when this fires, so the same coin is not offered
    # for the next round — being told to start again is no use otherwise.
    assert "will not be offered" in msg
    assert tango.spent_input_refusal(["a:0", "b:1"]).startswith("Coins")
    assert tango.spent_input_refusal([]) == ""


def test_the_send_paths_refuse_a_coin_a_round_is_holding():
    """There is no database here to prove it on, so this reads the endpoints.

    Both of them: /tx/prepare quotes the fee and /tx/build still signs for the
    older clients, and a guard on only one of them is a guard with a way round.
    """
    src = (ROOT / "views_api.py").read_text()
    for marker in ('"/api/v1/tx/prepare"', '"/api/v1/tx/build"'):
        start = src.index(marker)
        body = src[start : src.index("@silnt_api_router", start + len(marker))]
        assert "_refuse_tango_reserved(" in body, marker
        assert "validate_spendable_utxos(" in body, marker


def test_signing_checks_the_coins_still_exist_before_anyone_signs():
    src = (ROOT / "views_api.py").read_text()
    body = src[src.index("async def api_tango_sign"):]
    body = body[: body.index("@silnt_api_router")]
    assert "_refuse_spent_tango_inputs(" in body
    # Before the witness work, not after: the point is to refuse without
    # asking anyone to sign a transaction that cannot confirm.
    assert body.index("_refuse_spent_tango_inputs(") < body.index("verify_witnesses(")


def test_the_spent_check_asks_the_chain_not_only_our_columns():
    """THE CASE THAT KEPT FAILING. A wallet learns a coin was spent by scanning
    the block that spent it, so until the scanner reaches that height its own
    record still says unspent — which is exactly when the node disagrees. A
    check against our own columns passes, cheerfully, every time.

    And the record is repaired, or the coin stays in the coin list, gets picked
    for the next round, and fails identically. That was the loop.
    """
    src = (ROOT / "views_api.py").read_text()
    body = src[src.index("async def _refuse_spent_tango_inputs"):]
    body = body[: body.index("async def _refuse_tango_reserved")]
    assert "get_outspend_status(" in body
    assert "mark_utxos_spent_by_outpoints(" in body
    # An explorer that cannot answer must not refuse a good round.
    assert 'isinstance(res, dict)' in body and 'res.get("spent")' in body


def test_the_spent_check_covers_both_sides():
    """The coin that went is as likely to be the other side's, and the round is
    equally dead either way."""
    src = (ROOT / "views_api.py").read_text()
    body = src[src.index("async def _refuse_spent_tango_inputs"):]
    body = body[: body.index("async def _refuse_tango_reserved")]
    assert "rnd.a_wallet_id, rnd.a_inputs" in body
    assert "rnd.b_wallet_id, rnd.b_inputs" in body


def test_the_utxo_list_says_which_coins_a_round_is_holding():
    """So a coin does not simply vanish from Send and Tango with nothing to
    explain it."""
    src = (ROOT / "views_api.py").read_text()
    body = src[src.index("async def api_get_utxos"):]
    body = body[: body.index("@silnt_api_router")]
    assert "tango_reserved" in body
    assert "get_reserved_tango_outpoints(" in body


# ── taking your share in several pieces ──────────────────────────────────────
# One output a side gives two readings of the round — which of the two
# identical coins is yours — and that is one bit whatever else the transaction
# looks like. p pieces a side gives C(2p, p): six at two, twenty at three.
#
# It is the only lever that measured the same on every round shape, because it
# is combinatorics over identical outputs rather than an arithmetic coincidence
# that may or may not be there. The fee-split idea scored +1.58 bits on one
# constructed round and nothing at all on seven of eight realistic ones.

def pieces_plan(a_amt, b_amt, denom=25_000, rate=2, pieces=2):
    return tango.plan([coin(0xA0, a_amt, A_SECRET)],
                      [coin(0xB0, b_amt, B_SECRET)], denom, rate, pieces)


def spks(n, first=0x10):
    return [bytes([0x51, 0x20]) + bytes([first + i]) * 32 for i in range(n)]


def test_the_denomination_is_what_you_get_back_however_many_coins_it_is():
    """`denom` keeps meaning the total. Changing that under the user would be
    a different feature wearing the same field."""
    for p in (1, 2, 5):
        a = pieces_plan(400_000, 400_000, pieces=p)
        assert a["denom"] == 25_000
        assert a["pieces"] == p
        assert a["share"] * p == 25_000


def test_every_mixed_output_is_the_same_size_and_shape():
    """The whole privacy claim, and it has to hold across BOTH sides' pieces:
    2p outputs an observer cannot tell apart."""
    a = pieces_plan(400_000, 400_000, denom=24_000, pieces=3)
    tx = tango.assemble(
        [coin(0xA0, 400_000, A_SECRET), coin(0xB0, 400_000, B_SECRET)],
        a, spks(3, 0x10), spks(3, 0x40), A_CHG, B_CHG,
    )
    mixed = [o for o in tx.vout if o.value == a["share"]]
    assert len(mixed) == 6, [o.value for o in tx.vout]
    shapes = {(len(bytes(o.script_pubkey.data)), bytes(o.script_pubkey.data)[:2])
              for o in mixed}
    assert shapes == {(34, bytes([0x51, 0x20]))}


def test_the_pieces_are_not_grouped_by_side_in_the_transaction():
    """BIP-69 orders the identical outputs by script bytes, which are
    unrelated fresh keys. If A's pieces came out adjacent, the readings the
    pieces were added for would not exist."""
    a = pieces_plan(400_000, 400_000, pieces=2)
    a_spks, b_spks = spks(2, 0x10), spks(2, 0x11)
    tx = tango.assemble(
        [coin(0xA0, 400_000, A_SECRET), coin(0xB0, 400_000, B_SECRET)],
        a, a_spks, b_spks, A_CHG, B_CHG,
    )
    order = [bytes(o.script_pubkey.data) for o in tx.vout if o.value == a["share"]]
    assert order == sorted(order), "mixed outputs are not in BIP-69 order"


def test_an_amount_that_does_not_divide_is_refused():
    """Every output has to be the same size, so the remainder has nowhere to
    go: not into one piece, which would make it identifiable, and not into the
    fee, which is the dust leak by another name."""
    with pytest.raises(ValueError) as e:
        pieces_plan(400_000, 400_000, denom=25_001, pieces=2)
    assert "equal coins" in str(e.value)


def test_a_piece_below_the_dust_limit_is_refused():
    """Splitting far enough turns the shares into coins nobody can spend."""
    with pytest.raises(ValueError) as e:
        pieces_plan(400_000, 400_000, denom=1000, pieces=4)
    assert "dust limit" in str(e.value)


def test_the_fee_pays_for_every_piece():
    """Each extra pair of outputs is 86 more vbytes, and the plan has to price
    them or the transaction underpays the rate the user chose."""
    one = pieces_plan(400_000, 400_000, pieces=1)
    two = pieces_plan(400_000, 400_000, pieces=2)
    assert two["vsize"] - one["vsize"] == 86, (one["vsize"], two["vsize"])
    assert two["fee"] > one["fee"]


def test_a_side_that_derives_the_wrong_number_of_scripts_is_refused():
    """Silently building a round with three outputs where four were planned
    would pay somebody the wrong amount."""
    a = pieces_plan(400_000, 400_000, pieces=2)
    with pytest.raises(ValueError) as e:
        tango.outputs_for(a, spks(1), spks(2, 0x40), A_CHG, B_CHG)
    assert "needs its own output" in str(e.value)


def test_one_piece_is_still_the_old_shape():
    """Every round already broadcast was planned this way, and the columns
    holding a single script still read back."""
    a = pieces_plan(400_000, 400_000, pieces=1)
    assert a["share"] == a["denom"]
    tx = tango.assemble(
        [coin(0xA0, 400_000, A_SECRET), coin(0xB0, 400_000, B_SECRET)],
        a, A_MIX, B_MIX, A_CHG, B_CHG,
    )
    assert len([o for o in tx.vout if o.value == 25_000]) == 2


def test_coins_are_named_by_what_a_piece_is_worth():
    outs = {spks(1)[0].hex(): 12_500, A_CHG.hex(): 9_000}
    got = tango.coin_labels(
        outs, 12_500, [spks(1)[0].hex(), A_CHG.hex()], "bob", "2026-09-26",
    )
    assert got[spks(1)[0].hex()] == "Tango mix - bob · 2026-09-26"
    assert got[A_CHG.hex()] == "Tango change - bob · 2026-09-26"


# ── the guard the pieces need ────────────────────────────────────────────────


def share(txid, who="bob"):
    return {"txid": txid, "label": f"Tango mix - {who} · 2026-09-26"}


def change(txid, who="bob"):
    return {"txid": txid, "label": f"Tango change - {who} · 2026-09-26"}


def test_two_pieces_of_one_round_together_undo_it():
    """C(4,2) readings exist only while nobody can say which two of the four
    identical coins were one person's. Spending two of them says it."""
    assert tango.undoes_a_round([share("aa" * 32), share("aa" * 32)]) == "bob"


def test_pieces_of_DIFFERENT_rounds_are_not_this_failure():
    """Two rounds are two anonymity sets. Spending across them is the ordinary
    cost of using mixed coins, not the round undoing itself."""
    assert tango.undoes_a_round([share("aa" * 32), share("bb" * 32, "carol")]) is None


def test_the_share_and_change_rule_still_holds_with_txids():
    assert tango.undoes_a_round([share("aa" * 32), change("bb" * 32)]) == "bob"


def test_a_selection_with_no_txids_still_gets_the_older_rule():
    """Labels alone cannot say which round a coin is from, so they cannot trip
    the same-round rule — and must still trip the one they always did."""
    assert tango.undoes_a_round(
        ["Tango mix - bob", "Tango change - bob"]) == "bob"
    assert tango.undoes_a_round(["Tango mix - bob", "Tango mix - bob"]) is None


def test_one_piece_of_a_round_beside_an_ordinary_coin_is_fine():
    assert tango.undoes_a_round([share("aa" * 32), {"txid": "cc" * 32,
                                                    "label": "rent"}]) is None


def test_the_readings_a_round_offers_are_C_2p_choose_p():
    """The claim the pieces were added for, asserted against a real plan.

    An observer reading the transaction sees 2p outputs of one size and knows
    each side took p of them. The number of ways that could have gone is
    C(2p, p) — two at one piece, six at two, twenty at three — and that is the
    round's anonymity, before anything else about it is considered.

    Measured across eight realistic rounds this held on every one, which is
    what distinguished it from the fee-split idea: that scored +1.58 bits on
    one constructed round and nothing at all on seven of eight.

    It is only the ceiling. Change still attaches to its owner, the coordinator
    still sees everything, and spending two pieces together throws it away —
    which undoes_a_round refuses.
    """
    from math import comb

    for p, denom, expect in ((1, 24_000, 2), (2, 24_000, 6), (3, 24_000, 20)):
        a = pieces_plan(400_000, 400_000, denom=denom, pieces=p)
        tx = tango.assemble(
            [coin(0xA0, 400_000, A_SECRET), coin(0xB0, 400_000, B_SECRET)],
            a, spks(p, 0x10), spks(p, 0x40), A_CHG, B_CHG,
        )
        identical = [o for o in tx.vout if o.value == a["share"]]
        assert len(identical) == 2 * p
        assert comb(len(identical), p) == expect, (p, len(identical))
