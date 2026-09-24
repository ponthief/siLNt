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
    for s in (tango.PROPOSED, tango.ACCEPTED, tango.A_SIGNED):
        assert tango.can_cancel(s)
    assert not tango.can_cancel(tango.BROADCAST)


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


def test_a_marker_distinguishes_two_rounds():
    a = tango.change_label("alice", "7c2ef019-aaaa")
    b = tango.change_label("alice", "3f9a1122-bbbb")
    assert a != b
    assert a == "Tango change - alice #7c2e"
    assert b == "Tango change - alice #3f9a"


def test_the_marker_is_optional():
    """Callers without a round id, and every coin labelled before the marker
    existed, still get a usable name."""
    assert tango.change_label("alice") == "Tango change - alice"
    assert tango.mix_label("alice", "") == "Tango mix - alice"
    assert tango.mix_label(None, None) == "Tango mix"


def test_a_marker_without_a_name_still_reads():
    assert tango.mix_label("", "7c2ef019") == "Tango mix #7c2e"


def test_every_shape_this_has_ever_written_is_recognised():
    """Coins labelled by the earlier versions are the ones most likely to be
    sitting in a wallet right now. If the rule stopped recognising them it
    would stop refusing them, silently."""
    for mix in ("Tango mix", "Tango mix #7c2e",
                "Tango mix - alice", "Tango mix - alice #7c2e"):
        for change in ("Tango change", "Tango change #3f9a",
                       "Tango change - bob", "Tango change - bob #3f9a"):
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
