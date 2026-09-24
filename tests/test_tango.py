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
