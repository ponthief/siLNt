"""The fee on a Tango's change, and the two ways it was specified wrong.

THE FEATURE. A user who supplies a Lightning address has their round's change
output paid to the instance's Silent Payments address instead of their own
wallet, and the value sent to that Lightning address minus a service fee. The
change coin is the strongest remaining linkability problem in Tango — its value
is fixed by the round's arithmetic, so spending it later shows which of the two
identical shares were theirs — and getting it out of their wallet is the only
clean fix.

THE FIRST WRONG SPECIFICATION was 0.5% **of the total transaction**, deducted
from the change. Those are unrelated quantities: the denomination is what the
two sides agreed to mix, and the change is whatever their coin selection left
over. A large round with a small change is the normal case, so the fee goes
negative in ordinary use — at 1,000,000 sats a side, 0.5% of the round is
10,000 charged against a 750-sat change and the user is owed minus 9,250. The
percentage is charged on the change instead, which is the amount actually being
moved and the basis Boltz uses.

THE SECOND was mine. The first cut capped the fee at `change - DUST_SATS`, so
on a 600-sat change it charged 54 sats — below the floor, which exists because
under it the payout costs more than it collects — and routed anyway. A cap that
discounts is a subsidy nobody chose. The fee is never reduced now: either it
leaves a payout worth sending or the change stays where it is, which is
today's behaviour and not an error.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DUST_SATS = 546


def _payout():
    """Loaded by source with the dust import stubbed: helpers/wallet.py reaches
    LNbits for everything else it does, and this module wants one constant
    from it. The constant is asserted against the real file below, so the stub
    cannot drift."""
    src = (ROOT / "helpers" / "tangopayout.py").read_text()
    src = src.replace("from .wallet import DUST_SATS", f"DUST_SATS = {DUST_SATS}")
    ns: dict = {}
    exec(compile(src, "tangopayout.py", "exec"), ns)  # noqa: S102
    return ns


P = _payout()
payout_plan = P["payout_plan"]
min_change_to_route = P["min_change_to_route"]
payout_offered = P["payout_offered"]


def test_the_stubbed_dust_limit_is_the_real_one():
    """Everything below is priced against 546. If the wallet's limit moves and
    this does not, every threshold here is measuring nothing."""
    wallet = (ROOT / "helpers" / "wallet.py").read_text()
    assert f"DUST_SATS = {DUST_SATS}" in wallet


# ── the fee is charged on the change, not on the round ──────────────────────


@pytest.mark.parametrize(
    "change,expected_fee,expected_net",
    [
        (646, 100, 546),        # the smallest change worth routing
        (750, 100, 650),
        (2_500, 100, 2_400),
        (20_000, 100, 19_900),  # where the percentage catches the floor
        (20_001, 101, 19_900),  # and overtakes it
        (100_000, 500, 99_500),
        (1_000_000, 5_000, 995_000),
    ],
)
def test_the_split_at_the_defaults(change, expected_fee, expected_net):
    p = payout_plan(change)
    assert p.routed
    assert (p.fee_sats, p.net_sats) == (expected_fee, expected_net)
    assert p.gross_sats == change


def test_a_big_round_with_a_small_change_is_the_normal_case():
    """The original specification's failure, stated as a test rather than as a
    table in a document: the fee does not depend on the round at all, so a
    750-sat change costs the same 100 sats whether it came out of a 50,000-sat
    round or a 2,000,000-sat one."""
    assert payout_plan(750).fee_sats == 100


def test_the_fee_never_exceeds_the_change():
    """The property the first specification broke. Swept rather than sampled,
    because the failure was at a ratio nobody thought to try."""
    for change in range(0, 2_000_000, 37):
        p = payout_plan(change)
        assert p.fee_sats <= max(change, 0), change
        assert p.fee_sats >= 0 and p.net_sats >= 0, change


def test_the_parts_always_add_up_to_the_whole():
    for change in range(DUST_SATS, 500_000, 11):
        p = payout_plan(change)
        if p.routed:
            assert p.fee_sats + p.net_sats == p.gross_sats == change, change


def test_a_routed_payout_is_always_worth_sending():
    for change in range(0, 500_000, 13):
        p = payout_plan(change)
        if p.routed:
            assert p.net_sats >= DUST_SATS, change


# ── and it is never quietly discounted ──────────────────────────────────────


def test_a_change_that_cannot_carry_the_fee_is_not_routed_at_a_discount():
    """The bug in my first cut. 600 - 100 = 500, which is under the dust
    limit, so the old code charged 54 sats to make it fit. The floor is cost
    recovery: charging under it means the payout loses money, and doing that
    silently means nobody finds out."""
    p = payout_plan(600)
    assert not p.routed
    assert p.fee_sats == 0
    assert "too small to pay out" in p.reason
    # And the fee it would have wanted is named, so the reason is actionable.
    assert "100 sat fee" in p.reason


@pytest.mark.parametrize("change", [DUST_SATS, 600, 645])
def test_nothing_between_the_dust_limit_and_the_threshold_routes(change):
    assert not payout_plan(change).routed


def test_the_threshold_is_derived_rather_than_asserted():
    """A stated threshold is only worth stating if it cannot disagree with the
    arithmetic that produces it."""
    threshold = min_change_to_route()
    assert threshold == 646
    assert payout_plan(threshold).routed
    assert not payout_plan(threshold - 1).routed


@pytest.mark.parametrize("floor", [0, 1, 50, 100, 250, 1_000, 10_000])
@pytest.mark.parametrize("pct", [0.0, 0.005, 0.01, 0.25, 0.5, 0.9])
def test_the_threshold_is_the_smallest_change_that_routes(floor, pct):
    """Swept over both knobs, because the first version of this was right for
    the default floor and wrong for a floor of zero — it scanned `floor` steps
    up from the dust limit, which is no steps at all when the floor is 0 and
    the percentage is what holds the payout back."""
    t = min_change_to_route(fee_pct=pct, fee_floor_sats=floor)
    assert t is not None, (pct, floor)
    assert payout_plan(t, fee_pct=pct, fee_floor_sats=floor).routed, (pct, floor)
    assert not payout_plan(
        t - 1, fee_pct=pct, fee_floor_sats=floor
    ).routed, (pct, floor)


def test_a_percentage_that_can_never_leave_anything_has_no_threshold():
    """A setting that names a threshold nothing can reach should say nothing,
    so this is None rather than a number."""
    for pct in (1.0, 1.5, 10.0):
        assert min_change_to_route(fee_pct=pct) is None, pct


def test_the_zero_fee_threshold_is_just_the_dust_limit():
    assert min_change_to_route(fee_pct=0.0, fee_floor_sats=0) == DUST_SATS


# ── misconfiguration fails safe, in the only direction that is safe ─────────


@pytest.mark.parametrize(
    "kwargs",
    [
        {"fee_pct": 0.5},            # half of the change
        {"fee_pct": 1.5},            # more than the change
        {"fee_pct": -1.0},           # nonsense
        {"fee_floor_sats": 900},     # a floor above the change
        {"fee_floor_sats": -50},     # nonsense
    ],
)
def test_no_configuration_produces_a_negative_payout(kwargs):
    for change in (0, 546, 750, 5_000, 100_000):
        p = payout_plan(change, **kwargs)
        assert p.fee_sats >= 0 and p.net_sats >= 0, (change, kwargs)
        if p.routed:
            assert p.net_sats >= DUST_SATS, (change, kwargs)
            assert p.fee_sats + p.net_sats == change, (change, kwargs)


def test_a_fee_larger_than_the_change_means_no_payout_not_a_debt():
    p = payout_plan(750, fee_pct=1.5)
    assert not p.routed
    assert (p.fee_sats, p.net_sats) == (0, 0)
    assert p.gross_sats == 750


def test_a_negative_percentage_is_read_as_zero_not_as_a_rebate():
    p = payout_plan(100_000, fee_pct=-1.0, fee_floor_sats=0)
    assert p.routed and p.fee_sats == 0 and p.net_sats == 100_000


def test_the_fee_rounds_in_the_instance_s_favour():
    """0.5% of 20,050 is 100.25. A sat rounded the user's way on every payout
    is a slow leak; a sat rounded the other way is unnoticeable."""
    assert payout_plan(20_050, fee_floor_sats=0).fee_sats == 101


# ── nothing to pay out is not an error ──────────────────────────────────────


def test_a_clean_round_has_no_payout_and_says_so():
    p = payout_plan(0)
    assert not p.routed and p.reason == "no change to pay out"


def test_a_sub_dust_change_is_declined_by_name():
    """plan() already folds these into the miner fee — it iterates twice,
    because dropping one change shrinks the transaction and can lift the other
    back above dust — so one should never reach here. If one does, it is below
    the floor the instance's address may accumulate."""
    p = payout_plan(300)
    assert not p.routed
    assert "546" in p.reason


def test_every_refusal_gives_a_reason():
    """"No payout happened" is the one outcome a user will ask about, and a
    boolean cannot answer it."""
    for change in (0, 100, 546, 600, 645):
        p = payout_plan(change)
        assert not p.routed
        assert p.reason and len(p.reason) > 10, change


def test_a_routed_payout_carries_no_reason():
    assert payout_plan(5_000).reason is None


# ── mainnet only, and not as a preference ───────────────────────────────────


def test_only_mainnet_can_pay_out():
    assert payout_offered("mainnet")
    for network in ("signet", "testnet", "regtest", "", None, "MAINNET "):
        if network == "MAINNET ":
            assert payout_offered(network), "case and whitespace are not a network"
            continue
        assert not payout_offered(network), network


def test_the_network_rule_is_not_configurable():
    """A Lightning address is a mainnet endpoint and signet change is
    worthless, so routing it pays real sats for faucet coins — on repeat, by
    anyone. That is not an operator preference."""
    src = (ROOT / "helpers" / "tangopayout.py").read_text()
    body = src[src.index("def payout_offered"):]
    body = body[: body.index("\ndef ")] if "\ndef " in body else body
    assert "PAYOUT_NETWORKS" in body
    # No config argument to override it with.
    assert "def payout_offered(network: str) -> bool:" in src


def test_the_config_needs_all_three_before_it_will_route():
    """The flag, an address, and a network that can. Read from source: the
    model imports LNbits, and the point is the conjunction."""
    src = (ROOT / "models.py").read_text()
    body = src[src.index("def tango_payout_ready"):]
    body = body[: body.index("\n    def ")]
    assert "tango_change_payout_enabled" in body
    assert "tango_change_sp_address" in body
    assert "payout_offered(network)" in body


def test_the_feature_is_off_by_default():
    """It takes a coin out of someone's wallet. It does not start working
    because a version was deployed."""
    src = (ROOT / "models.py").read_text()
    assert "tango_change_payout_enabled: bool = False" in src
    assert 'tango_change_sp_address: str = ""' in src
    assert "tango_change_fee_pct: float = 0.005" in src
    assert "tango_change_fee_floor_sats: int = 100" in src
    # A one-confirmation payout can be reversed by a reorg and a Lightning
    # payment cannot be clawed back.
    assert "tango_change_min_confirmations: int = 3" in src
