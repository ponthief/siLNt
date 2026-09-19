"""Can the builder be talked into creating, or paying for, a dust output?

Reported from the mobile app: a 561-sat coin was selected — an amount the
wallet's own dust_check would flag as a suspected dust attack if it arrived —
and the Send screen went through to Confirm.

It should not have, and the reason is arithmetic rather than UI. One input and
two P2TR outputs is 154 vB, so at 1 sat/vB a 561-sat coin has 407 sats left
after the fee. That is below every dust floor in the codebase. There is no
amount that coin can send, so nothing should have been buildable at all.

(154, not the 129 this said originally: the fee formula priced P2TR outputs as
if they were P2WPKH until helpers/txsize.py. The conclusion only got stronger —
the coin has less left, not more.)

Worse, the builder did not merely allow it. `0 < change < DUST → fee += change`
had no counterpart on the recipient side, so asking to send 1 sat produced a
valid signed transaction paying 1 sat to the recipient and 560 sats to the
miner. These tests pin both ends shut.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name


def _load_real_wallet():
    """Load helpers/wallet.py for real.

    conftest registers a *stub* at siLNt.helpers.wallet, because scan.py only
    needs two functions from it and the real module pulls in LNbits. These tests
    are about the real module, so it is loaded here under its own name — leaving
    the stub in place for everything else — with the one host-application import
    it makes filled in.
    """
    name = f"{PKG}.helpers._wallet_under_test"
    if name in sys.modules:
        return sys.modules[name]
    for mod in ("lnbits", "lnbits.utils", "lnbits.utils.crypto"):
        sys.modules.setdefault(mod, types.ModuleType(mod))
    if not hasattr(sys.modules["lnbits.utils.crypto"], "AESCipher"):
        sys.modules["lnbits.utils.crypto"].AESCipher = object
    spec = importlib.util.spec_from_file_location(name, ROOT / "helpers" / "wallet.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_txsize():
    """helpers/txsize.py — no LNbits imports, so it loads straight."""
    spec = importlib.util.spec_from_file_location(
        f"{PKG}.helpers._txsize_under_test", ROOT / "helpers" / "txsize.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


wallet = _load_real_wallet()
DUST = wallet.DUST_SATS

# The coin from the report, and the fee the builder charges to spend it at the
# cheapest rate anyone would ever set. Derived rather than written down: it was
# 129 until the fee formula was corrected — the old one priced P2TR outputs as
# if they were P2WPKH — and a hardcoded figure just goes stale again.
REPORTED_COIN = 561
_txsize = _load_txsize()
FEE_AT_1 = _txsize.fee_for(
    _txsize.estimate_vsize(1, [_txsize.TAPROOT_OUTPUT_VBYTES] * 2), 1
)


def _amounts(total, amount, fee_rate=1):
    return wallet._compute_amounts([{"amount": total}], amount, fee_rate)


# ── the recipient end ────────────────────────────────────────────────────────

@pytest.mark.parametrize("amount", [1, 100, 330, 545])
def test_a_dust_payment_is_refused(amount):
    """330 is Bitcoin Core's P2TR relay floor; this wallet stops higher, at 546."""
    with pytest.raises(ValueError, match="dust limit"):
        _amounts(1_000_000, amount)


def test_the_reported_coin_cannot_fund_anything():
    """Every amount, not just the one that was tried.

    Below the floor it is refused as dust; at or above it there is not enough
    left after the fee. The gap is empty, which is the whole point: the Send
    screen had no business offering Confirm for this coin.
    """
    for amount in (1, 100, 432, DUST, DUST + 1, REPORTED_COIN):
        with pytest.raises(ValueError):
            _amounts(REPORTED_COIN, amount)


def test_the_refusal_says_what_the_coins_can_actually_send():
    """A number to act on, not just a rejection.

    When even the maximum is dust the message has to say so, rather than quote a
    ceiling that would itself be refused on the next attempt.
    """
    with pytest.raises(ValueError) as e:
        _amounts(REPORTED_COIN, DUST)
    msg = str(e.value)
    assert str(REPORTED_COIN - FEE_AT_1) in msg, msg
    assert "cannot fund any payment" in msg, msg

    # With a coin that CAN pay, the maximum quoted must be reachable.
    with pytest.raises(ValueError) as e:
        _amounts(10_000, 50_000)
    msg = str(e.value)
    assert "most these coins can send is" in msg, msg
    max_send = int(msg.split("most these coins can send is")[1].split()[0])
    total, fee, change, _ = _amounts(10_000, max_send)
    assert change == 0 and total - max_send == fee, (
        f"the quoted maximum {max_send} did not build"
    )


# ── the change end, and the fee it can silently inflate ─────────────────────

def test_dust_change_is_still_absorbed_into_the_fee():
    """Unchanged behaviour: an uneconomic change output is given to the miner."""
    total, fee, change, _ = _amounts(1_000, DUST)
    assert change == 0
    assert fee == 1_000 - DUST, "absorbed change must be exactly the remainder"


def test_absorption_can_no_longer_eat_a_whole_coin():
    """The money-loss case from the report, stated as a bound.

    Absorption is bounded by DUST-1 on top of the nominal fee, and it can only
    happen once the recipient is already getting at least DUST. Before the fix
    the recipient could get 1 sat while the miner got 560.
    """
    for total in range(DUST, DUST + 900, 37):
        for amount in (DUST, DUST + 50):
            try:
                _t, fee, _c, vsize = _amounts(total, amount)
            except ValueError:
                continue
            # The bound is against what the transaction was PRICED at — two
            # outputs — not the vsize returned, which after absorption
            # describes the one-output transaction actually built.
            nominal = _txsize.fee_for(
                _txsize.estimate_vsize(1, [_txsize.TAPROOT_OUTPUT_VBYTES] * 2), 1
            )
            assert fee - nominal < DUST, (
                f"total={total} amount={amount}: fee {fee} exceeds the nominal "
                f"{nominal} by {fee - nominal}, more than one dust output"
            )
            assert amount >= DUST


# ── ordinary sends must be untouched ─────────────────────────────────────────

@pytest.mark.parametrize(
    "total,amount,rate", [(100_000, 50_000, 1), (100_000, DUST, 1), (5_000_000, 1_000_000, 12)]
)
def test_normal_sends_still_build(total, amount, rate):
    import math

    t, fee, change, vsize = _amounts(total, amount, rate)
    assert t == total
    assert fee == max(1, math.ceil(vsize * rate)), "the fee stopped following the rate"
    assert change >= DUST, "a dust change output was created"
    assert amount + fee + change == total, "sats went missing"


def test_the_floor_matches_the_rest_of_the_codebase():
    """plain.py, payjoin_merge.py and this module must not drift apart.

    Three different spend paths with three different dust floors would mean a
    coin the wallet refuses to spend one way and happily burns another.
    """
    plain = (ROOT / "helpers" / "plain.py").read_text()
    assert f"DUST_SATS = {DUST}" in plain, "plain.py's dust floor no longer matches"
    merge = (ROOT / "helpers" / "payjoin_merge.py").read_text()
    assert f"DUST = {DUST}" in merge, "payjoin_merge.py's dust floor no longer matches"
