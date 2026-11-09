"""The per-wallet scan cooldown, and why sixty seconds were never sixty seconds.

Reported 2026-11-09, from the web app: *"as I was scanning in web, there was no
rate limit so I was able to press check for payments repeatedly. scans took
longer than 1 minute so maybe you set timer at the start, not the end."*

That is exactly what it was. `check_scan_allowed` stamps `_last_scan_time` at
the moment a scan is ALLOWED, so the window ran alongside the scan rather than
after it. Any scan longer than `WALLET_COOLDOWN_SECONDS` — which on mainnet is
most of them — left the cooldown already expired at the instant it finished,
and the next press went straight through. The limit existed, was correct, and
was unreachable for the case it was written for.

`mark_scan_finished` re-stamps it now, so the minute starts when the scan ends.
Both stamps are kept on purpose: the START one is what a second press DURING a
short scan hits, the FINISH one is what the next press after a long one hits.
`_active_scans` bounds how many run at once and says nothing about rate.

The tests drive time rather than sleeping through it — a minute per assertion
is not a test suite anyone runs.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    name = "silnt_scan_cooldown_under_test"
    if name in sys.modules:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "helpers" / "scan_rate_limiter.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def rl():
    """A fresh module per test: the counters are process-global by design."""
    return _load()


def _clock(rl, monkeypatch):
    """A time source the test moves by hand."""
    state = {"t": 1_000_000.0}
    monkeypatch.setattr(rl.time, "time", lambda: state["t"])
    return state


def _allow(rl, blocks=50):
    rl.check_scan_allowed("u1", "w1", "10.0.0.1", blocks)


def _refused(rl, blocks=50):
    from http import HTTPStatus

    with pytest.raises(Exception) as got:
        rl.check_scan_allowed("u1", "w1", "10.0.0.1", blocks)
    assert getattr(got.value, "status_code", None) == HTTPStatus.TOO_MANY_REQUESTS
    return got.value


def test_the_cooldown_is_a_minute(rl):
    assert rl.WALLET_COOLDOWN_SECONDS == 60


def test_a_long_scan_still_leaves_a_full_minute_after_it(rl, monkeypatch):
    """THE REPORTED BUG. A scan that runs for five minutes used to exhaust its
    own cooldown while it worked, so the press straight after it was allowed."""
    clock = _clock(rl, monkeypatch)
    _allow(rl)
    clock["t"] += 300                      # a five-minute scan
    rl.mark_scan_finished("u1", "w1", actual_blocks=50, estimated_blocks=50)

    _refused(rl)                           # pressed the moment it finished
    clock["t"] += 59
    _refused(rl)                           # and nearly a minute later
    clock["t"] += 2
    _allow(rl)                             # a minute after it ENDED


def test_pressing_during_a_short_scan_is_still_refused(rl, monkeypatch):
    """The start stamp has not gone. A scan in flight is inside its own window,
    and that is what a second press hits while the first is still running."""
    clock = _clock(rl, monkeypatch)
    _allow(rl)
    clock["t"] += 5
    _refused(rl)


def test_an_explicit_stop_still_clears_it(rl, monkeypatch):
    """Unchanged, and the reason the re-stamp is in the else branch: somebody
    who stopped a scan to fix the range retries immediately. The block budget
    is the real oracle-load guard there."""
    clock = _clock(rl, monkeypatch)
    _allow(rl)
    clock["t"] += 10
    rl.mark_scan_finished(
        "u1", "w1", actual_blocks=5, estimated_blocks=50, reset_wallet_cooldown=True
    )
    _allow(rl)


def test_the_finish_stamp_does_not_cost_the_budget_refund(rl, monkeypatch):
    """The two things mark_scan_finished does are independent. A scan that read
    5 of an estimated 50 blocks is still refunded 45, and re-stamping the
    cooldown must not disturb that."""
    clock = _clock(rl, monkeypatch)
    _allow(rl, blocks=50)
    clock["t"] += 120
    rl.mark_scan_finished("u1", "w1", actual_blocks=5, estimated_blocks=50)
    consumed = sum(count for _ts, count in rl._user_blocks_log["u1"])
    assert consumed == 5


def test_the_slot_is_released_either_way(rl, monkeypatch):
    """A finished scan frees its concurrency slot whether or not the cooldown
    was reset — the re-stamp sits after that, not instead of it."""
    clock = _clock(rl, monkeypatch)
    _allow(rl)
    assert "w1" in rl._active_scans["u1"]
    clock["t"] += 120
    rl.mark_scan_finished("u1", "w1")
    assert "w1" not in rl._active_scans["u1"]
