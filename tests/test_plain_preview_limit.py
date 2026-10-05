"""The SegWit address preview, and the one read that had no limit at all.

`GET /api/v1/plain/{wallet_id}` is how a client finds out which of its BIP-84
addresses have been used and what is unspent on them. Every call opens a
connection to the chain index and runs a lookup per address, and nothing capped
it: not a cooldown, not a per-user budget, nothing.

It surfaced from the other end on 2026-10-05, as a question about the Refresh
button on the phone's card — a button a user waiting on a payment can hold
down. The button came off, for a different reason (three buttons in a row at
phone width is three cramped stubs), and REMOVING A BUTTON IS NOT THE FIX.
Anyone can call the endpoint directly; a client is not where a server's limits
live. This is.

Legitimate traffic is small and known: the card walks on mount, the foreground
watcher polls every five minutes, the wallet screen's pull-to-refresh, and once
after a send. Thirty a minute is far above all of that together.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    """helpers/scan_rate_limiter.py, with the FastAPI bits it needs stubbed.

    It imports HTTPException and Request from fastapi at module scope. Only the
    exception is used here, and a real one is not needed to see that a limit
    fired — what matters is that it raises, with 429.
    """
    name = "silnt_rate_limiter_under_test"
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


def test_the_limit_exists_and_is_a_minute(rl):
    assert rl.MAX_PLAIN_PREVIEWS_PER_USER_MIN == 30


def test_ordinary_use_is_nowhere_near_it(rl):
    """Mount, a five-minute poll, a pull-to-refresh and a post-send check. Four
    calls where the limit is thirty — if this ever starts failing, the limit is
    wrong and not the caller."""
    for _ in range(4):
        rl.check_plain_preview_allowed("u1")


def test_holding_it_down_is_refused(rl):
    from http import HTTPStatus

    for _ in range(rl.MAX_PLAIN_PREVIEWS_PER_USER_MIN):
        rl.check_plain_preview_allowed("u1")
    with pytest.raises(Exception) as e:
        rl.check_plain_preview_allowed("u1")
    assert getattr(e.value, "status_code", None) == HTTPStatus.TOO_MANY_REQUESTS


def test_the_refusal_says_what_to_do(rl):
    for _ in range(rl.MAX_PLAIN_PREVIEWS_PER_USER_MIN):
        rl.check_plain_preview_allowed("u1")
    with pytest.raises(Exception) as e:
        rl.check_plain_preview_allowed("u1")
    detail = getattr(e.value, "detail", "")
    assert "Try again in a minute" in detail, detail
    # No address, no wallet id, no count of what anybody holds.
    assert "sat" not in detail.lower(), detail


def test_one_user_cannot_spend_another_s_allowance(rl):
    """Keyed per user. An account with a wallet on each network shares one
    allowance, which is right — the cost is the chain-index connection — but a
    stranger must not be able to exhaust it."""
    for _ in range(rl.MAX_PLAIN_PREVIEWS_PER_USER_MIN):
        rl.check_plain_preview_allowed("noisy")
    rl.check_plain_preview_allowed("quiet")


def test_the_window_slides(rl):
    """A minute later it is open again. Asserted through the prune helper
    rather than by sleeping, since the log holds bare timestamps."""
    import time

    for _ in range(rl.MAX_PLAIN_PREVIEWS_PER_USER_MIN):
        rl.check_plain_preview_allowed("u1")
    log = rl._plain_preview_log["u1"]
    assert len(log) == rl.MAX_PLAIN_PREVIEWS_PER_USER_MIN
    # Age every entry past the window; the next check should prune them all.
    rl._plain_preview_log["u1"] = [t - 61 for t in log]
    rl.check_plain_preview_allowed("u1")
    assert len(rl._plain_preview_log["u1"]) == 1


# ── the endpoint wiring ──────────────────────────────────────────────────────

API = (ROOT / "views_api.py").read_text()


def _endpoint(path: str) -> str:
    at = API.index(f'"{path}"')
    return API[at : API.index("@silnt_api_router", at + 10)]


def test_the_preview_endpoint_checks_the_limit():
    body = _endpoint("/api/v1/plain/{wallet_id}")
    assert "check_plain_preview_allowed(key_info.wallet.user)" in body, body


def test_ownership_is_checked_first():
    """Or a stranger's refused request would still spend the owner's
    allowance — a way to lock somebody out of their own balance."""
    body = _endpoint("/api/v1/plain/{wallet_id}")
    assert body.index("_plain_wallet_or_403(") < body.index(
        "check_plain_preview_allowed("
    ), body
