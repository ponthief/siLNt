"""`/api/v1/auth/register-start`, and the lock it did not have.

Ten LNbits accounts were created on a live instance on 2026-11-04, with no
email address and some with random-character usernames. They did NOT come
through this endpoint — `pending_registrations` has `email` as its PRIMARY KEY
and `confirm_registration` always sets one on the Account, so this path cannot
produce an email-less account — but the incident is what made the missing
limiter worth closing: this is the next public door along, and it was the one
that sends mail.

Why mail is the thing to protect. One unauthenticated call costs a bcrypt
hash, two account lookups and a pending-row write, all of which are local. The
email goes to an address the caller chooses, through the shared SMTP server,
and what pays for a flood is the instance's sending reputation.

Why Turnstile was not already enough, which is not a criticism of it:
`enforce` defaults to "browser", so a missing token is fatal only for a
request carrying an `Origin` header — set by the client, omitted by a script.
That is the shape of the control and was decided deliberately, because
RegisterScreen.tsx renders no widget and mainnet onboarding is mobile-app
only. It means Turnstile bounds the browser case and nothing bounded the rest.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from http import HTTPStatus

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    """helpers/register_rate_limiter.py on its own.

    It imports only time, collections, http, fastapi and loguru at module
    scope — no relative imports — which is what lets it be loaded this way.
    Keep it that way: a limiter that can only be exercised through a running
    LNbits is one nobody exercises.
    """
    name = "silnt_register_limiter_under_test"
    if name in sys.modules:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "helpers" / "register_rate_limiter.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def rl():
    """A fresh module per test: the counters are process-global by design."""
    return _load()


def _refused(fn, *a):
    with pytest.raises(Exception) as e:
        fn(*a)
    assert getattr(e.value, "status_code", None) == HTTPStatus.TOO_MANY_REQUESTS
    return getattr(e.value, "detail", "")


# ── the limits themselves ────────────────────────────────────────────────────

def test_one_person_registering_once_is_nowhere_near_any_limit(rl):
    rl.check_registration_allowed("1.2.3.4", "someone@example.com")


def test_a_typo_and_a_retry_are_fine(rl):
    """Mistype the username, find it taken, try again. A refused attempt still
    counts — it has to, or a caller grinding taken usernames would never be
    seen — so the limit has to leave room for an honest handful."""
    for _ in range(4):
        rl.check_registration_allowed("1.2.3.4", "someone@example.com")


def test_a_script_from_one_address_is_stopped(rl):
    for i in range(rl.MAX_STARTS_PER_IP_HOUR):
        rl.check_registration_allowed("9.9.9.9", f"bot{i}@example.com")
    _refused(rl.check_registration_allowed, "9.9.9.9", "bot-again@example.com")


def test_one_address_cannot_spend_another_s_allowance(rl):
    for i in range(rl.MAX_STARTS_PER_IP_HOUR):
        rl.check_registration_allowed("9.9.9.9", f"bot{i}@example.com")
    rl.check_registration_allowed("1.2.3.4", "someone@example.com")


def test_the_same_inbox_cannot_be_mail_bombed_from_many_addresses(rl):
    """THE POINT OF LIMIT 2. The per-IP cap is useless against a caller with a
    pool of addresses, and the victim here is a third party whose inbox fills
    up. Keyed on the address, so rotating the source does not help."""
    rl.check_registration_allowed("1.1.1.1", "victim@example.com")
    rl.record_registration_email("victim@example.com")
    _refused(rl.check_registration_allowed, "2.2.2.2", "victim@example.com")
    _refused(rl.check_registration_allowed, "3.3.3.3", "VICTIM@example.com")


def test_the_email_cooldown_is_case_and_space_insensitive(rl):
    rl.record_registration_email("  Victim@Example.com ")
    _refused(rl.check_registration_allowed, "2.2.2.2", "victim@example.com")


def test_a_different_address_is_unaffected(rl):
    rl.record_registration_email("victim@example.com")
    rl.check_registration_allowed("2.2.2.2", "someone-else@example.com")


def test_the_global_backstop_holds_when_every_ip_is_different(rl):
    """THE POINT OF LIMIT 3. get_client_ip trusts X-Forwarded-For, which the
    client sets. If LNbits is ever reachable without going through Caddy, a
    fresh header value per request defeats the per-IP limit completely — so
    there has to be a number no header can move.

    A limiter that one header defeats is the maths question all over again:
    checked somewhere that does not matter.
    """
    for i in range(rl.MAX_STARTS_GLOBAL_HOUR):
        rl.check_registration_allowed(f"10.0.{i // 256}.{i % 256}", f"a{i}@example.com")
    _refused(rl.check_registration_allowed, "10.9.9.9", "one-more@example.com")


def test_the_global_backstop_is_far_above_honest_traffic(rl):
    """It is a way to close signups — burn the budget and nobody can register
    until the window slides, which on mainnet is an outage, since onboarding
    is mobile-app only. That is the trade, and it only holds while the number
    is far above any real signup rate. If this instance ever grows past it,
    raise it; do not remove it."""
    assert rl.MAX_STARTS_GLOBAL_HOUR >= 20 * rl.MAX_STARTS_PER_IP_HOUR


# ── what a refusal is allowed to say ─────────────────────────────────────────

def test_every_limit_gives_the_same_message(rl):
    """Limit 2 keys on an address the CALLER DOES NOT OWN. A distinguishable
    refusal would answer "did somebody start registering this address in the
    last minute?", and this endpoint's whole security story is about not
    answering questions like that — turnstile.py: "the validation IS the
    leak". The operator gets which-limit in the log instead."""
    per_email = None
    per_ip = None

    rl.record_registration_email("victim@example.com")
    per_email = _refused(rl.check_registration_allowed, "1.1.1.1", "victim@example.com")

    fresh = _load()
    for i in range(fresh.MAX_STARTS_PER_IP_HOUR):
        fresh.check_registration_allowed("9.9.9.9", f"bot{i}@example.com")
    per_ip = _refused(fresh.check_registration_allowed, "9.9.9.9", "x@example.com")

    assert per_email == per_ip, (per_email, per_ip)


def test_the_refusal_names_nothing(rl):
    rl.record_registration_email("victim@example.com")
    detail = _refused(rl.check_registration_allowed, "1.1.1.1", "victim@example.com")
    for leak in ["victim", "example.com", "1.1.1.1", "account", "exists", "in use"]:
        assert leak not in detail.lower(), detail


# ── the counters themselves ──────────────────────────────────────────────────

def test_a_refused_attempt_does_not_also_spend_budget(rl):
    """The refusal already cost the caller the attempt. Recording it again
    would mean one blocked address could drain the global budget and close
    signups for everybody — turning limit 1 into a weapon against limit 3."""
    for i in range(rl.MAX_STARTS_PER_IP_HOUR):
        rl.check_registration_allowed("9.9.9.9", f"bot{i}@example.com")
    before = len(rl._global_log)
    for _ in range(50):
        _refused(rl.check_registration_allowed, "9.9.9.9", "more@example.com")
    assert len(rl._global_log) == before


def test_the_window_slides(rl):
    for i in range(rl.MAX_STARTS_PER_IP_HOUR):
        rl.check_registration_allowed("9.9.9.9", f"bot{i}@example.com")
    _refused(rl.check_registration_allowed, "9.9.9.9", "x@example.com")
    # Age every entry past the hour rather than sleeping through one.
    rl._ip_log["9.9.9.9"] = [t - 3601 for t in rl._ip_log["9.9.9.9"]]
    rl._global_log = [t - 3601 for t in rl._global_log]
    rl.check_registration_allowed("9.9.9.9", "x@example.com")


def test_an_email_that_never_went_out_does_not_lock_its_own_address(rl):
    """record_registration_email is called after the send, not before. A
    verification email nobody received must not refuse the retry that would
    actually deliver one."""
    rl.check_registration_allowed("1.1.1.1", "someone@example.com")
    # No record_registration_email — the send raised.
    rl.check_registration_allowed("1.1.1.1", "someone@example.com")


def test_a_missing_ip_is_still_a_bucket(rl):
    """get_client_ip returns "" when there is no client and no header. That
    must not be a free pass — it shares one bucket, which is the safe way to
    be wrong."""
    for i in range(rl.MAX_STARTS_PER_IP_HOUR):
        rl.check_registration_allowed("", f"bot{i}@example.com")
    _refused(rl.check_registration_allowed, "", "x@example.com")


# ── the wiring, which is where a limiter usually goes wrong ──────────────────

EV = (ROOT / "helpers" / "email_verification.py").read_text()
START = EV[EV.index("async def start_registration") : EV.index("async def complete_registration")]


def test_start_registration_checks_the_limit():
    assert "check_registration_allowed(" in START, START[:400]


def test_it_is_checked_before_turnstile_and_before_the_lookups():
    """Turnstile is a call to somebody else's service and the uniqueness
    lookup is the membership oracle. A local counter is cheaper than both and
    is what a flood should hit — and placed after them, it would be protecting
    the cheap part while leaving the expensive and the interesting parts
    open."""
    at_limit = START.index("check_registration_allowed(")
    assert at_limit < START.index("_require_turnstile("), START[:600]
    assert at_limit < START.index("get_account_by_username_or_email(")
    assert at_limit < START.index("_hash_password(")


def test_the_ip_comes_from_the_proxy_aware_helper():
    """Behind Caddy, request.client.host is Caddy. A per-IP limit built on it
    would be a per-INSTANCE limit, which would lock every user out at ten
    signups an hour while stopping no attacker at all."""
    assert "get_client_ip(request)" in START, START[:600]


def test_the_cooldown_is_stamped_only_after_the_send():
    """Stamping it at the top would mean a failed send locks the address out
    of the retry that would have worked."""
    assert "record_registration_email(" in START
    assert START.index("Verification email sent to") > START.index(
        "record_registration_email("
    ), "the stamp belongs next to the success log, after the send"
    assert START.index("record_registration_email(") > START.index(
        "send_email_notification("
    )
