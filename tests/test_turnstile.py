"""The bot check in front of account creation, and the three ways it could be
worse than nothing.

WHAT IT IS FOR. `start_registration` is the only public endpoint that creates
state on behalf of someone who has no account: it hashes a password, writes a
pending row and sends an email, and it answers "Username or email already in
use", which is a membership oracle for any address somebody cares to type. The
form carried a maths question that was checked in the browser and nowhere
else, so none of that was guarded against anything that skipped the page.

THE THREE FAILURES PINNED HERE, each of which looks like working code:

  * FAILING OPEN. A verifier that cannot be reached, treated as a pass, is a
    gate whose key is published — knock the verifier over, or sit on a slow
    path, and the check evaporates exactly when somebody is leaning on it.

  * A SITE KEY WITH NO SECRET. The widget renders, the user solves it, and
    nothing on the server ever asks whether the answer was right. The form
    looks protected. `turnstile_enabled` keys off the SECRET for this reason,
    and signup-config withholds the site key until one exists.

  * LOCKING OUT THE PHONE. The mobile app posts at the same endpoint with no
    widget and no token. Requiring one from every caller would close the only
    onboarding route mainnet has, which is a worse outage than the abuse it
    prevents.

Driven through httpx's MockTransport rather than a live Cloudflare: the point
is what this code does with each ANSWER, and a test that needs the network to
tell it that is a test that will be skipped.
"""

from __future__ import annotations

import importlib.util
import pathlib

import httpx
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "helpers" / f"{name}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


T = _load("turnstile")
TERMS = _load("terms")


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _ok(_request):
    return httpx.Response(200, json={"success": True})


def _refused(*codes):
    def handler(_request):
        return httpx.Response(200, json={"success": False, "error-codes": list(codes)})

    return handler


# ── configured, or not ───────────────────────────────────────────────────────

def test_the_secret_is_what_turns_it_on_not_the_site_key():
    """A site key alone must never read as enabled. That combination renders a
    widget nothing verifies, which is the failure that looks most like
    success."""
    assert T.turnstile_enabled("secret") is True
    assert T.turnstile_enabled("") is False
    assert T.turnstile_enabled("   ") is False
    assert T.turnstile_enabled(None) is False


@pytest.mark.asyncio
async def test_an_unconfigured_instance_is_not_a_silent_pass():
    """'Not configured' and 'failed' are opposite outcomes. This module
    refuses to collapse them — the CALLER decides what an instance with no
    keys does, and it decides to skip the check entirely. Returning True here
    would move that decision somewhere nobody would look for it."""
    ok, reason = await T.verify_turnstile("tok", "")
    assert ok is False
    assert "not configured" in reason.lower()


# ── the answers Cloudflare gives ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_good_solve_passes_with_no_reason_text():
    async with _client(_ok) as c:
        ok, reason = await T.verify_turnstile("tok", "secret", client=c)
    assert ok is True
    assert reason == ""


@pytest.mark.asyncio
async def test_a_reused_token_says_so_in_words_somebody_can_act_on():
    """`timeout-or-duplicate` is the single most common real failure — the
    user sat on the form, or the client retried with a spent token — and the
    answer is 'solve it again', which the raw code does not say."""
    async with _client(_refused("timeout-or-duplicate")) as c:
        ok, reason = await T.verify_turnstile("tok", "secret", client=c)
    assert ok is False
    assert "again" in reason.lower()


@pytest.mark.asyncio
async def test_a_bad_secret_points_at_the_secret_and_not_the_site_key():
    """The two keys look alike and are pasted into adjacent fields. A message
    naming the wrong one has cost more than one operator an afternoon."""
    async with _client(_refused("invalid-input-secret")) as c:
        ok, reason = await T.verify_turnstile("tok", "secret", client=c)
    assert ok is False
    assert "SECRET" in reason


@pytest.mark.asyncio
async def test_an_unknown_error_code_still_reaches_the_caller():
    """Cloudflare may add codes. An unrecognised one is passed through rather
    than swallowed into a generic failure — the code is what their
    documentation is indexed by."""
    async with _client(_refused("some-future-code")) as c:
        _ok_, reason = await T.verify_turnstile("tok", "secret", client=c)
    assert "some-future-code" in reason


@pytest.mark.asyncio
async def test_success_false_with_no_codes_is_still_a_failure():
    """A malformed answer is not a pass. Nothing requires Cloudflare to
    populate error-codes, and `success: false` is the field that decides."""
    async with _client(lambda _r: httpx.Response(200, json={"success": False})) as c:
        ok, _reason = await T.verify_turnstile("tok", "secret", client=c)
    assert ok is False


@pytest.mark.asyncio
async def test_a_missing_success_field_is_not_a_pass():
    """`body.get("success") is True` rather than a truthiness test, so an
    answer that omits the field — a captive portal, an error page served as
    JSON — cannot be read as a solve."""
    async with _client(lambda _r: httpx.Response(200, json={})) as c:
        ok, _reason = await T.verify_turnstile("tok", "secret", client=c)
    assert ok is False


# ── failing closed ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_an_unreachable_cloudflare_refuses_rather_than_waves_through():
    """THE one that matters. A verifier that cannot be reached must not be a
    pass; see the module docstring. The cost — no signups while
    challenges.cloudflare.com is down — is the deliberate side of this trade
    and is written down at the call site."""

    def explode(_request):
        raise httpx.ConnectError("no route to host")

    async with _client(explode) as c:
        ok, reason = await T.verify_turnstile("tok", "secret", client=c)
    assert ok is False
    assert "refused" in reason.lower()


@pytest.mark.asyncio
async def test_a_non_2xx_answer_is_a_failure_not_an_exception():
    """A 500 from Cloudflare has to come back as a verdict the endpoint can
    turn into a 400, not as an unhandled error that becomes a 500 of our own
    and tells the user nothing."""
    async with _client(lambda _r: httpx.Response(503, text="unavailable")) as c:
        ok, reason = await T.verify_turnstile("tok", "secret", client=c)
    assert ok is False
    assert "503" in reason


@pytest.mark.asyncio
async def test_a_redirect_is_refused_rather_than_followed():
    """This POST carries the secret. The only correct destination is the one
    in VERIFY_URL, so a 3xx is a sign something is intercepting the call — not
    an instruction to go and hand the secret somewhere else."""
    async with _client(
        lambda _r: httpx.Response(302, headers={"location": "https://example.invalid/"})
    ) as c:
        ok, _reason = await T.verify_turnstile("tok", "secret", client=c)
    assert ok is False


# ── what never leaves the process ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_failure_message_contains_the_secret():
    """Every one of these strings is rendered into an HTTP 400 the user sees.
    A secret in a failure message is a secret in a screenshot."""
    secret = "0xTOPSECRETVALUE"

    def explode(_request):
        raise httpx.ConnectError("boom")

    cases = [_refused("invalid-input-secret"), explode,
             lambda _r: httpx.Response(500, text=secret)]
    for handler in cases:
        async with _client(handler) as c:
            _ok_, reason = await T.verify_turnstile("tok", secret, client=c)
        assert secret not in reason


@pytest.mark.asyncio
async def test_an_empty_token_costs_no_round_trip():
    """The common bot case — a POST with no token at all — must not become the
    slow path. Cloudflare would answer missing-input-response; spending a
    network call to be told what we can already see hands an attacker a way to
    make every one of our requests wait on somebody else's server."""
    calls = []

    def count(request):
        calls.append(request)
        return _ok(request)

    async with _client(count) as c:
        ok, reason = await T.verify_turnstile("   ", "secret", client=c)
    assert ok is False
    assert calls == []
    assert "no Turnstile token" in reason


@pytest.mark.asyncio
async def test_the_client_ip_is_sent_when_known_and_omitted_when_not():
    """remoteip tightens the binding between a solve and the connection
    presenting it. Sending an empty one instead of omitting the field is the
    kind of thing that works until Cloudflare starts validating it."""
    seen = {}

    def capture(request):
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"success": True})

    async with _client(capture) as c:
        await T.verify_turnstile("tok", "secret", "203.0.113.9", client=c)
    assert "remoteip=203.0.113.9" in seen["body"]

    async with _client(capture) as c:
        await T.verify_turnstile("tok", "secret", None, client=c)
    assert "remoteip" not in seen["body"]


def test_the_endpoint_is_cloudflares_and_is_https():
    """Pinned so a copy-paste from a blog post cannot quietly point the
    secret at somebody else's host."""
    assert T.VERIFY_URL == (
        "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    )


# ── the terms version ────────────────────────────────────────────────────────

def test_only_the_current_terms_version_is_accepted():
    """An older version means a stale bundle showing text that is no longer
    the offer. Accepting it would record agreement to terms this instance has
    stopped publishing, which is the one thing the number exists to prevent."""
    assert TERMS.terms_version_ok(TERMS.TERMS_VERSION) is True
    assert TERMS.terms_version_ok(TERMS.TERMS_VERSION - 1) is False
    assert TERMS.terms_version_ok(TERMS.TERMS_VERSION + 1) is False


def test_a_junk_terms_version_is_refused_rather_than_raising():
    """It arrives over the wire from anybody. None is handled by the caller —
    it means 'did not claim' — and everything else here must come back False
    instead of a 500."""
    for bad in ("", "one", [], {}, object()):
        assert TERMS.terms_version_ok(bad) is False


def test_a_numeric_string_version_is_accepted():
    """JSON from a hand-rolled client may send it as a string. The value is
    the claim; its JSON type is not what the check is about."""
    assert TERMS.terms_version_ok(str(TERMS.TERMS_VERSION)) is True
