"""Cloudflare Turnstile, in front of the one endpoint that creates accounts.

WHAT IT REPLACES, AND WHY THAT MATTERED. The register form carried a maths
question — `a + b = ?` — and it was checked in `RegisterView.vue` and NOWHERE
ELSE. A client that never loads the page never sees it: POST straight at
`/api/v1/auth/register-start` and nothing asks for an answer. It stopped
nobody who had opened a network tab, which is everybody writing a bot. The
question stays as a fallback for an instance with no Turnstile keys, where a
visible speed bump beats nothing, but it has never been the control and is not
one now.

WHERE THE CHECK GOES: FIRST, before the username and email are looked up.
Two reasons, and the second is the one that is easy to miss.

  * An unverified request costs a bcrypt hash and two database reads. Those
    are the expensive parts of the endpoint, and a gate placed after them
    protects nothing worth protecting.

  * `start_registration` answers "Username or email already in use", which is
    a membership oracle for any address somebody cares to type. Turnstile in
    front of it means a bot cannot ask the question at all. This is the reason
    not to "just validate the cheap fields first" — the validation IS the
    leak.

FAIL CLOSED. A secret configured and Cloudflare unreachable refuses the
registration; it does not wave it through. Fail-open is the tempting choice —
nobody wants signup to depend on somebody else's uptime — but a gate that
opens when its verifier is unreachable is a gate whose key is published. Knock
the verifier over, or merely sit on a network path where it times out, and the
protection is gone at exactly the moment somebody is pushing on it. The cost
is honest and worth stating: if `challenges.cloudflare.com` is down, nobody
can sign up on this instance until it is back or the operator clears the
secret.

UNSET IS NOT CONFIGURED. An instance that has never set a secret runs the way
it always did — the maths question stands and this module declines to have an
opinion. That is a deliberate "no protection here" rather than an outage, the
same call `payout_address_pin` makes about its environment variable, and for
the same reason: failing closed on a value nobody has configured turns a
security improvement into a broken deployment on upgrade.

A TOKEN IS SINGLE USE. Cloudflare refuses the second presentation of one with
`timeout-or-duplicate`, so `verify_turnstile` is called exactly once per
registration and a failure is never retried with the same token. The widget on
the client resets itself instead, which is the only thing that produces a
fresh one.

NO PROJECT IMPORTS. This talks to one HTTP endpoint and returns a verdict;
keeping it free of siLNt's models and database is what lets the tests drive it
with a fake transport instead of a live Cloudflare.
"""

from __future__ import annotations

from typing import Iterable, Optional, Tuple

import httpx

# Cloudflare's siteverify endpoint. Documented, stable, and the only network
# call this module makes.
VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# Ten seconds. Long enough for a slow path to Cloudflare, short enough that a
# black hole does not hold a registration request open until the client gives
# up and retries — which, with a single-use token, would fail for a reason
# that has nothing to do with the user.
VERIFY_TIMEOUT_SECONDS = 10.0

# Cloudflare's published test keys. An operator wiring this up for the first
# time wants to see the widget render and the round trip succeed before
# creating real keys, and the admin page offers these by name. They are not
# secret — they are in Cloudflare's own documentation — and they ALWAYS pass,
# which is why the admin page says so beside them rather than leaving somebody
# to conclude their bot protection works.
TEST_SITE_KEY_ALWAYS_PASSES = "1x00000000000000000000AA"
TEST_SECRET_ALWAYS_PASSES = "1x0000000000000000000000000000000AA"

# What each documented error code means in a sentence somebody can act on.
# The raw codes are kept too — they are what Cloudflare's own documentation is
# indexed by — but a log line reading "invalid-input-secret" has sent more than
# one operator looking at their site key.
_CODE_REASONS = {
    "missing-input-secret": "the server was not given a Turnstile secret key",
    "invalid-input-secret": (
        "Cloudflare rejected this instance's Turnstile SECRET key — check the "
        "secret, not the site key"
    ),
    "missing-input-response": "no Turnstile token was submitted with the form",
    "invalid-input-response": "the Turnstile token was not valid for this site",
    "timeout-or-duplicate": (
        "the Turnstile token had already been used or had expired — solve the "
        "challenge again"
    ),
    "bad-request": "Cloudflare rejected the verification request as malformed",
    "internal-error": "Cloudflare had an internal error verifying the token",
}


def turnstile_enabled(secret: str) -> bool:
    """Whether this instance has Turnstile configured at all.

    The secret is what decides, never the site key. A site key alone renders a
    widget whose answer nothing checks, which is worse than no widget: it looks
    like protection. The signup-config endpoint therefore publishes the site
    key only when a secret is also set.
    """
    return bool((secret or "").strip())


def describe_codes(codes: Iterable[str]) -> str:
    """Turn Cloudflare's error-code list into one readable sentence."""
    seen = [c for c in (codes or []) if c]
    if not seen:
        return "Turnstile verification failed"
    parts = [_CODE_REASONS.get(c, c) for c in seen]
    return "Turnstile verification failed: " + "; ".join(parts)


async def verify_turnstile(
    token: str,
    secret: str,
    remote_ip: Optional[str] = None,
    *,
    client: Optional[httpx.AsyncClient] = None,
) -> Tuple[bool, str]:
    """Ask Cloudflare whether `token` is a real, unspent solve for this site.

    Returns (ok, reason). `reason` is empty on success and a sentence on
    failure, suitable for a 400's detail — it never contains the secret.

    `client` exists for the tests, which hand in an AsyncClient wired to a
    mock transport. Production passes nothing and gets a client scoped to the
    call.
    """
    if not turnstile_enabled(secret):
        # The caller decides what an unconfigured instance does; this module
        # refuses to guess, because "not configured" and "failed" are opposite
        # outcomes and collapsing them is how a gate silently stops gating.
        return False, "Turnstile is not configured on this server"

    if not (token or "").strip():
        # Short-circuited rather than sent: Cloudflare would answer
        # missing-input-response, and spending a round trip to be told what we
        # can already see makes the common bot case the slow path.
        return False, _CODE_REASONS["missing-input-response"]

    form = {"secret": secret.strip(), "response": token.strip()}
    if remote_ip:
        # Optional, and Cloudflare treats it as a hint rather than a
        # requirement. Sent when known because it tightens the binding between
        # the solve and the connection that presents it.
        form["remoteip"] = remote_ip

    owned = client is None
    c = client or httpx.AsyncClient(timeout=VERIFY_TIMEOUT_SECONDS)
    try:
        resp = await c.post(VERIFY_URL, data=form)
        # No redirect following, by the same reasoning as the ntfy publisher:
        # this is a POST carrying a secret, and the only correct destination is
        # the one in VERIFY_URL. A 3xx here is a sign something is intercepting
        # the call, not an instruction to go and hand the secret elsewhere.
        if resp.status_code >= 300:
            return False, (
                f"Turnstile verification failed: Cloudflare answered HTTP "
                f"{resp.status_code}"
            )
        body = resp.json()
    except Exception as exc:
        # FAIL CLOSED. See the module docstring — this is the branch the whole
        # decision is about, and it is deliberately not a pass.
        return False, (
            f"Turnstile verification could not be completed: {exc}. "
            f"Registration is refused rather than allowed through."
        )
    finally:
        if owned:
            await c.aclose()

    if body.get("success") is True:
        return True, ""
    return False, describe_codes(body.get("error-codes") or [])
