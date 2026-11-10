"""Two-factor policy: who it applies to, how a verified session is carried,
and what stops a six-digit code being ground down.

WHAT THIS CAN AND CANNOT DEFEND, stated first because it decides how much
weight the feature can carry.

Sign-in is LNbits core's `POST /api/v1/auth`, which this extension does not own
and cannot gate — the same second public door `CLAUDE.md` records for signup.
So a password alone still reaches the ACCOUNT. What 2FA gates is the WALLET:
`require_trusted_device` is the single dependency every siLNt endpoint hangs
off, and a user with 2FA on has no wallet behind it until a code is presented.

And like Turnstile, enforcement is scoped to the BROWSER surface
(`REQUIRES_ORIGIN`), because the phone app has no 2FA flow and locking it out
would be a worse failure than the one being fixed. That scoping is by a header
the client sets, so it is not an authentication boundary against somebody
already holding the account's API key and scripting against it — the trusted
device gate has exactly the same property and the project accepted it. This
raises the cost of a stolen PASSWORD, which is where it is actually spent.

Do not read more into it than that, and do not "fix" it by dropping the
browser scope until the phone implements the flow: the result is a wallet
nobody can open from their own phone.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict
from http import HTTPStatus
from typing import Optional

from fastapi import HTTPException, Request, Response

from .appenv import silnt_env

# How long a verified sign-in stays verified. Twelve hours: long enough that a
# day's use does not keep asking, short enough that a browser left open
# overnight asks again. Shorter than the device cookie by design — the device
# is remembered for a year, the SESSION is not, which is the whole distinction
# the feature rests on.
SESSION_TTL_SECONDS = 12 * 3600

# The emailed fallback's own lifetime, matching the device code's ten minutes.
EMAIL_CODE_TTL_SECONDS = 600

# Brute force. A six-digit code with a ±1 step window leaves three codes valid
# at any moment, so an unlimited verifier falls to ~333k tries. The emailed
# code has its own five-attempt cap in the row; this bounds the TOTP path,
# which has no row to count against.
MAX_VERIFY_ATTEMPTS = 10
VERIFY_WINDOW_SECONDS = 300
# And a cap on how often a code can be MAILED, so the verify screen cannot be
# turned into a way to flood somebody's inbox.
MAX_EMAIL_SENDS = 5
EMAIL_SEND_WINDOW_SECONDS = 3600

# WHICH CLIENT IS ASKING. The browser app sets this on every request it makes;
# the React Native client does not. See requires_twofa for why `Origin` was the
# wrong thing to read and what it cost.
WEB_CLIENT_HEADER = "X-Silnt-Web"

SESSION_COOKIE_PREFIX = "silnt_2fa_"
SESSION_HEADER = "X-Silnt-2FA"
COOKIE_DOMAIN = silnt_env("SILNT_DEVICE_COOKIE_DOMAIN") or None

# In-memory, like every other limiter here: single-process LNbits, and a
# counter reset on restart clears the attacker's along with everyone else's.
_verify_log: dict = defaultdict(list)   # user_id -> [ts, ...]
_email_log: dict = defaultdict(list)    # user_id -> [ts, ...]


def _prune(entries: list, age: int) -> list:
    cutoff = time.time() - age
    return [t for t in entries if t >= cutoff]


def requires_twofa(request: Request) -> bool:
    """Does the second factor apply to THIS request?

    Only to the web app, which says so on every request it makes
    (`X-Silnt-Web`, set in the browser client's own fetch wrapper). The phone
    has no 2FA screen, so enforcing it there would put a wallet behind a prompt
    that cannot render — see this module's docstring.

    **IT USED TO READ `Origin`, AND THAT WAS BROKEN IN A WAY WORTH RECORDING.**
    Chosen by analogy with `turnstile.py`, where it is correct: that guards one
    POST endpoint, and a browser sends `Origin` on every POST. This guards
    EVERY request, and a browser does **not** send `Origin` on a same-origin
    GET — which is what the deployed app behind Caddy makes almost all of them.
    Measured in Chromium against a same-origin page:

        GET  /api/get   → origin: null
        POST /api/post  → origin: http://127.0.0.1:8770

    So the gate answered "not required" for every GET and "required" for every
    POST. Reported 2026-11-10: the status read is a GET, so a fresh sign-in was
    told the session was verified and never prompted; then the first POST — the
    Turn off button — was refused with `twofa-required`; and the screen that
    re-checks before routing asked with a GET, was told "verified", and
    declined to show the gate, leaving a page of failed requests and no screen.
    One wrong signal, three symptoms.

    A header the client sets on every request is the honest form of "which app
    is this". It is client-settable, so it is not a boundary against a script
    holding the account's API key — the same caveat the trusted-device gate has
    always carried, and stated in this module's docstring rather than implied.
    """
    return request.headers.get(WEB_CLIENT_HEADER) == "1"


# ── The verified-session token ────────────────────────────────────────────────


def cookie_name_for_user(user_id: str) -> str:
    """Per-user, like the device cookie, so two accounts in one browser do not
    overwrite each other's verification."""
    safe = "".join(c for c in (user_id or "") if c.isalnum() or c in "_-")[:64]
    return SESSION_COOKIE_PREFIX + safe


def read_session_token(request: Request, user_id: str) -> Optional[str]:
    """From the cookie, or the header for a client that cannot keep cookies.

    The same two-way read `read_device_id` does, and for the same reason: a
    cross-site cookie is not reliably stored outside a browser.
    """
    v = request.cookies.get(cookie_name_for_user(user_id))
    if v:
        return v
    hdr = request.headers.get(SESSION_HEADER)
    return hdr.strip() if hdr else None


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def set_session_cookie(response: Response, user_id: str, token: str) -> None:
    """A SESSION cookie — no max_age, so it dies with the browser.

    That is deliberate and is half of "a code on every sign-in": a persistent
    cookie would make the second factor something a browser remembers, which
    is what the trusted-device cookie already is. HttpOnly so no script on the
    page can read it back out, which matters more here than for the device id
    because this one is the thing being checked.
    """
    response.set_cookie(
        key=cookie_name_for_user(user_id),
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        domain=COOKIE_DOMAIN,
    )


def clear_session_cookie(response: Response, user_id: str) -> None:
    response.delete_cookie(cookie_name_for_user(user_id), path="/", domain=COOKIE_DOMAIN)


# ── Limits ────────────────────────────────────────────────────────────────────


def check_verify_allowed(user_id: str) -> None:
    """Raise 429 if this account has tried too many codes lately.

    Counted per USER rather than per IP: the attacker here has the password,
    so they are authenticated as the user, and an IP limit is one proxy away
    from nothing. The cost is that somebody can lock their own verify screen
    for five minutes by fumbling ten codes — which is recoverable by waiting
    and is the right side of this trade for a wallet.
    """
    log = _verify_log[user_id] = _prune(_verify_log[user_id], VERIFY_WINDOW_SECONDS)
    if len(log) >= MAX_VERIFY_ATTEMPTS:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail="Too many incorrect codes. Wait a few minutes and try again.",
        )


def record_verify_attempt(user_id: str) -> None:
    """Recorded on a FAILURE only — a correct code should not spend the budget
    of the next honest sign-in."""
    _verify_log[user_id].append(time.time())


def clear_verify_attempts(user_id: str) -> None:
    _verify_log.pop(user_id, None)


def check_email_send_allowed(user_id: str) -> None:
    log = _email_log[user_id] = _prune(_email_log[user_id], EMAIL_SEND_WINDOW_SECONDS)
    if len(log) >= MAX_EMAIL_SENDS:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail="Too many codes requested. Wait a while before asking for another.",
        )


def record_email_send(user_id: str) -> None:
    """Stamped AFTER the send, like the registration limiter's own cooldown: a
    code nobody received must not refuse the retry that would deliver one."""
    _email_log[user_id].append(time.time())


def _reset_for_tests() -> None:
    _verify_log.clear()
    _email_log.clear()
