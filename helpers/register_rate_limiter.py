"""
Rate limiting for `/api/v1/auth/register-start`.

WHY THIS EXISTS, AND WHY IT IS NOT A SECOND BOT CHECK. Turnstile already sits
in front of this endpoint (helpers/turnstile.py) and it is a good control, but
it has a shape rather than a wall: `enforce` defaults to "browser", so a
missing token is fatal only for a request carrying an `Origin` header — and
that header is set by the client. A script omits it. That was a deliberate
decision, because `RegisterScreen.tsx` renders no widget and mainnet
onboarding is mobile-app only, and it means Turnstile is not the thing
bounding abuse here. Nothing was.

This endpoint is the most expensive public surface in the extension. One
unauthenticated call costs a bcrypt hash, two account lookups, a pending-row
write and **an email through the shared SMTP server**. The mail is the part
that reaches outside: it is sent to an address the caller chooses, and the
instance's sending reputation is what pays for a flood.

THREE LIMITS, EACH FOR A DIFFERENT ATTACK:

  1. Per IP, per hour — the ordinary case. Bounds one source.

  2. Per EMAIL ADDRESS — a cooldown, so a rotating-IP caller cannot mail-bomb
     one inbox. The same vector invite_rate_limiter.py guards, and the same
     answer.

  3. GLOBAL, per hour — the backstop, and the only one that cannot be forged.
     The per-IP limit is only as good as the IP, and the IP comes from
     `X-Forwarded-For` when one is present (get_client_ip, for Caddy). That
     header is client-settable: if LNbits is ever reachable without going
     through the proxy, a caller sets a fresh value per request and limit 1
     stops nobody. A limiter that one header defeats is the maths question all
     over again — checked on the client and nowhere that matters — so there is
     a number here that no header can move.

THE COST OF LIMIT 3, STATED RATHER THAN DISCOVERED: it is a way to close
signups. Burn the hourly global budget and nobody can register until the
window slides. On mainnet, where onboarding is mobile-app only, that is a real
outage rather than an inconvenience. It is set far above any honest signup
rate for exactly that reason — bounded abuse of an endpoint that sends mail is
worth more than an unbounded one, but only if the bound does not bite real
users. If this instance ever grows past it, raise it; do not remove it.

ONE MESSAGE FOR ALL THREE. The caller is told "too many, wait" and never which
limit tripped. Limit 2 keys on an address the caller does not own, so a
distinguishable refusal would answer "did somebody start registering THIS
address in the last minute?" — a small oracle, but this endpoint's whole
security story is about not answering questions like that (turnstile.py:
"the validation IS the leak"). The operator gets the detail in the log, where
it belongs: which limit, and the IP.

State is in-memory, like both existing limiters. That is right for
single-process LNbits and means the counters reset on restart — which is worth
knowing during an incident: restarting the server clears the attacker's
counters along with everyone else's.
"""

import time
from collections import defaultdict
from http import HTTPStatus

from fastapi import HTTPException
from loguru import logger

# Ten an hour from one address. A person registering one account makes one
# call; someone who mistypes a username, finds it taken and retries makes a
# handful. A family or an office behind one NAT makes a few more. Ten leaves
# room for all of that and no room for a script.
MAX_STARTS_PER_IP_HOUR = 10

# One verification email per address per minute. Long enough that a flood is
# pointless, short enough that somebody who did not get the first one is not
# left staring at a refusal — the mail itself takes a few seconds to arrive and
# a real person checks their inbox before pressing again.
RESEND_COOLDOWN_SECONDS = 60

# The backstop. An instance seeing this many honest registrations in an hour
# has a different problem to solve; ten accounts in a day was the attack that
# prompted this.
MAX_STARTS_GLOBAL_HOUR = 200

# One refusal, whatever tripped. See the note above on why.
_TOO_MANY = "Too many registration attempts. Please wait a few minutes and try again."

_ip_log: dict = defaultdict(list)   # ip -> [ts, ...]
_global_log: list = []              # [ts, ...]
_email_sent: dict = {}              # email (lowercased) -> ts of last send


def _prune(entries: list, age_seconds: int) -> list:
    cutoff = time.time() - age_seconds
    return [t for t in entries if t >= cutoff]


def _refuse(why: str, ip: str) -> None:
    """Log which limit fired, tell the caller nothing but to wait."""
    logger.warning(f"register-start refused ({why}) ip={ip or 'unknown'}")
    raise HTTPException(status_code=HTTPStatus.TOO_MANY_REQUESTS, detail=_TOO_MANY)


def check_registration_allowed(ip: str, email: str) -> None:
    """Raise 429 if this registration attempt exceeds a limit.

    Call it FIRST — before Turnstile, before the field validation, before the
    uniqueness lookups. Turnstile is a network call to somebody else's service
    and the uniqueness lookup is the membership oracle; a local counter is
    cheaper than either and should be what a flood hits.

    Counts the ATTEMPT, not the success. A caller grinding taken usernames
    never completes a registration, and a limiter that only counted completed
    ones would never see them.

    The per-email cooldown is CHECKED here and stamped in
    record_registration_email, because it is about mail that actually went out.
    """
    now = time.time()
    key = (email or "").strip().lower()

    _ip_log[ip] = _prune(_ip_log[ip], 3600)
    if len(_ip_log[ip]) >= MAX_STARTS_PER_IP_HOUR:
        _refuse("per-ip hourly", ip)

    global _global_log
    _global_log = _prune(_global_log, 3600)
    if len(_global_log) >= MAX_STARTS_GLOBAL_HOUR:
        _refuse("global hourly", ip)

    last = _email_sent.get(key, 0)
    if key and now - last < RESEND_COOLDOWN_SECONDS:
        _refuse("per-email cooldown", ip)

    # Recorded only once every limit has passed, so a refused attempt does not
    # also spend budget — the refusal already cost the caller the attempt.
    _ip_log[ip].append(now)
    _global_log.append(now)


def record_registration_email(email: str) -> None:
    """Start the per-address cooldown. Called after the mail actually went.

    Deliberately not called when the send fails: a verification email nobody
    received must not lock its own address out of a retry.
    """
    key = (email or "").strip().lower()
    if key:
        _email_sent[key] = time.time()
