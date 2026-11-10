"""RFC 6238 time-based one-time passwords, from the standard library.

WHY NOT A DEPENDENCY. This is ~40 lines of HMAC and a big-endian counter, all
of it in `hmac`, `hashlib`, `base64` and `struct`. An extension that ships with
LNbits inherits every dependency it adds, and `pyotp` is not installed on the
instance — so the choice is a new requirement for forty lines, or forty lines.
The RFC publishes its own test vectors, which is what makes the second option
safe: `tests/test_totp.py` runs all of them.

WHAT AN AUTHENTICATOR APP EXPECTS, and why none of these are configurable:
SHA-1, 6 digits, a 30-second step. Google Authenticator, Aegis, FreeOTP and
1Password all ignore the algorithm and digit count in an `otpauth://` URI, or
support only these — so offering a choice would produce a secret that scans
cleanly and then never matches. SHA-1 here is not a collision question: HMAC-
SHA1's security as a PRF is unaffected, and the output is truncated to six
digits either way.

THE VERIFY WINDOW IS ±1 STEP. A phone's clock drifts, and a user types six
digits across a step boundary; one step either side is what every
implementation allows. It is also why a code is acceptable for up to 90
seconds, which is the whole reason for the replay guard below.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote

# Fixed, for the reason in the docstring: an authenticator app that cannot
# honour these would produce a secret that scans and never verifies.
DIGITS = 6
STEP_SECONDS = 30
# One step either side. Raising this widens the window a stolen code is good
# for, which is the thing the replay guard exists to bound.
DEFAULT_WINDOW = 1
# 20 bytes = 160 bits, the RFC's own recommendation and what every app takes.
SECRET_BYTES = 20


def generate_secret() -> str:
    """A fresh base32 secret, in the form an authenticator app scans."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """Base32 in, raw bytes out.

    Tolerant on the way IN because a user may type the secret by hand when a
    camera is not available: spaces and lower case are what people produce,
    and the padding an app strips has to be put back or b32decode refuses.
    """
    s = (secret or "").strip().replace(" ", "").upper()
    if not s:
        raise ValueError("empty TOTP secret")
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s, casefold=True)


def code_at(secret: str, counter: int, digest: str = "sha1") -> str:
    """The code for one 30-second step, by the RFC's own construction."""
    key = _decode_secret(secret)
    msg = struct.pack(">Q", int(counter))
    mac = hmac.new(key, msg, getattr(hashlib, digest)).digest()
    # Dynamic truncation: the low nibble of the last byte picks the offset.
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**DIGITS)).zfill(DIGITS)


def counter_for(at: Optional[float] = None) -> int:
    return int((time.time() if at is None else at) // STEP_SECONDS)


def verify(
    secret: str,
    code: str,
    *,
    at: Optional[float] = None,
    window: int = DEFAULT_WINDOW,
    last_counter: Optional[int] = None,
) -> Optional[int]:
    """Check a code and return the counter it matched, or None.

    THE COUNTER IS THE RETURN VALUE, not a bool, and that is what makes the
    replay guard possible: the caller stores it and passes it back as
    `last_counter` next time. A code is valid for up to 90 seconds, so without
    that a code read over somebody's shoulder — or sitting in a proxy log, or
    retyped by anyone watching the screen — can be presented a second time
    inside its own window. RFC 6238 §5.2 says to refuse exactly this.

    COMPARED IN CONSTANT TIME. A six-digit space is small enough that a timing
    oracle on the comparison is worth closing even behind a rate limiter.
    """
    c = (code or "").strip().replace(" ", "")
    if not c.isdigit() or len(c) != DIGITS:
        return None
    now = counter_for(at)
    # Oldest first, so a code matching two steps (which cannot happen for a
    # correct implementation, but would for a degenerate secret) resolves to
    # the earliest — never one BELOW last_counter.
    for offset in range(-abs(window), abs(window) + 1):
        counter = now + offset
        if counter < 0:
            continue
        if last_counter is not None and counter <= last_counter:
            continue
        if hmac.compare_digest(code_at(secret, counter), c):
            return counter
    return None


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """The `otpauth://` URI an authenticator app scans.

    Both labels are percent-encoded, and the issuer appears TWICE on purpose —
    in the label prefix and as a parameter. Older apps read one and newer apps
    read the other; an app that reads neither files the entry under a bare
    username, which is unhelpful on a phone holding a dozen of them.
    """
    label = quote(f"{issuer}:{account}", safe="")
    return (
        f"otpauth://totp/{label}"
        f"?secret={quote(secret, safe='')}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
