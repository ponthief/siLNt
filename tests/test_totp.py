"""TOTP against RFC 6238's own test vectors, plus the replay guard.

The vectors are the reason writing this rather than taking a dependency is
safe: Appendix B of RFC 6238 publishes the expected code for eight specific
timestamps against a known secret, so an implementation either reproduces them
or it is wrong. A hand-rolled TOTP that is merely "self-consistent" — it
verifies what it generates — passes every behavioural test and is unusable
with any real authenticator app, which is the failure these pin.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    name = "silnt_totp_under_test"
    if name in sys.modules:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "helpers" / "totp.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def totp():
    return _load()


# RFC 6238 Appendix B. The seed is the ASCII "12345678901234567890", which the
# RFC gives as hex; base32 is what an authenticator app and this module take.
import base64 as _b64

RFC_SECRET_SHA1 = _b64.b32encode(b"12345678901234567890").decode().rstrip("=")

# (unix time, expected 8-digit code). The RFC prints eight digits; this module
# is fixed at six, so each is compared on its last six — the truncation is the
# same operation modulo a larger power of ten.
RFC_VECTORS_SHA1 = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("at,expected8", RFC_VECTORS_SHA1)
def test_rfc6238_vectors(totp, at, expected8):
    """THE CONTROL THAT MATTERS. An authenticator app computes exactly this."""
    counter = totp.counter_for(at)
    assert totp.code_at(RFC_SECRET_SHA1, counter) == expected8[-6:]


def test_a_secret_scans_as_base32(totp):
    s = totp.generate_secret()
    assert len(s) == 32 and set(s) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    # 20 bytes, the RFC's recommendation.
    assert len(_b64.b32decode(s + "=" * (-len(s) % 8))) == 20


def test_two_secrets_differ(totp):
    assert totp.generate_secret() != totp.generate_secret()


def test_a_hand_typed_secret_still_works(totp):
    """Somebody with no camera types it in, with spaces and in lower case."""
    s = totp.generate_secret()
    spaced = " ".join(s[i : i + 4] for i in range(0, len(s), 4)).lower()
    assert totp.code_at(spaced, 1) == totp.code_at(s, 1)


def test_the_current_code_verifies(totp):
    s = totp.generate_secret()
    at = 1_700_000_000
    code = totp.code_at(s, totp.counter_for(at))
    assert totp.verify(s, code, at=at) == totp.counter_for(at)


def test_one_step_either_side_is_accepted(totp):
    """A phone's clock drifts and six digits take a moment to type."""
    s = totp.generate_secret()
    at = 1_700_000_000
    now = totp.counter_for(at)
    for offset in (-1, 0, 1):
        assert totp.verify(s, totp.code_at(s, now + offset), at=at) == now + offset


def test_two_steps_away_is_not(totp):
    s = totp.generate_secret()
    at = 1_700_000_000
    now = totp.counter_for(at)
    for offset in (-2, 2):
        assert totp.verify(s, totp.code_at(s, now + offset), at=at) is None


def test_a_wrong_code_is_refused(totp):
    s = totp.generate_secret()
    at = 1_700_000_000
    real = totp.code_at(s, totp.counter_for(at))
    wrong = "000000" if real != "000000" else "111111"
    assert totp.verify(s, wrong, at=at) is None


def test_another_secret_does_not_open_it(totp):
    a, b = totp.generate_secret(), totp.generate_secret()
    at = 1_700_000_000
    assert totp.verify(a, totp.code_at(b, totp.counter_for(at)), at=at) is None


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 56", None, "12345a"])
def test_malformed_input_is_refused_without_throwing(totp, bad):
    s = totp.generate_secret()
    assert totp.verify(s, bad, at=1_700_000_000) is None


def test_a_used_code_cannot_be_presented_twice(totp):
    """THE REPLAY GUARD, RFC 6238 §5.2.

    A code is valid for up to 90 seconds with a ±1 window, so without this one
    read over a shoulder, sitting in a proxy log, or simply still on screen is
    good for a second use. The caller stores the counter that matched and hands
    it back.
    """
    s = totp.generate_secret()
    at = 1_700_000_000
    now = totp.counter_for(at)
    code = totp.code_at(s, now)
    matched = totp.verify(s, code, at=at)
    assert matched == now
    assert totp.verify(s, code, at=at, last_counter=matched) is None


def test_and_nor_can_an_earlier_one_inside_the_window(totp):
    """The previous step's code is still arithmetically valid; once a later one
    has been accepted it must not be, or the guard is one-deep and useless."""
    s = totp.generate_secret()
    at = 1_700_000_000
    now = totp.counter_for(at)
    assert totp.verify(s, totp.code_at(s, now - 1), at=at, last_counter=now) is None


def test_but_the_next_step_still_works(totp):
    """The guard must not lock the user out of their own next code."""
    s = totp.generate_secret()
    at = 1_700_000_000
    now = totp.counter_for(at)
    later = at + totp.STEP_SECONDS
    assert totp.verify(s, totp.code_at(s, now + 1), at=later, last_counter=now) == now + 1


def test_the_provisioning_uri_is_what_an_app_scans(totp):
    s = totp.generate_secret()
    uri = totp.provisioning_uri(s, "alice@example.com", "WhiSPa")
    assert uri.startswith("otpauth://totp/WhiSPa%3Aalice%40example.com?")
    assert f"secret={s}" in uri
    assert "issuer=WhiSPa" in uri
    assert "algorithm=SHA1" in uri and "digits=6" in uri and "period=30" in uri


def test_the_uri_escapes_an_account_that_would_break_it(totp):
    """An email with a '?' or '&' in it would otherwise truncate the secret."""
    uri = totp.provisioning_uri(totp.generate_secret(), "a&b?c@x.com", "WhiSPa")
    assert "a&b?c" not in uri
    assert uri.count("?") == 1


def test_the_parameters_are_not_configurable(totp):
    """Changing any of them produces a secret that scans and never matches."""
    assert (totp.DIGITS, totp.STEP_SECONDS, totp.SECRET_BYTES) == (6, 30, 20)
