"""The two-factor policy: who it applies to, and what bounds a 6-digit guess.

The TOTP arithmetic has its own file (test_totp.py, against the RFC vectors).
This one is about the decisions around it, each of which is a way the feature
could be real and useless:

  - applying to the phone, which has no flow, and locking a wallet behind a
    prompt its client cannot render;
  - a verified session that outlives the sign-in, so "every sign-in" asks once
    and never again;
  - a refusal the clients read as "device not trusted", which lands on the
    device-enrollment screen and emails the wrong code;
  - an unlimited verifier, which a 6-digit code does not survive.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(rel: str, name: str):
    """Load one helper, under a stub parent package.

    `helpers/twofa.py` imports its neighbour the way the rest of the tree does
    (`from .appenv import silnt_env`), which a bare spec_from_file_location
    cannot resolve — "attempted relative import with no known parent package".
    The fix belongs in the harness rather than in the module: loosening a
    production import to suit a test is how one file in the tree ends up
    written differently from its neighbours.

    So a package named for nothing is registered with `__path__` pointing at
    helpers/, and the module is loaded inside it. Only stdlib-importable
    neighbours resolve this way, which is all this one needs.
    """
    pkg_name = "silnt_helpers_under_test"
    if pkg_name not in sys.modules:
        import types

        pkg = types.ModuleType(pkg_name)
        pkg.__path__ = [str(ROOT / "helpers")]
        sys.modules[pkg_name] = pkg
    full = f"{pkg_name}.{name}"
    if full in sys.modules:
        del sys.modules[full]
    spec = importlib.util.spec_from_file_location(full, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def tf():
    mod = _load("helpers/twofa.py", "silnt_twofa_under_test")
    mod._reset_for_tests()
    return mod


class FakeRequest:
    def __init__(self, headers=None, cookies=None):
        self.headers = headers or {}
        self.cookies = cookies or {}


class FakeResponse:
    def __init__(self):
        self.cookies = {}
        self.deleted = []

    def set_cookie(self, key, value, **kw):
        self.cookies[key] = {"value": value, **kw}

    def delete_cookie(self, key, **kw):
        self.deleted.append(key)


# ── Who it applies to ─────────────────────────────────────────────────────────


def test_the_web_app_is_in_scope(tf):
    assert tf.requires_twofa(FakeRequest({"X-Silnt-Web": "1"})) is True


def test_the_phone_is_not(tf):
    """THE LOCKOUT THIS AVOIDS. React Native has no 2FA screen to render, so
    enforcing it there puts a wallet behind a prompt that cannot appear.
    Widening this means building the flow there first."""
    assert tf.requires_twofa(FakeRequest({"user-agent": "okhttp/4.9"})) is False


def test_a_GET_is_in_scope_exactly_as_a_POST_IS(tf):
    """THE BUG THIS REPLACED, and the reason the signal is a header.

    This read `Origin`, copied from turnstile.py where it is correct — that
    guards one POST endpoint, and a browser sends Origin on every POST. This
    guards EVERY request, and a browser does NOT send Origin on a same-origin
    GET, which behind Caddy is almost all of them. Measured in Chromium:

        GET  /api/get   → origin: null
        POST /api/post  → origin: http://127.0.0.1:8770

    So the gate said "not required" for every read and "required" for every
    write: a fresh sign-in was told it was verified and never prompted, the
    first POST was refused, and the screen that re-checks before routing asked
    with a GET, was told "verified", and showed nothing. Reported 2026-11-10.

    The header does not vary by method, which is the whole point of it.
    """
    for headers in (
        {"X-Silnt-Web": "1"},                                   # a GET
        {"X-Silnt-Web": "1", "origin": "https://wallet.example"},  # a POST
    ):
        assert tf.requires_twofa(FakeRequest(headers)) is True
    # And Origin alone no longer decides anything.
    assert tf.requires_twofa(FakeRequest({"origin": "https://wallet.example"})) is False


def test_the_scope_is_a_header_and_that_is_known(tf):
    """Not an authentication boundary against a scripted client: the same
    property the trusted-device gate has. Pinned so nobody reads more into the
    feature than it carries."""
    assert tf.requires_twofa(FakeRequest({})) is False
    # Only an exact "1" — a header echoed back with some other value is not an
    # assertion that this is the web app.
    assert tf.requires_twofa(FakeRequest({"X-Silnt-Web": "yes"})) is False


# ── The verified session ──────────────────────────────────────────────────────


def test_the_cookie_is_per_user(tf):
    a = tf.cookie_name_for_user("user-aaa")
    b = tf.cookie_name_for_user("user-bbb")
    assert a != b and a.startswith("silnt_2fa_")


def test_a_hostile_user_id_cannot_shape_the_cookie_name(tf):
    name = tf.cookie_name_for_user("a b;c=d\n/../")
    assert name == "silnt_2fa_abcd"


def test_the_session_cookie_dies_with_the_browser(tf):
    """HALF OF "a code on every sign-in". A max_age here would make the second
    factor something the browser remembers — which is what the trusted-device
    cookie already is, and the thing this is meant to be different from."""
    r = FakeResponse()
    tf.set_session_cookie(r, "u1", "tok")
    jar = r.cookies[tf.cookie_name_for_user("u1")]
    assert "max_age" not in jar or jar.get("max_age") is None
    assert jar["httponly"] is True
    assert jar["secure"] is True


def test_the_token_is_read_from_the_cookie(tf):
    name = tf.cookie_name_for_user("u1")
    assert tf.read_session_token(FakeRequest(cookies={name: "tok"}), "u1") == "tok"


def test_or_from_the_header_for_a_client_with_no_cookie_jar(tf):
    assert tf.read_session_token(FakeRequest({"X-Silnt-2FA": " tok "}), "u1") == "tok"


def test_another_users_cookie_is_not_read(tf):
    name = tf.cookie_name_for_user("someone-else")
    assert tf.read_session_token(FakeRequest(cookies={name: "tok"}), "u1") is None


def test_tokens_are_unguessable_and_distinct(tf):
    a, b = tf.new_session_token(), tf.new_session_token()
    assert a != b and len(a) >= 32


def test_signing_out_clears_the_cookie(tf):
    r = FakeResponse()
    tf.clear_session_cookie(r, "u1")
    assert tf.cookie_name_for_user("u1") in r.deleted


# ── Limits ────────────────────────────────────────────────────────────────────


def test_a_six_digit_code_cannot_be_ground_down(tf):
    """±1 step leaves three codes valid at once, so an unlimited verifier falls
    to about 333k tries. This is what stands between a stolen password and the
    wallet."""
    for _ in range(tf.MAX_VERIFY_ATTEMPTS):
        tf.check_verify_allowed("u1")
        tf.record_verify_attempt("u1")
    with pytest.raises(Exception) as got:
        tf.check_verify_allowed("u1")
    assert getattr(got.value, "status_code", None) == 429


def test_the_limit_is_per_account(tf):
    for _ in range(tf.MAX_VERIFY_ATTEMPTS):
        tf.record_verify_attempt("u1")
    tf.check_verify_allowed("u2")     # somebody else is unaffected


def test_a_correct_code_does_not_spend_the_next_sign_ins_budget(tf):
    for _ in range(tf.MAX_VERIFY_ATTEMPTS - 1):
        tf.record_verify_attempt("u1")
    tf.clear_verify_attempts("u1")
    for _ in range(tf.MAX_VERIFY_ATTEMPTS):
        tf.check_verify_allowed("u1")
        tf.record_verify_attempt("u1")


def test_the_window_slides(tf, monkeypatch):
    base = 1_700_000_000.0
    now = {"t": base}
    monkeypatch.setattr(tf.time, "time", lambda: now["t"])
    for _ in range(tf.MAX_VERIFY_ATTEMPTS):
        tf.record_verify_attempt("u1")
    with pytest.raises(Exception):
        tf.check_verify_allowed("u1")
    now["t"] = base + tf.VERIFY_WINDOW_SECONDS + 1
    tf.check_verify_allowed("u1")


def test_the_mailed_code_cannot_be_used_to_flood_an_inbox(tf):
    for _ in range(tf.MAX_EMAIL_SENDS):
        tf.check_email_send_allowed("u1")
        tf.record_email_send("u1")
    with pytest.raises(Exception) as got:
        tf.check_email_send_allowed("u1")
    assert getattr(got.value, "status_code", None) == 429


def test_the_session_is_shorter_than_the_device_cookie(tf):
    """The device is remembered for a year and the SESSION is not; if these
    ever met, the second factor would be asked once per browser for ever."""
    src = (ROOT / "helpers" / "device_auth.py").read_text()
    assert "DEVICE_COOKIE_MAX_AGE        = 365 * 24 * 3600" in src
    assert tf.SESSION_TTL_SECONDS <= 24 * 3600


def test_the_mailed_code_expires_in_minutes_not_hours(tf):
    assert 60 <= tf.EMAIL_CODE_TTL_SECONDS <= 900


# ── The refusal the clients have to tell apart ────────────────────────────────


def test_the_refusal_is_distinguishable_from_device_not_trusted():
    """THE TRAP. Both clients fold a 403 from require_trusted_device into
    `untrusted`, and untrusted lands on the device-enrollment screen — whose
    only action is to email a DEVICE code. A bare 403 here answers "enter your
    two-factor code" with "we have emailed you a device confirmation", on a
    browser that is already trusted."""
    src = (ROOT / "helpers" / "device_auth.py").read_text()
    assert 'TWOFA_REQUIRED_DETAIL = "twofa-required' in src
    assert "detail=TWOFA_REQUIRED_DETAIL" in src
    assert "device-not-trusted" in src          # the other one still says its own thing


def test_the_second_factor_is_checked_after_the_device():
    """A browser that is not trusted at all has a more basic thing to do, and
    checking 2FA first would queue two code prompts back to back."""
    src = (ROOT / "helpers" / "device_auth.py").read_text()
    body = src[src.index("async def require_trusted_device("):]
    body = body[: body.index("async def require_trusted_device_admin(")]
    assert body.index("get_trusted_device") < body.index("_require_twofa_session")


def test_both_gates_enforce_it():
    """The admin-key routes too: a second factor the admin surface walks around
    is a second factor on the read paths only."""
    src = (ROOT / "helpers" / "device_auth.py").read_text()
    assert src.count("await _require_twofa_session(request, user_id)") == 2


def test_the_way_out_is_not_behind_the_lock():
    """verify, email-send, status and revoke hang off require_invoice_key. Put
    any of them behind require_trusted_device and 2FA is a wallet nobody can
    open: the endpoint that clears the lock would need the lock cleared."""
    src = (ROOT / "views_api.py").read_text()
    for path in ("2fa/verify", "2fa/email/send", "2fa/session/revoke"):
        i = src.index(f'"/api/v1/auth/{path}"')
        window = src[i : i + 400]
        assert "require_invoice_key" in window, path
        assert "require_trusted_device" not in window, path


def test_but_setting_it_up_is_behind_the_device_gate():
    """Setting the factor up or taking it off is what somebody holding only the
    password would do."""
    src = (ROOT / "views_api.py").read_text()
    for path in ("2fa/totp/start", "2fa/totp/confirm", "2fa/disable"):
        i = src.index(f'"/api/v1/auth/{path}"')
        window = src[i : i + 400]
        assert "require_trusted_device" in window, path


def test_disabling_demands_a_fresh_code():
    """A twelve-hour session plus a browser walked away from is exactly when
    turning the factor OFF must cost a code rather than a click."""
    src = (ROOT / "views_api.py").read_text()
    body = src[src.index("async def api_twofa_disable("):]
    body = body[: body.index("@silnt_api_router", 10)]
    assert "check_verify_allowed" in body and "record_verify_attempt" in body
    assert "disable_twofa" in body


def test_enabling_leaves_the_session_verified():
    """Or switching 2FA on logs you out of the screen you switched it on from."""
    src = (ROOT / "views_api.py").read_text()
    body = src[src.index("async def api_twofa_totp_confirm("):]
    body = body[: body.index("@silnt_api_router", 10)]
    assert "create_twofa_session" in body and "set_session_cookie" in body


def test_the_secret_is_never_read_back_out():
    """It is returned once, at setup. No endpoint hands back an existing one —
    otherwise the API is a way to copy somebody's authenticator."""
    src = (ROOT / "views_api.py").read_text()
    status = src[src.index("async def api_twofa_status("):]
    status = status[: status.index("@silnt_api_router", 10)]
    assert "totp_secret" not in status
    assert '"secret"' not in status
