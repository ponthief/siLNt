"""Confirming a device sends ONE email, and it is the one with the code.

REPORTED 2026-11-07, web app: *"confirming a device sends an email that new
sign in attempt, but there is no email with the code"*.

Pressing "Send confirmation email" on the pending-device screen called
/auth/device-request-confirm, and that handler sent TWO emails back to back to
the same address: the six-digit code, and then "New device sign-in to your
wallet — someone may have your password". The second one is an answer to a
question the user had just answered the other way: they pressed the button
that says this device is theirs.

The alert was misplaced rather than misconceived, and two pieces of the source
said so before anyone looked at the mail:

  * the block carried its own comment — "This endpoint is CHECK-ONLY: it never
    sends a confirmation email or mutates state ... The confirmation email is
    sent only when the user explicitly asks, via /auth/device-request-confirm"
    — which describes device-check, while sitting inside request-confirm;
  * should_send_login_alert's docstring says its dedupe exists to "prevent
    spamming the user when an untrusted device repeatedly hits device-check".

So the alert moved to device-check, where an untrusted sign-in is actually
observed, and request-confirm sends one email.

Note what the ordering proved about the missing mail: the alert is sent AFTER
the code, and a failed code send raises 500 before reaching it. Receiving the
alert therefore means the code's send call returned ok — it was accepted and
then not delivered. Two messages to one address in one request is the likeliest
reason, which this change also removes.

Source-read, like test_route_authorization.py: nothing in this suite can start
FastAPI, and the whole of this bug is visible in the handler bodies.
"""

from __future__ import annotations

import ast
import io
import pathlib
import tokenize

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = (ROOT / "views_api.py").read_text()
TREE = ast.parse(SRC)

CODE_SUBJECT = "Your device confirmation code"
ALERT_SUBJECT = "New device sign-in to your wallet"


def _handler(name: str) -> str:
    for node in ast.walk(TREE):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name:
            return ast.get_source_segment(SRC, node) or ""
    pytest.fail(f"{name} not found in views_api.py")


def _no_comments(body: str) -> str:
    """The same source with every `#` comment removed.

    THIS FILE'S FIRST RUN NEEDED IT. The comment left in
    device-request-confirm explaining why the alert is no longer sent from
    there quotes the alert's subject line, so "the alarm is not in this
    handler" failed on the sentence saying the alarm is not in this handler.
    check-stealth.cjs hit it with DONT_KILL_APP and check-backup.mjs with
    Math.random(); a check that reads prose reports on prose.

    Tokenised rather than regexed, because a `#` inside one of these email
    bodies is not a comment.
    """
    out = body.splitlines()
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(body).readline))
    except tokenize.TokenError:
        return body
    for tok in toks:
        if tok.type == tokenize.COMMENT:
            row, col = tok.start
            out[row - 1] = out[row - 1][:col]
    return "\n".join(out)


def _sends(body: str) -> int:
    """How many times this handler hands something to the mailer."""
    return body.count("send_email_notification(")


CONFIRM_RAW = _handler("api_device_request_confirm")
CHECK_RAW = _handler("api_device_check")
CONFIRM = _no_comments(CONFIRM_RAW)
CHECK = _no_comments(CHECK_RAW)


# ── the reported bug ─────────────────────────────────────────────────────────

def test_confirm_sends_exactly_one_email():
    assert _sends(CONFIRM) == 1, (
        "device-request-confirm sent the code and then a security alarm. Two "
        "messages to one address in one request is also how one of them goes "
        "missing."
    )


def test_the_one_it_sends_is_the_code():
    assert CODE_SUBJECT in CONFIRM
    assert "confirmation code is" in CONFIRM


def test_confirm_does_not_raise_the_unknown_device_alarm():
    """The user pressed the button that means "this device is mine"."""
    assert ALERT_SUBJECT not in CONFIRM, CONFIRM[-400:]
    assert "should_send_login_alert" not in CONFIRM
    # NOT asserted: that the words "someone may have your password" are absent.
    # The code email carries its own "if this WASN'T you" line and should — it
    # is the mail a stranger's victim actually receives. What must not be here
    # is a SECOND message whose entire subject is that accusation.
    assert "signed in to from a device that isn't" not in CONFIRM


def test_the_code_email_still_says_where_the_sign_in_came_from():
    """What makes dropping the alarm from this path safe: the code mail already
    names the browser, the IP and the time, so somebody who did NOT ask for it
    still has what they need to act."""
    for part in ("A sign-in was attempted from", "Browser:", "IP:", "Time:"):
        assert part in CONFIRM, part


# ── where the alert went ─────────────────────────────────────────────────────

def test_the_alert_is_on_device_check_now():
    assert ALERT_SUBJECT in CHECK
    assert _sends(CHECK) == 1


def test_it_is_deduped_because_device_check_is_polled():
    """PendingDeviceView polls this on mount and LoginView calls it on every
    sign-in. should_send_login_alert holds one alert per (user, ua|ip) for 12
    hours; without it this endpoint is a mail loop."""
    assert "should_send_login_alert(user_id, sig)" in CHECK
    assert "hashlib.sha256" in CHECK


def test_it_only_fires_for_an_account_that_has_a_confirmed_device():
    """On a brand-new account the first sign-in is by definition from an
    unconfirmed device. Warning somebody that their own new account was reached
    by an unknown device is the noise that teaches people to ignore the real
    one."""
    assert "count_trusted_devices(user_id) > 0" in CHECK


def test_a_mail_failure_cannot_break_the_check():
    """The caller asked "is this device trusted". That question still has an
    answer when the mailer is down."""
    at_try = CHECK.index("try:")
    assert at_try < CHECK.index("send_email_notification(")
    assert "except Exception" in CHECK
    assert "Login-alert send skipped" in CHECK


def test_device_check_still_sends_no_code_and_mutates_no_device():
    """It stays CHECK-ONLY in every other respect — that is why the code is a
    separate, explicitly-requested endpoint in the first place."""
    assert "create_device_code" not in CHECK
    assert CODE_SUBJECT not in CHECK


# ── the comments that pointed at the bug must not point the wrong way again ──

def test_no_handler_claims_to_be_check_only_while_sending_a_code():
    """The misplaced block was found by its own comment contradicting the
    function it sat in. A comment that describes a different endpoint is worth
    failing on: it is what review reads instead of the code."""
    assert "CHECK-ONLY" not in CONFIRM_RAW, (
        "request-confirm exists to send a code; a comment calling it check-only "
        "is how the alert block got here"
    )
    # And the claim is true where it IS made.
    assert "CHECK-ONLY" in CHECK_RAW
    assert "create_device_code" not in CHECK
