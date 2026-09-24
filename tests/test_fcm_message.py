"""What goes over the wire to Google, and what does not.

Two invariants, both of which have already been broken once:

  * The message is DATA-ONLY. A `notification` block makes the
    firebase-messaging SDK on the device build and post the notification
    itself, inside Google's code, whenever the app is not in the foreground —
    and then the app cannot put its logo on it, because the large icon is the
    only full-colour slot a notification has and FCM has no field for one.
    Adding a `notification` block back would silently take the logo away again
    and leave no error behind.

  * No amounts. An FCM body and an FCM data value travel the same route
    through Google in plaintext, so "put it in data instead" is not a way
    round the rule. The clients compose the version with the figure in it
    locally (useCatchUpScan / useSendConfirmations).
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name

_spec = importlib.util.spec_from_file_location(
    f"{PKG}.helpers._fcm_for_tests", ROOT / "helpers" / "fcm.py"
)
fcm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = fcm
_spec.loader.exec_module(fcm)


def build(title="Payment received", body="You have a new payment.", data=None):
    return fcm._build_message("TOKEN", title, body, data or {"type": "payment"})


def test_no_notification_block():
    """The device SDK must not display this one — the app does."""
    assert "notification" not in build()["message"]


def test_title_and_body_are_in_data():
    data = build()["message"]["data"]
    assert data["title"] == "Payment received"
    assert data["body"] == "You have a new payment."


def test_caller_data_survives():
    """The `type` is what the receiver and the JS handler switch on."""
    assert build(data={"type": "send_confirmed"})["message"]["data"]["type"] == (
        "send_confirmed"
    )


def test_caller_data_cannot_clobber_title_or_body():
    msg = build(data={"type": "payment", "title": "spoofed", "body": "spoofed"})
    assert msg["message"]["data"]["title"] == "Payment received"
    assert msg["message"]["data"]["body"] == "You have a new payment."


def test_priority_is_high():
    """A normal-priority data message can be held until the device next wakes,
    which for a payment alert is no alert at all."""
    assert build()["message"]["android"]["priority"] == "high"


def test_token_is_the_target():
    assert build()["message"]["token"] == "TOKEN"


def _push_text_literals() -> list[str]:
    """Every string literal handed to send_fcm / send_fcm_report in views_api."""
    tree = ast.parse((ROOT / "views_api.py").read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = getattr(fn, "attr", None) or getattr(fn, "id", None)
        if name not in ("send_fcm", "send_fcm_report"):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                found.append(arg.value)
    return found


def test_every_push_text_was_found():
    """Guards the test below: if the call sites move, this fails rather than
    quietly passing on an empty list."""
    texts = _push_text_literals()
    assert len(texts) >= 6, texts  # three call sites, a title and a body each


def test_no_push_text_carries_a_number():
    for text in _push_text_literals():
        assert not re.search(r"\d", text), f"push text names a figure: {text!r}"


# ── which rejections kill a token ────────────────────────────────────────────
#
# A token FCM will never accept again has to be deleted, because nothing else
# ever will: the row sits in fcm_tokens and every push to that user retries it
# and logs the same failure. The 403 was missing from this list, which is what
# a service-account swap leaves behind — every token registered before the swap
# belongs to the old Firebase project, and no retry fixes one.

# Real FCM v1 bodies, trimmed. Both spellings of the sender condition appear in
# the same response, which is the reason the match ignores punctuation.
MISMATCH = (
    '{"error":{"code":403,"message":"SenderId mismatch","status":'
    '"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/'
    'google.firebase.fcm.v1.FcmError","errorCode":"SENDER_ID_MISMATCH"}]}}'
)
UNREGISTERED = (
    '{"error":{"code":404,"message":"Requested entity was not found.",'
    '"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/'
    'google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}'
)
BAD_TOKEN = (
    '{"error":{"code":400,"message":"The registration token is not a valid '
    'FCM registration token","status":"INVALID_ARGUMENT","details":[{"@type":'
    '"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":'
    '"INVALID_ARGUMENT"}]}}'
)
NO_PERMISSION = (
    '{"error":{"code":403,"message":"Firebase Cloud Messaging API has not '
    'been used in project 123 before or it is disabled.","status":'
    '"PERMISSION_DENIED"}}'
)
RATE_LIMITED = (
    '{"error":{"code":429,"message":"Quota exceeded","status":'
    '"RESOURCE_EXHAUSTED"}}'
)


def test_a_sender_id_mismatch_kills_the_token():
    """The one this was written for. Every push to a device registered before a
    project swap answers this, forever, until the row goes."""
    assert fcm.token_is_dead(403, MISMATCH)


def test_unregistered_and_malformed_still_kill_it():
    assert fcm.token_is_dead(404, UNREGISTERED)
    assert fcm.token_is_dead(400, BAD_TOKEN)


def test_a_403_about_the_project_does_not_kill_the_token():
    """A service account without the FCM scope, or an API not enabled, answers
    403 for EVERY token. Pruning on the status alone would empty the table over
    a server misconfiguration and leave nobody reachable once it was fixed."""
    assert not fcm.token_is_dead(403, NO_PERMISSION)


def test_a_transient_failure_does_not_kill_the_token():
    assert not fcm.token_is_dead(429, RATE_LIMITED)
    assert not fcm.token_is_dead(500, '{"error":{"code":500}}')
    assert not fcm.token_is_dead(200, "")


def test_the_right_code_with_the_wrong_status_is_not_enough():
    """Status and reason both have to agree, so a stray word in an unrelated
    message cannot delete somebody's device."""
    assert not fcm.token_is_dead(500, MISMATCH)
    assert not fcm.token_is_dead(403, UNREGISTERED)


def test_the_reason_given_for_a_403_names_the_cause():
    """It goes in the test-push report, where the person reading it needs to
    know this is their own project change and not a broken device."""
    reason = fcm.dead_token_reason(403)
    assert "different Firebase project" in reason
    assert "re-opening the app" in reason


def test_both_senders_share_one_classifier():
    """send_fcm used to duplicate the classification instead of delegating, and
    the two copies were identical until they were not — the 403 was missing
    from both, and fixing one would have left the other retrying forever."""
    src = (ROOT / "helpers" / "fcm.py").read_text()
    body = src[src.index("async def send_fcm("):src.index("async def send_fcm_report(")]
    assert "send_fcm_report(" in body
    assert "remove_fcm_token" not in body
    # One call site for the rule, in the reporting sender only.
    assert src.count("token_is_dead(") == 2   # the def, and the one use
