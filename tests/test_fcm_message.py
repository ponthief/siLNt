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
