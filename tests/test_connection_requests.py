"""Asking to connect with someone you already have a row with.

create_payjoin_contact returns the existing row when one exists between two
users — either direction, any status — and the endpoint answered "sent"
regardless. So two requests produced one pending row and both said they had
been sent. The one that did nothing gave no clue which it was.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    f"{ROOT.name}._connections_for_tests", ROOT / "helpers" / "connections.py"
)
conn = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = conn
_spec.loader.exec_module(conn)

refusal = conn.refusal_for_existing
may_reopen = conn.may_reopen


def test_nothing_between_us_is_not_a_refusal():
    assert refusal(None, True, "bob") is None
    assert refusal("", True, "bob") is None


def test_already_connected_is_refused():
    why = refusal("ACCEPTED", True, "bob")
    assert why and "already connected" in why
    # Either direction: a connection is mutual, so who asked is irrelevant.
    assert refusal("ACCEPTED", False, "bob") == why


def test_my_own_pending_request_says_it_is_still_waiting():
    why = refusal("PENDING", True, "bob")
    assert why and "already asked" in why
    # And points at the way out, since the row is already on their screen.
    assert "withdraw" in why.lower()


def test_their_pending_request_points_at_approving_it():
    """The case that reads as a bug otherwise: you ask, nothing appears under
    'sent', because the row is sitting in your INCOMING list."""
    why = refusal("PENDING", False, "bob")
    assert why and "asked to connect with YOU" in why
    assert "approve" in why.lower()


def test_being_declined_and_asking_again_is_refused():
    """Letting a fresh request overwrite the row would make "no" mean "ask
    again", which is not what the other person chose. The caller can clear it
    themselves, and their own declined requests ARE listed for them."""
    why = refusal("DECLINED", True, "bob")
    assert why and "declined your request" in why
    assert "Declined" in why          # names the section it is actually in
    assert not may_reopen("DECLINED", True)


def test_declining_someone_and_then_asking_them_reopens_it():
    """The bug this pair was written for. A DECLINED row is listed only for the
    REQUESTER, so the decliner cannot see it — being told to dismiss it first
    sent them hunting for a row their own screen does not show.

    Nothing is overridden by reopening: the only person a decline protects is
    the one who was told no, and here that is the person now asking."""
    assert refusal("DECLINED", False, "bob") is None
    assert may_reopen("DECLINED", False)


def test_nothing_else_reopens():
    """Reopening rewrites who asked whom, so it must not reach a row that is
    pending or accepted."""
    for state in ("ACCEPTED", "PENDING", "SOMETHING_NEW", "", None):
        for mine in (True, False):
            assert not may_reopen(state, mine), (state, mine)


def test_every_refusal_names_the_person():
    for state, mine in (
        ("ACCEPTED", True), ("ACCEPTED", False),
        ("PENDING", True), ("PENDING", False),
        ("DECLINED", True),
    ):
        why = refusal(state, mine, "bob")
        assert why and "bob" in why, (state, mine)


def test_case_and_space_in_the_stored_status_do_not_matter():
    assert refusal(" accepted ", True, "bob") == refusal("ACCEPTED", True, "bob")
    assert may_reopen(" declined ", False)


def test_an_unknown_status_does_not_block_a_connection():
    """A state nobody anticipated should not silently make two people
    unconnectable. The insert's own duplicate guard still holds."""
    assert refusal("SOMETHING_NEW", True, "bob") is None
