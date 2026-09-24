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


def test_a_decline_is_not_reopened_by_asking_again():
    """Letting a fresh request overwrite a DECLINED row would make "no" mean
    "ask again", which is not what the person who declined chose."""
    mine = refusal("DECLINED", True, "bob")
    assert mine and "declined your request" in mine
    assert "dismiss" in mine.lower()

    theirs = refusal("DECLINED", False, "bob")
    assert theirs and "You declined" in theirs
    assert "dismiss" in theirs.lower()


def test_the_two_declined_messages_are_different():
    """Who declined whom is the thing the user needs to know, and it decides
    whose Dismiss button they are looking for."""
    assert refusal("DECLINED", True, "bob") != refusal("DECLINED", False, "bob")


def test_every_message_names_the_person():
    for state in ("ACCEPTED", "PENDING", "DECLINED"):
        for mine in (True, False):
            why = refusal(state, mine, "bob")
            assert why and "bob" in why, (state, mine)


def test_case_and_space_in_the_stored_status_do_not_matter():
    assert refusal(" accepted ", True, "bob") == refusal("ACCEPTED", True, "bob")


def test_an_unknown_status_does_not_block_a_connection():
    """A state nobody anticipated should not silently make two people
    unconnectable. The insert's own duplicate guard still holds."""
    assert refusal("SOMETHING_NEW", True, "bob") is None
