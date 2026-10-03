"""The resume point: what it means, and the two ways it was wrong.

The resume point (`wallets.last_scan_height`) is one claim: every block up to
here has been LOOKED AT. Everything about catching up rests on it, and nothing
in the app can tell that it is wrong — a wallet whose resume point is too high
reports itself fully scanned while a payment sits in a block nothing ever read.

TWO BUGS, found the same day a mainnet wallet's balance had to be repaired by
editing this column by hand (2026-10-03).

 1. It started at `start`, the FIRST BLOCK OF THE RANGE, before anything had
    looked at it. A scan that read no blocks — the first one unindexed, or a
    stop before the first batch — wrote that block as scanned. The next scan
    began one above it and the block was skipped for good.

 2. It could go BACKWARDS. A deliberate rescan of earlier blocks rewound it to
    the end of that range, so the next scan redid everything above — hours on
    mainnet. That also made any "rescan older blocks" control a trap, which is
    why the phone did not offer one and the user had to edit the database.
"""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCAN = (ROOT / "helpers" / "scan.py").read_text()


def _fn(src: str, name: str) -> str:
    at = src.index(f"def {name}(")
    nxt = src.find("\nasync def ", at + 10)
    other = src.find("\ndef ", at + 10)
    cls = src.find("\nclass ", at + 10)
    ends = [i for i in (nxt, other, cls) if i != -1]
    return src[at:min(ends)] if ends else src[at:]


def test_nothing_is_claimed_scanned_before_anything_is():
    scan = _fn(SCAN, "_scan_wallet")
    assert "last_scanned_height = start - 1" in scan, (
        "starting at `start` claims the first block was looked at before "
        "anything looked at it"
    )
    assert "last_scanned_height = start\n" not in scan


def test_the_resume_point_only_moves_forward():
    body = _fn(SCAN, "set_last_scan_height")
    # The guard is in the statement, so two scans finishing at once cannot
    # have the slower one's older value land last.
    assert "last_scan_height < :height" in body
    assert "last_scan_height IS NULL" in body, (
        "a wallet that has never scanned has NULL here, and NULL < x is NULL"
    )
    assert "WHERE id = :id" in body


def test_a_rescan_of_older_blocks_cannot_undo_newer_ones():
    """The property the phone's rescan control depends on. Expressed against
    the statement, since there is no database here: an UPDATE that can only
    raise the value cannot lower it, whatever range was scanned."""
    body = _fn(SCAN, "set_last_scan_height")
    sql = body[body.index('"UPDATE'):]
    assert "SET last_scan_height = :height" in sql
    # No unguarded write anywhere in the module.
    assert SCAN.count("SET last_scan_height = :height") == 1
    assert "NEVER BACKWARDS" in body


def test_the_hold_at_a_gap_still_holds():
    """These two changes must not disturb the other rule: a block that could
    not be read stops the resume point advancing, so it is looked at again."""
    scan = _fn(SCAN, "_scan_wallet")
    assert "if scan_gap_height is None:\n                last_scanned_height = h" in scan
    # And with the off-by-one fixed, an immediate gap now leaves the resume
    # point BELOW the unread block rather than on it.
    assert "last_scanned_height = start - 1" in scan
