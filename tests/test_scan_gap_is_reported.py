"""A scan that skipped a block must not report a finished one.

WHAT HAPPENED. A mainnet wallet's Silent Payments change never appeared. The
log said `oracle has not indexed block X`, and then `block X could not be
read, so the resume point was held` — which is correct and careful. The app
showed the wallet scanned to the tip with nothing left to do, and offered no
way back to block X.

Both were true at once. The counters reach their total whether or not every
block could be read: the unreadable one is skipped, the blocks above it are
still scanned, `blocks_scanned` still reaches `total_blocks`, and the bar
still fills. Meanwhile `last_scan_height` is held BELOW the gap so the block
is looked at again. So the scan says complete, the resume point says it is
not, and the only thing that could reconcile them — which block was missed —
was in a log nobody reading the app can see.

So the gap travels with the progress record, which is what the app polls.
"""

from __future__ import annotations

import ast
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


def test_the_progress_record_carries_the_gap():
    body = _fn(SCAN, "set_scan_progress")
    assert '"gap": gap' in body
    # Default None, so a caller that does not know cannot accidentally clear a
    # gap by writing progress without one... and so every writer must pass it.
    assert "gap=None" in body


def test_a_wallet_with_no_scan_reports_no_gap():
    """The default record the endpoint returns has to have the key, or the
    clients read undefined and treat it as "no gap" by luck rather than by
    contract."""
    body = _fn(SCAN, "get_scan_progress")
    assert '"gap": None' in body


def test_every_progress_write_after_the_first_passes_the_gap():
    """A single writer that forgets it CLEARS the gap: the record is replaced
    wholesale, so the next poll says the scan came back clean.

    The first write is the exception and has to be. It happens before the
    block loop, where a fresh scan has not found a gap yet — starting clean is
    how a gap that has since been indexed stops being reported."""
    scan = _fn(SCAN, "_scan_wallet")
    writes = scan.count("set_scan_progress(")
    with_gap = scan.count("gap=scan_gap_height")
    assert writes >= 4, writes
    assert writes - 1 == with_gap, (
        f"{writes} progress writes in _scan_wallet, {with_gap} pass the gap"
    )
    # And the one without it is the opener, not a later write that would wipe
    # a gap the scan had already found.
    first = scan.index("set_scan_progress(")
    assert "gap=" not in scan[first:scan.index(")", first)]
    assert first < scan.index("for batch_start in range("), (
        "the only write without a gap must be the one before the block loop"
    )


def test_the_resume_point_is_still_held_below_the_gap():
    """The careful half, which was always right and must stay. Advancing past
    an unread block marks it scanned without having looked at it, and any
    payment in it is then invisible until somebody rescans by hand."""
    scan = _fn(SCAN, "_scan_wallet")
    assert "if scan_gap_height is None:\n                    scan_gap_height = h" in scan
    assert "if scan_gap_height is None:\n                last_scanned_height = h" in scan


def test_the_log_separates_the_two_reasons_a_block_is_unreadable():
    """One clears itself and one never will, and they need different things
    from whoever reads the log. A block the oracle has not reached yet is a
    wait; a block below where it began indexing is a re-index, and no amount
    of rescanning helps."""
    scan = _fn(SCAN, "_scan_wallet")
    assert "behind_tip = scan_gap_height >= last_scanned_height" in scan
    assert "clears itself" in scan
    assert "re-indexed" in scan


def test_not_indexed_is_still_distinct_from_empty():
    """The distinction underneath all of this: an unindexed block and a block
    that really holds nothing are not the same, and treating them alike is how
    a scanner marks a block scanned without having looked at it."""
    assert "class BlockNotIndexedError" in SCAN
    body = SCAN[SCAN.index("class BlockNotIndexedError"):]
    assert "oracle has not indexed block" in body
