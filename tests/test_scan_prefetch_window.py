"""The scan keeps several batches downloading ahead of the one it matches.

WHY. With the Rust matcher on 8 workers, 1,400 mainnet blocks scanned in 36s
and 13s of that was the loop waiting for a fetch: a batch took ~0.58s to
download and ~0.35s to match, so a lookahead of ONE batch could hide at most
0.35s of every 0.58s. (With one worker, matching took 1.0s a batch and the same
single batch of lookahead hid the fetch completely: 0.5s of fetch wait in 61s.)
A fetch longer than the match it overlaps needs more than one in flight.

What goes wrong quietly if this is undone is not an error: the scan still
finishes with the same answer, only slower, which is exactly why it is pinned.
"""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCAN = (ROOT / "helpers" / "scan.py").read_text()


def _scan_wallet() -> str:
    at = SCAN.index("async def _scan_wallet(")
    nxt = SCAN.find("\nasync def ", at + 10)
    return SCAN[at:nxt] if nxt != -1 else SCAN[at:]


def test_depth_is_a_bounded_setting_defaulting_above_one():
    body = _scan_wallet()
    assert '_env_int("SILNT_SCAN_PREFETCH_DEPTH", 3, 1, 8)' in body


def test_the_window_is_topped_up_after_a_batch_is_taken():
    body = _scan_wallet()
    assert "def top_up_prefetch(" in body
    assert "for ahead in range(1, PREFETCH_DEPTH + 1):" in body
    # Called once the batch's data is in hand, before matching it, so the
    # downloads run across the match.
    take = body.index("ready = prefetch.pop(batch_start, None)")
    top = body.index("top_up_prefetch(batch_start)")
    match = body.index("await match_range_batch(")
    assert take < top < match


def test_a_failed_range_drops_every_queued_fetch():
    """After a range error the loop falls back to per-block scanning and nothing
    will ever await what is queued: a task left running holds a connection and
    its result goes nowhere."""
    body = _scan_wallet()
    err = body.index("use_range = False\n                cancel_prefetch()")
    assert err > body.index("if data.error is not None:")


def test_a_stop_and_the_end_of_the_loop_cancel_the_window():
    body = _scan_wallet()
    assert body.count("cancel_prefetch()") >= 4
    assert "if should_stop(wallet_id):\n            return" in body  # no top-up once stopped


def test_a_batch_is_only_taken_if_it_is_the_one_asked_for():
    """A queued fetch keyed by batch_start must also carry its heights: taking
    the wrong batch's data would match one range's tweaks against another's
    and report the blocks scanned."""
    body = _scan_wallet()
    assert "if ready is not None and ready[0] == batch:" in body
    assert "prefetch: dict[int, tuple[list[int], asyncio.Task]] = {}" in body
