"""Turning a date into a block height, and back.

The phone's rescan chooser asks the user WHEN, and the scan endpoint takes
heights. Over a few days a height can be estimated from the tip — ten minutes
a block, round up, and the error is a handful of blocks. Over years it cannot:
at a planning rate of nine minutes a block, five years back overshoots the
real height by roughly twenty thousand blocks, about five months. For a scan
window seven days wide that is not a rounding error, it is the wrong window
entirely, and it would report "nothing found" about blocks it never read.

So the height is LOOKED UP, by binary search over the explorer's block
timestamps. log2 of the indexed span is twenty-odd requests on mainnet, on a
pooled keep-alive connection, for an action a person took deliberately.

The search lives in `search_steps`/`narrow` as pure functions over
(low, high, probe timestamp) so the bisection can be tested without a network,
and `height_at` is the thin shell that fetches.

ONE THING THE SEARCH MUST NOT DO: return a height whose block is EARLIER than
the date asked for, when an exact match does not exist. A window starting
before the chosen day still contains it; a window starting after it does not.
So this answers with the FIRST block at or after the timestamp, and the caller
clamps that into the indexed range.
"""

from __future__ import annotations

from typing import Optional

from loguru import logger


# Bitcoin block timestamps are not monotonic — a block may carry a time up to
# two hours before its parent's (the consensus rule is only median-time-past),
# so a plain bisection on a non-monotonic sequence can walk past the answer by
# a block or two. The slack is absorbed by searching for the first block at or
# after the target and then stepping BACK this many blocks, which is cheap
# (the window is seven days wide) and cannot land late.
TIMESTAMP_SLACK_BLOCKS = 12

# A bisection over the whole of mainnet is 20 steps. The cap is a guard
# against a pathological explorer, not a real limit.
MAX_SEARCH_STEPS = 48


def narrow(low: int, high: int, probe: int, probe_ts: int, target_ts: int) -> tuple:
    """One bisection step: the new (low, high) after probing `probe`.

    `low` is always a height known to be at or before the answer and `high`
    one known to be at or after it, so the loop ends with low == high on the
    first block at or after `target_ts`.
    """
    if probe_ts < target_ts:
        return (probe + 1, high)
    return (low, probe)


def search_steps(low: int, high: int) -> int:
    """How many probes a bisection of this span needs. For tests and logging."""
    steps = 0
    while low < high:
        low = low + (high - low) // 2 + 1
        steps += 1
    return steps


def probe_height(low: int, high: int) -> int:
    """The midpoint, biased low so the loop always shrinks."""
    return low + (high - low) // 2


def back_off(height: int, floor: int) -> int:
    """Step back over the timestamp slack, without going below the floor."""
    return max(floor, height - TIMESTAMP_SLACK_BLOCKS)


def clamp(height: int, low: int, high: int) -> int:
    return max(low, min(high, height))


async def height_at(
    target_ts: int,
    low: int,
    high: int,
    block_time,
) -> Optional[int]:
    """First block at or after `target_ts`, searched within [low, high].

    `block_time` is an awaitable height -> unix seconds (or None when the
    explorer cannot say). A probe that cannot be read aborts the search rather
    than being guessed at: half an answer here is a window in the wrong place.
    """
    if low > high:
        return None
    lo, hi, steps = int(low), int(high), 0
    while lo < hi:
        steps += 1
        if steps > MAX_SEARCH_STEPS:
            logger.warning(f"height_at: gave up after {steps} probes")
            return None
        mid = probe_height(lo, hi)
        ts = await block_time(mid)
        if not ts:
            logger.warning(f"height_at: no timestamp for block {mid}")
            return None
        lo, hi = narrow(lo, hi, mid, int(ts), int(target_ts))
    return back_off(lo, int(low))
