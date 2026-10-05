"""Turning a date into a block height, over years rather than days.

The phone's rescan chooser asks WHEN and the scan endpoint takes heights. Over
a few days the height can be estimated off the tip — ten minutes a block,
round up, error of a handful. Over years it cannot: at a planning rate of nine
minutes a block, five years back overshoots by roughly twenty thousand blocks,
about five months. For a window seven days wide that is not a rounding error,
it is the wrong window, and the scan would report "nothing found" about blocks
it never read — which is the exact failure the rescan exists to undo.

So helpers/blocktime.py bisects the explorer's block timestamps. The search is
pure functions over (low, high, probe) so it runs here with no network, and
the fetch is the thin shell around it.

THE DIRECTION IS THE WHOLE POINT. When no block sits exactly on the date, the
answer must be EARLIER rather than later: a window starting before the chosen
day still contains it, one starting after it does not. Bitcoin block
timestamps are not monotonic either — a block may carry a time up to two hours
before its parent's, since consensus only constrains median-time-past — so the
search steps back over a slack of blocks rather than trusting the bisection to
land exactly.
"""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "silnt_blocktime_under_test", ROOT / "helpers" / "blocktime.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BT = _load()

# Ten minutes a block from a round start, which is what a well-behaved chain
# looks like. The search must not depend on the spacing being this tidy — see
# the jitter and the non-monotonic cases below.
GENESIS_TS = 1_600_000_000
SPACING = 600


def chain(low: int, high: int, spacing: int = SPACING):
    """A fetcher over a synthetic chain, counting its probes."""
    probes: list = []

    async def block_time(h: int) -> int:
        probes.append(h)
        if h < low or h > high:
            return 0
        return GENESIS_TS + (h - low) * spacing

    return block_time, probes


def find(target_ts, low, high, fetcher):
    return asyncio.run(BT.height_at(target_ts, low, high, fetcher))


# ── the bisection itself ─────────────────────────────────────────────────────


def test_narrow_keeps_the_answer_between_the_bounds():
    """`low` is always at or before the answer and `high` at or after it, so
    the loop can only end on the first block at or after the target."""
    # A probe EARLIER than the target cannot be the answer, so low moves past
    # it.
    assert BT.narrow(100, 200, 150, 500, 900) == (151, 200)
    # A probe at or after the target might BE the answer, so high keeps it.
    assert BT.narrow(100, 200, 150, 900, 900) == (100, 150)
    assert BT.narrow(100, 200, 150, 1000, 900) == (100, 150)


def test_the_probe_always_shrinks_the_span():
    """A midpoint that rounded the wrong way would spin on a two-block span."""
    for low, high in ((0, 1), (5, 6), (100, 101), (0, 2), (10, 1_000_000)):
        mid = BT.probe_height(low, high)
        assert low <= mid < high, (low, high, mid)


def test_the_whole_of_mainnet_is_about_twenty_probes():
    """The cost of looking it up, stated. This is why it is affordable for an
    action somebody took deliberately, and not for one on every render."""
    steps = BT.search_steps(1, 900_000)
    assert 19 <= steps <= 21, steps
    assert steps < BT.MAX_SEARCH_STEPS


# ── what it finds ────────────────────────────────────────────────────────────


def test_an_exact_timestamp_finds_its_own_block():
    f, _ = chain(100, 1_100)
    # Block 600 is 500 spacings in.
    got = find(GENESIS_TS + 500 * SPACING, 100, 1_100, f)
    assert got == 600 - BT.TIMESTAMP_SLACK_BLOCKS, got


def test_a_timestamp_between_blocks_lands_before_it_never_after():
    """The one rule. A window starting before the chosen day contains it; one
    starting after it does not."""
    f, _ = chain(100, 1_100)
    for offset in (1, 59, 300, 599):
        target = GENESIS_TS + 500 * SPACING + offset
        got = find(target, 100, 1_100, f)
        assert got is not None
        # Whatever it answers, the block it names is at or before the target.
        assert GENESIS_TS + (got - 100) * SPACING <= target, (offset, got)


def test_the_slack_is_subtracted_and_never_below_the_floor():
    """Block timestamps are not monotonic, so the bisection can land a block
    or two late. Stepping back absorbs that — and must not walk out of the
    indexed range doing it."""
    f, _ = chain(100, 1_100)
    got = find(GENESIS_TS, 100, 1_100, f)
    assert got == 100, got
    assert BT.back_off(105, 100) == 100
    assert BT.back_off(1_000, 100) == 1_000 - BT.TIMESTAMP_SLACK_BLOCKS


def test_a_date_before_the_indexed_range_is_the_floor():
    f, _ = chain(100, 1_100)
    assert find(GENESIS_TS - 10 * 86_400, 100, 1_100, f) == 100


def test_a_date_after_the_tip_is_the_tip_less_the_slack():
    """Clamped by the endpoint, which reports that it clamped. Here the search
    simply runs out of chain."""
    f, _ = chain(100, 1_100)
    got = find(GENESIS_TS + 10_000 * SPACING, 100, 1_100, f)
    assert got == 1_100 - BT.TIMESTAMP_SLACK_BLOCKS, got


def test_jittery_spacing_still_lands_at_or_before():
    """Real blocks are not evenly spaced. Built monotonic but irregular."""
    times = {}
    t = GENESIS_TS
    for h in range(100, 2_101):
        times[h] = t
        t += 120 + (h * 7919) % 1_500  # 2 to 27 minutes, deterministic

    async def f(h):
        return times.get(h, 0)

    for want_h in (250, 800, 1_500, 2_000):
        target = times[want_h]
        got = find(target, 100, 2_100, f)
        assert got is not None
        assert times[got] <= target, (want_h, got)
        # And not uselessly early: within the slack of the real block.
        assert got >= want_h - BT.TIMESTAMP_SLACK_BLOCKS - 1, (want_h, got)


def test_a_block_that_goes_backwards_in_time_does_not_land_late():
    """The consensus rule is median-time-past, so a block may carry a time up
    to two hours before its parent's. A bisection over a non-monotonic
    sequence can overshoot by a block or two; the slack is what covers it."""
    times = {}
    t = GENESIS_TS
    for h in range(0, 2_001):
        # Every 50th block reports an hour early.
        times[h] = t - 3_600 if h % 50 == 0 else t
        t += SPACING

    async def f(h):
        return times.get(h, 0)

    for want_h in (500, 1_000, 1_501):
        got = find(times[want_h], 0, 2_000, f)
        assert got is not None
        assert got <= want_h, (want_h, got)


# ── when it cannot answer ────────────────────────────────────────────────────


def test_an_unreadable_probe_gives_up_rather_than_guessing():
    """Half an answer is a window in the wrong place. The endpoint turns this
    into a 503 and the client keeps its day unresolved."""
    async def dead(_h):
        return 0

    assert find(GENESIS_TS, 100, 1_100, dead) is None


def test_an_inverted_range_is_no_answer():
    f, _ = chain(100, 1_100)
    assert find(GENESIS_TS, 1_100, 100, f) is None


def test_a_single_block_range_needs_no_probe():
    f, probes = chain(500, 500)
    assert find(GENESIS_TS, 500, 500, f) == 500
    assert probes == [], probes


def test_the_probe_count_is_bounded():
    """A guard against a pathological explorer, not a real limit."""
    assert BT.MAX_SEARCH_STEPS > BT.search_steps(1, 10_000_000)


def test_clamp_holds_both_ends():
    assert BT.clamp(50, 100, 200) == 100
    assert BT.clamp(250, 100, 200) == 200
    assert BT.clamp(150, 100, 200) == 150


# ── the endpoints that use it ────────────────────────────────────────────────

API = (ROOT / "views_api.py").read_text()


def _endpoint(path: str) -> str:
    at = API.index(f'"{path}"')
    return API[at : API.index("@silnt_api_router", at + 10)]


def test_the_height_endpoint_takes_a_moment_not_a_date():
    """A date is only a date in somebody's timezone. The client resolves its
    own local midnight and sends the unix second, so nothing here has to guess
    where the phone is."""
    body = _endpoint("/api/v1/blocks/height-at")
    assert "ts: int = Query(" in body, body
    assert "YYYY" not in body, body


def test_the_height_endpoint_refuses_rather_than_estimates():
    """A window in the wrong place reports nothing found about blocks it never
    read, so an explorer that cannot answer is a 503 and not a guess."""
    body = _endpoint("/api/v1/blocks/height-at")
    assert "SERVICE_UNAVAILABLE" in body, body
    assert "height_at(" in body, body
    # No fallback arithmetic anywhere in it.
    assert "600" not in body and "144" not in body, body


def test_the_height_endpoint_clamps_and_says_so():
    """So a client can tell "this is your date" from "this is as far back as
    there is"."""
    body = _endpoint("/api/v1/blocks/height-at")
    assert "clamp(found, min_height, tip)" in body, body
    assert '"clamped": height != found' in body, body


def test_the_range_endpoint_gives_both_ends_with_their_dates():
    """The floor on "when" is the oldest block the oracle holds, not a fixed
    number of days."""
    body = _endpoint("/api/v1/blocks/indexed-range")
    for field in ("min_height", "min_time", "tip", "tip_time"):
        assert f'"{field}"' in body, f"{field} missing from the range"


def test_both_endpoints_require_the_network_explicitly():
    """The same rule as /api/v1/config: a mainnet build must not be served
    signet's min_scan_height."""
    for path in ("/api/v1/blocks/indexed-range", "/api/v1/blocks/height-at"):
        body = _endpoint(path)
        assert "network: Optional[str] = Query(None)" in body, path
        assert "`network` query parameter is required" in body, path


def test_both_endpoints_need_a_trusted_device():
    for path in ("/api/v1/blocks/indexed-range", "/api/v1/blocks/height-at"):
        assert "require_trusted_device" in _endpoint(path), path


def test_the_block_time_fetch_works_against_plain_esplora():
    """mempool.space has a one-call timestamp endpoint and an instance may be
    pointed at a self-hosted esplora, which does not. Two hops, so either
        works."""
    scan = (ROOT / "helpers" / "scan.py").read_text()
    at = scan.index("async def get_block_time(")
    body = scan[at : scan.index("\nasync def ", at + 10)]
    assert "/api/block-height/" in body, body
    assert "/api/block/" in body, body
    # Cached: a block's timestamp cannot change, and the bisection re-probes
    # the same midpoints on every search over the same range.
    assert "_BLOCK_TIME_CACHE" in body, body
    assert "_trim_block_time_cache()" in body, body
    # The pooled, TLS-verifying client, not the oracle's.
    assert "get_mempool_client()" in body, body
