"""Tests for the range-endpoint scan path.

The thing worth proving is not that the range path is faster — that follows from
making one request instead of three hundred — but that it finds exactly what the
per-block path finds, and that when it cannot read a block it says so instead of
reporting the block as empty. An empty block and an unreadable one look the same
to everything downstream, and the difference is somebody's money.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from coincurve import PublicKey
from conftest import FAKE_DB, scan


def response(payload, status=200):
    return httpx.Response(
        status,
        json=payload,
        request=httpx.Request("GET", "http://oracle.example/test"),
    )


class RecordingClient(scan.BlindBitOracleClient):
    """An oracle client whose HTTP layer is a dictionary of canned responses.

    `delay` makes each response take that long, which is what lets a test tell
    concurrent requests from sequential ones: three 100ms requests take 100ms
    together and 300ms one after another.
    """

    def __init__(
        self,
        routes: dict[str, object],
        base_url="http://oracle.example",
        delay: float = 0.0,
    ):
        super().__init__(base_url)
        self.routes = routes
        self.delay = delay
        self.paths: list[str] = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def _get(self, path: str) -> httpx.Response:
        self.paths.append(path)
        self.stats.requests += 1
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            for prefix, payload in self.routes.items():
                if path.startswith(prefix):
                    if isinstance(payload, Exception):
                        raise payload
                    return response(payload)
            return response({"error": "not found"}, status=404)
        finally:
            self.in_flight -= 1


def all_range_routes(heights, tweak_hex=None, utxo=None):
    """Routes for every endpoint a batch fetches, so none of them 404s.

    A current oracle: it serves /range/compute-index, so the scanner takes the
    reverse-matching path. The compute-index entry is built from the same tweak
    and txid as the UTXO, because the reverse matcher joins them on txid.
    """
    entry = None
    if tweak_hex:
        entry = {
            "txid": (utxo or {}).get("txid", "00" * 32),
            "tweak": tweak_hex,
            "outputs": [(utxo or {}).get("pubkey", "")[:16]] if utxo else [],
        }
    return {
        "/range/compute-index": {
            "blocks": [block_entry(h, [entry] if entry else []) for h in heights]
        },
        "/range/tweaks": {
            "blocks": [
                block_entry(h, [tweak_hex] if tweak_hex else []) for h in heights
            ]
        },
        "/range/utxos": {
            "blocks": [block_entry(h, [utxo] if utxo else []) for h in heights]
        },
        "/range/spent-outputs": {"blocks": [block_entry(h, []) for h in heights]},
    }


def legacy_range_routes(heights, tweak_hex=None, utxo=None):
    """An oracle from before /range/compute-index existed: that route 404s."""
    routes = all_range_routes(heights, tweak_hex, utxo)
    routes.pop("/range/compute-index")
    return routes


def block_entry(height: int, index: list) -> dict:
    return {
        "block_identifier": {
            "block_hash": f"{height:064x}",
            "block_height": height,
        },
        "index": index,
    }


# --- capability detection ---------------------------------------------------


@pytest.mark.asyncio
async def test_range_limit_read_from_info():
    client = RecordingClient({"/info": {"height": 500, "max_range_blocks": 100}})
    assert await client.get_range_limit() == 100


@pytest.mark.asyncio
async def test_range_limit_probed_only_once():
    client = RecordingClient({"/info": {"height": 500, "max_range_blocks": 100}})
    await client.get_range_limit()
    await client.get_range_limit()
    await client.get_range_limit()
    assert client.paths.count("/info") == 1


@pytest.mark.asyncio
async def test_oracle_without_range_support_reports_zero():
    # An older oracle: /info has no max_range_blocks at all.
    client = RecordingClient({"/info": {"height": 500}})
    assert await client.get_range_limit() == 0


@pytest.mark.asyncio
async def test_unreachable_info_reports_zero_rather_than_raising():
    # Falling back to per-block scanning is correct; failing the scan is not.
    client = RecordingClient({"/info": httpx.ConnectError("refused")})
    assert await client.get_range_limit() == 0


# --- range parsing ----------------------------------------------------------


@pytest.mark.asyncio
async def test_tweaks_range_keyed_by_height():
    tweak_a = "02" + "11" * 32
    tweak_b = "03" + "22" * 32
    client = RecordingClient(
        {
            "/range/tweaks": {
                "blocks": [
                    block_entry(100, [tweak_a]),
                    block_entry(101, []),
                    block_entry(102, [tweak_a, tweak_b]),
                ]
            }
        }
    )

    got = await client.get_tweaks_range(100, 102)
    assert set(got) == {100, 101, 102}
    assert got[100] == [bytes.fromhex(tweak_a)]
    assert got[101] == []
    assert got[102] == [bytes.fromhex(tweak_a), bytes.fromhex(tweak_b)]


@pytest.mark.asyncio
async def test_truncated_range_response_raises():
    """The oracle truncates a stream it could not finish, so it fails to parse.

    That must surface as an exception. If it came back as an empty or partial
    block list, the scanner would mark the missing blocks scanned.
    """
    client = scan.BlindBitOracleClient("http://oracle.example")

    async def _truncated(path):
        return httpx.Response(
            200,
            content=b'{"blocks":[{"block_identifier":{"block_height":100},"index":[]}',
            request=httpx.Request("GET", "http://oracle.example" + path),
        )

    client._get = _truncated

    # httpx raises json.JSONDecodeError, which is a ValueError.
    with pytest.raises(ValueError):
        await client.get_tweaks_range(100, 110)


# --- scanning a range -------------------------------------------------------

SCAN_SECRET = bytes.fromhex(
    "0101010101010101010101010101010101010101010101010101010101010101"
)
SPEND_SECRET = bytes.fromhex(
    "0202020202020202020202020202020202020202020202020202020202020202"
)
SPEND_PUB = PublicKey.from_secret(SPEND_SECRET).format(compressed=True)


def payment_to_us(tweak_secret: bytes) -> tuple[str, str]:
    """Build a real BIP-352 payment to (SCAN_SECRET, SPEND_PUB).

    Returns (tweak_hex, output_pubkey_hex) as the oracle would serve them.
    Derived with the module's own primitives so the test states the protocol
    once and the scanner has to agree with it.
    """
    tweak = PublicKey.from_secret(tweak_secret).format(compressed=True)
    shared = scan.create_shared_secret(tweak, SCAN_SECRET)
    output_pub, _ = scan.create_output_pub_key_and_tweak(shared, SPEND_PUB, 0)
    return tweak.hex(), output_pub.hex()


@pytest.mark.asyncio
async def test_range_scan_finds_a_real_payment():
    tweak_hex, output_hex = payment_to_us(b"\x33" * 32)
    txid = "ab" * 32

    client = RecordingClient(
        {
            "/range/tweaks": {"blocks": [block_entry(100, [tweak_hex])]},
            "/range/utxos": {
                "blocks": [
                    block_entry(
                        100,
                        [
                            {
                                "txid": txid,
                                "vout": 1,
                                "amount": 123_456,
                                "pubkey": output_hex,
                                "timestamp": 1_700_000_000,
                            }
                        ],
                    )
                ]
            },
        }
    )

    results = await scan.scan_blocks_range(
        [100], client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )

    assert len(results) == 1
    owned = results[0]
    assert not isinstance(owned, Exception), owned
    assert len(owned) == 1, "the payment was not detected"
    assert owned[0].txid.hex() == txid
    assert owned[0].vout == 1
    assert owned[0].amount == 123_456
    assert owned[0].pub_key.hex() == output_hex


@pytest.mark.asyncio
async def test_range_scan_matches_per_block_scan():
    """The two paths must agree, because only one of them is exercised in prod."""
    tweak_hex, output_hex = payment_to_us(b"\x44" * 32)
    txid = "cd" * 32
    utxo = {
        "txid": txid,
        "vout": 0,
        "amount": 5_000,
        "pubkey": output_hex,
        "timestamp": 1_700_000_000,
    }

    range_client = RecordingClient(
        {
            "/range/tweaks": {"blocks": [block_entry(100, [tweak_hex])]},
            "/range/utxos": {"blocks": [block_entry(100, [utxo])]},
        }
    )
    per_block_client = RecordingClient(
        {
            "/tweaks/100": {"index": [tweak_hex]},
            "/utxos/100": {"index": [utxo]},
        }
    )

    from_range = (
        await scan.scan_blocks_range(
            [100], range_client, SCAN_SECRET, SPEND_PUB, [], "signet"
        )
    )[0]
    from_block = await scan.scan_block(
        100, per_block_client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )

    assert [
        (o.txid, o.vout, o.amount, o.pub_key, o.priv_key_tweak) for o in from_range
    ] == [(o.txid, o.vout, o.amount, o.pub_key, o.priv_key_tweak) for o in from_block]


@pytest.mark.asyncio
async def test_block_absent_from_range_is_an_error_not_an_empty_block():
    """The distinction the whole design rests on.

    Height 101 is missing from the response, meaning the oracle never indexed
    it. Reporting [] would let the caller record it as scanned.
    """
    client = RecordingClient(all_range_routes([100, 102]))

    results = await scan.scan_blocks_range(
        [100, 101, 102], client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )

    assert results[0] == []
    assert isinstance(results[1], scan.BlockNotIndexedError)
    assert results[1].height == 101
    assert results[2] == []


@pytest.mark.asyncio
async def test_a_hundred_blocks_cost_three_requests():
    """The reason the endpoints exist: 100 blocks used to be 300 requests.

    Three, not four: the compute index replaces the tweaks request rather than
    adding to it.
    """
    tweak_hex, _ = payment_to_us(b"\x55" * 32)
    heights = list(range(1000, 1100))
    utxo = {
        "txid": "ee" * 32,
        "vout": 0,
        "amount": 1,
        "pubkey": "ff" * 32,
        "timestamp": 1,
    }

    client = RecordingClient(all_range_routes(heights, tweak_hex, utxo))

    await scan.scan_blocks_range(heights, client, SCAN_SECRET, SPEND_PUB, [], "signet")

    assert len(client.paths) == 3, client.paths
    assert client.stats.blocks == 100


@pytest.mark.asyncio
async def test_batch_requests_are_issued_concurrently():
    """The three requests do not depend on each other, so they go out together.

    Serialising them was half of a real regression: a batch that waits for the
    tweaks before asking for the UTXOs pays a round trip it does not need to,
    on every batch, and on a busy chain that is not small.
    """
    heights = list(range(100, 110))
    delay = 0.1
    client = RecordingClient(all_range_routes(heights), delay=delay)

    started = time.perf_counter()
    await scan.fetch_range_batch(heights, client)
    elapsed = time.perf_counter() - started

    assert len(client.paths) == 3, client.paths
    assert (
        client.max_in_flight == 3
    ), f"peak concurrency was {client.max_in_flight}; the requests ran in sequence"
    # Sequential would be 3 * delay. Generous bound so a slow machine does not
    # make this flaky, while still failing outright on serialisation.
    assert elapsed < delay * 2, f"{elapsed:.3f}s for three {delay}s requests"


@pytest.mark.asyncio
async def test_matching_issues_no_requests():
    """What makes the pipeline possible.

    The scan loop prefetches batch N+1 while batch N matches. That only
    overlaps anything if matching is pure computation — if it reaches back to
    the oracle mid-match, the two stages serialise again and the wall clock
    goes back to being their sum. This is the structural guard on that.
    """
    tweak_hex, output_hex = payment_to_us(b"\x66" * 32)
    heights = [100, 101]
    utxo = {
        "txid": "ab" * 32,
        "vout": 0,
        "amount": 7,
        "pubkey": output_hex,
        "timestamp": 1_700_000_000,
    }
    client = RecordingClient(all_range_routes(heights, tweak_hex, utxo))

    data = await scan.fetch_range_batch(heights, client)
    requests_after_fetch = len(client.paths)

    results = await scan.match_range_batch(
        data, client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )

    assert len(client.paths) == requests_after_fetch, (
        f"matching made {len(client.paths) - requests_after_fetch} oracle "
        f"request(s): {client.paths[requests_after_fetch:]}"
    )
    # And it still found the payments, so the guard is not vacuous.
    assert all(len(r) == 1 for r in results), results


@pytest.mark.asyncio
async def test_prefetch_overlaps_matching():
    """A batch's fetch runs while the previous batch is still matching.

    Modelled directly: start the next fetch, then do the (blocking) match, and
    check the fetch finished during it rather than after. This is the shape the
    scan loop implements.
    """
    tweak_hex, output_hex = payment_to_us(b"\x77" * 32)
    heights = [100, 101]
    utxo = {
        "txid": "cd" * 32,
        "vout": 0,
        "amount": 9,
        "pubkey": output_hex,
        "timestamp": 1_700_000_000,
    }
    routes = all_range_routes(heights, tweak_hex, utxo)

    prefetch_client = RecordingClient(routes, delay=0.15)
    match_client = RecordingClient(routes)
    data = await scan.fetch_range_batch(heights, match_client)

    started = time.perf_counter()
    prefetch = asyncio.create_task(scan.fetch_range_batch(heights, prefetch_client))
    await scan.match_range_batch(
        data, match_client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )
    await prefetch
    elapsed = time.perf_counter() - started

    # Sequential would be the match plus the full 0.15s fetch. Overlapped, the
    # total is bounded by the slower of the two.
    assert elapsed < 0.3, f"{elapsed:.3f}s — the prefetch did not overlap the match"


@pytest.mark.asyncio
async def test_empty_height_list_is_harmless():
    client = RecordingClient({})
    results = await scan.scan_blocks_range(
        [], client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )
    assert results == []
    assert client.paths == []


# --- spent outputs ----------------------------------------------------------


@pytest.mark.asyncio
async def test_spent_outputs_use_one_request_when_ranges_are_available():
    heights = list(range(200, 260))
    client = RecordingClient(
        {
            "/info": {"height": 300, "max_range_blocks": 100},
            "/range/spent-outputs": {
                "blocks": [block_entry(h, ["aa" * 8]) for h in heights]
            },
        }
    )

    got = await scan._fetch_spent_outputs(client, heights)

    assert set(got) == set(heights)
    assert got[200] == {"aa" * 8}
    range_calls = [p for p in client.paths if p.startswith("/range/spent-outputs")]
    assert len(range_calls) == 1, client.paths


@pytest.mark.asyncio
async def test_spent_outputs_fall_back_to_per_block():
    heights = [200, 201]
    routes = {"/info": {"height": 300}}  # no range support
    for h in heights:
        routes[f"/spent-outputs/{h}"] = {"index": ["bb" * 8]}
    client = RecordingClient(routes)

    got = await scan._fetch_spent_outputs(client, heights)

    assert got == {200: {"bb" * 8}, 201: {"bb" * 8}}
    assert sum(p.startswith("/spent-outputs/") for p in client.paths) == 2


@pytest.mark.asyncio
async def test_spent_outputs_range_failure_falls_back_rather_than_raising():
    heights = [200, 201]
    routes = {
        "/info": {"height": 300, "max_range_blocks": 100},
        "/range/spent-outputs": httpx.ConnectError("boom"),
    }
    for h in heights:
        routes[f"/spent-outputs/{h}"] = {"index": ["cc" * 8]}
    client = RecordingClient(routes)

    got = await scan._fetch_spent_outputs(client, heights)

    assert got == {200: {"cc" * 8}, 201: {"cc" * 8}}


@pytest.mark.asyncio
async def test_owned_utxo_query_runs_once_per_batch_not_once_per_block():
    """This query does not depend on the height.

    It used to sit inside the per-height coroutine, so a batch issued one
    identical query per block. At the batch sizes the range endpoints make
    practical that is a hundred round trips to learn the same thing.
    """
    heights = list(range(300, 400))
    client = RecordingClient(
        {
            "/info": {"height": 500, "max_range_blocks": 100},
            "/range/spent-outputs": {"blocks": [block_entry(h, []) for h in heights]},
        }
    )

    FAKE_DB.fetchall_calls.clear()
    FAKE_DB.rows = [{"txid": "ab" * 32, "vout": 0, "pub_key": "dd" * 32}]

    await scan.mark_spent_utxos_batch(
        heights, client, "wallet-1", {"ab" * 32 + ":0": {}}, "signet"
    )

    utxo_queries = [q for q, _ in FAKE_DB.fetchall_calls if "FROM silnt.utxos" in q]
    assert (
        len(utxo_queries) == 1
    ), f"{len(utxo_queries)} identical queries for {len(heights)} blocks"


# --- oracle generations -----------------------------------------------------


@pytest.mark.asyncio
async def test_current_oracle_uses_compute_index_and_not_tweaks():
    """With the route available, the scanner takes the reverse-matching path."""
    tweak_hex, output_hex = payment_to_us(b"\x88" * 32)
    utxo = {
        "txid": "ab" * 32,
        "vout": 0,
        "amount": 4_200,
        "pubkey": output_hex,
        "timestamp": 1_700_000_000,
    }
    client = RecordingClient(all_range_routes([100], tweak_hex, utxo))

    data = await scan.fetch_range_batch([100], client)

    assert data.compute_index is not None, "compute index was not used"
    assert not any(p.startswith("/range/tweaks") for p in client.paths), client.paths

    results = await scan.match_range_batch(
        data, client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )
    assert len(results[0]) == 1, "the payment was not detected on the reverse path"
    assert results[0][0].amount == 4_200


@pytest.mark.asyncio
async def test_oracle_without_compute_index_falls_back_to_tweaks():
    """An older oracle 404s the route; the scan continues on forward matching."""
    tweak_hex, output_hex = payment_to_us(b"\x99" * 32)
    utxo = {
        "txid": "cd" * 32,
        "vout": 1,
        "amount": 777,
        "pubkey": output_hex,
        "timestamp": 1_700_000_000,
    }
    client = RecordingClient(legacy_range_routes([100], tweak_hex, utxo))

    data = await scan.fetch_range_batch([100], client)

    assert data.error is None, data.error
    assert data.compute_index is None
    assert data.tweaks is not None, "no tweaks fetched after the 404"
    assert any(p.startswith("/range/tweaks") for p in client.paths), client.paths

    results = await scan.match_range_batch(
        data, client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )
    assert len(results[0]) == 1, "the payment was not detected on the fallback path"
    assert results[0][0].amount == 777


@pytest.mark.asyncio
async def test_compute_index_probe_happens_once_per_client():
    """After a 404 the scanner stops asking, rather than paying for it per batch."""
    client = RecordingClient(legacy_range_routes(list(range(100, 120))))

    await scan.fetch_range_batch(list(range(100, 110)), client)
    first = sum(1 for p in client.paths if p.startswith("/range/compute-index"))
    await scan.fetch_range_batch(list(range(110, 120)), client)
    second = sum(1 for p in client.paths if p.startswith("/range/compute-index"))

    assert first == 1, f"probed {first} times in the first batch"
    assert second == 1, f"probed again on the second batch (total {second})"


# --- the phase line has to say which path ran -------------------------------


def test_phases_names_the_per_block_path_and_does_not_claim_free_matching():
    """A scan that fell back must not read as a scan with fast matching.

    The reported symptom that made this necessary: `match 0.0s` on a scan that
    had silently dropped to the per-block path. The zero was accurate — the
    counter is only touched on the range path — but read as "matching cost
    nothing", which is the opposite of the truth.
    """
    stats = scan.OracleStats()
    stats.blocks = 3292
    stats.wall_seconds = 414.1
    stats.fetch_seconds = 391.1
    stats.match_seconds = 3970.8  # summed over a single-threaded executor
    stats.spent_seconds = 20.6
    stats.persist_seconds = 1.5
    stats.used_range = False

    line = stats.phases()

    assert "PER-BLOCK" in line, line
    assert "not separable" in line, line
    assert (
        "match 0.0s" not in line
    ), f"still claims matching was free on the per-block path: {line}"
    # The EC figure exceeds the wall clock; it must be labelled, not presented
    # as a duration.
    assert "summed across waiters" in line, line
    assert "queued" in line, line


def test_phases_names_the_range_path():
    stats = scan.OracleStats()
    stats.blocks = 119
    stats.wall_seconds = 23.0
    stats.fetch_seconds = 2.0
    stats.match_batch_seconds = 19.0
    stats.match_seconds = 18.5
    stats.used_range = True
    stats.used_compute_index = True

    line = stats.phases()
    assert "range+compute-index" in line, line
    assert "fetch-wait 2.0s" in line, line
    assert "match 19.0s" in line, line
    assert "queued" not in line, line


def test_phases_distinguishes_range_with_and_without_compute_index():
    stats = scan.OracleStats()
    stats.wall_seconds = 10.0
    stats.used_range = True
    stats.used_compute_index = False
    assert "range+tweaks" in stats.phases()


def test_as_dict_reports_the_path():
    stats = scan.OracleStats()
    stats.used_range = True
    stats.used_compute_index = True
    d = stats.as_dict()
    assert d["used_range"] is True
    assert d["used_compute_index"] is True


# --- the phase line has to say which MATCHER ran ----------------------------
#
# used_compute_index says the index was FETCHED. SILNT_SCAN_FORWARD_MATCH
# changes the matcher without changing a single request, so a scan with the
# switch left on printed a phase line identical to one without it while costing
# several times as much. The matcher is the expensive choice; it has to be in
# the line.


def test_phases_names_the_matcher_and_the_label_count():
    stats = scan.OracleStats()
    stats.blocks = 7362
    stats.wall_seconds = 898.0
    stats.fetch_seconds = 2.9
    stats.match_batch_seconds = 886.4
    stats.match_seconds = 884.4
    stats.tweaks = 1_494_809
    stats.used_range = True
    stats.used_compute_index = True
    stats.matcher = "reverse"
    stats.labels = 4

    line = stats.phases()
    assert "matcher reverse" in line, line
    assert "4 labels" in line, line
    # 886.4s over 1,494,809 tweaks is 593us each — the number that says whether
    # the matching is behaving, and it should not have to be divided by hand.
    assert "593us/tweak" in line, line


def test_phases_distinguishes_the_two_matchers_on_the_same_path():
    """The bug this exists for: identical fetch path, different matcher."""
    def line_for(matcher):
        stats = scan.OracleStats()
        stats.wall_seconds = 100.0
        stats.used_range = True
        stats.used_compute_index = True
        stats.matcher = matcher
        stats.labels = 8
        return stats.phases()

    forward = line_for("forward (forced by SILNT_SCAN_FORWARD_MATCH)")
    reverse = line_for("reverse")

    assert "range+compute-index" in forward and "range+compute-index" in reverse
    assert forward != reverse, (
        "the two matchers print the same phase line, which is exactly the "
        "ambiguity this is meant to remove"
    )
    assert "SILNT_SCAN_FORWARD_MATCH" in forward, forward


def test_phases_admits_when_the_matcher_is_unknown():
    """A scan that matched nothing should not name a matcher it never ran."""
    stats = scan.OracleStats()
    stats.wall_seconds = 1.0
    stats.used_range = True
    assert "matcher unknown" in stats.phases()


@pytest.mark.asyncio
async def test_reverse_path_records_itself_as_the_matcher():
    tweak_hex, output_hex = payment_to_us(b"\x88" * 32)
    utxo = {
        "txid": "ab" * 32, "vout": 0, "amount": 4_200,
        "pubkey": output_hex, "timestamp": 1_700_000_000,
    }
    client = RecordingClient(all_range_routes([100], tweak_hex, utxo))
    data = await scan.fetch_range_batch([100], client)
    await scan.match_range_batch(data, client, SCAN_SECRET, SPEND_PUB, [], "signet")

    assert client.stats.matcher == "reverse", client.stats.matcher
    assert "matcher reverse" in client.stats.phases()


@pytest.mark.asyncio
async def test_forcing_forward_is_visible_in_the_stats_and_warned_about(
    monkeypatch, caplog
):
    """Turning the kill switch on must be loud and must show up in the timing.

    It is meant to be set for one scan to answer "is the reverse matcher losing
    outputs" and then unset. Left on, it silently multiplies every later scan's
    matching cost by roughly 0.63 + 0.28 per label.
    """
    tweak_hex, output_hex = payment_to_us(b"\x88" * 32)
    utxo = {
        "txid": "ab" * 32, "vout": 0, "amount": 4_200,
        "pubkey": output_hex, "timestamp": 1_700_000_000,
    }
    client = RecordingClient(all_range_routes([100], tweak_hex, utxo))
    data = await scan.fetch_range_batch([100], client)

    warnings: list[str] = []
    monkeypatch.setattr(scan, "_FORWARD_MATCH_ONLY", True)
    monkeypatch.setattr(scan, "_warned_forward_forced", False)
    monkeypatch.setattr(
        scan.logger, "warning", lambda msg, *a, **kw: warnings.append(str(msg))
    )

    results = await scan.match_range_batch(
        data, client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )

    # Forcing the matcher must not change what is found.
    assert len(results[0]) == 1, "forcing the forward matcher lost the payment"
    assert results[0][0].amount == 4_200

    assert client.stats.matcher.startswith("forward"), client.stats.matcher
    assert "SILNT_SCAN_FORWARD_MATCH" in client.stats.phases()
    assert warnings, "the switch changed the cost of the scan without saying so"
    assert "SILNT_SCAN_FORWARD_MATCH" in warnings[0], warnings[0]


@pytest.mark.asyncio
async def test_forward_forced_warning_fires_once_not_per_batch(monkeypatch):
    tweak_hex, output_hex = payment_to_us(b"\x88" * 32)
    utxo = {
        "txid": "ab" * 32, "vout": 0, "amount": 4_200,
        "pubkey": output_hex, "timestamp": 1_700_000_000,
    }
    warnings: list[str] = []
    monkeypatch.setattr(scan, "_FORWARD_MATCH_ONLY", True)
    monkeypatch.setattr(scan, "_warned_forward_forced", False)
    monkeypatch.setattr(
        scan.logger, "warning", lambda msg, *a, **kw: warnings.append(str(msg))
    )

    for _ in range(3):
        client = RecordingClient(all_range_routes([100], tweak_hex, utxo))
        data = await scan.fetch_range_batch([100], client)
        await scan.match_range_batch(
            data, client, SCAN_SECRET, SPEND_PUB, [], "signet"
        )

    assert len(warnings) == 1, f"warned {len(warnings)} times across three batches"


# --- the fallback must never be silent --------------------------------------


class _Recorder:
    """Captures the module's loguru calls, which conftest otherwise stubs out."""

    def __init__(self):
        self.warnings = []
        self.infos = []

    def warning(self, msg, *a, **k):
        self.warnings.append(msg % a if a else msg)

    def info(self, msg, *a, **k):
        self.infos.append(msg % a if a else msg)

    def __getattr__(self, _n):
        return lambda *a, **k: None


@pytest.mark.asyncio
async def test_missing_field_warns_rather_than_falling_back_silently(monkeypatch):
    """The case that cost two debugging rounds.

    /info answers, but the binary predates the endpoints so the field is
    absent. This used to set the limit to 0 and log nothing at all — the only
    symptom being a request count three times higher, several lines away.
    """
    rec = _Recorder()
    monkeypatch.setattr(scan, "logger", rec)
    client = RecordingClient({"/info": {"height": 500, "network": "signet"}})

    assert await client.get_range_limit() == 0
    assert rec.warnings, "fell back with no warning at all"
    joined = " ".join(rec.warnings)
    assert "max_range_blocks" in joined
    assert "Rebuild and restart" in joined, joined


@pytest.mark.asyncio
async def test_unreachable_info_warns(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(scan, "logger", rec)
    client = RecordingClient({"/info": httpx.ConnectError("refused")})

    assert await client.get_range_limit() == 0
    assert any("/info failed" in w for w in rec.warnings), rec.warnings


@pytest.mark.asyncio
async def test_explicit_zero_warns(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(scan, "logger", rec)
    client = RecordingClient({"/info": {"height": 5, "max_range_blocks": 0}})

    assert await client.get_range_limit() == 0
    assert any("disabled" in w for w in rec.warnings), rec.warnings


@pytest.mark.asyncio
async def test_non_numeric_value_warns(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(scan, "logger", rec)
    client = RecordingClient({"/info": {"max_range_blocks": "lots"}})

    assert await client.get_range_limit() == 0
    assert any("not a number" in w for w in rec.warnings), rec.warnings


@pytest.mark.asyncio
async def test_support_is_announced(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(scan, "logger", rec)
    client = RecordingClient({"/info": {"height": 5, "max_range_blocks": 100}})

    assert await client.get_range_limit() == 100
    assert any("serves block ranges" in i for i in rec.infos), rec.infos
    assert not rec.warnings, rec.warnings
