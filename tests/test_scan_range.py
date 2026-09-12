"""Tests for the range-endpoint scan path.

The thing worth proving is not that the range path is faster — that follows from
making one request instead of three hundred — but that it finds exactly what the
per-block path finds, and that when it cannot read a block it says so instead of
reporting the block as empty. An empty block and an unreadable one look the same
to everything downstream, and the difference is somebody's money.
"""

from __future__ import annotations

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
    """An oracle client whose HTTP layer is a dictionary of canned responses."""

    def __init__(self, routes: dict[str, object], base_url="http://oracle.example"):
        super().__init__(base_url)
        self.routes = routes
        self.paths: list[str] = []

    async def _get(self, path: str) -> httpx.Response:
        self.paths.append(path)
        self.stats.requests += 1
        for prefix, payload in self.routes.items():
            if path.startswith(prefix):
                if isinstance(payload, Exception):
                    raise payload
                return response(payload)
        return response({"error": "not found"}, status=404)


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
    client = RecordingClient(
        {"/range/tweaks": {"blocks": [block_entry(100, []), block_entry(102, [])]}}
    )

    results = await scan.scan_blocks_range(
        [100, 101, 102], client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )

    assert results[0] == []
    assert isinstance(results[1], scan.BlockNotIndexedError)
    assert results[1].height == 101
    assert results[2] == []


@pytest.mark.asyncio
async def test_utxos_not_fetched_when_no_block_has_tweaks():
    """Nothing to match them against, so the request is pure waste."""
    client = RecordingClient(
        {
            "/range/tweaks": {"blocks": [block_entry(h, []) for h in range(100, 110)]},
            "/range/utxos": {"blocks": []},
        }
    )

    results = await scan.scan_blocks_range(
        list(range(100, 110)), client, SCAN_SECRET, SPEND_PUB, [], "signet"
    )

    assert all(r == [] for r in results)
    assert not any(p.startswith("/range/utxos") for p in client.paths), client.paths


@pytest.mark.asyncio
async def test_a_hundred_blocks_cost_two_requests():
    """The reason the endpoints exist: 100 blocks used to be 300 requests."""
    tweak_hex, output_hex = payment_to_us(b"\x55" * 32)
    heights = list(range(1000, 1100))

    client = RecordingClient(
        {
            "/range/tweaks": {"blocks": [block_entry(h, [tweak_hex]) for h in heights]},
            "/range/utxos": {
                "blocks": [
                    block_entry(
                        h,
                        [
                            {
                                "txid": "ee" * 32,
                                "vout": 0,
                                "amount": 1,
                                "pubkey": "ff" * 32,
                                "timestamp": 1,
                            }
                        ],
                    )
                    for h in heights
                ]
            },
        }
    )

    await scan.scan_blocks_range(heights, client, SCAN_SECRET, SPEND_PUB, [], "signet")

    assert len(client.paths) == 2, client.paths
    assert client.stats.blocks == 100


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
