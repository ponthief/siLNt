"""The optional out-of-process matcher, and what it is never allowed to do.

The service (whispa-matcher) is an OPTIONAL second source of matching results.
These tests hold it to two promises:

1. Off unless asked. Nothing changes for a deployment that does not set
   SILNT_RUST_MATCHER_NETWORKS, and it can be restricted to one network.
2. It can only add a source, never lose a payment. Whatever goes wrong — the
   service is down, refuses, answers out of order, errors on a block, names a
   label we did not ask about — that block is matched in Python. The failure to
   keep out is "I could not tell" becoming "there is nothing here", because a
   block reported empty is a payment that stays invisible and a resume point that
   moves past it.

The fake service below runs the REAL Python matchers underneath and encodes
their answer the way the service does, so every scenario has a known right
answer, and a test can corrupt exactly one thing.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import socket
import subprocess
import time
from types import SimpleNamespace

import httpx
import pytest
from conftest import scan

import test_reverse_matching as corpus

rm = scan.rust_matcher
SCAN_SECRET, SPEND_PUB, LABELS = corpus.SCAN_SECRET, corpus.SPEND_PUB, corpus.LABELS
URL = "http://127.0.0.1:18787"
TOKEN = "t" * 24


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("SILNT_RUST_MATCHER"):
            monkeypatch.delenv(key)
    rm.reset()
    yield
    rm.reset()


def enable(monkeypatch, *, mode="shadow", networks="signet", url=URL, token=TOKEN):
    monkeypatch.setenv("SILNT_RUST_MATCHER_NETWORKS", networks)
    monkeypatch.setenv("SILNT_RUST_MATCHER_URL", url)
    monkeypatch.setenv("SILNT_RUST_MATCHER_TOKEN", token)
    monkeypatch.setenv("SILNT_RUST_MATCHER_MODE", mode)
    rm.reset()


def make_data(n_blocks=4, seed=11, reverse=False):
    import random

    rng = random.Random(seed)
    heights, index, utxos = [], {}, {}
    for i in range(n_blocks):
        h = 5000 + i
        tweaks, compute_index, us = corpus.build_block(
            rng, [([None], 1), ([2], 2), ([None, 0], 0), ([], 3)]
        )
        heights.append(h)
        index[h] = compute_index if reverse else tweaks
        utxos[h] = us
    return scan.RangeBatch(
        heights=heights,
        tweaks=None if reverse else index,
        utxos=utxos,
        compute_index=index if reverse else None,
    )


def client():
    return SimpleNamespace(stats=scan.OracleStats())


def python_only(data):
    """What the scan produced before this feature existed."""
    out = {}
    use_reverse = data.compute_index is not None
    idx = data.compute_index if use_reverse else data.tweaks
    fn = scan.sync_block_reverse if use_reverse else scan.sync_block
    for h in data.heights:
        out[h] = fn(idx[h], data.utxos[h], SCAN_SECRET, SPEND_PUB, LABELS)
    return out


def fp(owned):
    return scan._fingerprint(owned)


def rows_for(block, secret, spend, label_ms):
    labels = [scan.create_label(secret, m) for m in label_ms]
    utxos = block["utxos"]
    if "compute_index" in block:
        owned = scan.sync_block_reverse(block["compute_index"], utxos, secret, spend, labels)
    else:
        owned = scan.sync_block([bytes.fromhex(t) for t in block["tweaks"]], utxos, secret, spend, labels)
    return [
        {
            "txid": o.txid.hex(), "vout": o.vout, "amount": o.amount,
            "timestamp": o.timestamp, "priv_key_tweak": o.priv_key_tweak.hex(),
            "pub_key": o.pub_key.hex(), "label_m": o.label.m if o.label else None,
        }
        for o in owned
    ]


class FakeService:
    """A stand-in for whispa-matcher backed by the real Python matchers."""

    def __init__(self, monkeypatch):
        self.requests = []
        self.status = 200
        self.block_errors = set()      # heights to report an error for
        self.tamper = lambda height, rows: rows
        self.misalign = False
        self.bodies = []
        monkeypatch.setattr(rm, "_http", self._http)

    def _http(self, cfg):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(self._handle),
            base_url=cfg.url,
            headers={"Authorization": f"Bearer {cfg.token}"},
        )

    def _handle(self, request):
        import json

        self.requests.append(request)
        self.bodies.append(request.content)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": "refused"})
        body = json.loads(request.content)
        secret, spend = bytes.fromhex(body["scan_secret"]), bytes.fromhex(body["spend_pubkey"])
        results = []
        for block in body["blocks"]:
            h = block["height"]
            if h in self.block_errors:
                results.append({"height": h, "matches": [], "error": "boom"})
            else:
                rows = self.tamper(h, rows_for(block, secret, spend, body["labels"]))
                results.append({"height": h, "matches": rows})
        if self.misalign:
            results.reverse()
        return httpx.Response(200, json={"results": results, "elapsed_ms": 1})


async def run(data, network="signet"):
    c = client()
    results = await scan.match_range_batch(data, c, SCAN_SECRET, SPEND_PUB, LABELS, network)
    return c, results


# --- promise 1: off unless asked ---------------------------------------------


@pytest.mark.asyncio
async def test_off_by_default_and_the_service_is_never_contacted(monkeypatch):
    svc = FakeService(monkeypatch)
    data = make_data()
    c, results = await run(data)
    assert svc.requests == []
    assert rm.config_for("signet") is None
    assert (c.stats.rust_blocks, c.stats.rust_fallbacks, c.stats.rust_mismatches) == (0, 0, 0)
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]


@pytest.mark.asyncio
async def test_a_network_not_named_is_untouched(monkeypatch):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, networks="signet")
    c, _ = await run(make_data(), network="mainnet")
    assert svc.requests == [], "mainnet was sent to the service though only signet was named"
    assert rm.config_for("mainnet") is None
    assert rm.config_for("signet") is not None


def test_all_names_every_network(monkeypatch):
    enable(monkeypatch, networks="all")
    assert rm.config_for("mainnet") and rm.config_for("signet")


@pytest.mark.parametrize(
    "kw, why",
    [
        (dict(url=""), "no url"),
        (dict(token=""), "no token"),
        (dict(token="short"), "token the service itself would refuse"),
        (dict(url="http://matcher.example.com:8787"), "plain http to a public host"),
        (dict(url="ftp://127.0.0.1"), "not http"),
    ],
)
def test_a_half_configured_or_unsafe_setup_stays_in_process(monkeypatch, kw, why):
    enable(monkeypatch, **kw)
    assert rm.config_for("signet") is None, why


def test_private_and_loopback_http_is_allowed_and_public_http_can_be_overridden(monkeypatch):
    for url in ("http://127.0.0.1:8787", "http://localhost:8787", "http://10.0.0.5:8787",
                "http://192.168.1.9:8787", "https://matcher.example.com"):
        enable(monkeypatch, url=url)
        assert rm.config_for("signet") is not None, url
    enable(monkeypatch, url="http://matcher.example.com:8787")
    monkeypatch.setenv("SILNT_RUST_MATCHER_ALLOW_REMOTE_HTTP", "1")
    rm.reset()
    assert rm.config_for("signet") is not None


def test_an_unknown_mode_is_shadow_not_active(monkeypatch):
    enable(monkeypatch, mode="yolo")
    assert rm.config_for("signet").mode == "shadow"


# --- shadow: the service is checked, never trusted ---------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True])
async def test_shadow_agrees_with_python_and_uses_pythons_answer(monkeypatch, reverse):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="shadow")
    data = make_data(reverse=reverse)
    c, results = await run(data)
    assert len(svc.requests) == 1, "the whole batch is one request"
    assert c.stats.rust_mismatches == 0
    assert c.stats.rust_blocks == len(data.heights) and c.stats.rust_fallbacks == 0
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    assert sum(len(r) for r in results) > 0, "the corpus found nothing; the comparison is empty"


@pytest.mark.asyncio
async def test_shadow_notices_a_service_that_loses_a_payment_and_still_returns_pythons(monkeypatch):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="shadow")
    data = make_data()
    victim = data.heights[1]
    svc.tamper = lambda h, rows: rows[1:] if h == victim else rows   # drops one match
    c, results = await run(data)
    assert c.stats.rust_mismatches == 1
    expected = python_only(data)
    assert [fp(r) for r in results] == [fp(expected[h]) for h in data.heights], (
        "shadow mode let the service change what the scan stored"
    )


@pytest.mark.asyncio
async def test_shadow_notices_an_invented_output_too(monkeypatch):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="shadow")
    data = make_data()

    def invent(h, rows):
        if rows:
            return rows + [{**rows[0], "vout": 99}]
        return rows

    svc.tamper = invent
    c, results = await run(data)
    assert c.stats.rust_mismatches >= 1
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]


# --- active: the service's answer, with Python behind it ---------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True])
async def test_active_uses_the_service_and_does_not_run_python(monkeypatch, reverse):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="active")
    data = make_data(reverse=reverse)
    expected = python_only(data)

    async def forbidden(*_a, **_k):
        raise AssertionError("active mode ran the Python matcher for an answered block")

    monkeypatch.setattr(scan, "_match_in_thread", forbidden)
    c, results = await run(data)
    assert [fp(r) for r in results] == [fp(expected[h]) for h in data.heights]
    assert c.stats.rust_blocks == len(data.heights) and c.stats.rust_fallbacks == 0


@pytest.mark.asyncio
async def test_active_falls_back_when_the_service_is_down(monkeypatch):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="active")
    svc.status = 503
    data = make_data()
    c, results = await run(data)
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    assert c.stats.rust_fallbacks == len(data.heights) and c.stats.rust_blocks == 0


@pytest.mark.asyncio
async def test_active_falls_back_when_the_connection_fails(monkeypatch):
    enable(monkeypatch, mode="active")

    def refuse(_cfg):
        def handler(_request):
            raise httpx.ConnectError("refused")

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=URL)

    monkeypatch.setattr(rm, "_http", refuse)
    data = make_data()
    c, results = await run(data)
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    assert c.stats.rust_fallbacks == len(data.heights)


@pytest.mark.asyncio
async def test_one_block_the_service_cannot_process_is_matched_in_python_alone(monkeypatch):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="active")
    data = make_data()
    svc.block_errors = {data.heights[2]}
    c, results = await run(data)
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    assert c.stats.rust_blocks == len(data.heights) - 1 and c.stats.rust_fallbacks == 1


@pytest.mark.asyncio
async def test_a_response_that_does_not_line_up_is_discarded_whole(monkeypatch):
    """Answers filed under the wrong block would be a payment on the wrong height."""
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="active")
    svc.misalign = True
    data = make_data()
    c, results = await run(data)
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    assert c.stats.rust_blocks == 0 and c.stats.rust_fallbacks == len(data.heights)


@pytest.mark.asyncio
async def test_a_label_we_did_not_ask_about_is_not_trusted(monkeypatch):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="active")
    data = make_data()
    svc.tamper = lambda h, rows: [{**r, "label_m": 4242} if r["label_m"] is not None else r for r in rows]
    c, results = await run(data)
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    assert c.stats.rust_fallbacks >= 1


@pytest.mark.asyncio
async def test_a_block_the_python_matcher_raises_on_is_still_an_error(monkeypatch):
    """The scan reads an Exception per block as a GAP (the resume point stops
    below it). The service must not turn that into an empty result."""
    enable(monkeypatch, mode="shadow")
    FakeService(monkeypatch)
    data = make_data()
    bad = data.heights[0]
    data.tweaks[bad] = ["05" + "11" * 32] + list(data.tweaks[bad])   # not a point
    results = await scan.match_range_batch(data, client(), SCAN_SECRET, SPEND_PUB, LABELS, "signet")
    assert isinstance(results[0], Exception)


# --- the service is a source of results, not of anything else ----------------


@pytest.mark.asyncio
async def test_blocks_with_nothing_to_match_are_not_sent(monkeypatch):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="active")
    data = make_data(n_blocks=2)
    data.utxos[data.heights[0]] = []                       # nothing to match against
    data.heights.append(9999)                              # absent from the index entirely
    c, results = await run(data)
    import json
    sent = [b["height"] for b in json.loads(svc.bodies[0])["blocks"]]
    assert sent == [data.heights[1]]
    assert results[0] == []
    assert isinstance(results[-1], scan.BlockNotIndexedError)


@pytest.mark.asyncio
async def test_the_secret_and_token_reach_the_service_and_never_the_log(monkeypatch):
    messages = []

    class Recorder:
        def __getattr__(self, _name):
            return lambda *a, **k: messages.append(" ".join(str(x) for x in (a, k)))

    monkeypatch.setattr(rm, "logger", Recorder())
    monkeypatch.setattr(scan, "logger", Recorder())
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="shadow")
    data = make_data()
    svc.status = 500                                       # force the warning path
    await run(data)
    svc.status = 200
    svc.tamper = lambda h, rows: rows[1:] if rows else rows   # and the mismatch path
    rm._warned.clear()
    await run(data)

    # It was sent...
    assert SCAN_SECRET.hex().encode() in svc.bodies[0]
    assert svc.requests[0].headers["authorization"] == f"Bearer {TOKEN}"
    # ...and appears nowhere a person could read it.
    joined = "\n".join(messages)
    assert messages, "no log lines were produced; the test checked nothing"
    for secret in (SCAN_SECRET.hex(), TOKEN):
        assert secret not in joined


@pytest.mark.asyncio
async def test_single_block_path_goes_through_the_same_dispatch(monkeypatch):
    """scan_block (the per-block fallback when a range fetch fails) too."""
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="active")
    data = make_data(n_blocks=1)
    h = data.heights[0]

    class Oracle:
        stats = scan.OracleStats()

        async def get_tweaks(self, _h):
            return data.tweaks[h]

        async def get_utxos(self, _h):
            return data.utxos[h]

    async def no_ts(*_a, **_k):
        return 1_700_000_000

    monkeypatch.setattr(scan, "get_block_ts", no_ts)
    got = await scan.scan_block(h, Oracle(), SCAN_SECRET, SPEND_PUB, LABELS, "signet")
    assert len(svc.requests) == 1
    assert fp(got) == fp(python_only(data)[h]) or {x[:3] for x in fp(got)} == {x[:3] for x in fp(python_only(data)[h])}


# --- against the real service, when it is built ------------------------------

_BIN = pathlib.Path(
    os.environ.get(
        "WHISPA_MATCHER_BIN",
        pathlib.Path(__file__).resolve().parents[2] / "whispa-matcher/target/release/whispa-matcher",
    )
)


@pytest.fixture(scope="module")
def real_service():
    if not _BIN.exists():
        pytest.skip(f"whispa-matcher not built at {_BIN} (set WHISPA_MATCHER_BIN)")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        [str(_BIN)],
        env={**os.environ, "MATCHER_TOKEN": TOKEN, "MATCHER_BIND": f"127.0.0.1:{port}", "RUST_LOG": "warn"},
    )
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("service did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["shadow", "active"])
@pytest.mark.parametrize("reverse", [False, True])
async def test_against_the_real_service(monkeypatch, real_service, mode, reverse):
    enable(monkeypatch, mode=mode, url=real_service)
    data = make_data(n_blocks=12, seed=29, reverse=reverse)
    expected = python_only(data)
    c, results = await run(data)
    assert [fp(r) for r in results] == [fp(expected[h]) for h in data.heights]
    assert sum(len(r) for r in results) > 0
    assert c.stats.rust_mismatches == 0
    assert c.stats.rust_blocks == len(data.heights) and c.stats.rust_fallbacks == 0
    await rm.aclose()


@pytest.mark.asyncio
async def test_a_dead_real_service_falls_back_cleanly(monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    enable(monkeypatch, mode="active", url=f"http://127.0.0.1:{port}")   # nothing listening
    data = make_data()
    c, results = await run(data)
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    assert c.stats.rust_fallbacks == len(data.heights)
    await rm.aclose()


def test_the_scan_timing_line_says_when_the_service_was_involved_and_when_not():
    quiet = scan.OracleStats(blocks=10, wall_seconds=1.0)
    assert "rust matcher" not in quiet.summary(), "a deployment without the feature sees noise"
    used = scan.OracleStats(blocks=10, wall_seconds=1.0, rust_blocks=9, rust_seconds=0.4,
                            rust_fallbacks=1, rust_mismatches=2)
    line = used.summary()
    assert "rust matcher: 9 blocks" in line and "1 fell back" in line and "2 MISMATCHED" in line
    assert used.as_dict()["rust_mismatches"] == 2


# --- where a matcher call's time goes ----------------------------------------
#
# Added 2026-11-23 after a mainnet log showed the matcher call at 71% of a big
# catch-up with no way to tell the curve work from the wire. These pin that the
# split is filled in from what really happened, and that asking for it changes
# nothing about what is sent or answered.


@pytest.mark.asyncio
async def test_a_matcher_call_reports_where_its_time_went(monkeypatch):
    svc = FakeService(monkeypatch)
    enable(monkeypatch, mode="active")
    data = make_data()
    c, results = await run(data)
    st = c.stats
    assert st.rust_requests >= 1
    assert st.rust_sent_bytes == sum(len(b) for b in svc.bodies), "bytes out are the real body"
    assert st.rust_received_bytes > 0
    assert st.rust_encode_seconds > 0 and st.rust_roundtrip_seconds > 0
    assert st.rust_build_seconds > 0 and st.rust_parse_seconds > 0 and st.rust_convert_seconds > 0
    # The fake sends elapsed_ms: 1 on each response, and the stats say so.
    assert st.rust_service_reported and st.rust_service_seconds == pytest.approx(0.001 * st.rust_requests)
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    await rm.aclose()


@pytest.mark.asyncio
async def test_a_service_that_reports_no_time_is_not_credited_with_zero(monkeypatch):
    svc = FakeService(monkeypatch)
    handle = svc._handle

    def without_elapsed(request):
        import json
        r = handle(request)
        body = json.loads(r.content)
        body.pop("elapsed_ms", None)
        return httpx.Response(200, json=body)

    svc._handle = without_elapsed
    enable(monkeypatch, mode="active")
    c, _ = await run(make_data())
    assert c.stats.rust_service_reported is False
    assert "service says n/a" in c.stats.rust_line(), "a missing figure must read as missing, not 0.0s"
    assert c.stats.as_dict()["rust_service_seconds"] is None
    await rm.aclose()


@pytest.mark.asyncio
async def test_timing_is_kept_when_the_call_fails(monkeypatch):
    svc = FakeService(monkeypatch)
    svc.status = 503
    enable(monkeypatch, mode="active")
    data = make_data()
    c, results = await run(data)
    assert c.stats.rust_fallbacks == len(data.heights)
    assert c.stats.rust_requests == 1 and c.stats.rust_roundtrip_seconds > 0
    assert [fp(r) for r in results] == [fp(python_only(data)[h]) for h in data.heights]
    await rm.aclose()


@pytest.mark.asyncio
async def test_asking_for_timing_changes_nothing_on_the_wire(monkeypatch):
    svc = FakeService(monkeypatch)
    cfg = enable(monkeypatch, mode="active") or rm.config_for("signet")
    data = make_data()
    jobs = [(h, "forward", data.tweaks[h], data.utxos[h]) for h in data.heights
            if data.tweaks.get(h) and data.utxos.get(h)]
    kw = dict(scan_secret=SCAN_SECRET, spend_pub=SPEND_PUB,
              label_indices=[l.m for l in LABELS], jobs=jobs)
    plain = await rm.match_blocks(cfg, **kw)
    timed = await rm.match_blocks(cfg, timing={}, **kw)
    assert svc.bodies[0] == svc.bodies[1], "the request must be byte-identical either way"
    assert {h: [m.pub_key for m in v] for h, v in plain.items()} == \
           {h: [m.pub_key for m in v] for h, v in timed.items()}
    await rm.aclose()


def test_the_rust_line_is_silent_without_the_matcher_and_names_every_part():
    quiet = scan.OracleStats(blocks=10, wall_seconds=1.0)
    assert quiet.rust_requests == 0, "the scan only logs the line when a request was made"
    used = scan.OracleStats(
        rust_seconds=54.1, rust_build_seconds=1.5, rust_encode_seconds=2.5,
        rust_roundtrip_seconds=60.0, rust_parse_seconds=0.7, rust_convert_seconds=0.4,
        rust_service_seconds=41.0, rust_service_reported=True, rust_requests=3,
        rust_sent_bytes=50 * 1024 * 1024, rust_received_bytes=3 * 1024 * 1024,
    )
    line = used.rust_line()
    for part in ("matcher call 54.1s wall", "build 1.5s", "encode 2.5s", "round-trip 60.0s",
                 "service says 41.0s", "50.0 MB out", "3.0 MB back", "3 requests", "summed",
                 "parse 0.7s", "convert 0.4s"):
        assert part in line, part
