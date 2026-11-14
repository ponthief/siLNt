"""Optional out-of-process BIP-352 matching: the whispa-matcher service.

The scanner's CPU cost is the curve arithmetic that decides which of a block's
outputs are ours. This hands that step to a separate process (the Rust service
in the whispa-matcher repository), so it can use more than one core — the
in-process matching pool is a single thread, and widening it makes matching
slower, not faster (GIL contention, measured at ~4x slower on four threads).

OFF BY DEFAULT, and gated per network, so it can be tried on signet alone:

    SILNT_RUST_MATCHER_NETWORKS   signet            comma list; "all" for every
                                                    network; empty/unset = off
    SILNT_RUST_MATCHER_URL        http://127.0.0.1:8787
    SILNT_RUST_MATCHER_TOKEN      the service's MATCHER_TOKEN (>= 16 chars)
    SILNT_RUST_MATCHER_MODE       shadow (default) | active
    SILNT_RUST_MATCHER_TIMEOUT    seconds per request, default 120

Two modes, and `shadow` is the default because it is the one that earns trust:

* **shadow** — Python matches exactly as before and its result is what the scan
  uses. The service is asked the same question in parallel and the answers are
  compared; a difference is logged loudly and counted. Nothing the service says
  can change what is stored.
* **active** — the service's answer is used, and Python is the fallback.

In both modes the service can only ever ADD a result source. A transport error,
a non-200, a response that does not line up with the request, a block the
service reports an error for, or a label index nobody asked about — every one of
those is treated as "no answer" and the block is matched in Python. The failure
this must never produce is a block quietly reported as empty, because that is a
payment that stays invisible and a resume point that moves past it.

The scan secret is sent to the service. It is the scan key only (it detects
payments, it cannot spend), the same secret background scanning already holds,
but it still goes over a connection, so a plain-http URL is refused unless it
points at this machine or a private network — or the operator says otherwise in
SILNT_RUST_MATCHER_ALLOW_REMOTE_HTTP. Nothing in this module logs a request
body, the token, or the secret.

Read every setting through silnt_env, not os.getenv: some deployments load .env
into LNbits' settings without exporting it, and a flag that silently does
nothing is indistinguishable from a feature that is broken.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass
from typing import Optional, Sequence
from urllib.parse import urlsplit

import httpx
from loguru import logger

from .appenv import silnt_env

MODE_SHADOW = "shadow"
MODE_ACTIVE = "active"

_MIN_TOKEN_LEN = 16
# Blocks per HTTP request, and requests in flight. The service queues blocks for
# CPU itself; this only bounds one request's size and the connections used.
_CHUNK_BLOCKS = 200
_MAX_IN_FLIGHT = 4
# How long a parsed configuration is trusted. Short, so that flipping the flag
# in .env takes effect on the next scan without a restart — which is what makes
# it practical to try — and long enough that a scan's hundreds of batches do not
# each re-read the file.
_CONFIG_TTL = 30.0


@dataclass(frozen=True)
class MatcherConfig:
    url: str
    token: str
    mode: str
    timeout: float


class MatcherUnavailable(Exception):
    """The service gave no usable answer for the request as a whole."""


@dataclass(frozen=True)
class Match:
    txid: bytes
    vout: int
    amount: int
    timestamp: int
    priv_key_tweak: bytes
    pub_key: bytes
    label_m: Optional[int]


# --- configuration ------------------------------------------------------------

_cache: tuple[float, tuple, dict[str, Optional[MatcherConfig]]] = (0.0, (), {})
_warned: dict[str, float] = {}


def _warn_every(key: str, seconds: float, message: str, *args) -> None:
    """A problem that persists should be said, not said for every batch."""
    now = time.monotonic()
    if now - _warned.get(key, -1e9) >= seconds:
        _warned[key] = now
        logger.warning(message, *args)


def _host_is_private(host: str) -> bool:
    if host in ("localhost", "ip6-localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a hostname: cannot be known to be private from here
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _read_settings() -> tuple:
    return (
        silnt_env("SILNT_RUST_MATCHER_NETWORKS"),
        silnt_env("SILNT_RUST_MATCHER_URL"),
        silnt_env("SILNT_RUST_MATCHER_TOKEN"),
        silnt_env("SILNT_RUST_MATCHER_MODE"),
        silnt_env("SILNT_RUST_MATCHER_TIMEOUT"),
        silnt_env("SILNT_RUST_MATCHER_ALLOW_REMOTE_HTTP"),
    )


def _build(raw: tuple) -> Optional[MatcherConfig]:
    _networks, url, token, mode, timeout, allow_http = raw
    url = url.strip().rstrip("/")
    if not url or not token:
        _warn_every(
            "incomplete", 300,
            "SILNT_RUST_MATCHER_NETWORKS is set but SILNT_RUST_MATCHER_URL or "
            "SILNT_RUST_MATCHER_TOKEN is missing; matching stays in-process.",
        )
        return None
    if len(token) < _MIN_TOKEN_LEN:
        _warn_every(
            "token", 300,
            "SILNT_RUST_MATCHER_TOKEN is shorter than %d characters, which the "
            "service itself refuses; matching stays in-process.", _MIN_TOKEN_LEN,
        )
        return None
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        _warn_every("url", 300, "SILNT_RUST_MATCHER_URL is not an http(s) URL; "
                    "matching stays in-process.")
        return None
    if (
        parts.scheme == "http"
        and not _host_is_private(parts.hostname)
        and allow_http.strip().lower() not in ("1", "true", "yes")
    ):
        _warn_every(
            "plain-http", 300,
            "SILNT_RUST_MATCHER_URL is plain http to a host that is not loopback "
            "or a private address, and the scan secret goes in every request. "
            "Use https, a private address, or set "
            "SILNT_RUST_MATCHER_ALLOW_REMOTE_HTTP=1 if the link is trusted. "
            "Matching stays in-process.",
        )
        return None
    mode = (mode or MODE_SHADOW).strip().lower()
    if mode not in (MODE_SHADOW, MODE_ACTIVE):
        _warn_every("mode", 300, "SILNT_RUST_MATCHER_MODE=%r is not shadow or "
                    "active; using shadow.", mode)
        mode = MODE_SHADOW
    try:
        secs = max(1.0, min(600.0, float(timeout))) if timeout else 120.0
    except ValueError:
        secs = 120.0
    return MatcherConfig(url=url, token=token, mode=mode, timeout=secs)


def config_for(network: str) -> Optional[MatcherConfig]:
    """The service configuration for this network, or None to match in-process."""
    global _cache
    now = time.monotonic()
    expires, raw, built = _cache
    if now >= expires:
        raw = _read_settings()
        built = {}
        _cache = (now + _CONFIG_TTL, raw, built)
    networks = {n.strip().lower() for n in raw[0].split(",") if n.strip()}
    net = (network or "").strip().lower()
    if not networks or not ("all" in networks or "*" in networks or net in networks):
        return None
    if "cfg" not in built:
        built["cfg"] = _build(raw)  # type: ignore[assignment]
    return built["cfg"]  # type: ignore[return-value]


def reset() -> None:
    """Forget cached configuration and the connection. For tests and shutdown."""
    global _cache, _client, _client_key
    _cache = (0.0, (), {})
    _warned.clear()
    _client, _client_key = None, None


# --- transport ----------------------------------------------------------------

_client: Optional[httpx.AsyncClient] = None
_client_key: Optional[tuple] = None


def _http(cfg: MatcherConfig) -> httpx.AsyncClient:
    global _client, _client_key
    key = (cfg.url, cfg.token, cfg.timeout)
    if _client is None or _client.is_closed or _client_key != key:
        _client = httpx.AsyncClient(
            base_url=cfg.url,
            timeout=cfg.timeout,
            headers={"Authorization": f"Bearer {cfg.token}"},
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4,
                                keepalive_expiry=60.0),
        )
        _client_key = key
    return _client


async def aclose() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


def _wire_block(height: int, mode: str, entries: Sequence, utxos: Sequence[dict]) -> dict:
    """One block in the service's shape. Only the fields it reads are sent."""
    block: dict = {"height": height}
    if mode == "reverse":
        block["compute_index"] = [
            {"txid": e["txid"], "tweak": e["tweak"]} for e in entries
        ]
    else:
        block["tweaks"] = [t.hex() if isinstance(t, (bytes, bytearray)) else t for t in entries]
    block["utxos"] = [
        {
            "txid": u["txid"],
            "vout": u["vout"],
            "pubkey": u["pubkey"],
            "amount": u["amount"],
            **({"timestamp": u["timestamp"]} if u.get("timestamp") else {}),
        }
        for u in utxos
    ]
    return block


def _match_from_json(m: dict) -> Match:
    return Match(
        txid=bytes.fromhex(m["txid"]),
        vout=int(m["vout"]),
        amount=int(m["amount"]),
        timestamp=int(m["timestamp"]),
        priv_key_tweak=bytes.fromhex(m["priv_key_tweak"]),
        pub_key=bytes.fromhex(m["pub_key"]),
        label_m=None if m["label_m"] is None else int(m["label_m"]),
    )


async def _send(cfg: MatcherConfig, header: dict, blocks: list[dict]) -> list:
    try:
        r = await _http(cfg).post("/v1/match", json={**header, "blocks": blocks})
    except httpx.HTTPError as e:
        raise MatcherUnavailable(f"service unreachable: {type(e).__name__}") from e
    if r.status_code != 200:
        try:
            detail = str(r.json().get("error", ""))[:200]
        except ValueError:
            detail = ""
        raise MatcherUnavailable(f"service answered {r.status_code} {detail}".strip())
    try:
        results = r.json()["results"]
    except (ValueError, KeyError, TypeError) as e:
        raise MatcherUnavailable("service sent an unreadable response") from e
    # One result per block, in order, for the heights that were sent. Anything
    # else and an answer could be filed under the wrong block.
    if len(results) != len(blocks) or any(
        res.get("height") != blk["height"] for res, blk in zip(results, blocks)
    ):
        raise MatcherUnavailable("service response does not line up with the request")
    return results


async def match_blocks(
    cfg: MatcherConfig,
    *,
    scan_secret: bytes,
    spend_pub: bytes,
    label_indices: Sequence[int],
    jobs: Sequence[tuple],
) -> dict[int, "list[Match] | str"]:
    """Match blocks on the service.

    `jobs` are `(height, "forward" | "reverse", entries, utxos)`. Returns, per
    height, the matches or — if the service could not process that block — an
    error string. Raises MatcherUnavailable if there is no usable answer at all.
    """
    header = {
        "scan_secret": scan_secret.hex(),
        "spend_pubkey": spend_pub.hex(),
        "labels": list(label_indices),
    }
    blocks = [_wire_block(h, mode, entries, utxos) for h, mode, entries, utxos in jobs]
    chunks = [blocks[i : i + _CHUNK_BLOCKS] for i in range(0, len(blocks), _CHUNK_BLOCKS)]
    gate = asyncio.Semaphore(_MAX_IN_FLIGHT)

    async def one(chunk: list[dict]) -> list:
        async with gate:
            return await _send(cfg, header, chunk)

    parts = await asyncio.gather(*(one(c) for c in chunks))
    out: dict[int, "list[Match] | str"] = {}
    try:
        for part in parts:
            for res in part:
                if res.get("error"):
                    out[res["height"]] = str(res["error"])
                else:
                    out[res["height"]] = [_match_from_json(m) for m in res["matches"]]
    except (KeyError, TypeError, ValueError) as e:
        raise MatcherUnavailable("service sent a malformed match") from e
    return out
