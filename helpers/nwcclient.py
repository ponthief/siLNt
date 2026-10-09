"""Talking to an NWC wallet service: the socket half of helpers/nwc.py.

Everything that needs a network lives here, and nothing that needs a decision
does. The rules — what a connection string may look like, which answer belongs
to which request, whether a failure is worth retrying, which chain the wallet
is allowed to be on — are in nwc.py and are tested without a relay.

ONE CONNECTION PER CALL, deliberately. A long-lived socket to a relay is a
reconnect loop, a resubscribe, and a window in which a reply arrives for a
request this process has forgotten; a payout runs once every few minutes and
can afford a fresh socket. The cost of the simple version is a TLS handshake.
The cost of the clever one is a payout recorded against another payout's
preimage.

`websockets` is imported inside the functions. A relay client is not needed to
import this extension, to run its tests, or to use it without NWC configured,
and an import error at module scope would take all of that down with it.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from typing import Optional

from loguru import logger

from . import nostr
from .nwc import (
    DEFAULT_TIMEOUT_SECONDS,
    INFO_TIMEOUT_SECONDS,
    KIND_INFO,
    KIND_RESPONSE,
    NwcConnection,
    NwcError,
    NwcTemporaryError,
    build_request,
    network_mismatch,
    parse_uri,
    read_response,
    response_for,
    sats_from_msat,
)


def _websockets():
    try:
        import websockets  # noqa: F401

        return websockets
    except ImportError as e:  # pragma: no cover - deployment problem
        raise NwcTemporaryError(
            "This server has no websocket client installed, so it cannot "
            f"reach an NWC wallet ({e}). Install `websockets`."
        )


async def _open(relay: str):
    ws = _websockets()
    # open_timeout keeps a relay that accepts a TCP connection and then says
    # nothing from holding the whole payout pass.
    return await ws.connect(relay, open_timeout=15, close_timeout=5)


async def _encryption_scheme(ws, conn: NwcConnection) -> str:
    """Which scheme this wallet service speaks, from its own info event.

    ASKED RATHER THAN ASSUMED, because getting it wrong is silence. A service
    that cannot decrypt a request cannot tell us so — it does not know what we
    sent — so it simply never answers, and the payout fails on a timeout that
    names nothing. The kind-13194 event is replaceable and costs one
    round trip against a relay we have already connected to.

    No info event, or one with no `encryption` tag, means NIP-04: that is what
    the spec says to assume, and it is what every service that predates the
    tag does.
    """
    sub = secrets.token_hex(8)
    await ws.send(json.dumps([
        "REQ", sub,
        {"kinds": [KIND_INFO], "authors": [conn.wallet_pubkey], "limit": 1},
    ]))
    scheme = nostr.NIP04
    deadline = time.time() + INFO_TIMEOUT_SECONDS
    try:
        while time.time() < deadline:
            raw = await asyncio.wait_for(
                ws.recv(), timeout=max(1, deadline - time.time())
            )
            msg = json.loads(raw)
            if not isinstance(msg, list) or not msg:
                continue
            if msg[0] == "EVENT" and len(msg) >= 3:
                event = msg[2] or {}
                if int(event.get("kind") or 0) != KIND_INFO:
                    continue
                for tag in event.get("tags") or []:
                    if len(tag) >= 2 and tag[0] == "encryption":
                        advertised = str(tag[1] or "").split()
                        if nostr.NIP44_V2 in advertised:
                            scheme = nostr.NIP44_V2
                        elif nostr.NIP04 in advertised:
                            scheme = nostr.NIP04
                        break
            elif msg[0] in ("EOSE", "CLOSED") and len(msg) >= 2 and msg[1] == sub:
                break
    except (asyncio.TimeoutError, ValueError):
        # A relay that will not answer about capabilities is not yet a reason
        # to fail the payout: NIP-04 is the documented default and the request
        # below is the real test.
        pass
    finally:
        try:
            await ws.send(json.dumps(["CLOSE", sub]))
        except Exception:
            pass
    return scheme


async def _one_relay(conn: NwcConnection, relay: str, method: str,
                     params: dict, timeout: int) -> dict:
    async with await _open(relay) as ws:
        scheme = await _encryption_scheme(ws, conn)
        # `since` rather than everything the relay holds, so a response to a
        # request made an hour ago is not replayed into this one's stream. The
        # id check in response_for is the real guard; this only keeps the
        # stream short.
        #
        # FIVE MINUTES RATHER THAN ONE, because the timestamp on the answer is
        # the WALLET SERVICE's clock, not ours. A service running a couple of
        # minutes behind would have its reply filtered out by the relay, and
        # the payout would fail on a timeout with nothing anywhere saying why.
        since = int(time.time()) - 300
        request = build_request(
            conn, method, params, scheme=scheme, expires_in=timeout + 60
        )
        sub = secrets.token_hex(8)
        await ws.send(json.dumps([
            "REQ", sub,
            {
                "kinds": [KIND_RESPONSE],
                "authors": [conn.wallet_pubkey],
                "#p": [conn.client_pubkey],
                "since": since,
            },
        ]))
        await ws.send(json.dumps(["EVENT", request]))

        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise NwcTemporaryError(
                    f"The NWC wallet did not answer a {method} within "
                    f"{timeout}s."
                )
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=left)
            except asyncio.TimeoutError:
                raise NwcTemporaryError(
                    f"The NWC wallet did not answer a {method} within "
                    f"{timeout}s."
                )
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(msg, list) or not msg:
                continue
            if msg[0] == "OK" and len(msg) >= 4 and msg[1] == request["id"]:
                if not msg[2]:
                    # The relay refused to store our request, so nothing will
                    # ever answer it. Another relay might take it.
                    raise NwcTemporaryError(
                        f"The relay rejected the request: {msg[3]}"
                    )
            elif msg[0] == "EVENT" and len(msg) >= 3:
                event = msg[2] or {}
                if response_for(event, conn, request["id"]):
                    return read_response(conn, event, method)
            elif msg[0] == "CLOSED" and len(msg) >= 2 and msg[1] == sub:
                raise NwcTemporaryError(
                    f"The relay closed the subscription: "
                    f"{msg[2] if len(msg) > 2 else ''}"
                )


async def call(uri: str, method: str, params: Optional[dict] = None,
               timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """One NIP-47 call, trying each relay in the connection string in turn.

    A connection string may name several relays, and they are alternatives
    rather than a quorum: the wallet service listens on all of them, so the
    first that answers is the answer. A PERMANENT failure stops immediately —
    it is the wallet refusing, not the relay — and trying the next one would
    only ask the same wallet the same question again.
    """
    conn = parse_uri(uri)
    last: Optional[Exception] = None
    for relay in conn.relays:
        try:
            return await _one_relay(conn, relay, method, params or {}, timeout)
        except NwcError:
            raise
        except NwcTemporaryError as e:
            last = e
            logger.warning(f"nwc: {relay} did not serve {method}: {e}")
        except Exception as e:
            last = NwcTemporaryError(f"{relay}: {e}")
            logger.warning(f"nwc: {relay} failed on {method}: {e}")
    raise last or NwcTemporaryError("No relay in the connection string answered.")


async def get_info(uri: str) -> dict:
    return await call(uri, "get_info", {}, timeout=INFO_TIMEOUT_SECONDS)


async def get_balance_sats(uri: str) -> int:
    result = await call(uri, "get_balance", {}, timeout=INFO_TIMEOUT_SECONDS)
    return sats_from_msat(result.get("balance"))


async def pay_bolt11(uri: str, bolt11: str,
                     timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Pay an invoice. Returns the wallet's own result — the preimage is the
    proof it went, and is what gets recorded on the payout row.

    NO AMOUNT IS SENT. The invoice carries it, and passing `amount` as well
    would let a mismatch between the two be resolved by the wallet service
    rather than by us.
    """
    return await call(uri, "pay_invoice", {"invoice": bolt11}, timeout=timeout)


async def check_network(uri: str, network: str) -> Optional[str]:
    """Why this wallet may not pay that chain's change. None when it may.

    Asked LIVE and never cached in config: a connection string can be
    re-pointed at a different wallet without this server being told, and the
    whole guard is worth nothing if it runs once at setup.
    """
    info = await get_info(uri)
    return network_mismatch(info.get("network"), network)
