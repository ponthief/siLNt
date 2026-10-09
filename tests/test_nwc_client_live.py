"""helpers/nwcclient.py against a relay and a wallet service that exist.

THE PART THAT SPENDS THE MONEY IS THE PART NOTHING ELSE EXERCISES. Every other
test in this area is pure: connection strings, which answer belongs to which
request, whether a failure is worth retrying. None of them open a socket, and a
payout that never leaves is indistinguishable from a relay that never answers —
so a bug in the transport would be reported as "Lightning is down" and looked
for anywhere but here.

So: a real websockets server, in-process, on a loopback port, playing both the
relay and the wallet service. It stores a kind-13194 info event, answers REQ
with it, acks EVENT, decrypts each request with the wallet's own key and signs
an answer back. Everything the client does against Coinos it does against this.

Skipped where `websockets` is not installed. It is a declared dependency and
is imported lazily by nwcclient for the same reason this skips: an instance
that pays out from an LNbits wallet, or not at all, does not need it.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

websockets = pytest.importorskip("websockets")

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from helpers import nostr  # noqa: E402
from helpers.nwc import NwcError, NwcTemporaryError  # noqa: E402
from helpers import nwcclient  # noqa: E402

WALLET_SEC = "a" * 63 + "1"
WALLET_PUB = nostr.pubkey_of(WALLET_SEC)
CLIENT_SEC = "b" * 63 + "2"


class FakeWallet:
    """A relay and the wallet service behind it, in one socket.

    `answers` maps a method to what to send back: a dict is a `result`, an
    (code, message) tuple is an `error`, and None means answer nothing at all —
    which is how a timeout is produced on purpose.
    """

    def __init__(self, answers: dict, *, encryption: str = "nip44_v2",
                 info_event: bool = True, reply_to_wrong_request: bool = False):
        self.answers = answers
        self.encryption = encryption
        self.info_event = info_event
        self.reply_to_wrong_request = reply_to_wrong_request
        self.server = None
        self.url = ""
        self.seen: list = []

    async def __aenter__(self):
        self.server = await websockets.serve(self._handle, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]
        self.url = f"ws://127.0.0.1:{port}"
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()

    def uri(self, secret: str = CLIENT_SEC) -> str:
        return (
            f"nostr+walletconnect://{WALLET_PUB}"
            f"?relay={self.url}&secret={secret}"
        )

    def _info(self):
        tags = [["encryption", self.encryption]] if self.encryption else []
        return nostr.sign_event(WALLET_SEC, 13194, "pay_invoice get_balance "
                                "get_info", tags)

    async def _handle(self, ws):
        subs: dict = {}
        async for raw in ws:
            msg = json.loads(raw)
            if msg[0] == "REQ":
                sub, filt = msg[1], msg[2]
                if 13194 in (filt.get("kinds") or []) and self.info_event:
                    await ws.send(json.dumps(["EVENT", sub, self._info()]))
                subs[sub] = filt
                await ws.send(json.dumps(["EOSE", sub]))
            elif msg[0] == "CLOSE":
                subs.pop(msg[1], None)
            elif msg[0] == "EVENT":
                event = msg[1]
                await ws.send(json.dumps(["OK", event["id"], True, ""]))
                if int(event.get("kind") or 0) != 23194:
                    continue
                body = json.loads(nostr.decrypt(
                    "nip44_v2", WALLET_SEC, event["pubkey"], event["content"]
                ))
                self.seen.append(body)
                reply = self.answers.get(body["method"], ("OTHER", "no"))
                if reply is None:
                    continue
                if isinstance(reply, tuple):
                    payload = {
                        "result_type": body["method"],
                        "error": {"code": reply[0], "message": reply[1]},
                    }
                else:
                    payload = {"result_type": body["method"], "result": reply}
                # Answered in the scheme the request used, as the spec says.
                scheme = "nip04"
                for tag in event.get("tags") or []:
                    if len(tag) >= 2 and tag[0] == "encryption":
                        scheme = tag[1]
                answer = nostr.sign_event(
                    WALLET_SEC, 23195,
                    nostr.encrypt(scheme, WALLET_SEC, event["pubkey"],
                                  json.dumps(payload)),
                    [
                        ["e", "0" * 64 if self.reply_to_wrong_request
                         else event["id"]],
                        ["p", event["pubkey"]],
                    ],
                )
                for sub in list(subs):
                    await ws.send(json.dumps(["EVENT", sub, answer]))


@pytest.mark.asyncio
async def test_a_payment_goes_out_and_comes_back_with_a_preimage():
    async with FakeWallet({"pay_invoice": {"preimage": "ab" * 32,
                                           "fees_paid": 1000}}) as w:
        out = await nwcclient.pay_bolt11(w.uri(), "lnbc100n1xyz")
        assert out["preimage"] == "ab" * 32
    # NO AMOUNT IS SENT. The invoice carries it, and passing one as well would
    # let a mismatch be resolved by the wallet service rather than by us.
    assert w.seen[-1] == {"method": "pay_invoice",
                          "params": {"invoice": "lnbc100n1xyz"}}


@pytest.mark.asyncio
async def test_a_balance_comes_back_in_sats():
    async with FakeWallet({"get_balance": {"balance": 7_999}}) as w:
        assert await nwcclient.get_balance_sats(w.uri()) == 7


@pytest.mark.asyncio
async def test_a_signet_wallet_may_pay_signet_change():
    """The whole point of this change, end to end."""
    async with FakeWallet({"get_info": {"network": "signet",
                                        "alias": "coinos"}}) as w:
        assert await nwcclient.check_network(w.uri(), "signet") is None


@pytest.mark.asyncio
async def test_a_mainnet_wallet_is_refused_for_signet_change():
    async with FakeWallet({"get_info": {"network": "mainnet"}}) as w:
        why = await nwcclient.check_network(w.uri(), "signet")
    assert why and "mainnet" in why


@pytest.mark.asyncio
async def test_a_wallet_that_will_not_say_is_refused():
    """Silence is the case a default would have paid for."""
    async with FakeWallet({"get_info": {"alias": "quiet"}}) as w:
        why = await nwcclient.check_network(w.uri(), "signet")
    assert why and "does not report" in why


@pytest.mark.asyncio
async def test_the_wallet_refusing_permanently_raises_NwcError():
    """Which is what stops the retries: a connection with no send permission
    does not acquire one by being asked six times."""
    async with FakeWallet({"pay_invoice": ("UNAUTHORIZED", "no send")}) as w:
        with pytest.raises(NwcError):
            await nwcclient.pay_bolt11(w.uri(), "lnbc1")


@pytest.mark.asyncio
async def test_a_payment_failing_is_temporary():
    async with FakeWallet({"pay_invoice": ("PAYMENT_FAILED", "no route")}) as w:
        with pytest.raises(NwcTemporaryError) as e:
            await nwcclient.pay_bolt11(w.uri(), "lnbc1")
    assert "no route" in str(e.value)


@pytest.mark.asyncio
async def test_an_answer_to_another_request_is_not_taken():
    """THE ONE THAT WOULD COST MONEY: two payouts in flight on one connection
    taking each other's answer. Here the service tags its reply with the wrong
    request id, and the client waits rather than believing it."""
    async with FakeWallet({"pay_invoice": {"preimage": "ff" * 32}},
                          reply_to_wrong_request=True) as w:
        with pytest.raises(NwcTemporaryError) as e:
            await nwcclient.pay_bolt11(w.uri(), "lnbc1", timeout=2)
    assert "did not answer" in str(e.value)


@pytest.mark.asyncio
async def test_a_silent_wallet_times_out_rather_than_hanging():
    async with FakeWallet({"get_balance": None}) as w:
        with pytest.raises(NwcTemporaryError):
            await nwcclient.call(w.uri(), "get_balance", {}, timeout=2)


@pytest.mark.asyncio
async def test_a_nip04_only_service_is_spoken_to_in_nip04():
    """NIP-44 is preferred and NIP-04 is what a lot of services still speak.
    Sending the wrong one is SILENCE — a service that cannot decrypt a request
    does not know what it was asked and cannot say so — which is why the
    scheme is read off the info event rather than assumed."""
    async with FakeWallet({"get_balance": {"balance": 1_000}},
                          encryption="nip04") as w:
        assert await nwcclient.get_balance_sats(w.uri()) == 1


@pytest.mark.asyncio
async def test_no_info_event_means_nip04():
    """What the spec says to assume, and what every service predating the tag
    does."""
    async with FakeWallet({"get_balance": {"balance": 2_000}},
                          info_event=False) as w:
        assert await nwcclient.get_balance_sats(w.uri()) == 2


@pytest.mark.asyncio
async def test_a_dead_relay_is_tried_and_the_live_one_answers():
    """A connection string may name several relays, and they are alternatives
    rather than a quorum: the wallet service listens on all of them."""
    async with FakeWallet({"get_balance": {"balance": 5_000}}) as w:
        uri = (
            f"nostr+walletconnect://{WALLET_PUB}"
            f"?relay=ws://127.0.0.1:1&relay={w.url}&secret={CLIENT_SEC}"
        )
        assert await nwcclient.get_balance_sats(uri) == 5


@pytest.mark.asyncio
async def test_a_wallet_refusing_is_not_asked_again_on_the_next_relay():
    """Trying the next relay would ask the same wallet the same question. The
    refusal is the wallet's, not the relay's."""
    async with FakeWallet({"get_balance": ("RESTRICTED", "read only")}) as w:
        uri = (
            f"nostr+walletconnect://{WALLET_PUB}"
            f"?relay={w.url}&relay={w.url}&secret={CLIENT_SEC}"
        )
        with pytest.raises(NwcError):
            await nwcclient.get_balance_sats(uri)
    # Asked once, not once per relay.
    assert len([s for s in w.seen if s["method"] == "get_balance"]) == 1


@pytest.mark.asyncio
async def test_every_relay_failing_reports_the_last_reason():
    with pytest.raises(NwcTemporaryError):
        await nwcclient.get_balance_sats(
            f"nostr+walletconnect://{WALLET_PUB}"
            f"?relay=ws://127.0.0.1:1&secret={CLIENT_SEC}"
        )
