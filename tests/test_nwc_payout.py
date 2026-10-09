"""Paying a Tango's change out of a wallet that is not on this server.

WHY THIS EXISTS. Until now the only payout wallet was an LNbits wallet here,
which meant mainnet — nothing in this extension can ask such a wallet which
chain its funding source runs on, so mainnet had to be assumed and every other
chain refused outright. That refusal was never really about chains. It was
about the wallet: paying a signet round's change out of a mainnet wallet buys
faucet coins with real sats, on repeat, for anyone who asks.

Nostr Wallet Connect reaches a wallet somebody else runs, and NIP-47 has it
SAY which chain it is on. So the rule is enforced where the answer is, and a
Coinos signet wallet can pay signet change.

EVERYTHING HERE IS THE PROTOCOL AND THE POLICY, with no relay in sight —
helpers/nwc.py is pure for that reason, the way tangopayoutrun.py is pure
beside tangopayout.py. A wallet protocol's error handling is exactly the part
nobody exercises on purpose, and against a live relay it is only exercised by
a real failure at a bad moment.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

import sys  # noqa: E402

sys.path.insert(0, str(ROOT))

from helpers import nostr  # noqa: E402
from helpers.nwc import (  # noqa: E402
    KIND_REQUEST,
    KIND_RESPONSE,
    NwcError,
    NwcTemporaryError,
    build_request,
    is_permanent,
    network_mismatch,
    normalise_network,
    parse_uri,
    read_response,
    response_for,
    sats_from_msat,
    valid_uri,
)

WALLET_SEC = "aa" * 32
CLIENT_SEC = "bb" * 32
WALLET_PUB = nostr.pubkey_of(WALLET_SEC)
RELAY = "wss://relay.example.org"
URI = f"nostr+walletconnect://{WALLET_PUB}?relay={RELAY}&secret={CLIENT_SEC}"


def _fn(path: str, name: str) -> str:
    """One function's source out of a module too heavy to import.

    PARSED, not sliced. Cutting at the next `def` runs past module-level
    constants that happen to sit between two functions, and a slice that
    quietly includes them makes a "this is not mentioned here" assertion pass
    or fail on where somebody put a constant.
    """
    src = (ROOT / path).read_text()
    for node in ast.walk(ast.parse(src)):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{path} has no {name}()")


# ── the connection string ────────────────────────────────────────────────────


def test_a_good_connection_string_parses():
    conn = parse_uri(URI)
    assert conn.wallet_pubkey == WALLET_PUB
    assert conn.relays == [RELAY]
    assert conn.secret == CLIENT_SEC
    assert conn.client_pubkey == nostr.pubkey_of(CLIENT_SEC)


def test_several_relays_are_alternatives_and_all_kept():
    """A wallet service listens on all of them, so the first that answers is
    the answer — but only if they all survive parsing."""
    conn = parse_uri(URI + "&relay=wss://two.example.org")
    assert conn.relays == [RELAY, "wss://two.example.org"]


def test_a_url_encoded_relay_is_decoded():
    conn = parse_uri(
        f"nostr+walletconnect://{WALLET_PUB}"
        f"?relay=wss%3A%2F%2Frelay.example.org&secret={CLIENT_SEC}"
    )
    assert conn.relays == [RELAY]


def test_the_scheme_may_be_written_without_the_slashes():
    conn = parse_uri(f"nostr+walletconnect:{WALLET_PUB}?relay={RELAY}&secret={CLIENT_SEC}")
    assert conn.wallet_pubkey == WALLET_PUB


def test_the_optional_lightning_address_is_kept():
    conn = parse_uri(URI + "&lud16=pay@example.org")
    assert conn.lud16 == "pay@example.org"


@pytest.mark.parametrize("bad,why", [
    ("", "no connection string"),
    ("https://example.org", "wrong scheme"),
    (f"nostr+walletconnect://xyz?relay={RELAY}&secret={CLIENT_SEC}", "short key"),
    (f"nostr+walletconnect://{'zz' * 32}?relay={RELAY}&secret={CLIENT_SEC}", "not hex"),
    (f"nostr+walletconnect://{WALLET_PUB}?secret={CLIENT_SEC}", "no relay"),
    (f"nostr+walletconnect://{WALLET_PUB}?relay={RELAY}", "no secret"),
    (f"nostr+walletconnect://{WALLET_PUB}?relay={RELAY}&secret=ab", "short secret"),
    (f"nostr+walletconnect://{WALLET_PUB}?relay=https://x.org&secret={CLIENT_SEC}",
     "relay is not a websocket"),
])
def test_every_refusal_names_itself(bad, why):
    """An operator is pasting 200 opaque characters into a form field.
    "Invalid" on its own is a support ticket."""
    with pytest.raises(NwcError) as e:
        parse_uri(bad)
    assert len(str(e.value)) > 20, why
    assert not valid_uri(bad)


def test_redacting_keeps_the_secret_out():
    """It is a SPENDING key: whoever holds it can empty the payout wallet. So
    nothing that renders a connection renders the whole thing."""
    conn = parse_uri(URI)
    out = conn.redacted()
    assert CLIENT_SEC not in out
    assert conn.secret not in out
    assert repr(conn).find(CLIENT_SEC) == -1
    # And still says enough to tell one connection from another.
    assert WALLET_PUB[:8] in out and RELAY in out


# ── the request ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("scheme", [nostr.NIP04, nostr.NIP44_V2])
def test_a_request_is_addressed_signed_and_readable_by_the_wallet(scheme):
    conn = parse_uri(URI)
    ev = build_request(conn, "pay_invoice", {"invoice": "lnbc1"}, scheme=scheme)
    assert ev["kind"] == KIND_REQUEST
    assert ["p", WALLET_PUB] in ev["tags"]
    assert ["encryption", scheme] in ev["tags"]
    assert nostr.verify_event(ev)
    assert ev["pubkey"] == conn.client_pubkey
    body = json.loads(
        nostr.decrypt(scheme, WALLET_SEC, conn.client_pubkey, ev["content"])
    )
    assert body == {"method": "pay_invoice", "params": {"invoice": "lnbc1"}}


def test_a_request_can_be_given_an_expiry():
    """A request that sat on a relay through a restart must not be paid an
    hour later, after the payout it belonged to was given up on and the user
    told it failed."""
    conn = parse_uri(URI)
    ev = build_request(conn, "pay_invoice", {}, created_at=1000, expires_in=150)
    assert ["expiration", "1150"] in ev["tags"]


def test_no_expiry_tag_when_none_was_asked_for():
    ev = build_request(parse_uri(URI), "get_info", {})
    assert not any(t[0] == "expiration" for t in ev["tags"])


# ── which answer belongs to which request ────────────────────────────────────


def _response(method, payload, *, request_id="e" * 64, sec=WALLET_SEC,
              to=None, kind=KIND_RESPONSE, tags=None):
    conn = parse_uri(URI)
    content = nostr.encrypt(
        nostr.NIP44_V2, sec, to or conn.client_pubkey, json.dumps(payload)
    )
    return nostr.sign_event(
        sec, kind, content,
        tags if tags is not None
        else [["e", request_id], ["p", to or conn.client_pubkey]],
    )


def test_the_matching_answer_is_accepted():
    ev = _response("get_balance", {"result_type": "get_balance",
                                   "result": {"balance": 7000}})
    assert response_for(ev, parse_uri(URI), "e" * 64)


def test_an_answer_to_another_request_is_not_ours():
    """THE ONE THAT WOULD COST MONEY. Two payouts in flight on one connection
    would otherwise take each other's answer, and one of them would be
    recorded as paid on the other's preimage."""
    ev = _response("pay_invoice", {"result_type": "pay_invoice",
                                   "result": {"preimage": "ab"}})
    assert not response_for(ev, parse_uri(URI), "f" * 64)


def test_an_answer_from_another_key_is_refused():
    """A relay is an untrusted middlebox and can hand back any event at all,
    including a real one signed by somebody else."""
    ev = _response("get_balance", {"result": {}}, sec="cc" * 32)
    assert not response_for(ev, parse_uri(URI), "e" * 64)


def test_a_forged_answer_is_refused():
    ev = _response("get_balance", {"result": {}})
    ev["content"] = "tampered"
    assert not response_for(ev, parse_uri(URI), "e" * 64)


def test_an_answer_addressed_to_somebody_else_is_refused():
    other = nostr.pubkey_of("dd" * 32)
    ev = _response("get_balance", {"result": {}}, to=other)
    assert not response_for(ev, parse_uri(URI), "e" * 64)


def test_an_answer_with_no_p_tag_is_still_ours():
    """The spec makes `p` a SHOULD. Refusing on its absence would turn a
    working wallet into a timeout that names nothing."""
    ev = _response("get_balance", {"result_type": "get_balance",
                                   "result": {"balance": 1}},
                   tags=[["e", "e" * 64]])
    assert response_for(ev, parse_uri(URI), "e" * 64)


def test_the_wrong_kind_is_refused():
    ev = _response("get_balance", {"result": {}}, kind=1)
    assert not response_for(ev, parse_uri(URI), "e" * 64)


# ── reading it ───────────────────────────────────────────────────────────────


def test_a_result_comes_back():
    ev = _response("get_balance", {"result_type": "get_balance",
                                   "result": {"balance": 7000}})
    assert read_response(parse_uri(URI), ev, "get_balance") == {"balance": 7000}


def test_an_answer_to_a_different_method_is_refused():
    """A pay_invoice answered with a get_balance has either been muddled with
    another request or is not the service we think. Reading a `balance` as a
    payment would record a payout as paid that never went out."""
    ev = _response("get_balance", {"result_type": "get_balance",
                                   "result": {"balance": 7000}})
    with pytest.raises(NwcTemporaryError):
        read_response(parse_uri(URI), ev, "pay_invoice")


def test_a_result_that_is_not_an_object_is_refused():
    ev = _response("pay_invoice", {"result_type": "pay_invoice", "result": None})
    with pytest.raises(NwcTemporaryError):
        read_response(parse_uri(URI), ev, "pay_invoice")


def test_unreadable_content_is_temporary_not_permanent():
    """A payout must not be abandoned over one garbled frame."""
    ev = _response("pay_invoice", {"result": {}})
    ev = nostr.sign_event(WALLET_SEC, KIND_RESPONSE, "not-encrypted", ev["tags"])
    with pytest.raises(NwcTemporaryError):
        read_response(parse_uri(URI), ev, "pay_invoice")


@pytest.mark.parametrize("code", [
    "UNAUTHORIZED", "RESTRICTED", "NOT_IMPLEMENTED",
    "UNSUPPORTED_ENCRYPTION", "QUOTA_EXCEEDED",
])
def test_the_wallet_refusing_stops_the_retries(code):
    """None of these become true by asking again, and five more attempts only
    delay telling an operator the one thing they can act on."""
    assert is_permanent(code)
    ev = _response("pay_invoice", {
        "result_type": "pay_invoice",
        "error": {"code": code, "message": "no"},
    })
    with pytest.raises(NwcError):
        read_response(parse_uri(URI), ev, "pay_invoice")


@pytest.mark.parametrize("code", [
    "INSUFFICIENT_BALANCE", "RATE_LIMITED", "PAYMENT_FAILED", "INTERNAL",
    "OTHER", "SOMETHING_NEW",
])
def test_the_wallet_failing_is_worth_retrying(code):
    """INSUFFICIENT_BALANCE especially: that one is an operator topping the
    wallet up, which is exactly what the retry window is for — and what the
    liquidity floor exists to make rare. An unknown code is treated the same
    way, because a code this version has not heard of is not evidence of
    anything final."""
    assert not is_permanent(code)
    ev = _response("pay_invoice", {
        "result_type": "pay_invoice",
        "error": {"code": code, "message": "later"},
    })
    with pytest.raises(NwcTemporaryError):
        read_response(parse_uri(URI), ev, "pay_invoice")


def test_an_error_carries_its_text_through():
    ev = _response("pay_invoice", {
        "result_type": "pay_invoice",
        "error": {"code": "PAYMENT_FAILED", "message": "no route to 03ab"},
    })
    with pytest.raises(NwcTemporaryError) as e:
        read_response(parse_uri(URI), ev, "pay_invoice")
    assert "no route to 03ab" in str(e.value)


# ── amounts ──────────────────────────────────────────────────────────────────


def test_a_balance_is_floored_not_rounded():
    """Rounded up, a balance is one this instance would promise a payout
    against and not have."""
    assert sats_from_msat(7_999) == 7
    assert sats_from_msat(8_000) == 8
    assert sats_from_msat(0) == 0
    assert sats_from_msat(None) == 0
    assert sats_from_msat(-1) == 0


# ── which chain ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("reported,want", [
    ("mainnet", "mainnet"), ("bitcoin", "mainnet"), ("main", "mainnet"),
    ("signet", "signet"), ("SIGNET", "signet"), (" signet ", "signet"),
    ("testnet", "testnet"), ("testnet3", "testnet"), ("testnet4", "testnet"),
    ("regtest", "regtest"),
    ("", ""), (None, ""), ("liquid", ""),
])
def test_networks_are_normalised(reported, want):
    assert normalise_network(reported) == want


def test_a_signet_wallet_may_pay_signet_change():
    """The whole point of the change. A Coinos signet wallet reports signet,
    and signet change is paid in signet sats."""
    assert network_mismatch("signet", "signet") is None


def test_a_mainnet_wallet_may_not_pay_signet_change():
    """The failure the old chain list existed to prevent, now stated against
    the thing it was always about."""
    why = network_mismatch("mainnet", "signet")
    assert why and "mainnet" in why and "signet" in why


def test_silence_is_a_refusal():
    why = network_mismatch(None, "mainnet")
    assert why and "does not report" in why


# ── the wiring ───────────────────────────────────────────────────────────────


def test_the_chain_is_checked_again_at_the_moment_of_paying():
    """The liquidity pass checked it, minutes or hours ago, and a connection
    string can be re-pointed at another wallet in between. This is the call
    that actually spends."""
    body = _fn("views_api.py", "_pay_payout_invoice")
    assert "check_network" in body
    assert "raise NwcError(mismatch)" in body
    assert body.index("check_network") < body.index("pay_bolt11")


def test_the_chain_is_checked_before_the_balance_is_believed():
    """A healthy balance on the wrong chain is the exact failure. Reading it
    first and refusing afterwards would be the same answer; reading it first
    and forgetting to refuse would not, so the order is pinned."""
    body = _fn("views_api.py", "_nwc_payout_balance")
    assert body.index("check_network") < body.index("get_balance_sats")


def test_an_unreachable_wallet_stops_rounds_routing():
    """Not offering the setting for a few minutes costs a user a privacy
    improvement. Offering it against an unknown wallet costs them a coin."""
    body = _fn("views_api.py", "_nwc_payout_balance")
    assert "return None" in body
    assert "raise" not in body.replace("raise", "", 0).split("return None")[0]


def test_a_wallet_refusing_is_reported_as_ours_not_the_user_s():
    """'unpayable' tells the user to go and change their Lightning address.
    A connection with no send permission is not their address's fault, and
    telling them it is would send them to fix something that is not broken."""
    src = (ROOT / "views_api.py").read_text()
    assert "permanent, ours, error = True, True, str(e)" in src
    assert "status_after(attempts, permanent, ours)" in src

    run = (ROOT / "helpers" / "tangopayoutrun.py").read_text()
    body = run[run.index("def status_after"):]
    body = body[: body.index("\n\n\n")]
    assert "ours" in body


def test_status_after_separates_whose_fault_it_was():
    from helpers.tangopayoutrun import MAX_ATTEMPTS, status_after

    # The destination's, which the user can fix.
    assert status_after(1, True) == "unpayable"
    # Ours and final: stop trying, and do not send them after their address.
    assert status_after(1, True, True) == "failed"
    # Ours and not final: keep trying.
    assert status_after(1, False) == "pending"
    assert status_after(MAX_ATTEMPTS, False) == "failed"


def test_the_balance_is_cached_briefly_and_the_spend_check_is_not():
    """_tango_routes_change calls the liquidity read at propose AND at accept,
    inside the request — for an LNbits wallet that is a local database row,
    for an NWC wallet it is two relay round trips with somebody waiting on
    them. Thirty seconds of staleness cannot push a decision past a floor that
    is an amount-independent buffer in the first place.

    The check that actually spends is not cached, and that is the half worth
    pinning: a connection string can be re-pointed between the two.
    """
    src = (ROOT / "views_api.py").read_text()
    assert "NWC_STATE_TTL_SECONDS = 30" in src
    balance = _fn("views_api.py", "_nwc_payout_balance")
    assert "_nwc_state_cache" in balance
    paying = _fn("views_api.py", "_pay_payout_invoice")
    assert "_nwc_state_cache" not in paying
    assert "check_network" in paying


def test_the_cache_is_keyed_on_the_connection_not_just_the_chain():
    """Re-pointing the string at another wallet must invalidate the answer
    rather than inherit it — the other wallet may be on another chain."""
    key = _fn("views_api.py", "_nwc_cache_key")
    assert "network" in key and "sha256" in key
    # And the credential itself is not what gets kept in a process-lifetime
    # dict that somebody will print while debugging.
    assert "uri.encode" in key


def test_a_failure_is_cached_too():
    """A relay that is down should not be dialled afresh by every propose on
    the instance."""
    balance = _fn("views_api.py", "_nwc_payout_balance")
    assert "_nwc_state_cache[key] = (now + NWC_STATE_TTL_SECONDS, balance, reason)" in balance


def test_the_payout_source_is_whichever_is_configured():
    src = (ROOT / "models.py").read_text()
    body = src[src.index("def payout_source"):]
    body = body[: body.index("\n    def ")]
    # NWC first: an operator with both set gets the one that can name its own
    # chain, and the health endpoint says which is in use.
    assert body.index("tango_change_payout_nwc") < body.index(
        "tango_change_payout_wallet_id"
    )


def test_a_bad_connection_string_is_refused_at_the_config_door():
    """At payout time the change output has already become the instance's and
    the user is owed. The one moment somebody can fix a typo is while they are
    looking at the field."""
    body = _fn("views_api.py", "api_update_backend_config")
    assert "parse_uri(nwc_uri)" in body


def test_the_relay_client_is_not_imported_at_module_scope():
    """A server with no websocket library still starts, and still serves every
    wallet that does not pay out over NWC."""
    src = (ROOT / "views_api.py").read_text()
    head = src[: src.index("\n@silnt_api_router")]
    assert "from .helpers.nwc import NwcError" in head
    # The word appears in the comment that explains this; the import does not.
    assert re.search(r"^from \.helpers\.nwcclient import", head, re.M) is None
    assert re.search(r"^import .*nwcclient", head, re.M) is None
    client = (ROOT / "helpers" / "nwcclient.py").read_text()
    assert re.search(r"^import websockets", client, re.M) is None
