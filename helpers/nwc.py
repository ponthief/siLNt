"""Nostr Wallet Connect (NIP-47), the protocol half.

WHAT THIS IS FOR. A Tango's routed change is owed to the user over Lightning,
and until now the only wallet this instance could pay from was an LNbits
wallet on the same server — which meant mainnet, because that is the only
chain an LNbits funding source here runs on. NWC is a second way to reach a
wallet: a connection string, a relay, and a request signed to the wallet
service's key. It is what makes a Coinos SIGNET wallet reachable, and with it
a signet round's change can be paid in signet sats instead of not at all.

PURE ON PURPOSE, like tangopayoutrun.py beside tangopayout.py. Everything here
is strings and dictionaries: parsing the connection, building the request,
reading the answer, deciding whether a failure is worth retrying. The socket
is in nwcclient.py. The split is what makes the rules assertable — they are
otherwise only exercised against a live relay, and a wallet protocol's error
handling is exactly the part nobody exercises on purpose.

THE NETWORK IS THE WHOLE POINT, so it is checked and not configured. A payout
source has to be on the same chain as the round whose change it is paying, and
NIP-47's own `get_info` reports which chain it is on. That reported value is
what this instance believes — not a config key an operator can get wrong, and
not a hardcoded list of chains. A wallet that will not say is refused: the
failure being guarded against is an instance paying real sats for faucet
coins, and "probably signet" is not an answer to it.
"""

from __future__ import annotations

import json
import time
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

from . import nostr


# NIP-47 event kinds.
KIND_INFO = 13194        # the wallet service's capabilities, replaceable
KIND_REQUEST = 23194     # ours
KIND_RESPONSE = 23195    # theirs

URI_SCHEME = "nostr+walletconnect"

# How long to wait for a wallet service to answer. A Lightning payment can
# genuinely take a while to settle, and the wallet service only answers once it
# has — so this is a payment timeout, not a network one.
DEFAULT_TIMEOUT_SECONDS = 90
# get_info and get_balance are answered out of the service's own state.
INFO_TIMEOUT_SECONDS = 20


class NwcError(Exception):
    """A failure that will not become a success by asking again: a bad
    connection string, a rejected method, an amount the wallet refuses."""


class NwcTemporaryError(Exception):
    """A failure worth retrying: a relay that would not connect, a timeout, a
    route that was not there this minute."""


class NwcConnection:
    """A parsed connection string. Carries a spending credential, so it knows
    how to print itself without one."""

    __slots__ = ("wallet_pubkey", "relays", "secret", "lud16")

    def __init__(self, wallet_pubkey: str, relays: list, secret: str,
                 lud16: str = ""):
        self.wallet_pubkey = wallet_pubkey
        self.relays = relays
        self.secret = secret
        self.lud16 = lud16

    @property
    def client_pubkey(self) -> str:
        """Ours, derived from the secret. The wallet service addresses its
        answers to this, and it is what a `p` tag on a response must carry."""
        return nostr.pubkey_of(self.secret)

    def redacted(self) -> str:
        """Safe to log, to store in a health record, to put in an API
        response. THE SECRET IS A SPENDING KEY — anyone holding it can empty
        the payout wallet — so nothing that renders a connection renders the
        whole thing. The wallet pubkey and relay are not sensitive and are
        what an operator needs to recognise which connection this is.
        """
        return (
            f"{URI_SCHEME}://{self.wallet_pubkey[:8]}…"
            f"?relay={self.relays[0] if self.relays else '(none)'}"
            f"&secret=…"
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging only
        return f"NwcConnection({self.redacted()})"


def parse_uri(uri: str) -> NwcConnection:
    """A connection string to something usable, or a named refusal.

    Every rejection says what is wrong with it. An operator pasting one of
    these into a config field is pasting 200 opaque characters, and "invalid"
    on its own is a support ticket.
    """
    text = (uri or "").strip()
    if not text:
        raise NwcError("No NWC connection string.")
    # urlparse does not treat an unknown scheme as hierarchical, so the host
    # lands in `path` for some inputs. Normalising to // form first keeps the
    # wallet pubkey in `netloc` wherever it was written.
    if not text.lower().startswith(URI_SCHEME + "://"):
        if text.lower().startswith(URI_SCHEME + ":"):
            text = URI_SCHEME + "://" + text.split(":", 1)[1].lstrip("/")
        else:
            raise NwcError(
                f"An NWC connection string starts with {URI_SCHEME}://"
            )
    parsed = urlparse(text)
    wallet = (parsed.netloc or parsed.path.lstrip("/")).strip().lower()
    if len(wallet) != 64 or any(c not in "0123456789abcdef" for c in wallet):
        raise NwcError(
            "The NWC connection string does not start with a 32-byte wallet "
            "public key."
        )
    q = parse_qs(parsed.query)
    relays = [unquote(r).strip() for r in q.get("relay", []) if (r or "").strip()]
    if not relays:
        raise NwcError("The NWC connection string names no relay.")
    for r in relays:
        if not r.lower().startswith(("wss://", "ws://")):
            raise NwcError(f"{r} is not a relay URL.")
    secret = (q.get("secret", [""])[0] or "").strip().lower()
    if len(secret) != 64 or any(c not in "0123456789abcdef" for c in secret):
        raise NwcError(
            "The NWC connection string carries no 32-byte secret."
        )
    return NwcConnection(
        wallet_pubkey=wallet,
        relays=relays,
        secret=secret,
        lud16=(q.get("lud16", [""])[0] or "").strip(),
    )


def valid_uri(uri: str) -> bool:
    try:
        parse_uri(uri)
        return True
    except NwcError:
        return False


# ── The request and the answer ───────────────────────────────────────────────


def build_request(conn: NwcConnection, method: str, params: dict,
                  scheme: str = nostr.NIP44_V2,
                  created_at: Optional[int] = None,
                  expires_in: Optional[int] = None) -> dict:
    """A signed, encrypted kind-23194 event.

    The `encryption` tag says which scheme the body used, and the spec has the
    service answer in the same one. An `expiration` tag is set so a request
    that sat on a relay through a restart is dropped rather than paid late —
    a payout we have already given up on and reported must not go out an hour
    later as well.
    """
    at = int(created_at if created_at is not None else time.time())
    body = json.dumps({"method": method, "params": params or {}},
                      separators=(",", ":"))
    tags = [["p", conn.wallet_pubkey], ["encryption", scheme]]
    if expires_in:
        tags.append(["expiration", str(at + int(expires_in))])
    return nostr.sign_event(
        conn.secret,
        KIND_REQUEST,
        nostr.encrypt(scheme, conn.secret, conn.wallet_pubkey, body),
        tags,
        created_at=at,
    )


def response_for(event: dict, conn: NwcConnection, request_id: str) -> bool:
    """Is this event the answer to that request?

    FOUR THINGS, and the signature is only one of them. A relay can hand back
    any event at all, including a real one from somebody else, so: the right
    kind, signed by the WALLET SERVICE's key and not merely signed, addressed
    to us, and tagged with the id of the request we are waiting on. Without
    the last, two payouts in flight on one connection could take each other's
    answer — and one of them would be recorded as paid on the other's
    preimage.
    """
    if int(event.get("kind") or 0) != KIND_RESPONSE:
        return False
    if str(event.get("pubkey") or "").lower() != conn.wallet_pubkey:
        return False
    if not nostr.verify_event(event):
        return False
    tags = event.get("tags") or []
    if not any(
        len(t) >= 2 and t[0] == "e" and str(t[1]) == request_id for t in tags
    ):
        return False
    # A `p` tag is a SHOULD in the spec, so its absence is not a refusal — but
    # if it is there and names somebody else, this is not our answer.
    for t in tags:
        if len(t) >= 2 and t[0] == "p" and str(t[1]).lower() != conn.client_pubkey:
            return False
    return True


def read_response(conn: NwcConnection, event: dict, method: str) -> dict:
    """The decrypted `result` of a response, or the right exception.

    `result_type` is checked against the method asked for. A service that
    answered a pay_invoice with a get_balance result has either muddled two
    requests or is not the service we think, and reading a `balance` field as
    a payment would record a payout as paid that never went out.
    """
    try:
        body = nostr.decrypt(
            nostr.NIP44_V2, conn.secret, conn.wallet_pubkey,
            str(event.get("content") or ""),
        )
    except Exception as e:
        raise NwcTemporaryError(f"Could not read the wallet's answer: {e}")
    try:
        payload = json.loads(body)
    except ValueError:
        raise NwcTemporaryError("The wallet's answer was not JSON.")

    error = payload.get("error")
    if error:
        code = str((error or {}).get("code") or "OTHER")
        message = str((error or {}).get("message") or "").strip()
        raise_for_code(code, message)

    result_type = str(payload.get("result_type") or "")
    if result_type and result_type != method:
        raise NwcTemporaryError(
            f"The wallet answered a {method} with a {result_type}."
        )
    result = payload.get("result")
    if not isinstance(result, dict):
        raise NwcTemporaryError(f"The wallet's {method} answer carried no result.")
    return result


# NIP-47's own error codes, split by whether asking again could ever help.
#
# RESTRICTED and UNAUTHORIZED are the connection's permissions — a send-less
# string, a budget that has run out, a revoked connection. None of those clear
# on their own, and five more attempts only delay telling an operator the one
# thing they can act on.
#
# INSUFFICIENT_BALANCE is deliberately NOT permanent: it is the operator
# topping the wallet up, which is exactly what the retry window is for. It is
# also what the liquidity floor exists to make rare.
PERMANENT_CODES = frozenset({
    "UNAUTHORIZED",
    "RESTRICTED",
    "NOT_IMPLEMENTED",
    "UNSUPPORTED_ENCRYPTION",
    "QUOTA_EXCEEDED",
})


def is_permanent(code: str) -> bool:
    return str(code or "").strip().upper() in PERMANENT_CODES


def raise_for_code(code: str, message: str = "") -> None:
    text = f"{code}: {message}" if message else str(code)
    if is_permanent(code):
        raise NwcError(text)
    raise NwcTemporaryError(text)


# ── Which chain is on the other end ──────────────────────────────────────────

# What a wallet service may call each chain, mapped to what this extension
# calls it. "bitcoin" is not in NIP-47's list and is what several services send
# anyway; reading it as mainnet is safe in the direction that matters, since
# mainnet is the chain whose coins are worth something.
_NETWORK_ALIASES = {
    "mainnet": "mainnet",
    "main": "mainnet",
    "bitcoin": "mainnet",
    "signet": "signet",
    "testnet": "testnet",
    "test": "testnet",
    "testnet3": "testnet",
    "testnet4": "testnet",
    "regtest": "regtest",
}


def normalise_network(reported: str) -> str:
    """A wallet service's `network` in this extension's vocabulary, or ""."""
    return _NETWORK_ALIASES.get(str(reported or "").strip().lower(), "")


def network_mismatch(reported: str, ours: str) -> Optional[str]:
    """Why this wallet must not pay for that chain's rounds. None when it may.

    THE REFUSAL WHEN NOTHING WAS REPORTED IS THE IMPORTANT ONE. A wallet that
    does not say which chain it is on used to be impossible to have, because
    the only payout source was an LNbits wallet on this server and the chain
    was assumed. Over NWC the wallet is somebody else's and the assumption is
    gone — and the specific thing assuming wrongly buys is an instance paying
    real sats out for signet change, on repeat, to anyone who asks. So silence
    is a refusal rather than a default.
    """
    want = (ours or "").strip().lower()
    got = normalise_network(reported)
    if not got:
        return (
            "The NWC wallet does not report which Bitcoin network it is on, "
            "so it cannot be used to pay out — see helpers/nwc.py."
        )
    if got != want:
        return (
            f"The NWC wallet is on {got}, and it would be paying out "
            f"{want} change."
        )
    return None


def sats_from_msat(msat) -> int:
    """Floor, never round. A balance rounded UP is a balance this instance
    would promise a payout against and not have."""
    return max(0, int(msat or 0) // 1000)
