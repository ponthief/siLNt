"""Resolving a Lightning address, and refusing the ones that cannot be paid.

WHAT IT IS FOR. A Tango round leaves a change output. It is the strongest
remaining linkability problem in the protocol — its value is fixed by the
round's arithmetic, so spending it later, to anyone, identifies which of the
two identical shares were its owner's. A user may instead give a Lightning
address for that value to be sent to; the output itself goes to the instance's
SP address. See TANGO_CHANGE_CREDIT.md.

WHY IT IS CHECKED WHEN IT IS SAVED. The alternative is finding out at payout
time, which is after the coin has already left their wallet and become ours.
A provider whose minimum is above a typical change, or an address with no
LNURL endpoint at all, has to be refused while the person is looking at the
field.

LUD-16, then LUD-06:

    user@domain  ->  GET https://domain/.well-known/lnurlp/user
                     {tag: "payRequest", callback, minSendable, maxSendable}
                     GET callback?amount=<msat>  ->  {pr: "<bolt11>"}

THE PART THAT IS NOT A FORMALITY: this makes the server fetch a URL whose host
the user chose, which is a server-side request forgery primitive pointed at
whatever the backend can reach. `_safe_host` is the guard — https only, no IP
literals, no localhost or internal suffixes — and it runs before any request
leaves. It is not a complete defence (a hostname whose DNS answer is a private
address still resolves there) and it is not claimed as one; a deployment that
cares should also egress-filter. What it does stop is the obvious form, which
is someone typing `bob@127.0.0.1` into a settings field.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

import httpx

# A conservative address shape. Deliberately stricter than an email: this is
# going to become a hostname in a URL.
_LOCAL_RE = re.compile(r"^[a-z0-9._%+\-]{1,64}$")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

# Hosts that must never be fetched, whatever the user typed.
_BLOCKED_SUFFIXES = (
    ".local", ".localhost", ".internal", ".lan", ".home", ".arpa", ".onion",
)
_BLOCKED_NAMES = ("localhost", "metadata", "metadata.google.internal")

# Enough for a payRequest document; anything larger is not one.
_MAX_BYTES = 64 * 1024
_TIMEOUT = 10.0


class LnAddressError(ValueError):
    """Why this address cannot be used, in words meant for the person who
    typed it."""


def split_address(address: str) -> tuple[str, str]:
    """('satoshi', 'coinos.io'), or raise with the reason."""
    text = (address or "").strip().lower()
    if not text:
        raise LnAddressError("Enter a Lightning address.")
    if text.count("@") != 1:
        raise LnAddressError(
            "A Lightning address looks like name@domain, for example "
            "satoshi@coinos.io."
        )
    local, _, domain = text.partition("@")
    if not _LOCAL_RE.match(local):
        raise LnAddressError("The part before the @ has characters that are not allowed.")
    if not _DOMAIN_RE.match(domain):
        raise LnAddressError("The part after the @ is not a domain name.")
    return local, domain


def _safe_host(domain: str) -> None:
    """Refuse a host the backend has no business fetching. See the module
    docstring: this is the SSRF guard, and it runs before any request."""
    if domain in _BLOCKED_NAMES or domain.endswith(_BLOCKED_SUFFIXES):
        raise LnAddressError("That domain cannot be used for a Lightning address.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return          # a name, which is what we want
    # An IP literal reached the domain regex only if something is wrong with
    # it, but say no explicitly rather than relying on that.
    raise LnAddressError("A Lightning address needs a domain name, not an IP address.")


def lnurlp_url(address: str) -> str:
    """The LUD-16 well-known URL. https only, and never derived from anything
    the response says — a redirect to http, or to another host, is the same
    hole the scheme check closes."""
    local, domain = split_address(address)
    _safe_host(domain)
    return f"https://{domain}/.well-known/lnurlp/{local}"


class PayEndpoint:
    """What the provider says it will accept."""

    __slots__ = ("callback", "min_sendable_msat", "max_sendable_msat", "metadata")

    def __init__(self, callback: str, min_msat: int, max_msat: int, metadata: str = ""):
        self.callback = callback
        self.min_sendable_msat = min_msat
        self.max_sendable_msat = max_msat
        self.metadata = metadata

    def accepts_sats(self, sats: int) -> bool:
        msat = int(sats) * 1000
        return self.min_sendable_msat <= msat <= self.max_sendable_msat

    def dict(self) -> dict:
        return {
            "callback": self.callback,
            "min_sendable_msat": self.min_sendable_msat,
            "max_sendable_msat": self.max_sendable_msat,
        }


def parse_pay_response(doc: dict) -> PayEndpoint:
    """Read a payRequest document, or say what is wrong with it.

    Separate from the fetch so it can be tested without a network, which is
    the only way the awkward shapes — a string where a number belongs, a
    reversed min/max — get covered at all.
    """
    if not isinstance(doc, dict):
        raise LnAddressError("That address did not return a Lightning endpoint.")
    if (doc.get("status") or "").upper() == "ERROR":
        raise LnAddressError(
            (doc.get("reason") or "").strip()[:200]
            or "That address's provider refused the request."
        )
    if (doc.get("tag") or "") != "payRequest":
        raise LnAddressError("That address does not accept Lightning payments.")
    callback = (doc.get("callback") or "").strip()
    if not callback.lower().startswith("https://"):
        raise LnAddressError("That address's provider did not give a secure callback.")
    try:
        lo = int(doc["minSendable"])
        hi = int(doc["maxSendable"])
    except (KeyError, TypeError, ValueError):
        raise LnAddressError("That address's provider did not say what it accepts.")
    if lo <= 0 or hi <= 0 or hi < lo:
        raise LnAddressError("That address's provider reported limits that make no sense.")
    return PayEndpoint(callback, lo, hi, str(doc.get("metadata") or ""))


async def resolve(address: str) -> PayEndpoint:
    """Fetch and parse the payRequest document. Raises LnAddressError."""
    url = lnurlp_url(address)
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            # A redirect can move the request to a host that never passed
            # _safe_host, which would be the guard letting go of the thing it
            # was holding.
            follow_redirects=False,
        ) as client:
            r = await client.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError:
        raise LnAddressError(
            "Could not reach that address's provider. Check the spelling, or "
            "try again shortly."
        )
    if r.status_code != 200:
        raise LnAddressError(
            f"That address's provider answered {r.status_code}. Check the spelling."
        )
    if len(r.content) > _MAX_BYTES:
        raise LnAddressError("That address's provider returned something too large to be a Lightning endpoint.")
    try:
        doc = r.json()
    except ValueError:
        raise LnAddressError("That address did not return a Lightning endpoint.")
    return parse_pay_response(doc)
