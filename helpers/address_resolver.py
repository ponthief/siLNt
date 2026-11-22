import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from http import HTTPStatus
from fastapi import HTTPException
from loguru import logger

from .dnssec_chain import (
    DnssecBogus,
    DnssecUnsigned,
    KeyCache,
    NoRecord,
    Reply,
    Validator,
)

# Recursive resolvers used as TRANSPORT ONLY. Nothing they say about validity is
# read — their AD flag is ignored on purpose. BIP-353: "Clients ... MUST NOT
# trust a remote resolver to validate DNSSEC records on their behalf." Every
# signature is checked here, up to the root, by helpers/dnssec_chain.py.
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DNSSEC_RESOLVERS = RESOLVERS            # old name, kept for anything that imports it

# Validated DNSKEY sets, so a lookup is one TXT query plus the zones not seen
# lately rather than the whole chain every time. Never holds a payment
# instruction.
_KEY_CACHE = KeyCache()


def _network_fetch(name: dns.name.Name, rdtype: int) -> Reply:
    """Ask a resolver for `name`/`rdtype` with DO set and CD set.

    CD (checking disabled) makes a validating resolver hand the data over whether
    or not it could validate it, so a failure to validate on THEIR side cannot
    hide an answer from the validation that matters, which is ours.
    """
    request = dns.message.make_query(name, rdtype, want_dnssec=True)
    request.flags |= dns.flags.CD

    last_error = None
    for nameserver in RESOLVERS:
        try:
            response, _used_tcp = dns.query.udp_with_fallback(request, nameserver, timeout=10)
        except Exception as e:
            last_error = e
            logger.warning(f"DNS query to {nameserver} failed: {e}, trying next")
            continue
        if response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return Reply(rcode=response.rcode(), answer=list(response.answer))
        # SERVFAIL, REFUSED and the rest are the resolver's trouble, not an answer.
        last_error = Exception(f"RCODE {response.rcode()} from {nameserver}")
    raise Exception(f"All resolvers failed. Last error: {last_error}")


def _query_txt_with_dnssec(qname: str) -> tuple[list[str], bool]:
    """Every TXT record at `qname` (following CNAME / DNAME), each read off a chain
    of signatures that was verified here up to the root.

    Returns (texts, True). A name that is not signed raises DnssecUnsigned, one
    whose signatures do not hold raises DnssecBogus, and one with nothing
    published raises the same dnspython errors the callers already handle.
    """
    try:
        found = Validator(_network_fetch, cache=_KEY_CACHE).resolve_txt(qname)
    except NoRecord as e:
        if e.nxdomain:
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.NoAnswer()
    return found.texts, True


def _domain_resolves(domain: str) -> bool:
    """Does the bare domain exist at all?

    Only ever called on the failure path, to tell a typo in the domain apart
    from a BitMail that simply isn't published. Any doubt answers True, because
    the caller uses this to pick wording — guessing "that domain doesn't exist"
    at someone whose DNS is merely slow is worse than the vaguer message.
    """
    for rdtype in (dns.rdatatype.SOA, dns.rdatatype.A):
        try:
            request = dns.message.make_query(dns.name.from_text(domain), rdtype)
            response = dns.query.udp(request, DNSSEC_RESOLVERS[0], timeout=5)
            if response.rcode() != dns.rcode.NXDOMAIN:
                return True
        except Exception:
            return True
    return False


# Every message below is read by someone trying to pay a person, in a small red
# line on a phone. "No TXT record found for alice.user._bitcoin-payment.ex.com"
# told them nothing they could act on. Three things decide the wording:
#
#   1. Say what it means for the payment, not what the resolver returned.
#   2. Say whose problem it is — the address, the recipient's setup, or ours.
#   3. Never call an address invalid when it might be fine. A DNS outage and a
#      domain without DNSSEC are not typos, and telling someone their friend's
#      address is bogus because a resolver timed out sends them chasing the
#      wrong thing. Those two keep their own wording, and stay retryable.
#
# The precise DNS name stays in the logs, where whoever is debugging will look.


def _unsigned_refusal(address: str, domain: str, dns_domain: str) -> HTTPException:
    """A security refusal, not a bad address — say so, and give them the way round.
    Softening this into "invalid address" would hide the one case where the lookup
    succeeded and we still won't trust the answer."""
    logger.warning(f"BIP353 {address}: DNSSEC not validated for {dns_domain}")
    return HTTPException(
        status_code=HTTPStatus.BAD_REQUEST,
        detail=(
            f"{address} can’t be used safely: {domain} isn’t signed with "
            f"DNSSEC, so there’s no way to prove its BitMail record hasn’t "
            f"been altered. Ask the recipient for their sp1… address instead."
        ),
    )


def bip353_resolve(address: str) -> dict:
    address = address.strip()
    user, _, domain = address.partition("@")
    if not user or not domain or "@" in domain:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                f"“{address}” isn’t a valid BitMail address. "
                f"It should look like name@example.com."
            ),
        )

    dns_domain = f"{user}.user._bitcoin-payment.{domain}"

    try:
        records, dnssec_valid = _query_txt_with_dnssec(dns_domain)

        if not records:
            raise dns.resolver.NoAnswer()

        if not dnssec_valid:
            raise _unsigned_refusal(address, domain, dns_domain)

        # BIP-353: ignore TXT records that do not begin with "bitcoin:" (ignoring
        # case), and treat MORE THAN ONE that does as invalid. Taking the first
        # would let whoever can add a record to the zone choose which payment
        # instruction wins; refusing means nobody can.
        matching = [r for r in records if r[:8].lower() == "bitcoin:"]
        if len(matching) > 1:
            logger.warning(f"BIP353 {address}: {len(matching)} bitcoin: records at {dns_domain}")
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    f"The BitMail record for {address} is ambiguous: it publishes "
                    f"more than one payment instruction, so none of them can be "
                    f"trusted. Only the recipient can fix that."
                ),
            )
        if not matching:
            logger.warning(f"BIP353 {address}: {dns_domain} holds {records!r}")
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    f"The BitMail record for {address} is published but malformed — "
                    f"it doesn’t contain a Bitcoin address. Only the recipient can "
                    f"fix that."
                ),
            )
        result = matching[0]

        # logger.info(f"BIP353 resolved {address} → {result} (DNSSEC validated)")
        return {
            "address": address,
            "dns_domain": dns_domain,
            "result": result,
            "dnssec": True,
        }

    except HTTPException:
        raise
    except DnssecUnsigned as exc:
        logger.warning(f"BIP353 {address}: not signed: {exc}")
        raise _unsigned_refusal(address, domain, dns_domain)
    except DnssecBogus as exc:
        # Signatures were there and did not hold. Distinct from "not signed": this
        # is the case where the record may have been ALTERED, so it is never
        # softened into a typo and never retried into success.
        logger.warning(f"BIP353 {address}: DNSSEC validation FAILED for {dns_domain}: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                f"{address} can’t be used safely: its BitMail record failed DNSSEC "
                f"verification, so it may have been altered. Don’t send to it; ask "
                f"the recipient for their sp1… address another way."
            ),
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Both mean the same thing to the payer: nothing is published here. The
        # reported case — a record that existed and was deleted — lands on one
        # or the other depending on whether siblings remain, so they must not
        # read differently. The only split worth making is whether the domain
        # itself is reachable, because that is the difference between a typo
        # and a BitMail that is gone.
        logger.info(f"BIP353 {address}: nothing published at {dns_domain}")
        if not _domain_resolves(domain):
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail=(
                    f"No BitMail found for {address} — the domain {domain} doesn’t "
                    f"exist. Check the spelling."
                ),
            )
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=(
                f"No BitMail found for {address}. It may have been removed, or "
                f"never set up. Check it with the recipient, or ask for their "
                f"sp1… address."
            ),
        )
    except Exception as exc:
        # Our problem or the network's, and it may well work in a minute. This
        # must never read as "bad address" — that sends the payer off correcting
        # something that was right all along.
        logger.error(f"BIP353 {address}: lookup failed for {dns_domain}: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=(
                f"Couldn’t look up {address} right now — the DNS lookup didn’t "
                f"complete. The address may be fine; this is usually temporary, "
                f"so try again in a moment."
            ),
        )
