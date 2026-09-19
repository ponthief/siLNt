import dns.resolver
import dns.message
import dns.query
import dns.name
import dns.rdatatype
import dns.flags
from http import HTTPStatus
from fastapi import HTTPException
from loguru import logger

# DNSSEC-validating resolvers — both validate the full chain and set AD flag
DNSSEC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Authentic Data flag (RFC 4035) — set by resolver when DNSSEC validation passed
AD_FLAG = 0x0020


def _query_txt_with_dnssec(qname: str) -> tuple[list[str], bool]:
    qname_obj = dns.name.from_text(qname)
    request = dns.message.make_query(qname_obj, dns.rdatatype.TXT, want_dnssec=True)

    last_error = None
    for nameserver in DNSSEC_RESOLVERS:
        try:
            try:
                response = dns.query.tcp(request, nameserver, timeout=10)
            except Exception:
                response = dns.query.udp(request, nameserver, timeout=10)

            dnssec_valid = bool(response.flags & AD_FLAG)

            records = []
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.TXT:
                    for rdata in rrset:
                        records.append("".join(s.decode() for s in rdata.strings))

            if records:
                return records, dnssec_valid

            # NXDOMAIN → domain itself doesn't exist
            if response.rcode() == dns.rcode.NXDOMAIN:
                raise dns.resolver.NXDOMAIN()

            # ★ NEW: resolver answered successfully (NOERROR) but there are no
            # TXT records → the name has no BIP-353 record. This is a definitive
            # "not found", NOT a resolver failure. Raise NoAnswer so the caller
            # maps it to 404 instead of falling through to "all resolvers failed".
            if response.rcode() == dns.rcode.NOERROR:
                raise dns.resolver.NoAnswer(response=response)

            # Any other RCODE (SERVFAIL etc.) → try the next resolver
            last_error = Exception(f"RCODE {response.rcode()} from {nameserver}")
            continue

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except Exception as e:
            last_error = e
            logger.warning(f"DNSSEC query to {nameserver} failed: {e}, trying next")
            continue

    raise Exception(f"All DNSSEC resolvers failed. Last error: {last_error}")


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
            # A security refusal, not a bad address — say so, and give them the
            # way round it. Softening this into "invalid address" would hide
            # the one case where the lookup succeeded and we still won't trust
            # the answer.
            logger.warning(f"BIP353 {address}: DNSSEC not validated for {dns_domain}")
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    f"{address} can’t be used safely: {domain} isn’t signed with "
                    f"DNSSEC, so there’s no way to prove its BitMail record hasn’t "
                    f"been altered. Ask the recipient for their sp1… address instead."
                ),
            )

        result = records[0]

        if not result.startswith("bitcoin:"):
            logger.warning(f"BIP353 {address}: {dns_domain} holds {result!r}")
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    f"The BitMail record for {address} is published but malformed — "
                    f"it doesn’t contain a Bitcoin address. Only the recipient can "
                    f"fix that."
                ),
            )

        # logger.info(f"BIP353 resolved {address} → {result} (DNSSEC validated)")
        return {
            "address": address,
            "dns_domain": dns_domain,
            "result": result,
            "dnssec": True,
        }

    except HTTPException:
        raise
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
