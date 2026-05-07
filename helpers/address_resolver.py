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
DNSSEC_RESOLVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9']

# Authentic Data flag (RFC 4035) — set by resolver when DNSSEC validation passed
AD_FLAG = 0x0020


def _query_txt_with_dnssec(qname: str) -> tuple[list[str], bool]:
    """
    Query a TXT record using a DNSSEC-validating resolver.
    Returns (txt_records, dnssec_validated).
    dnssec_validated is True only when the AD flag is set in the response,
    meaning the upstream resolver successfully validated the DNSSEC chain.
    Tries each resolver in DNSSEC_RESOLVERS in order.
    """
    qname_obj = dns.name.from_text(qname)

    # Build query with DO (DNSSEC OK) bit set so resolver includes RRSIGs
    request = dns.message.make_query(qname_obj, dns.rdatatype.TXT, want_dnssec=True)

    last_error = None
    for nameserver in DNSSEC_RESOLVERS:
        try:
            # Try TCP first (more reliable for DNSSEC responses which can be large)
            try:
                response = dns.query.tcp(request, nameserver, timeout=10)
            except Exception:
                response = dns.query.udp(request, nameserver, timeout=10)

            # AD flag set = resolver validated the full DNSSEC chain
            dnssec_valid = bool(response.flags & AD_FLAG)

            # Extract TXT records from answer section
            records = []
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.TXT:
                    for rdata in rrset:
                        records.append("".join(s.decode() for s in rdata.strings))

            if records:
                return records, dnssec_valid

            # Check for NXDOMAIN (RCODE 3)
            if response.rcode() == dns.rcode.NXDOMAIN:
                raise dns.resolver.NXDOMAIN()

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except Exception as e:
            last_error = e
            logger.warning(f"DNSSEC query to {nameserver} failed: {e}, trying next")
            continue

    raise Exception(f"All DNSSEC resolvers failed. Last error: {last_error}")


def bip353_resolve(address: str) -> dict:
    try:
        user, domain = address.strip().split("@")
    except ValueError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid BIP353 address format. Expected user@domain.com",
        )

    dns_domain = f"{user}.user._bitcoin-payment.{domain}"

    try:
        records, dnssec_valid = _query_txt_with_dnssec(dns_domain)

        if not records:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail=f"No TXT record found for {dns_domain}",
            )

        if not dnssec_valid:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=(
                    f"DNSSEC validation failed for {dns_domain}. "
                    "The domain must have valid DNSSEC signatures. "
                    "Resolving this address would be unsafe."
                ),
            )

        result = records[0]

        if not result.startswith("bitcoin:"):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=f"TXT record does not contain a valid bitcoin: URI: {result}",
            )

        logger.info(f"BIP353 resolved {address} → {result} (DNSSEC validated)")
        return {
            "address":    address,
            "dns_domain": dns_domain,
            "result":     result,
            "dnssec":     True,
        }

    except HTTPException:
        raise
    except dns.resolver.NXDOMAIN:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"Domain not found: {dns_domain}",
        )
    except dns.resolver.NoAnswer:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=f"No TXT record found for {address}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"DNS resolution failed: {str(exc)}",
        )