import dns.resolver
from http import HTTPStatus
from fastapi import HTTPException


def bip353_resolve(address: str):
    try:
        user, domain = address.strip().split("@")
    except ValueError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid BIP353 address format. Expected user@domain.com",
        )
    try:
        dns_domain = f"{user}.user._bitcoin-payment.{domain}"
        answers = dns.resolver.resolve(dns_domain, "TXT")
        result = ""
        for rdata in answers:
            result = "".join([a.decode() for a in rdata.strings])
            break
        if not result:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail=f"No TXT record found for {dns_domain}",
            )
        return {"address": address, "dns_domain": dns_domain, "result": result}
    except dns.resolver.NXDOMAIN:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail=f"Domain not found for {address}"
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
