"""What does a payer see when a BitMail lookup fails?

Reported from the mobile app: sending to a BitMail whose DNS record had been
deleted showed "no txt record found". True, and useless — the payer does not
know what a TXT record is, cannot tell whose fault it is, and cannot tell
whether to retry or retype.

These tests pin the wording rather than the plumbing, because wording is what
broke. They drive the mapping with injected failures instead of real DNS: the
question is which message each condition produces, and a test that needs the
network to answer that is a test that fails on a train.

The rule being enforced throughout: never call an address invalid unless it
IS invalid. A DNS outage and a domain without DNSSEC are not typos, and saying
so sends the payer to correct something that was already right.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name


def _load():
    name = f"{PKG}.helpers.address_resolver"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "helpers" / "address_resolver.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ar = _load()
dns = ar.dns
HTTPException = ar.HTTPException

GOOD_TXT = "bitcoin:?sp=sp1qqw2nmn0mlrp5rjdgqmc9y8gxhsdtvwqzrxqf3qerp"


def _resolve(address, *, raises=None, records=None, dnssec=True, domain_exists=True):
    """Run bip353_resolve with the DNS layer replaced."""
    def fake_query(_qname):
        if raises is not None:
            raise raises
        return records, dnssec

    ar._query_txt_with_dnssec = fake_query
    ar._domain_resolves = lambda _d: domain_exists
    with pytest.raises(HTTPException) as e:
        ar.bip353_resolve(address)
    return e.value


def _clean(detail: str) -> str:
    """The checks below are about wording, so normalise the smart quotes."""
    return detail.replace("’", "'").replace("“", '"').replace("”", '"')


# ── the reported case ────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "failure",
    [dns.resolver.NoAnswer(), dns.resolver.NXDOMAIN()],
    ids=["no-answer", "nxdomain"],
)
def test_a_deleted_record_reads_as_a_missing_bitmail(failure):
    """Deleting a record gives NoAnswer or NXDOMAIN depending on whether
    siblings remain under the same name. The payer must not see two different
    explanations for one situation."""
    err = _resolve("alice@example.com", raises=failure)
    detail = _clean(err.detail)
    assert err.status_code == 404
    assert "No BitMail found for alice@example.com" in detail
    assert "removed" in detail, "should allow that it used to exist"
    assert "sp1" in detail, "should offer the way round it"
    assert "TXT" not in detail and "txt" not in detail.split("@")[0]
    assert "_bitcoin-payment" not in detail


def test_a_missing_domain_is_told_apart_from_a_missing_record():
    """A typo in the domain and a BitMail that was removed need different
    advice — check the spelling, versus check with the recipient."""
    err = _resolve("a@exmaple.com", raises=dns.resolver.NXDOMAIN(), domain_exists=False)
    detail = _clean(err.detail)
    assert err.status_code == 404
    assert "exmaple.com doesn't exist" in detail
    assert "spelling" in detail


# ── the two that must never be called "invalid" ─────────────────────────────

def test_a_dns_outage_does_not_blame_the_address():
    err = _resolve("bob@example.com", raises=Exception("all resolvers failed"))
    detail = _clean(err.detail)
    assert err.status_code == 502, "must stay retryable, not a 4xx"
    assert "may be fine" in detail
    assert "temporary" in detail
    assert "invalid" not in detail.lower()
    assert "resolver" not in detail.lower(), "internal detail belongs in the log"


def test_a_domain_without_dnssec_is_a_security_refusal_not_a_typo():
    err = _resolve("bob@example.com", records=[GOOD_TXT], dnssec=False)
    detail = _clean(err.detail)
    assert err.status_code == 400
    assert "DNSSEC" in detail, "say why it was refused"
    assert "example.com" in detail, "name the domain at fault"
    assert "sp1" in detail, "give them a way to pay anyway"
    assert "invalid" not in detail.lower()
    # It must stay distinguishable from "not found" — a wallet that collapses a
    # failed signature check into "couldn't find it" hides an attack.
    assert "No BitMail found" not in detail


# ── the remaining paths ──────────────────────────────────────────────────────

@pytest.mark.parametrize("address", ["notanemail", "@example.com", "bob@", "a@b@c.com"])
def test_a_malformed_address_says_what_one_looks_like(address):
    with pytest.raises(HTTPException) as e:
        ar.bip353_resolve(address)
    detail = _clean(e.value.detail)
    assert e.value.status_code == 400
    assert "isn't a valid BitMail address" in detail
    assert "name@example.com" in detail


def test_a_published_but_broken_record_blames_the_recipient():
    err = _resolve("bob@example.com", records=["not a bitcoin uri"])
    detail = _clean(err.detail)
    assert err.status_code == 400
    assert "published but malformed" in detail
    assert "recipient" in detail
    # The raw record contents are log material, not something to show a payer.
    assert "not a bitcoin uri" not in detail


def test_a_good_address_still_resolves():
    ar._query_txt_with_dnssec = lambda _q: ([GOOD_TXT], True)
    out = ar.bip353_resolve("bob@example.com")
    assert out["result"] == GOOD_TXT
    assert out["dnssec"] is True
    assert out["dns_domain"] == "bob.user._bitcoin-payment.example.com"


# ── the property that ties them together ─────────────────────────────────────

def test_no_message_leaks_dns_jargon_at_the_payer():
    """The specific regression: none of these should mention TXT records or the
    _bitcoin-payment name. Whoever is debugging reads the logs."""
    cases = [
        _resolve("a@example.com", raises=dns.resolver.NoAnswer()),
        _resolve("a@example.com", raises=dns.resolver.NXDOMAIN(), domain_exists=False),
        _resolve("a@example.com", raises=Exception("boom")),
        _resolve("a@example.com", records=["junk"]),
    ]
    for err in cases:
        detail = _clean(err.detail)
        for jargon in ("TXT record", "_bitcoin-payment", "NXDOMAIN", "rcode", "RCODE"):
            assert jargon not in detail, f"{jargon!r} leaked into: {detail}"
