"""Local DNSSEC validation, for BIP-353 payment instructions.

WHY THIS EXISTS. BIP-353 says a client resolving a payment instruction "MUST
fully validate DNSSEC signatures leading to the DNS root" and "MUST NOT trust a
remote resolver to validate DNSSEC records on their behalf". This extension used
to ask 1.1.1.1 / 8.8.8.8 / 9.9.9.9 and believe the AD flag in the answer — which
is a resolver saying "I validated this", carried over plain DNS that anyone on
the path can forge, naming nobody who can be held to it. Cake Wallet's
(2026-11-22) was the neighbouring bug: the address came from one source and a
proof from another and nothing compared them. Here there is one source, and the
answer is only ever read off records whose signatures chain to the root.

WHAT IT DOES. Given a way to fetch records (network in production, a fixture in
tests — this module opens no socket), it:

  1. takes the TXT record for the name, following CNAME and DNAME records,
     every one of which must be signed;
  2. checks each RRSIG against its zone's DNSKEY set;
  3. proves that DNSKEY set from the zone's DS record in the parent, whose own
     signature is proved the same way, up to the root;
  4. and stops at the root's DNSKEY set, which must match a trust anchor written
     into this file (IANA root-anchors.xml).

The recursive resolver is therefore transport only. It is asked with the CD
(checking disabled) bit so it returns the data whether or not it could validate
it, and nothing it says about validity is read.

WHAT IT REFUSES, each a way a forged answer gets in:

  * an answer the name does not lead to. The records used are found by FOLLOWING
    the chain from the name asked, so a validly signed record for some other name
    is not mistaken for this one (the Cake finding: "a valid proof for any other
    signed name passes");
  * SHA-1 signatures and RSA keys under 1024 bits (BIP-353 MUST NOT accept them);
  * a signature outside its validity window, judged against `now`;
  * a wildcard-expanded answer. Accepting one needs an NSEC/NSEC3 proof that no
    closer name exists, and without it a resolver can synthesise an answer for a
    name that has its own record. That proof is not implemented, so such answers
    are REFUSED, not accepted on the signature alone. This is the one case BIP-353
    allows that this does not: a record published by wildcard is not payable.
  * a zone with no DS record in its parent (not securely delegated).

DS digest types 1, 2 and 4 are accepted: BIP-353 says a resolver MAY accept SHA-1
DS records, and a domain whose only DS is SHA-1 would otherwise be unpayable.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset

T = dns.rdatatype
IN = dns.rdataclass.IN

# Signing algorithms we accept (RFC 8624 "MUST/RECOMMENDED"): RSASHA256,
# RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519, ED448. Everything else —
# RSASHA1 (5), RSASHA1-NSEC3-SHA1 (7) and the obsolete 1, 3, 6, 12 — is refused.
ALLOWED_ALGORITHMS = frozenset({8, 10, 13, 14, 15, 16})
RSA_ALGORITHMS = frozenset({8, 10})
MIN_RSA_BITS = 1024

# DS digest types: 1 SHA-1 (BIP-353 permits), 2 SHA-256, 4 SHA-384.
DS_DIGESTS = {1: "SHA1", 2: "SHA256", 4: "SHA384"}

# DNSKEY flag bits (RFC 4034).
_FLAG_ZONE = 0x0100
_FLAG_REVOKE = 0x0080

MAX_HOPS = 8          # CNAME / DNAME links followed before giving up
MAX_CHAIN = 130       # zones above the signer; a name has at most 127 labels
KEY_CACHE_CAP = 3600  # seconds; a validated key set is never trusted longer


class DnssecError(Exception):
    """Base for every refusal below."""


class DnssecUnsigned(DnssecError):
    """There is no signature chain to check: the name is not signed, or its zone
    is not securely delegated. Reported to the payer as "not signed with DNSSEC"."""


class DnssecBogus(DnssecError):
    """Signatures are present and do not hold: wrong, expired, weak, or a shape
    this validator will not accept. Reported as a refusal, never as a bad
    address, because the record may have been altered."""


class NoRecord(DnssecError):
    """Nothing is published at the name. Unauthenticated, so it can deny a
    payment but never redirect one."""

    def __init__(self, message: str = "", nxdomain: bool = False):
        super().__init__(message)
        self.nxdomain = nxdomain


@dataclass(frozen=True)
class Anchor:
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes


# IANA root-anchors.xml, https://data.iana.org/root-anchors/root-anchors.xml.
# 19036 (retired 2019-01-11) is deliberately absent.
ROOT_ANCHORS = (
    Anchor(20326, 8, 2, bytes.fromhex(
        "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")),
    Anchor(38696, 8, 2, bytes.fromhex(
        "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")),
)


@dataclass
class Reply:
    """What a fetch returns: the response code and the ANSWER section's RRsets
    (RRSIGs included). Nothing the resolver says about validity is carried."""
    rcode: int
    answer: list = field(default_factory=list)


@dataclass
class TxtResult:
    """Every TXT record at the final label, each as the concatenation of its own
    character-strings (BIP-353: never across records), and how long the chain is
    good for."""
    texts: list
    ttl: int
    expires: int


Fetch = Callable[[dns.name.Name, int], Reply]


# ── key and signature policy ────────────────────────────────────────────────

def _rsa_bits(key) -> int:
    """Modulus size of an RSA DNSKEY (RFC 3110 layout)."""
    data = key.key
    if not data:
        return 0
    if data[0] == 0:
        if len(data) < 3:
            return 0
        exp_len, start = int.from_bytes(data[1:3], "big"), 3
    else:
        exp_len, start = data[0], 1
    modulus = data[start + exp_len:]
    return int.from_bytes(modulus, "big").bit_length() if modulus else 0


def key_acceptable(key) -> bool:
    """A zone key we are willing to verify with."""
    if key.protocol != 3 or not (key.flags & _FLAG_ZONE) or (key.flags & _FLAG_REVOKE):
        return False
    alg = int(key.algorithm)
    if alg not in ALLOWED_ALGORITHMS:
        return False
    if alg in RSA_ALGORITHMS and _rsa_bits(key) < MIN_RSA_BITS:
        return False
    return True


def _filter_keys(rdataset) -> dns.rdataset.Rdataset:
    out = dns.rdataset.Rdataset(IN, T.DNSKEY)
    out.update_ttl(rdataset.ttl)
    for key in rdataset:
        if key_acceptable(key):
            out.add(key)
    return out


def _ds_matches(zone: dns.name.Name, key, ds) -> bool:
    """Does this DS (or anchor) name this DNSKEY?"""
    if int(ds.digest_type) not in DS_DIGESTS:
        return False
    if int(ds.algorithm) != int(key.algorithm) or int(ds.key_tag) != dns.dnssec.key_id(key):
        return False
    algorithm = DS_DIGESTS[int(ds.digest_type)]
    try:
        try:
            # `validating` is what lets a SHA-1 digest be CHECKED (BIP-353 allows
            # it) where dnspython's default policy refuses to MAKE one. It does
            # not exist before dnspython 2.8, where there is no such refusal.
            made = dns.dnssec.make_ds(zone, key, algorithm, validating=True)
        except TypeError:
            made = dns.dnssec.make_ds(zone, key, algorithm)
    except Exception:
        return False
    return bytes(made.digest) == bytes(ds.digest)


class KeyCache:
    """Validated DNSKEY sets, so a lookup does not re-walk the chain every time.

    An entry is good until the earliest of its TTL, the end of the signature
    window that proved it, and KEY_CACHE_CAP — never longer than what proved it.
    Payment instructions themselves are NEVER cached here (BIP-353 limits that
    separately and nothing in this extension does it).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._items: dict = {}

    def get(self, zone, now: int):
        with self._lock:
            hit = self._items.get(zone)
            if hit and hit[1] > now:
                return hit[0]
            if hit:
                del self._items[zone]
        return None

    def put(self, zone, keys, expires: int):
        with self._lock:
            self._items[zone] = (keys, expires)

    def clear(self):
        with self._lock:
            self._items.clear()


class Validator:
    def __init__(
        self,
        fetch: Fetch,
        *,
        now: Optional[int] = None,
        anchors=ROOT_ANCHORS,
        cache: Optional[KeyCache] = None,
    ):
        self._fetch_raw = fetch
        self.now = int(time.time()) if now is None else int(now)
        self.anchors = tuple(anchors)
        self.cache = cache
        self._replies: dict = {}

    # ── plumbing ────────────────────────────────────────────────────────────

    def _fetch(self, name: dns.name.Name, rdtype: int) -> Reply:
        key = (name, int(rdtype))
        if key not in self._replies:
            self._replies[key] = self._fetch_raw(name, rdtype)
        return self._replies[key]

    @staticmethod
    def _index(reply: Reply):
        """({(owner, type): rrset}, {(owner, covered type): rrsig rrset})."""
        rrs, sigs = {}, {}
        for rrset in reply.answer:
            if rrset.rdtype == T.RRSIG:
                sigs[(rrset.name, int(rrset.covers))] = rrset
            else:
                rrs[(rrset.name, int(rrset.rdtype))] = rrset
        return rrs, sigs

    # ── an RRset against its zone's keys ────────────────────────────────────

    def _check(self, rrset, sigs, *, parent_signer: bool = False):
        """Verify `rrset` with `sigs`; returns (ttl, expires). Raises Unsigned
        when there is no signature at all, Bogus when there is and it fails."""
        owner = rrset.name
        what = f"{owner} {dns.rdatatype.to_text(rrset.rdtype)}"
        if sigs is None or len(sigs) == 0:
            raise DnssecUnsigned(f"{what} carries no signature")

        labels = len(owner.labels) - 1                      # the root label is not counted
        usable = []
        for sig in sigs:
            if int(sig.algorithm) not in ALLOWED_ALGORITHMS:
                continue
            if sig.labels < labels:
                # A wildcard produced this answer. Without the NSEC/NSEC3 proof
                # that no closer name exists the signature proves nothing about
                # THIS name, so it is refused rather than trusted.
                raise DnssecBogus(f"{what} is wildcard-expanded; that is not supported")
            if sig.labels > labels:
                raise DnssecBogus(f"{what} has an impossible label count")
            usable.append(sig)
        if not usable:
            raise DnssecBogus(f"{what} is signed only with an unsupported or weak algorithm")

        failure = None
        for signer in {s.signer for s in usable}:
            if not owner.is_subdomain(signer) or (parent_signer and owner == signer):
                failure = f"{what} is signed by {signer}, which is not its zone"
                continue
            keys = self.keys_for(signer)
            subset = dns.rrset.RRset(owner, IN, T.RRSIG, covers=rrset.rdtype)
            for s in usable:
                if s.signer == signer:
                    subset.add(s, sigs.ttl)
            try:
                dns.dnssec.validate(rrset, subset, {signer: keys}, now=self.now)
            except dns.dnssec.ValidationFailure as exc:
                failure = f"{what}: {exc}"
                continue
            expires = min(int(s.expiration) for s in subset)
            return int(rrset.ttl), expires
        raise DnssecBogus(failure or f"{what} did not validate")

    # ── zone keys, proved up to the root ────────────────────────────────────

    def keys_for(self, zone: dns.name.Name, _depth: int = 0) -> dns.rdataset.Rdataset:
        if _depth > MAX_CHAIN:
            raise DnssecBogus("DNSSEC chain is implausibly long")
        if self.cache is not None:
            cached = self.cache.get(zone, self.now)
            if cached is not None:
                return cached

        rrs, sigs = self._index(self._fetch(zone, T.DNSKEY))
        dnskeys = rrs.get((zone, int(T.DNSKEY)))
        key_sigs = sigs.get((zone, int(T.DNSKEY)))
        if dnskeys is None or key_sigs is None:
            raise DnssecBogus(f"no signed DNSKEY set for {zone}")
        offered = _filter_keys(dnskeys)

        if zone == dns.name.root:
            entry = self._entry_keys(zone, offered, self.anchors)
        else:
            ds, ds_ttl, ds_expires = self._ds_for(zone, _depth)
            entry = self._entry_keys(zone, offered, ds)
        if len(entry) == 0:
            raise DnssecBogus(f"no DNSKEY of {zone} matches its trust anchor / DS")

        usable = [s for s in key_sigs if int(s.algorithm) in ALLOWED_ALGORITHMS]
        if not usable:
            raise DnssecBogus(f"DNSKEY set of {zone} uses only unsupported algorithms")
        subset = dns.rrset.RRset(zone, IN, T.RRSIG, covers=T.DNSKEY)
        for s in usable:
            subset.add(s, key_sigs.ttl)
        try:
            # The set is proved by one of its OWN keys that the DS / anchor names.
            dns.dnssec.validate(dnskeys, subset, {zone: entry}, now=self.now)
        except dns.dnssec.ValidationFailure as exc:
            raise DnssecBogus(f"DNSKEY set of {zone}: {exc}")

        expires = min([int(s.expiration) for s in subset] + [self.now + KEY_CACHE_CAP,
                                                             self.now + int(dnskeys.ttl)])
        if zone != dns.name.root:
            expires = min(expires, ds_expires, self.now + int(ds_ttl))
        if self.cache is not None:
            self.cache.put(zone, offered, expires)
        return offered

    @staticmethod
    def _entry_keys(zone, offered, ds_like) -> dns.rdataset.Rdataset:
        """The keys in `offered` that a DS / anchor names: the secure entry points."""
        entry = dns.rdataset.Rdataset(IN, T.DNSKEY)
        entry.update_ttl(offered.ttl)
        for key in offered:
            if any(_ds_matches(zone, key, ds) for ds in ds_like):
                entry.add(key)
        return entry

    def _ds_for(self, zone: dns.name.Name, depth: int):
        rrs, sigs = self._index(self._fetch(zone, T.DS))
        ds = rrs.get((zone, int(T.DS)))
        if ds is None:
            raise DnssecUnsigned(f"{zone} has no DS record in its parent: not securely delegated")
        ttl, expires = self._check(ds, sigs.get((zone, int(T.DS))), parent_signer=True)
        return ds, ttl, expires

    # ── the TXT record for a name ───────────────────────────────────────────

    def resolve_txt(self, qname) -> TxtResult:
        name = dns.name.from_text(qname) if isinstance(qname, str) else qname
        have: dict = {}
        sigs_all: dict = {}

        def absorb(reply: Reply):
            rrs, sigs = self._index(reply)
            have.update(rrs)
            sigs_all.update(sigs)

        first = self._fetch(name, T.TXT)
        absorb(first)
        if first.rcode == dns.rcode.NXDOMAIN:
            raise NoRecord(f"{name} does not exist", nxdomain=True)

        ttl_floor, expires = None, None

        def note(ttl, exp):
            nonlocal ttl_floor, expires
            ttl_floor = ttl if ttl_floor is None else min(ttl_floor, ttl)
            expires = exp if expires is None else min(expires, exp)

        cur = name
        for _ in range(MAX_HOPS + 1):
            txt = have.get((cur, int(T.TXT)))
            if txt is not None:
                note(*self._check(txt, sigs_all.get((cur, int(T.TXT)))))
                return TxtResult(
                    texts=[b"".join(rd.strings).decode("utf-8", errors="replace") for rd in txt],
                    ttl=int(ttl_floor),
                    expires=int(expires),
                )

            # A signed DNAME above `cur` comes FIRST: the CNAME a resolver
            # synthesises from it is unsigned by construction, and must be
            # ignored rather than demanded a signature it can never have.
            nxt = self._through_dname(cur, have, sigs_all, note)
            if nxt is not None:
                cur = nxt
            else:
                cname = have.get((cur, int(T.CNAME)))
                if cname is not None:
                    # dnspython holds CNAME and DNAME as singletons: a second record
                    # collapses into the first, so a signature made over TWO of them
                    # no longer matches what is checked and the RRset is refused.
                    note(*self._check(cname, sigs_all.get((cur, int(T.CNAME)))))
                    cur = cname[0].target
                else:
                    # Nothing leads on from here. If we have not moved, the name
                    # simply has no TXT; if we have, the resolver gave us the
                    # chain but not its end, so ask for the end.
                    if cur == name:
                        raise NoRecord(f"no TXT record at {name}")
                    reply = self._fetch(cur, T.TXT)
                    absorb(reply)
                    if (cur, int(T.TXT)) not in have:
                        raise NoRecord(f"no TXT record at {cur}", nxdomain=reply.rcode == dns.rcode.NXDOMAIN)
                    continue
            if (cur, int(T.TXT)) not in have and (cur, int(T.CNAME)) not in have:
                absorb(self._fetch(cur, T.TXT))
        raise DnssecBogus(f"more than {MAX_HOPS} CNAME/DNAME links from {name}")

    def _through_dname(self, cur, have, sigs_all, note):
        """The name `cur` becomes through a signed DNAME above it, or None. The
        CNAME a resolver synthesises for a DNAME is unsigned and is NOT used: the
        substitution is computed here from the signed DNAME itself."""
        for (owner, rtype), rrset in have.items():
            if rtype != int(T.DNAME) or owner == cur or not cur.is_subdomain(owner):
                continue
            note(*self._check(rrset, sigs_all.get((owner, int(T.DNAME)))))
            prefix = cur.relativize(owner)
            return prefix.concatenate(rrset[0].target)
        return None
