"""BIP-353 says a client must validate DNSSEC to the root itself and must not trust
a remote resolver to do it. This file holds helpers/dnssec_chain.py to that.

Four layers, because each catches what the others cannot:

1. THE BIP'S OWN VECTORS (fixtures/bip353-proofs.json). Real proofs, signed
   by the real DNS root and zones, taken from the BIP's "Example proofs". They are
   the only test here that proves the trust anchors are right and that the code
   verifies real signatures rather than ones this file made itself. They are valid
   only inside their own signature windows, so each test says "now" explicitly.
2. ATTACKS ON THOSE VECTORS. Flip a byte, ask for a different name than the proof
   answers, strip the signatures, withhold the DS, use the wrong anchor.
3. A ZONE THIS FILE BUILDS AND SIGNS, for what no real vector can show: SHA-1,
   wildcard expansion, DNAME, a forged DS, a zone run by the attacker.
4. THE RESOLVER. A forged AD flag over plain DNS — the attack the old code was
   open to — buys nothing.

Run where `cryptography` works; signature checks call it.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import pathlib
import struct
import sys
import types

import pytest

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass as C
import dns.rdataset
import dns.rdatatype as T
import dns.rrset

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name


def _load_resolver():
    name = f"{PKG}.helpers.address_resolver"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "helpers" / "address_resolver.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ar = _load_resolver()
dc = importlib.import_module(f"{PKG}.helpers.dnssec_chain")
# test_bitmail_errors replaces these on the module and never puts them back, so
# the real ones are taken now, at collection, before any test has run.
REAL_QUERY = ar._query_txt_with_dnssec
REAL_FETCH = ar._network_fetch

VECTORS = json.loads((ROOT / "fixtures" / "bip353-proofs.json").read_text())["vectors"]


# ── a proof (RFC 9102) as the records a resolver would hand back ────────────

def rrsets_from_stream(blob: bytes) -> list:
    pos, sets = 0, {}
    while pos < len(blob):
        name, used = dns.name.from_wire(blob, pos)
        pos += used
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", blob[pos:pos + 10])
        pos += 10
        rd = dns.rdata.from_wire(rclass, rtype, blob, pos, rdlen)
        pos += rdlen
        covers = rd.type_covered if rtype == T.RRSIG else 0
        key = (name, rtype, covers)
        if key not in sets:
            sets[key] = dns.rrset.RRset(name, rclass, rtype, covers)
        sets[key].add(rd, ttl)
    return list(sets.values())


def proof_fetch(sets):
    return lambda name, rdtype: dc.Reply(dns.rcode.NOERROR, list(sets))


def qname_of(address: str) -> str:
    user, _, domain = address.partition("@")
    return f"{user}.user._bitcoin-payment.{domain}"


def vector(key):
    v = VECTORS[key]
    return rrsets_from_stream(bytes.fromhex(v["proof_hex"])), qname_of(v["name"]), v["valid_at"]


def resolve(sets, qname, now, **kw):
    return dc.Validator(proof_fetch(sets), now=now, **kw).resolve_txt(qname)


# ── 1. the BIP's vectors ────────────────────────────────────────────────────

def test_the_simple_vector_validates_against_the_real_root():
    sets, q, now = vector("simple")
    r = resolve(sets, q, now)
    assert "bitcoin:?bc=bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l" in r.texts
    # Both records come back; choosing between them is the caller's rule.
    assert "bitcoin is cool!" in r.texts


def test_a_record_reached_through_a_cname_validates():
    sets, q, now = vector("override_cname_wild")
    r = resolve(sets, q, now)
    assert len(r.texts) == 1 and r.texts[0].lower().startswith("bitcoin:")


@pytest.mark.parametrize("key", ["cname_wild", "cname_wild_missing_nsec3"])
def test_a_wildcard_expanded_answer_is_refused(key):
    """BIP-valid (the first), and refused anyway: accepting a wildcard answer
    needs the NSEC3 proof that no closer name exists, which is not implemented,
    so it is not trusted on the signature alone. The second lacks that proof and
    would be refused by any validator; both fail the same, closed."""
    sets, q, now = vector(key)
    with pytest.raises(dc.DnssecBogus) as e:
        resolve(sets, q, now)
    assert "wildcard" in str(e.value)


def test_every_vector_is_refused_once_its_signatures_have_expired():
    for key in ("simple", "override_cname_wild", "two_bitcoin_records"):
        sets, q, _ = vector(key)
        with pytest.raises(dc.DnssecBogus):
            resolve(sets, q, 1_795_000_000)       # November 2026, long after


def test_nothing_validates_before_its_signatures_begin():
    sets, q, _ = vector("simple")
    with pytest.raises(dc.DnssecBogus):
        resolve(sets, q, 1_600_000_000)


# ── 2. attacks on a real, valid proof ───────────────────────────────────────

def test_a_record_altered_after_signing_is_refused():
    sets, q, now = vector("simple")
    forged, did = [], False
    for rrset in sets:
        if rrset.rdtype == T.TXT and any(b"bc1qztwy6" in b"".join(rd.strings) for rd in rrset):
            fake = dns.rrset.RRset(rrset.name, rrset.rdclass, T.TXT)
            fake.add(dns.rdata.from_text(
                C.IN, T.TXT, '"bitcoin:?bc=bc1qattackerattackerattackerattackerattackerxx"'), rrset.ttl)
            rrset, did = fake, True
        forged.append(rrset)
    assert did, "the test altered nothing"
    with pytest.raises(dc.DnssecBogus):
        resolve(forged, q, now)


def test_a_valid_proof_for_another_name_is_not_taken_for_this_one():
    """The Cake finding: 'a valid proof for any other signed name passes'. Here the
    records used are found by following the name that was ASKED, so a perfectly
    signed answer for a neighbour is simply not the one."""
    sets, _, now = vector("simple")
    other = "mallory.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja"
    with pytest.raises(dc.NoRecord):
        resolve(sets, other, now)


def test_the_wrong_trust_anchor_fails():
    sets, q, now = vector("simple")
    only_new = (dc.ROOT_ANCHORS[1],)           # the 2024 key did not sign in August 2025
    with pytest.raises(dc.DnssecBogus):
        resolve(sets, q, now, anchors=only_new)
    with pytest.raises(dc.DnssecBogus):
        resolve(sets, q, now, anchors=())


def test_an_anchor_with_one_wrong_digit_fails():
    sets, q, now = vector("simple")
    bad = dc.Anchor(20326, 8, 2, bytes([dc.ROOT_ANCHORS[0].digest[0] ^ 1]) + dc.ROOT_ANCHORS[0].digest[1:])
    with pytest.raises(dc.DnssecBogus):
        resolve(sets, q, now, anchors=(bad, dc.ROOT_ANCHORS[1]))


def test_a_record_with_its_signature_stripped_is_unsigned_not_trusted():
    sets, q, now = vector("simple")
    stripped = [s for s in sets if not (s.rdtype == T.RRSIG and s.covers == T.TXT)]
    assert len(stripped) < len(sets)
    with pytest.raises(dc.DnssecUnsigned):
        resolve(stripped, q, now)


def test_a_zone_with_no_ds_in_its_parent_is_not_securely_delegated():
    sets, q, now = vector("simple")
    no_ds = [s for s in sets if s.rdtype != T.DS and not (s.rdtype == T.RRSIG and s.covers == T.DS)]
    assert len(no_ds) < len(sets)
    with pytest.raises(dc.DnssecUnsigned):
        resolve(no_ds, q, now)


def test_a_swapped_dnskey_set_is_refused():
    """An attacker who serves his own DNSKEY for a zone cannot make the parent's
    DS name it."""
    sets, q, now = vector("simple")
    zone = dns.name.from_text("bitcoin.ninja.")          # the zone that signs the TXT
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    mine = dns.dnssec.make_dnskey(key.public_key(), 13, flags=257)
    swapped, did = [], False
    for s in sets:
        if s.rdtype == T.DNSKEY and s.name == zone:
            fake = dns.rrset.RRset(zone, C.IN, T.DNSKEY)
            fake.add(mine, s.ttl)
            s = fake
            did = True
        swapped.append(s)
    assert did, "the test swapped nothing"
    with pytest.raises(dc.DnssecBogus):
        resolve(swapped, q, now)


# ── 3. a zone this file builds, for what no real vector can show ────────────

NOW = 1_800_000_000
INCEPTION, EXPIRATION = NOW - 3600, NOW + 7 * 86400


def _key(algorithm):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    if algorithm in (5, 7, 8, 10):
        return rsa.generate_private_key(65537, 2048)
    return ec.generate_private_key(ec.SECP256R1() if algorithm == 13 else ec.SECP384R1())


def _sig(rrset, zone, private, dnskey, inception=INCEPTION, expiration=EXPIRATION):
    rd = dns.dnssec.sign(rrset, private, zone, dnskey, inception=inception, expiration=expiration)
    out = dns.rrset.RRset(rrset.name, C.IN, T.RRSIG, covers=rrset.rdtype)
    out.add(rd, rrset.ttl)
    return out


class Net:
    """A small signed DNS tree with a resolver in front of it."""

    def __init__(self):
        self.published = {}      # (name, type) -> [rrset, rrsig...]
        self.log = []
        self.zones = {}

    def publish(self, *rrsets):
        key = (rrsets[0].name, int(rrsets[0].rdtype))
        self.published[key] = list(rrsets)

    def zone(self, name, *, algorithm=13, parent=None, delegate=True, ds_digest="SHA256"):
        z = Zone(self, name, algorithm, parent)
        self.zones[z.name] = z
        if parent is not None and delegate:
            ds = dns.dnssec.make_ds(z.name, z.dnskey, ds_digest, validating=True)
            ds_set = dns.rrset.RRset(z.name, C.IN, T.DS)
            ds_set.add(ds, 3600)
            self.publish(ds_set, _sig(ds_set, parent.name, parent.private, parent.dnskey))
        return z

    def anchors(self, root):
        ds = dns.dnssec.make_ds(root.name, root.dnskey, "SHA256", validating=True)
        return (dc.Anchor(ds.key_tag, ds.algorithm, ds.digest_type, ds.digest),)

    # the resolver: follows CNAME and DNAME for the caller, as a real one does
    def fetch(self, name, rdtype):
        self.log.append((name, int(rdtype)))
        out, cur = [], name
        for _ in range(8):
            got = self.published.get((cur, int(rdtype)))
            if got:
                out += got
                break
            cn = self.published.get((cur, int(T.CNAME)))
            if cn and rdtype != T.CNAME:
                out += cn
                cur = cn[0][0].target
                continue
            moved = False
            for (owner, rt), sets in self.published.items():
                if rt == int(T.DNAME) and cur != owner and cur.is_subdomain(owner):
                    out += sets
                    new = cur.relativize(owner).concatenate(sets[0][0].target)
                    synth = dns.rrset.RRset(cur, C.IN, T.CNAME)
                    synth.add(dns.rdata.from_text(C.IN, T.CNAME, new.to_text()), 3600)
                    out.append(synth)                      # unsigned, as a resolver makes it
                    cur, moved = new, True
                    break
            if not moved:
                break
        return dc.Reply(dns.rcode.NOERROR if out else dns.rcode.NXDOMAIN, out)


class Zone:
    def __init__(self, net, name, algorithm, parent):
        self.net, self.name = net, dns.name.from_text(name)
        self.private = _key(algorithm)
        self.dnskey = dns.dnssec.make_dnskey(self.private.public_key(), algorithm, flags=257)
        keys = dns.rrset.RRset(self.name, C.IN, T.DNSKEY)
        keys.add(self.dnskey, 3600)
        net.publish(keys, _sig(keys, self.name, self.private, self.dnskey))

    def txt(self, owner, *records, sign=True, window=None):
        """records: each a tuple of character-strings, one TXT record apiece.
        `window` is (inception, expiration) for THIS record's signature only."""
        owner = dns.name.from_text(owner)
        rrset = dns.rrset.RRset(owner, C.IN, T.TXT)
        for strings in records:
            rrset.add(dns.rdata.from_text(C.IN, T.TXT, " ".join(f'"{s}"' for s in strings)), 300)
        w = {} if window is None else {"inception": window[0], "expiration": window[1]}
        self.net.publish(*([rrset, _sig(rrset, self.name, self.private, self.dnskey, **w)] if sign else [rrset]))
        return rrset


def tree(**leaf):
    net = Net()
    root = net.zone(".")
    tld = net.zone("test.", parent=root)
    leaf_zone = net.zone("example.test.", parent=tld, **leaf)
    return net, root, tld, leaf_zone


GOOD = "bitcoin:?sp=sp1qqexample"
NAME = "alice.user._bitcoin-payment.example.test."


def check(net, root, qname=NAME, now=NOW, **kw):
    return dc.Validator(net.fetch, now=now, anchors=net.anchors(root), **kw).resolve_txt(qname)


def test_a_properly_signed_chain_validates():
    net, root, _, leaf = tree()
    leaf.txt(NAME, (GOOD,))
    assert check(net, root).texts == [GOOD]


def test_the_character_strings_of_one_record_join_and_records_do_not():
    net, root, _, leaf = tree()
    leaf.txt(NAME, ("bitcoin:?sp=sp1qq", "example"), ("other",))
    assert check(net, root).texts == ["bitcoin:?sp=sp1qqexample", "other"]


def test_an_attacker_who_signs_with_his_own_keys_is_refused():
    """The point of the whole file. Everything is perfectly signed — by him."""
    genuine, root, _, _ = tree()
    attacker, _aroot, _atld, aleaf = tree()
    aleaf.txt(NAME, ("bitcoin:?sp=sp1qqattacker",))
    with pytest.raises(dc.DnssecBogus):
        dc.Validator(attacker.fetch, now=NOW, anchors=genuine.anchors(root)).resolve_txt(NAME)


def test_an_attacker_who_controls_only_the_leaf_zone_is_refused():
    """The genuine root and TLD, and the genuine DS for example.test — but the
    zone's own keys and record replaced by the attacker's."""
    net, root, tld, leaf = tree()
    leaf.txt(NAME, (GOOD,))
    evil_net = Net()
    evil = evil_net.zone("example.test.")                # his keys, no delegation
    evil.txt(NAME, ("bitcoin:?sp=sp1qqattacker",))
    for key, sets in evil_net.published.items():
        net.published[key] = sets
    with pytest.raises(dc.DnssecBogus):
        check(net, root)


def test_a_zone_with_no_ds_is_unsigned():
    net, root, _, leaf = tree(delegate=False)
    leaf.txt(NAME, (GOOD,))
    with pytest.raises(dc.DnssecUnsigned):
        check(net, root)


def test_an_unsigned_record_is_unsigned():
    net, root, _, leaf = tree()
    leaf.txt(NAME, (GOOD,), sign=False)
    with pytest.raises(dc.DnssecUnsigned):
        check(net, root)


@pytest.mark.parametrize("algorithm", [5, 7])
def test_sha1_signatures_are_refused(algorithm):
    """BIP-353: MUST NOT accept signatures which use SHA-1."""
    net, root, _, leaf = tree(algorithm=algorithm)
    leaf.txt(NAME, (GOOD,))
    with pytest.raises(dc.DnssecBogus):
        check(net, root)


def test_a_sha1_ds_digest_is_accepted_because_the_bip_allows_it():
    net, root, _, leaf = tree(ds_digest="SHA1")
    leaf.txt(NAME, (GOOD,))
    assert check(net, root).texts == [GOOD]


def _rsa_dnskey(modulus_bits):
    modulus = (1 << (modulus_bits - 1)) | 1
    key = bytes([3]) + (65537).to_bytes(3, "big") + modulus.to_bytes(modulus_bits // 8, "big")
    return dns.rdata.from_wire(
        C.IN, T.DNSKEY, struct.pack("!HBB", 257, 3, 8) + key, 0, 4 + len(key))


def test_an_rsa_key_under_1024_bits_is_refused_and_one_at_1024_is_not():
    assert not dc.key_acceptable(_rsa_dnskey(512))
    assert not dc.key_acceptable(_rsa_dnskey(1016))
    assert dc.key_acceptable(_rsa_dnskey(1024))
    assert dc.key_acceptable(_rsa_dnskey(2048))


def test_revoked_and_non_zone_keys_are_not_used():
    ok = _rsa_dnskey(2048)
    revoked = dns.rdata.from_wire(C.IN, T.DNSKEY, struct.pack("!HBB", 257 | 0x80, 3, 8) + ok.key, 0, 4 + len(ok.key))
    not_zone = dns.rdata.from_wire(C.IN, T.DNSKEY, struct.pack("!HBB", 1, 3, 8) + ok.key, 0, 4 + len(ok.key))
    assert not dc.key_acceptable(revoked)
    assert not dc.key_acceptable(not_zone)


def test_a_wildcard_expanded_answer_is_refused_even_though_it_verifies():
    """A resolver can synthesise this for a name that has its own record. The
    signature is real; it says nothing about THIS name."""
    net, root, _, leaf = tree()
    star = leaf.txt("*.user._bitcoin-payment.example.test.", (GOOD,))
    sig = net.published[(star.name, int(T.TXT))][1]
    fake_owner = dns.name.from_text(NAME)
    answer = dns.rrset.RRset(fake_owner, C.IN, T.TXT)
    answer.add(star[0], star.ttl)
    answer_sig = dns.rrset.RRset(fake_owner, C.IN, T.RRSIG, covers=T.TXT)
    answer_sig.add(sig[0], sig.ttl)
    net.published[(fake_owner, int(T.TXT))] = [answer, answer_sig]
    with pytest.raises(dc.DnssecBogus) as e:
        check(net, root)
    assert "wildcard" in str(e.value)


def test_a_signed_cname_is_followed():
    net, root, _, leaf = tree()
    target = dns.name.from_text("bob.user._bitcoin-payment.example.test.")
    leaf.txt(target.to_text(), (GOOD,))
    cname = dns.rrset.RRset(dns.name.from_text(NAME), C.IN, T.CNAME)
    cname.add(dns.rdata.from_text(C.IN, T.CNAME, target.to_text()), 300)
    net.publish(cname, _sig(cname, leaf.name, leaf.private, leaf.dnskey))
    assert check(net, root).texts == [GOOD]


def test_an_unsigned_cname_is_not_followed():
    net, root, _, leaf = tree()
    target = dns.name.from_text("bob.user._bitcoin-payment.example.test.")
    leaf.txt(target.to_text(), (GOOD,))
    cname = dns.rrset.RRset(dns.name.from_text(NAME), C.IN, T.CNAME)
    cname.add(dns.rdata.from_text(C.IN, T.CNAME, target.to_text()), 300)
    net.publish(cname)
    with pytest.raises(dc.DnssecUnsigned):
        check(net, root)


def test_a_signed_dname_is_followed_and_its_unsigned_cname_is_not_trusted():
    """A resolver makes a CNAME out of a DNAME and nobody signs it. The
    substitution is computed from the signed DNAME, so a forged synthesised CNAME
    pointing somewhere else changes nothing."""
    net, root, _, leaf = tree()
    leaf.txt("alice.user._bitcoin-payment.new.example.test.", (GOOD,))
    leaf.txt("alice.user._bitcoin-payment.evil.example.test.", ("bitcoin:?sp=sp1qqattacker",))
    dname = dns.rrset.RRset(dns.name.from_text("old.example.test."), C.IN, T.DNAME)
    dname.add(dns.rdata.from_text(C.IN, T.DNAME, "new.example.test."), 300)
    net.publish(dname, _sig(dname, leaf.name, leaf.private, leaf.dnskey))
    # old.example.test -> new.example.test, for a name that sits under it
    leaf.txt("alice.user._bitcoin-payment.new.example.test.", (GOOD,))
    q = "alice.user._bitcoin-payment.old.example.test."
    assert check(net, root, qname=q).texts == [GOOD]

    real_fetch = net.fetch

    def forging(name, rdtype):
        reply = real_fetch(name, rdtype)
        reply.answer = [
            r for r in reply.answer if r.rdtype != T.CNAME
        ] + [_cname(name, "alice.user._bitcoin-payment.evil.example.test.")]
        reply.answer += net.published[(dns.name.from_text("alice.user._bitcoin-payment.evil.example.test."), int(T.TXT))]
        return reply

    assert dc.Validator(forging, now=NOW, anchors=net.anchors(root)).resolve_txt(q).texts == [GOOD]


def _cname(owner, target):
    out = dns.rrset.RRset(owner, C.IN, T.CNAME)
    out.add(dns.rdata.from_text(C.IN, T.CNAME, target), 300)
    return out


def test_a_cname_loop_is_bounded():
    net, root, _, leaf = tree()
    a = dns.name.from_text(NAME)
    b = dns.name.from_text("bob.user._bitcoin-payment.example.test.")
    for src, dst in ((a, b), (b, a)):
        c = _cname(src, dst.to_text())
        net.publish(c, _sig(c, leaf.name, leaf.private, leaf.dnskey))
    with pytest.raises(dc.DnssecError):
        check(net, root)


def test_a_signature_window_is_enforced_at_both_ends():
    net, root, _, leaf = tree()
    leaf.txt(NAME, (GOOD,))
    with pytest.raises(dc.DnssecBogus):
        check(net, root, now=EXPIRATION + 1)
    with pytest.raises(dc.DnssecBogus):
        check(net, root, now=INCEPTION - 86400)


def test_a_record_signature_outside_its_window_is_refused_though_the_keys_are_fresh():
    """The zone's own signatures are current; only the TXT's has lapsed (or has not
    begun). The window check on the record itself is what catches it — the chain
    above it would pass."""
    net, root, _, leaf = tree()
    leaf.txt(NAME, (GOOD,), window=(NOW - 86400 * 30, NOW - 86400))
    with pytest.raises(dc.DnssecBogus):
        check(net, root)
    net, root, _, leaf = tree()
    leaf.txt(NAME, (GOOD,), window=(NOW + 86400, NOW + 86400 * 30))
    with pytest.raises(dc.DnssecBogus):
        check(net, root)
    net, root, _, leaf = tree()
    leaf.txt(NAME, (GOOD,), window=(NOW - 86400, NOW + 86400))
    assert check(net, root).texts == [GOOD]


def test_nothing_published_is_not_found_and_not_a_security_failure():
    net, root, _, leaf = tree()
    with pytest.raises(dc.NoRecord) as e:
        check(net, root)
    assert e.value.nxdomain


# ── the key cache ───────────────────────────────────────────────────────────

def test_validated_keys_are_cached_and_the_cache_expires():
    net, root, _, leaf = tree()
    leaf.txt(NAME, (GOOD,))
    cache = dc.KeyCache()
    check(net, root, cache=cache)
    first = len(net.log)
    net.log.clear()
    check(net, root, cache=cache)
    keyfetches = [e for e in net.log if e[1] in (int(T.DNSKEY), int(T.DS))]
    assert first > 1 and keyfetches == []          # the second walk asked only for the TXT
    net.log.clear()
    check(net, root, now=NOW + dc.KEY_CACHE_CAP + 1, cache=cache)
    assert [e for e in net.log if e[1] in (int(T.DNSKEY), int(T.DS))]   # and it re-proves later


def test_no_cache_means_every_lookup_walks_the_chain():
    net, root, _, leaf = tree()
    leaf.txt(NAME, (GOOD,))
    check(net, root)
    first = len(net.log)
    check(net, root)
    assert len(net.log) == 2 * first


# ── 4. the resolver ─────────────────────────────────────────────────────────

def _fresh(monkeypatch):
    monkeypatch.setattr(ar, "_query_txt_with_dnssec", REAL_QUERY)
    monkeypatch.setattr(ar, "_network_fetch", REAL_FETCH)
    monkeypatch.setattr(ar, "_KEY_CACHE", dc.KeyCache())
    monkeypatch.setattr(ar, "_domain_resolves", lambda _d: True)


def _at(monkeypatch, when):
    monkeypatch.setattr(dc, "time", types.SimpleNamespace(time=lambda: when))


def test_bip353_resolve_end_to_end_on_a_real_proof(monkeypatch):
    _fresh(monkeypatch)
    sets, _, now = vector("simple")
    monkeypatch.setattr(ar, "_network_fetch", proof_fetch(sets))
    _at(monkeypatch, now)
    out = ar.bip353_resolve("simple@dnssec_proof_tests.bitcoin.ninja")
    assert out["result"] == "bitcoin:?bc=bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l"
    assert out["dnssec"] is True


def test_two_bitcoin_records_are_refused(monkeypatch):
    """A valid DNSSEC proof that BIP-353 still says to refuse: taking the first
    would let anyone who can add a record to the zone choose which one wins."""
    _fresh(monkeypatch)
    sets, _, now = vector("two_bitcoin_records")
    monkeypatch.setattr(ar, "_network_fetch", proof_fetch(sets))
    _at(monkeypatch, now)
    with pytest.raises(ar.HTTPException) as e:
        ar.bip353_resolve("invalid@dnssec_proof_tests.bitcoin.ninja")
    assert e.value.status_code == 400 and "ambiguous" in e.value.detail


def test_a_tampered_record_is_a_security_refusal_not_a_typo(monkeypatch):
    _fresh(monkeypatch)
    sets, _, now = vector("simple")
    forged, did = [], False
    for rrset in sets:
        if rrset.rdtype == T.TXT and any(b"bc1qztwy6" in b"".join(rd.strings) for rd in rrset):
            fake = dns.rrset.RRset(rrset.name, rrset.rdclass, T.TXT)
            fake.add(dns.rdata.from_text(C.IN, T.TXT, '"bitcoin:?bc=bc1qattacker"'), rrset.ttl)
            rrset, did = fake, True
        forged.append(rrset)
    assert did, "the test altered nothing"
    monkeypatch.setattr(ar, "_network_fetch", proof_fetch(forged))
    _at(monkeypatch, now)
    with pytest.raises(ar.HTTPException) as e:
        ar.bip353_resolve("simple@dnssec_proof_tests.bitcoin.ninja")
    assert e.value.status_code == 400
    assert "failed DNSSEC verification" in e.value.detail and "altered" in e.value.detail


def test_a_forged_ad_flag_buys_nothing(monkeypatch):
    """The attack the old code was open to. A resolver answer, plain DNS, AD set,
    and a TXT record nothing has signed. The old code read that flag as proof."""
    _fresh(monkeypatch)
    seen = {}

    def forged(request, nameserver, timeout=10):
        seen["request"] = request
        response = dns.message.make_response(request)
        response.flags |= dns.flags.AD
        rrset = dns.rrset.from_text(request.question[0].name, 300, "IN", "TXT", '"bitcoin:?sp=sp1qqattacker"')
        response.answer.append(rrset)
        return response, False

    monkeypatch.setattr(ar.dns.query, "udp_with_fallback", forged)
    with pytest.raises(ar.HTTPException) as e:
        ar.bip353_resolve("alice@example.com")
    assert "isn’t signed with DNSSEC" in e.value.detail
    # and it asked for the data whether or not the resolver could validate it
    req = seen["request"]
    assert req.flags & dns.flags.CD and req.ednsflags & dns.flags.DO


def test_the_resolvers_verdict_is_never_read():
    """AD is a claim by somebody on the path. Nothing may branch on it."""
    import io, tokenize
    src = (ROOT / "helpers" / "address_resolver.py").read_text()
    code = " ".join(
        t.string for t in tokenize.generate_tokens(io.StringIO(src).readline)
        if t.type not in (tokenize.COMMENT, tokenize.STRING)
    )
    assert "AD_FLAG" not in code and "flags &" not in code and "dns . flags . AD" not in code
    assert "dns . flags . CD" in code


def test_the_trust_anchors_are_the_ianas():
    """root-anchors.xml: 20326 and 38696, SHA-256. 19036 retired in 2019."""
    tags = {a.key_tag for a in dc.ROOT_ANCHORS}
    assert tags == {20326, 38696}
    assert all(a.algorithm == 8 and a.digest_type == 2 and len(a.digest) == 32 for a in dc.ROOT_ANCHORS)
