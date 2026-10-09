"""helpers/nostr.py against the specs' own vectors.

HAND-WRITTEN CRYPTO THAT NOTHING CHECKS IS HOW A PAYOUT QUEUE FILLS UP. Every
failure in this module looks the same from the outside — a relay that never
answers — so a bug here would be reported as "Lightning is down" and
investigated anywhere but here.

The NIP-44 vectors are the reference ones, vendored to fixtures/ so this runs
with no network: paulmillr/nip44 nip44.vectors.json, which is what the NIP
itself points implementations at. NIP-04 has no published vector set, so it is
pinned by round-trip plus the one property that matters — that the two sides
of an ECDH agree — and by its wire shape.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helpers import nostr  # noqa: E402


VECTORS = json.load(
    open(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "fixtures",
            "nip44-vectors.json",
        )
    )
)["v2"]


# ── Keys ─────────────────────────────────────────────────────────────────────


def test_pubkey_is_x_only():
    """32 bytes, not 33. A compressed key with its prefix left on is a
    different key to every relay and every wallet service."""
    sec = "11" * 32
    pub = nostr.pubkey_of(sec)
    assert len(pub) == 64
    assert len(bytes.fromhex(pub)) == 32


def test_ecdh_agrees_both_ways():
    """The property the whole protocol rests on. If this were one-sided the
    requests would encrypt and never decrypt."""
    a, b = "11" * 32, "22" * 32
    assert nostr.shared_x(a, nostr.pubkey_of(b)) == nostr.shared_x(
        b, nostr.pubkey_of(a)
    )


def test_shared_x_is_not_hashed():
    """coincurve's own ecdh() hashes the point; NIP-04 uses the raw x as an
    AES key and NIP-44 feeds it to HKDF. Anything that silently swapped one
    for the other would pass a round-trip test and fail against every real
    wallet, so it is asserted against the curve rather than against ourselves.
    """
    from coincurve import PrivateKey, PublicKey

    a, b = "11" * 32, "22" * 32
    point = PublicKey(
        bytes.fromhex("02" + nostr.pubkey_of(b))
    ).multiply(PrivateKey(bytes.fromhex(a)).secret)
    assert nostr.shared_x(a, nostr.pubkey_of(b)) == point.format()[1:]
    assert nostr.shared_x(a, nostr.pubkey_of(b)) != PrivateKey(
        bytes.fromhex(a)
    ).ecdh(bytes.fromhex("02" + nostr.pubkey_of(b)))


# ── Events ───────────────────────────────────────────────────────────────────


def test_event_id_has_no_whitespace():
    """The id is sha256 of a compact JSON array. A space after each comma is a
    different id, and a signature every relay rejects."""
    import hashlib

    tags = [["p", "ab" * 32]]
    # Spelled out rather than re-derived, so a change to the serialisation has
    # to be made twice before it passes.
    payload = '[0,"' + "cd" * 32 + '",7,23194,[["p","' + "ab" * 32 + '"]],"hi"]'
    assert " " not in payload
    assert nostr.event_id("cd" * 32, 7, 23194, tags, "hi") == (
        hashlib.sha256(payload.encode()).hexdigest()
    )


def test_signed_event_verifies():
    ev = nostr.sign_event("33" * 32, 23194, "body", [["p", "ab" * 32]])
    assert nostr.verify_event(ev)
    assert ev["pubkey"] == nostr.pubkey_of("33" * 32)


def test_a_tampered_event_does_not_verify():
    """A relay is an untrusted middlebox and can hand back anything."""
    ev = nostr.sign_event("33" * 32, 23194, "body", [])
    ev["content"] = "other"
    assert not nostr.verify_event(ev)


def test_a_resigned_event_by_another_key_does_not_pass_as_ours():
    """The signature is valid; the key is a stranger's. Callers compare the
    pubkey themselves, and this records that verify_event alone will not."""
    theirs = nostr.sign_event("44" * 32, 23195, "body", [])
    assert nostr.verify_event(theirs)
    assert theirs["pubkey"] != nostr.pubkey_of("33" * 32)


# ── NIP-44, against the reference vectors ────────────────────────────────────


@pytest.mark.parametrize("v", VECTORS["valid"]["get_conversation_key"])
def test_conversation_key_vectors(v):
    got = nostr.nip44_conversation_key(v["sec1"], v["pub2"])
    assert got.hex() == v["conversation_key"]


@pytest.mark.parametrize("v", VECTORS["valid"]["get_message_keys"]["keys"])
def test_message_key_vectors(v):
    ck = bytes.fromhex(VECTORS["valid"]["get_message_keys"]["conversation_key"])
    chacha_key, chacha_nonce, hmac_key = nostr.nip44_message_keys(
        ck, bytes.fromhex(v["nonce"])
    )
    assert chacha_key.hex() == v["chacha_key"]
    assert chacha_nonce.hex() == v["chacha_nonce"]
    assert hmac_key.hex() == v["hmac_key"]


@pytest.mark.parametrize("v", VECTORS["valid"]["calc_padded_len"])
def test_padding_vectors(v):
    unpadded, padded = v
    assert nostr.calc_padded_len(unpadded) == padded


@pytest.mark.parametrize("v", VECTORS["valid"]["encrypt_decrypt"])
def test_encrypt_vectors(v):
    """Byte for byte, with the vector's own nonce. A round-trip test alone
    would pass on an implementation nothing else can read."""
    ck = nostr.nip44_conversation_key(v["sec1"], nostr.pubkey_of(v["sec2"]))
    assert ck.hex() == v["conversation_key"]
    got = nostr.nip44_encrypt(ck, v["plaintext"], bytes.fromhex(v["nonce"]))
    assert got == v["payload"]
    assert nostr.nip44_decrypt(ck, v["payload"]) == v["plaintext"]


@pytest.mark.parametrize("v", VECTORS["valid"]["encrypt_decrypt_long_msg"])
def test_long_message_vectors(v):
    import hashlib

    ck = bytes.fromhex(v["conversation_key"])
    plaintext = v["pattern"] * v["repeat"]
    assert hashlib.sha256(plaintext.encode()).hexdigest() == v["plaintext_sha256"]
    got = nostr.nip44_encrypt(ck, plaintext, bytes.fromhex(v["nonce"]))
    assert hashlib.sha256(got.encode()).hexdigest() == v["payload_sha256"]


@pytest.mark.parametrize("v", VECTORS["invalid"]["decrypt"])
def test_invalid_payloads_are_refused(v):
    """Every one of these must raise rather than return something.

    The MAC check is the one that matters: ChaCha20 is a stream cipher, so an
    unauthenticated payload decrypts into *something* for any key, and a
    wallet service's answer is the last place to accept that.
    """
    ck = bytes.fromhex(v["conversation_key"])
    with pytest.raises(Exception):
        nostr.nip44_decrypt(ck, v["payload"])


@pytest.mark.parametrize("v", VECTORS["invalid"]["encrypt_msg_lengths"])
def test_refused_plaintext_lengths(v):
    ck = b"\x01" * 32
    with pytest.raises(ValueError):
        nostr.nip44_encrypt(ck, "a" * v)


@pytest.mark.parametrize("v", VECTORS["invalid"]["get_conversation_key"])
def test_invalid_conversation_keys(v):
    with pytest.raises(Exception):
        nostr.nip44_conversation_key(v["sec1"], v["pub2"])


def test_nip44_nonce_is_not_reused():
    """Two encryptions of the same text under the same key must differ. The
    per-message keys come from the nonce, so a fixed one reuses a keystream."""
    ck = nostr.nip44_conversation_key("11" * 32, nostr.pubkey_of("22" * 32))
    assert nostr.nip44_encrypt(ck, "pay") != nostr.nip44_encrypt(ck, "pay")


# ── NIP-04 ───────────────────────────────────────────────────────────────────


def test_nip04_round_trips_between_the_two_keys():
    a, b = "11" * 32, "22" * 32
    payload = nostr.nip04_encrypt(a, nostr.pubkey_of(b), "pay me")
    assert nostr.nip04_decrypt(b, nostr.pubkey_of(a), payload) == "pay me"


def test_nip04_wire_shape():
    """"<base64>?iv=<base64>", which is the whole format and what the sniffing
    in decrypt() keys on."""
    payload = nostr.nip04_encrypt("11" * 32, nostr.pubkey_of("22" * 32), "x")
    import base64

    ct, _, iv = payload.partition("?iv=")
    assert iv and len(base64.b64decode(iv)) == 16
    assert len(base64.b64decode(ct)) % 16 == 0


def test_nip04_pads_a_full_block():
    """PKCS#7 adds a whole block when the plaintext already fits, and a
    decryptor that trusted the last byte without that would truncate."""
    text = "0123456789abcdef"          # exactly one block
    a, b = "11" * 32, "22" * 32
    out = nostr.nip04_decrypt(
        b, nostr.pubkey_of(a), nostr.nip04_encrypt(a, nostr.pubkey_of(b), text)
    )
    assert out == text


def test_nip04_refuses_a_payload_with_no_iv():
    with pytest.raises(ValueError):
        nostr.nip04_decrypt("11" * 32, nostr.pubkey_of("22" * 32), "aGVsbG8=")


# ── The door that picks ──────────────────────────────────────────────────────


@pytest.mark.parametrize("scheme", [nostr.NIP04, nostr.NIP44_V2])
def test_both_schemes_round_trip_through_the_one_door(scheme):
    a, b = "11" * 32, "22" * 32
    payload = nostr.encrypt(scheme, a, nostr.pubkey_of(b), "hello")
    assert nostr.decrypt(scheme, b, nostr.pubkey_of(a), payload) == "hello"


def test_decrypt_reads_the_scheme_off_the_payload():
    """A service that answered in the OTHER scheme is still answering us.
    Refusing on that alone would turn a working wallet into a timeout, so the
    reader goes by the payload's shape rather than by what was asked for."""
    a, b = "11" * 32, "22" * 32
    as_nip04 = nostr.encrypt(nostr.NIP04, a, nostr.pubkey_of(b), "hello")
    assert nostr.decrypt(nostr.NIP44_V2, b, nostr.pubkey_of(a), as_nip04) == "hello"
    as_nip44 = nostr.encrypt(nostr.NIP44_V2, a, nostr.pubkey_of(b), "hello")
    assert nostr.decrypt(nostr.NIP04, b, nostr.pubkey_of(a), as_nip44) == "hello"


def test_an_unknown_scheme_is_refused_rather_than_guessed():
    with pytest.raises(ValueError):
        nostr.encrypt("nip44_v1", "11" * 32, nostr.pubkey_of("22" * 32), "x")
