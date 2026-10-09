"""Nostr events and the two ways NIP-47 encrypts them.

WHY A WALLET REPO GREW A NOSTR MODULE. Nostr Wallet Connect (NIP-47) is the
only remote-control protocol the signet Lightning wallets actually speak, and
it is nostr all the way down: the request is a signed event, the answer is a
signed event, and the body of each is encrypted to the other party's key. None
of that is reusable from elsewhere in this repo, so it is here, kept pure and
kept small — no sockets, no config, no clock. helpers/nwc.py does the talking.

WHAT IS AND IS NOT SECURITY-CRITICAL HERE. Getting the encryption wrong does
not lose money: a request the wallet service cannot decrypt is a request it
ignores, and the payout retries and then reports a failure somebody can read.
What WOULD lose money is signing the wrong thing, so the event id is built the
way the protocol says and the signature covers it, and nothing in this module
ever sees an invoice or an amount — it moves opaque strings.

BOTH SCHEMES, because a wallet service picks. NIP-44 v2 is what the spec
prefers and NIP-04 is what it falls back to when the service advertises no
`encryption` tag. Implementing one of them would have meant guessing which,
and the failure mode of guessing is silence on a relay. Both are pinned
against the specs' own vectors (fixtures/nip44-vectors.json), because
hand-written crypto that nothing checks is how a payout queue fills up.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import time
from typing import Optional

from coincurve import PrivateKey, PublicKey, PublicKeyXOnly
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ── Keys ─────────────────────────────────────────────────────────────────────
#
# A nostr public key is X-ONLY: 32 bytes, the point's x coordinate, with the
# even-y point implied. Every conversion back to a full point in this file
# prefixes 0x02 for that reason, and getting it wrong would produce a shared
# secret the other side does not share.


def _privkey(privkey_hex: str) -> PrivateKey:
    raw = bytes.fromhex((privkey_hex or "").strip())
    if len(raw) != 32:
        raise ValueError("A nostr private key is 32 bytes of hex.")
    return PrivateKey(raw)


def pubkey_of(privkey_hex: str) -> str:
    """The x-only public key for a private key, 64 hex characters."""
    return _privkey(privkey_hex).public_key.format(compressed=True)[1:].hex()


def shared_x(privkey_hex: str, pubkey_hex: str) -> bytes:
    """The ECDH shared point's X COORDINATE, raw — not hashed.

    coincurve's own `ecdh` applies libsecp256k1's default hash on the way out,
    which is not what either nostr scheme wants: NIP-04 uses this as an AES key
    directly and NIP-44 feeds it to HKDF. Multiplying and taking the
    compressed form's tail is the unhashed value both specs mean.
    """
    pub = bytes.fromhex((pubkey_hex or "").strip())
    if len(pub) == 32:
        pub = b"\x02" + pub
    if len(pub) != 33:
        raise ValueError("A nostr public key is 32 bytes of hex.")
    point = PublicKey(pub).multiply(_privkey(privkey_hex).secret)
    return point.format(compressed=True)[1:]


# ── Events ───────────────────────────────────────────────────────────────────


def event_id(
    pubkey: str, created_at: int, kind: int, tags: list, content: str
) -> str:
    """The id every nostr event is signed over.

    sha256 of a JSON ARRAY with no whitespace, in this exact order. The
    separators matter — a space after each comma is a different id and a
    signature nothing will accept.
    """
    payload = json.dumps(
        [0, pubkey, int(created_at), int(kind), tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sign_event(privkey_hex: str, kind: int, content: str, tags: list,
               created_at: Optional[int] = None) -> dict:
    """A complete, signed event. BIP-340 over the id, as nostr uses."""
    pub = pubkey_of(privkey_hex)
    at = int(created_at if created_at is not None else time.time())
    eid = event_id(pub, at, kind, tags, content)
    sig = _privkey(privkey_hex).sign_schnorr(bytes.fromhex(eid))
    return {
        "id": eid,
        "pubkey": pub,
        "created_at": at,
        "kind": int(kind),
        "tags": tags,
        "content": content,
        "sig": sig.hex(),
    }


def verify_event(event: dict) -> bool:
    """Whether an event's id and signature are its own.

    Used on the way IN. A relay is an untrusted middlebox: it can hand back any
    event it likes, and without this a response could be forged by whoever runs
    it. The caller additionally checks the pubkey is the wallet service's —
    a valid signature by the wrong key is a stranger's answer.
    """
    try:
        pub = str(event.get("pubkey") or "")
        eid = event_id(
            pub,
            int(event.get("created_at") or 0),
            int(event.get("kind") or 0),
            event.get("tags") or [],
            str(event.get("content") or ""),
        )
        if eid != str(event.get("id") or ""):
            return False
        return PublicKeyXOnly(bytes.fromhex(pub)).verify(
            bytes.fromhex(str(event.get("sig") or "")), bytes.fromhex(eid)
        )
    except Exception:
        return False


# ── NIP-04: AES-256-CBC, deprecated and still what many services speak ───────


def nip04_encrypt(privkey_hex: str, pubkey_hex: str, plaintext: str) -> str:
    """"<base64 ciphertext>?iv=<base64 iv>", which is the whole format."""
    key = shared_x(privkey_hex, pubkey_hex)
    iv = os.urandom(16)
    data = plaintext.encode("utf-8")
    pad = 16 - (len(data) % 16)          # PKCS#7, and a full block when it fits
    data += bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return (
        base64.b64encode(ct).decode("ascii")
        + "?iv="
        + base64.b64encode(iv).decode("ascii")
    )


def nip04_decrypt(privkey_hex: str, pubkey_hex: str, payload: str) -> str:
    text = (payload or "").strip()
    if "?iv=" not in text:
        raise ValueError("Not a NIP-04 payload: no iv.")
    ct_b64, iv_b64 = text.split("?iv=", 1)
    key = shared_x(privkey_hex, pubkey_hex)
    dec = Cipher(
        algorithms.AES(key), modes.CBC(base64.b64decode(iv_b64))
    ).decryptor()
    data = dec.update(base64.b64decode(ct_b64)) + dec.finalize()
    if not data:
        raise ValueError("Empty NIP-04 plaintext.")
    pad = data[-1]
    if pad < 1 or pad > 16 or len(data) < pad:
        raise ValueError("Bad NIP-04 padding.")
    return data[: len(data) - pad].decode("utf-8")


# ── NIP-44 v2: ChaCha20 + HMAC-SHA256, with padding ──────────────────────────
#
# The padding is not decoration. NIP-04 leaks the plaintext's length to anyone
# watching the relay, and for a wallet protocol the length of a request is a
# fair guess at which method it was.

NIP44_VERSION = 2
_MIN_PLAINTEXT = 1
_MAX_PLAINTEXT = 65535


def nip44_conversation_key(privkey_hex: str, pubkey_hex: str) -> bytes:
    """HKDF-extract over the shared x, salted with the version.

    One per pair of keys, and reusable: the per-message keys below are derived
    from it with the message's own nonce, which is what stops two messages
    sharing a keystream.
    """
    return hmac.new(
        b"nip44-v2", shared_x(privkey_hex, pubkey_hex), hashlib.sha256
    ).digest()


def nip44_message_keys(conversation_key: bytes, nonce: bytes) -> tuple:
    """(chacha_key, chacha_nonce, hmac_key) — HKDF-expand, 76 bytes."""
    if len(conversation_key) != 32:
        raise ValueError("A conversation key is 32 bytes.")
    if len(nonce) != 32:
        raise ValueError("A nip44 nonce is 32 bytes.")
    out = b""
    block = b""
    counter = 1
    while len(out) < 76:
        block = hmac.new(
            conversation_key, block + nonce + bytes([counter]), hashlib.sha256
        ).digest()
        out += block
        counter += 1
    return out[0:32], out[32:44], out[44:76]


def calc_padded_len(unpadded: int) -> int:
    """How long the padded plaintext is, which the spec fixes exactly.

    Everything up to 32 bytes pads to 32; past that it is the next power of
    two, divided into eight buckets once that power is over 256. The point is
    that a length tells an observer very little, not that it tells them
    nothing.
    """
    n = int(unpadded)
    if n <= 0:
        raise ValueError("Nothing to pad.")
    if n <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(n - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((n - 1) // chunk + 1)


def _chacha(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    # `cryptography` takes a 16-byte ChaCha20 nonce: a 4-byte little-endian
    # block counter in front of the 12-byte nonce proper. NIP-44 starts the
    # counter at zero.
    cipher = Cipher(
        algorithms.ChaCha20(key, (0).to_bytes(4, "little") + nonce12), mode=None
    )
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def nip44_encrypt(
    conversation_key: bytes, plaintext: str, nonce: Optional[bytes] = None
) -> str:
    """base64(version || nonce || ciphertext || mac).

    `nonce` is injectable for the spec's vectors only. Left to itself it is 32
    random bytes, and it must be: the per-message keys come from it, so a
    repeat would reuse a keystream.
    """
    data = plaintext.encode("utf-8")
    if not (_MIN_PLAINTEXT <= len(data) <= _MAX_PLAINTEXT):
        raise ValueError(
            f"A nip44 plaintext is 1..{_MAX_PLAINTEXT} bytes, not {len(data)}."
        )
    nonce = nonce if nonce is not None else os.urandom(32)
    chacha_key, chacha_nonce, hmac_key = nip44_message_keys(
        conversation_key, nonce
    )
    padded = (
        len(data).to_bytes(2, "big")
        + data
        + b"\x00" * (calc_padded_len(len(data)) - len(data))
    )
    ciphertext = _chacha(chacha_key, chacha_nonce, padded)
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(
        bytes([NIP44_VERSION]) + nonce + ciphertext + mac
    ).decode("ascii")


def nip44_decrypt(conversation_key: bytes, payload: str) -> str:
    text = (payload or "").strip()
    if text.startswith("#"):
        # The spec's own marker for a version this reader does not know.
        raise ValueError("Unsupported nip44 version.")
    raw = base64.b64decode(text, validate=True)
    if len(raw) < 99:
        raise ValueError("A nip44 payload is at least 99 bytes.")
    if raw[0] != NIP44_VERSION:
        raise ValueError(f"Unsupported nip44 version {raw[0]}.")
    nonce, ciphertext, mac = raw[1:33], raw[33:-32], raw[-32:]
    chacha_key, chacha_nonce, hmac_key = nip44_message_keys(
        conversation_key, nonce
    )
    # Before decrypting, and in constant time. An unauthenticated ChaCha20
    # stream decrypts anything into something.
    want = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(want, mac):
        raise ValueError("Bad nip44 MAC.")
    padded = _chacha(chacha_key, chacha_nonce, ciphertext)
    length = int.from_bytes(padded[0:2], "big")
    data = padded[2 : 2 + length]
    if (
        length < _MIN_PLAINTEXT
        or len(data) != length
        or len(padded) != 2 + calc_padded_len(length)
    ):
        raise ValueError("Bad nip44 padding.")
    return data.decode("utf-8")


# ── One door for both ────────────────────────────────────────────────────────

NIP04 = "nip04"
NIP44_V2 = "nip44_v2"


def encrypt(scheme: str, privkey_hex: str, pubkey_hex: str, plaintext: str) -> str:
    if scheme == NIP44_V2:
        return nip44_encrypt(
            nip44_conversation_key(privkey_hex, pubkey_hex), plaintext
        )
    if scheme == NIP04:
        return nip04_encrypt(privkey_hex, pubkey_hex, plaintext)
    raise ValueError(f"Unknown encryption scheme {scheme!r}.")


def decrypt(scheme: str, privkey_hex: str, pubkey_hex: str, payload: str) -> str:
    """Decrypt, preferring the scheme asked for and recognising the other.

    A service that answered in the scheme we did not request is still
    answering us, and the shape of a payload says which it used — NIP-04
    carries "?iv=" and nothing else does. Refusing on that basis alone would
    turn a working wallet into an unexplained timeout.
    """
    text = (payload or "").strip()
    looks_nip04 = "?iv=" in text
    use = NIP04 if looks_nip04 else NIP44_V2
    if use == NIP44_V2:
        return nip44_decrypt(
            nip44_conversation_key(privkey_hex, pubkey_hex), text
        )
    return nip04_decrypt(privkey_hex, pubkey_hex, text)
