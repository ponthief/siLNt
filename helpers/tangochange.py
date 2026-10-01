"""Deriving a Tango's routed change output, and proving it to both clients.

A user who gives a Lightning address has their round's change output pay the
INSTANCE's Silent Payments address instead of their own wallet, with the value
sent on over Lightning minus a fee. helpers/tangopayout.py has the fee;
helpers/lnaddress.py has the address; this has the output itself.

SEPARATE FROM tangopayout.py ON PURPOSE. That module is the fee rule, it is
pure arithmetic, and both clients mirror it so they can show the net before
anyone signs. This one reaches the curve and cannot be mirrored — see below —
so keeping them apart keeps the mirrored half mirrorable.

── THE PROBLEM, which payjoin_sp.py::payment_script already states ──────────

    "Derived by the PAYEE, who is the only party with the scan key it needs;
     the payer cannot compute it and cannot check it."

A BIP-352 output is P_k = B_spend + t_k·G, where t_k comes from the shared
secret input_hash·b_scan·A_sum. A client has A_sum and input_hash — both are
public, from the frozen input set — and B_scan and B_spend from the instance's
address. It has neither b_scan nor the input private keys, so it cannot compute
the shared secret and cannot re-derive the script.

That matters because a taproot key-path signature commits to every output.
Without some check, a coordinator could put any script in the change position
and both sides would sign it. "The server said so" is not a check; the same
mistake shipped in the PayJoin and let every substitution through.

── THE CHECK THAT IS AVAILABLE ──────────────────────────────────────────────

Reveal t_k with the round. A client then verifies

    script == OP_1 <x(B_spend + t_k·G)>

against the SP address it has from the config. What that proves is the part
that matters: the output's private key is b_spend + t_k, and only the holder
of b_spend can spend it. **The change cannot be redirected to a third party.**

What it does NOT prove is that t_k is the real shared-secret derivative — a
server could hand over any t_k with a matching script. The money still goes to
the instance either way; what the instance loses is the ability to FIND that
coin by scanning, which is its own problem and not the user's. So the guarantee
is exactly "this pays the configured instance address", which is the guarantee
the user needs.

Revealing t_k leaks nothing: it is a hash output, it says nothing about
b_scan, and the counterparty already knows the round's outputs and already
knows from the round record that this side is routing — it has to, or the two
sides could not agree on the output set they are both signing.

── THE SCAN SECRET ──────────────────────────────────────────────────────────

Computing t_k needs the instance's b_scan, so `tango_change_scan_secret` is a
config value. It is a VIEW KEY, not a spending key: b_scan finds the
instance's outputs, and spending them needs b_spend, which should stay offline
in whatever wallet holds the seed. A leaked b_scan tells an attacker which
outputs belong to the service; it does not let them take any. That is a
different kind of secret from the ones CLAUDE.md says are never stored, which
are users' spending keys.
"""

from __future__ import annotations

from typing import Optional

from .curve import ser256
from .curve_native import point_add, point_mul, pubkey_point_gen_from_int
from .payjoin_sp import PayjoinInput, input_digest
from .wallet import (
    SECP256K1_N,
    compressed_pubkey_to_point,
    parse_sp_address,
    tagged_hash,
)


# WHICH k EACH SIDE GETS, and it is fixed by role rather than by order.
#
# Both routed change outputs in a round pay the SAME recipient — the instance —
# so they must use different k, or they are one address paid twice: one coin,
# not two, and the second side's money lands on the first side's script.
# Deriving them from the role means both clients compute both without
# negotiating anything.
PAYOUT_K = {"a": 0, "b": 1}


def payout_k(role: str) -> int:
    r = (role or "").strip().lower()
    if r not in PAYOUT_K:
        raise ValueError(f"A Tango has sides 'a' and 'b', not {role!r}.")
    return PAYOUT_K[r]


def _spk(point) -> bytes:
    return bytes([0x51, 0x20]) + ser256(point[0])


def derive_payout_output(
    sp_address: str,
    scan_secret: bytes,
    inputs: list[PayjoinInput],
    role: str,
) -> tuple[bytes, bytes]:
    """(scriptPubKey, t_k) for one side's routed change.

    The instance is the payee here, so this is the ordinary payee-side
    derivation — the same one payjoin_sp::own_output_point does — with t_k
    kept rather than thrown away, because the clients need it to check the
    result.
    """
    b_scan_pub, b_spend = parse_sp_address((sp_address or "").strip())
    a_sum, input_hash = input_digest(inputs)
    b_scan = int.from_bytes(scan_secret, "big") % SECP256K1_N
    if b_scan == 0:
        raise ValueError("The instance's Tango change scan key is not a key.")

    ecdh = point_mul(a_sum, (b_scan * input_hash) % SECP256K1_N)
    ecdh_compressed = bytes([0x02 + (ecdh[1] % 2)]) + ser256(ecdh[0])
    k = payout_k(role)
    t_k_bytes = tagged_hash(
        "BIP0352/SharedSecret", ecdh_compressed + k.to_bytes(4, "big")
    )
    t_k = int.from_bytes(t_k_bytes, "big")
    if t_k == 0 or t_k >= SECP256K1_N:
        raise ValueError("t_k out of range")

    point = point_add(
        compressed_pubkey_to_point(b_spend), pubkey_point_gen_from_int(t_k)
    )
    # b_scan_pub is read only to prove the address parsed into two keys; the
    # derivation uses the secret, and a mismatch between them is the operator
    # configuring an address and a scan key from different wallets. Checked
    # here rather than left to produce coins nobody can find.
    if len(b_scan_pub) != 33 or len(b_spend) != 33:
        raise ValueError("The instance's Tango change address is malformed.")
    return _spk(point), t_k_bytes


def verify_payout_output(
    sp_address: str, tweak: bytes, script: bytes
) -> bool:
    """Does `script` pay the holder of `sp_address`'s spend key?

    THE MIRRORED HALF. services/tango.ts has the same function, and
    fixtures/tango-change-payout.json holds this one's answers so the two
    cannot drift — a client that accepts a script this would reject is a client
    that signs away a change output.

    Needs no secret, which is the whole point: B_spend comes out of the public
    address and t_k comes with the round.
    """
    try:
        _, b_spend = parse_sp_address((sp_address or "").strip())
    except Exception:
        return False
    if len(tweak) != 32 or len(script) != 34:
        return False
    t_k = int.from_bytes(tweak, "big")
    if t_k == 0 or t_k >= SECP256K1_N:
        return False
    try:
        point = point_add(
            compressed_pubkey_to_point(b_spend), pubkey_point_gen_from_int(t_k)
        )
    except Exception:
        return False
    return _spk(point) == bytes(script)


def payout_change_spks(
    sp_address: str,
    scan_secret: bytes,
    inputs: list[PayjoinInput],
    a_routed: bool,
    b_routed: bool,
) -> dict:
    """Both sides' routed change scripts and tweaks, as the round records them.

    Returns only the sides that route. A side without a Lightning address keeps
    its own change script, derived by its own device, exactly as every round
    did before this existed.
    """
    out: dict = {}
    for role, routed in (("a", a_routed), ("b", b_routed)):
        if not routed:
            continue
        spk, tweak = derive_payout_output(sp_address, scan_secret, inputs, role)
        out[role] = {"spk": spk.hex(), "tweak": tweak.hex()}
    return out


def scan_key_matches(sp_address: str, scan_secret: str) -> bool:
    """Is `scan_secret` the scan key OF `sp_address`?

    WHY THIS HAD TO EXIST. An SP address carries B_scan as a PUBLIC key, and
    the scan SECRET cannot be derived from it — that is the discrete log, and
    if it were possible Silent Payments would be worthless, because anyone
    could scan anyone's payments. So the two config values are entered
    separately, and nothing stopped them being from different wallets.

    A mismatch is the worst kind of wrong, because nothing notices:

      * derive_payout_output uses the SECRET for the shared secret and the
        address's B_SPEND for the point, so with a mismatched pair it still
        produces a valid output, spendable by the holder of B_spend;
      * verify_payout_output only checks B_spend, so both clients accept it and
        the round completes;
      * the instance then cannot FIND that coin, because it would scan with
        the key the output was not derived against.

    Money arrives somewhere real and invisible. One scalar multiplication
    rules it out, so it is checked when the config is saved.
    """
    try:
        b_scan_pub, _ = parse_sp_address((sp_address or "").strip())
    except Exception:
        return False
    text = (scan_secret or "").strip()
    try:
        secret = bytes.fromhex(text)
    except ValueError:
        return False
    if len(secret) != 32:
        return False
    k = int.from_bytes(secret, "big")
    if k == 0 or k >= SECP256K1_N:
        return False
    try:
        point = pubkey_point_gen_from_int(k)
    except Exception:
        return False
    derived = bytes([0x02 + (point[1] % 2)]) + ser256(point[0])
    return derived == b_scan_pub
