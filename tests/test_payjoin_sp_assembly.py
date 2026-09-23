"""Does the key-free coordinator half assemble what the parties signed?

helpers/payjoin_sp.py is split so the server never holds a key: it assembles
from outpoints, x-only public keys, amounts and the two scriptPubKeys the
parties derived at home, and it verifies the witnesses it is handed against
the public keys already in the frozen input set.

That split only holds if three things are true, and each is easy to break
without any test noticing until a real PayJoin fails on the network:

  * The coordinator's transaction is the one the parties signed. Inputs in
    `canonical` order, outputs in BIP-69 — get either wrong and the signatures
    verify against nothing.
  * A party can only sign its own inputs. `owner_indices` decides that, from
    the outpoints, and a bug there lets one side sign for the other.
  * A bad signature is refused by the coordinator rather than by the network.

The keys here are throwaway values made in the test. This exercises the same
`taproot_sighash` that wallet.py signs real sends with, so a signature that
verifies here is one bitcoind would accept.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

import coincurve
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name


def _load(module: str):
    name = f"{PKG}.helpers._{module}_for_pjsp_tests"
    if name in sys.modules:
        return sys.modules[name]
    for m in ("lnbits", "lnbits.utils", "lnbits.utils.crypto"):
        sys.modules.setdefault(m, types.ModuleType(m))
    if not hasattr(sys.modules["lnbits.utils.crypto"], "AESCipher"):
        sys.modules["lnbits.utils.crypto"].AESCipher = object
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "helpers" / f"{module}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


wallet = _load("wallet")
sys.modules[f"{PKG}.helpers.wallet"] = wallet
pjsp = _load("payjoin_sp")


def xonly(secret: bytes) -> bytes:
    """The x-only key for a secret, with the secret negated if that is what it
    takes to land on even Y — which is how a taproot key sits on chain."""
    return coincurve.PrivateKey(secret).public_key.format(compressed=True)[1:]


def even_secret(secret: bytes) -> bytes:
    """The secret that actually signs for `xonly(secret)`: BIP-340 signs with
    whichever of d or n-d gives the even-Y point."""
    key = coincurve.PrivateKey(secret)
    if key.public_key.format(compressed=True)[0] == 0x02:
        return secret
    n = pjsp.SECP256K1_N
    return ((n - int.from_bytes(secret, "big")) % n).to_bytes(32, "big")


def utxo(txid_byte: int, vout: int, amount: int, secret: bytes):
    return pjsp.PayjoinInput(
        txid=bytes([txid_byte]).hex() * 32,
        vout=vout,
        pub_key=xonly(secret),
        amount=amount,
    )


PAYER_SECRET = bytes([0xA1]) * 32
PAYEE_SECRET = bytes([0xB2]) * 32

# Deliberately NOT in canonical order, and the payee's txid sorts before the
# payer's — so a coordinator that kept submission order would be caught.
PAYER_INPUTS = [utxo(0xEE, 1, 200_000, PAYER_SECRET)]
PAYEE_INPUTS = [utxo(0x11, 0, 50_000, PAYEE_SECRET)]
ALL_INPUTS = PAYER_INPUTS + PAYEE_INPUTS

PAYMENT_SPK = bytes([0x51, 0x20]) + bytes([0xC3]) * 32
CHANGE_SPK = bytes([0x51, 0x20]) + bytes([0xD4]) * 32


def amounts():
    return pjsp.plan(PAYER_INPUTS, PAYEE_INPUTS, 100_000, 2.0)


def unsigned():
    return pjsp.assemble(ALL_INPUTS, amounts(), PAYMENT_SPK, CHANGE_SPK)


def sign(secret: bytes, indices, tx):
    """What a client does on the device: sighash, then a schnorr signature."""
    digests = pjsp.sighashes(tx, ALL_INPUTS)
    key = coincurve.PrivateKey(even_secret(secret))
    return {
        str(n): key.sign_schnorr(digests[n]).rjust(64, b"\x00").hex()
        for n in indices
    }


# ── the transaction is the one both parties will sign ────────────────────────


def test_inputs_are_in_canonical_order_not_submission_order():
    tx = unsigned()
    got = [(vin.txid[::-1].hex(), vin.vout) for vin in tx.vin]
    want = [(i.txid, i.vout) for i in pjsp.canonical(ALL_INPUTS)]
    assert got == want
    # And that really is a reordering, or this test proves nothing.
    assert want != [(i.txid, i.vout) for i in ALL_INPUTS]


def test_outputs_are_bip69_ordered():
    tx = unsigned()
    keys = [(o.value, bytes(o.script_pubkey.data)) for o in tx.vout]
    assert keys == sorted(keys)


def test_the_payment_output_carries_the_payees_contribution():
    """The payee's input comes straight back out, so it is no worse off for
    taking part — and the payer pays only the amount plus the fee."""
    a = amounts()
    assert a["payment"] == a["amount"] + a["payee_in"]
    values = {bytes(o.script_pubkey.data): o.value for o in unsigned().vout}
    assert values[PAYMENT_SPK] == a["payment"]
    assert values[CHANGE_SPK] == a["change"]


def test_nothing_else_is_paid():
    assert len(unsigned().vout) == 2


def test_change_below_dust_becomes_one_output():
    a = pjsp.plan(PAYER_INPUTS, PAYEE_INPUTS, 199_400, 2.0)
    assert a["change"] == 0
    tx = pjsp.assemble(ALL_INPUTS, a, PAYMENT_SPK, None)
    assert len(tx.vout) == 1


def test_assemble_refuses_change_with_no_script():
    a = amounts()
    assert a["change"] > 0
    with pytest.raises(ValueError, match="no change script"):
        pjsp.assemble(ALL_INPUTS, a, PAYMENT_SPK, None)


# ── each party signs its own inputs, and only those ──────────────────────────


def test_owner_indices_splits_the_frozen_set():
    payer = pjsp.owner_indices(ALL_INPUTS, PAYER_INPUTS)
    payee = pjsp.owner_indices(ALL_INPUTS, PAYEE_INPUTS)
    assert payer.isdisjoint(payee)
    assert payer | payee == set(range(len(ALL_INPUTS)))


def test_both_parties_signatures_verify_and_finalize():
    tx = unsigned()
    payer_idx = pjsp.owner_indices(ALL_INPUTS, PAYER_INPUTS)
    payee_idx = pjsp.owner_indices(ALL_INPUTS, PAYEE_INPUTS)

    payer_w = pjsp.verify_witnesses(
        tx, ALL_INPUTS, sign(PAYER_SECRET, payer_idx, tx), payer_idx
    )
    payee_w = pjsp.verify_witnesses(
        tx, ALL_INPUTS, sign(PAYEE_SECRET, payee_idx, tx), payee_idx
    )

    tx_hex = pjsp.finalize(tx, {**payer_w, **payee_w})
    assert tx_hex
    # Re-parsed, it still has a witness on every input.
    from embit.transaction import Transaction

    parsed = Transaction.from_string(tx_hex)
    assert len(parsed.vin) == len(ALL_INPUTS)
    assert all(len(vin.witness.items) == 1 for vin in parsed.vin)


def test_a_party_cannot_sign_the_other_partys_input():
    tx = unsigned()
    payer_idx = pjsp.owner_indices(ALL_INPUTS, PAYER_INPUTS)
    payee_idx = pjsp.owner_indices(ALL_INPUTS, PAYEE_INPUTS)
    # The payer signs the payee's input, correctly, with a key it does not have
    # — so this is refused on ownership, not on cryptography.
    forged = sign(PAYEE_SECRET, payee_idx, tx)
    with pytest.raises(ValueError, match="not yours to sign"):
        pjsp.verify_witnesses(tx, ALL_INPUTS, forged, payer_idx)


def test_a_signature_over_a_different_transaction_is_refused():
    """The case this exists for: the coordinator changed something after the
    party signed. Sign the one-output variant, submit against the two-output
    one."""
    other = pjsp.assemble(
        ALL_INPUTS, pjsp.plan(PAYER_INPUTS, PAYEE_INPUTS, 199_400, 2.0),
        PAYMENT_SPK, None,
    )
    payer_idx = pjsp.owner_indices(ALL_INPUTS, PAYER_INPUTS)
    stale = sign(PAYER_SECRET, payer_idx, other)
    with pytest.raises(ValueError, match="does not match"):
        pjsp.verify_witnesses(unsigned(), ALL_INPUTS, stale, payer_idx)


def test_a_missing_witness_is_refused():
    tx = unsigned()
    payer_idx = pjsp.owner_indices(ALL_INPUTS, PAYER_INPUTS)
    with pytest.raises(ValueError, match="No witness for input"):
        pjsp.verify_witnesses(tx, ALL_INPUTS, {}, payer_idx)


def test_a_witness_of_the_wrong_length_is_refused():
    tx = unsigned()
    payer_idx = pjsp.owner_indices(ALL_INPUTS, PAYER_INPUTS)
    n = next(iter(payer_idx))
    with pytest.raises(ValueError, match="is 65 bytes"):
        pjsp.verify_witnesses(
            tx, ALL_INPUTS, {str(n): "00" * 65}, payer_idx
        )


def test_a_witness_that_is_not_hex_is_refused():
    tx = unsigned()
    payer_idx = pjsp.owner_indices(ALL_INPUTS, PAYER_INPUTS)
    n = next(iter(payer_idx))
    with pytest.raises(ValueError, match="not hex"):
        pjsp.verify_witnesses(tx, ALL_INPUTS, {str(n): "zz"}, payer_idx)


def test_finalize_refuses_an_unsigned_input():
    tx = unsigned()
    payer_idx = pjsp.owner_indices(ALL_INPUTS, PAYER_INPUTS)
    only_payer = pjsp.verify_witnesses(
        tx, ALL_INPUTS, sign(PAYER_SECRET, payer_idx, tx), payer_idx
    )
    with pytest.raises(ValueError, match="has no signature"):
        pjsp.finalize(tx, only_payer)


# ── the split itself: no function the coordinator calls takes a key ──────────


def test_the_coordinator_half_needs_no_secret():
    """A guard on the architecture, not the maths. If someone later gives
    assemble/sighashes/verify_witnesses/finalize a key parameter, the server
    would be able to hold one — which is the thing this design exists to
    prevent."""
    import inspect

    for fn in (
        pjsp.assemble,
        pjsp.sighashes,
        pjsp.owner_indices,
        pjsp.verify_witnesses,
        pjsp.finalize,
        pjsp.plan,
        pjsp.input_digest,
        pjsp.canonical,
    ):
        params = set(inspect.signature(fn).parameters)
        assert not params & {
            "scan_secret",
            "spend_secret",
            "priv_key_tweak",
            "seed",
            "mnemonic",
        }, f"{fn.__name__} takes a secret"
