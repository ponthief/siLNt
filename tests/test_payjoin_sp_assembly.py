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


# ── whose turn it is ─────────────────────────────────────────────────────────
#
# Extracted from the endpoints so it can be tested at all. Spread across four
# handlers these conditions drift, and the failure mode is a party signing out
# of turn: the signature covers a transaction that is about to change, so it
# verifies against nothing and the PayJoin dies with nobody able to say why.


def test_the_payee_moves_first_then_the_payer_then_the_payee():
    assert pjsp.whose_turn(pjsp.PROPOSED) == "payee"
    assert pjsp.whose_turn(pjsp.CONTRIBUTED) == "payer"
    assert pjsp.whose_turn(pjsp.PAYER_SIGNED) == "payee"


def test_nobody_is_waited_on_once_it_is_terminal():
    assert pjsp.whose_turn(pjsp.BROADCAST) is None
    assert pjsp.whose_turn(pjsp.CANCELLED) is None


@pytest.mark.parametrize(
    "status,role",
    [
        (pjsp.PROPOSED, "payee"),
        (pjsp.CONTRIBUTED, "payer"),
        (pjsp.PAYER_SIGNED, "payee"),
    ],
)
def test_require_turn_allows_the_party_whose_turn_it_is(status, role):
    pjsp.require_turn(status, role)


@pytest.mark.parametrize(
    "status,role",
    [
        (pjsp.PROPOSED, "payer"),
        (pjsp.CONTRIBUTED, "payee"),
        (pjsp.PAYER_SIGNED, "payer"),
    ],
)
def test_require_turn_refuses_the_other_party(status, role):
    with pytest.raises(ValueError, match="waiting on the"):
        pjsp.require_turn(status, role)


def test_the_payer_cannot_sign_before_the_payee_has_contributed():
    """The one that matters most: signing at PROPOSED means signing before the
    input set is frozen, so every output is still to be derived and the
    signature could not commit to them."""
    with pytest.raises(ValueError, match="waiting on the payee"):
        pjsp.require_turn(pjsp.PROPOSED, "payer")


@pytest.mark.parametrize("status", [pjsp.BROADCAST, pjsp.CANCELLED])
@pytest.mark.parametrize("role", ["payer", "payee"])
def test_neither_party_may_act_on_a_finished_payjoin(status, role):
    with pytest.raises(ValueError, match="already"):
        pjsp.require_turn(status, role)


def test_an_unknown_status_stops_everything_rather_than_defaulting():
    with pytest.raises(ValueError, match="cannot go on"):
        pjsp.require_turn("SOMETHING_NEW", "payer")


def test_a_role_that_is_not_a_party_is_refused():
    with pytest.raises(ValueError, match="not a party"):
        pjsp.require_turn(pjsp.PROPOSED, "coordinator")


def test_cancelling_is_open_until_broadcast():
    for s in (pjsp.PROPOSED, pjsp.CONTRIBUTED, pjsp.PAYER_SIGNED):
        assert pjsp.can_cancel(s)
    assert not pjsp.can_cancel(pjsp.BROADCAST)
    assert not pjsp.can_cancel(pjsp.CANCELLED)


# ── wire shapes ──────────────────────────────────────────────────────────────
#
# These checks were Field(pattern=...) on the request models until an LNbits on
# Pydantic v1 refused to import the extension over the min_length beside them.
# They live here now because the Field spellings are not portable between the
# two Pydantic majors, and because under v1 `pattern=` silently enforces
# nothing — validation that looks present and is absent, on the endpoints that
# decide where money goes.

GOOD_INPUT = {"txid": "ab" * 32, "vout": 0, "pub_key": "cd" * 32, "amount": 1000}


def test_a_well_formed_input_passes():
    pjsp.validate_wire_input(GOOD_INPUT)


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("txid", "ab" * 31, "64 hex"),
        ("txid", "zz" * 32, "64 hex"),
        ("txid", "", "64 hex"),
        ("pub_key", "cd" * 33, "x-only"),
        ("pub_key", "not hex at all" + "0" * 50, "x-only"),
        ("vout", -1, "cannot be negative"),
        ("vout", "later", "whole number"),
        ("amount", 0, "more than zero"),
        ("amount", -5, "more than zero"),
        ("amount", None, "whole number"),
    ],
)
def test_a_malformed_input_is_refused(field, value, match):
    bad = {**GOOD_INPUT, field: value}
    with pytest.raises(ValueError, match=match):
        pjsp.validate_wire_input(bad)


def test_a_33_byte_compressed_key_is_refused():
    """An SP PayJoin's input set is taproot only: input_digest lifts each key
    to even Y, which is meaningless for a 33-byte key that already states its
    parity. Catching it here beats catching it in the curve code."""
    with pytest.raises(ValueError, match="x-only"):
        pjsp.validate_wire_input({**GOOD_INPUT, "pub_key": "02" + "cd" * 32})


def test_no_inputs_is_refused():
    with pytest.raises(ValueError, match="at least one coin"):
        pjsp.validate_wire_inputs([])


def test_the_same_coin_twice_is_refused():
    """Individually fine, together a double spend the network would reject."""
    with pytest.raises(ValueError, match="listed twice"):
        pjsp.validate_wire_inputs([GOOD_INPUT, dict(GOOD_INPUT)])


def test_the_same_txid_at_different_vouts_is_fine():
    pjsp.validate_wire_inputs([GOOD_INPUT, {**GOOD_INPUT, "vout": 1}])


def test_a_p2tr_script_passes():
    pjsp.validate_spk("5120" + "ab" * 32)


@pytest.mark.parametrize(
    "spk",
    [
        "0014" + "ab" * 20,      # P2WPKH — not what a PayJoin output is
        "5120" + "ab" * 31,      # too short
        "5120" + "zz" * 32,      # not hex
        "",
        None,
    ],
)
def test_anything_but_a_p2tr_script_is_refused(spk):
    with pytest.raises(ValueError, match="P2TR"):
        pjsp.validate_spk(spk)


def test_the_request_models_carry_no_unportable_field_constraints():
    """The regression guard for the outage itself.

    `min_length` on a list and `pattern=` on a str are Pydantic v2 spellings.
    Under v1, the first warns "set but not enforced" — loudly enough to stop
    LNbits importing the extension — and the second enforces nothing at all.
    Read as source rather than through pydantic, so this says the same thing
    whichever version is installed where the tests run.
    """
    import re as _re

    src = (ROOT / "models.py").read_text(encoding="utf-8")
    start = src.index("class PayjoinSpInput")
    block = src[start:]
    offenders = _re.findall(r"^\s+\w+.*Field\([^)]*\b(pattern|min_length|min_items|regex)\s*=",
                            block, _re.M)
    assert not offenders, (
        f"SP PayJoin models use {sorted(set(offenders))}, which do not mean the "
        f"same thing in Pydantic v1 and v2. Validate in helpers/payjoin_sp.py "
        f"instead."
    )


# ── the advertised flow's turn rules ─────────────────────────────────────────
#
# The payee posts an amount and a contact takes it. It needs two states the
# directed flow does not, for the reason everything here bends around: every
# SP output comes from the WHOLE input set, and at advertisement time half of
# it does not exist. So the payee cannot derive when it posts, and must come
# back once someone claims.


def test_an_open_offer_is_nobodys_turn_in_particular():
    """Not None-because-finished and not a role: any contact may take it.
    Callers that conflate the two would either hide a live offer or offer a
    Sign button for a PayJoin with no payer."""
    assert pjsp.whose_turn(pjsp.OPEN) is None
    assert pjsp.is_open(pjsp.OPEN)
    assert not pjsp.is_open(pjsp.BROADCAST)
    assert not pjsp.is_open(pjsp.PROPOSED)


@pytest.mark.parametrize("role", ["payer", "payee"])
def test_nobody_can_sign_an_unclaimed_offer(role):
    """The failure this prevents: signing before a payer exists means signing
    before the input set is frozen, so every output is still to be derived."""
    with pytest.raises(ValueError, match="still open for someone to take"):
        pjsp.require_turn(pjsp.OPEN, role)


def test_after_a_claim_the_payee_derives():
    assert pjsp.whose_turn(pjsp.CLAIMED) == "payee"
    pjsp.require_turn(pjsp.CLAIMED, "payee")
    with pytest.raises(ValueError, match="waiting on the payee"):
        pjsp.require_turn(pjsp.CLAIMED, "payer")


def test_the_two_flows_converge_at_contributed():
    """From CONTRIBUTED on, an advertised PayJoin and a directed one are the
    same object and share /sign — so the turn table must not branch."""
    for status in (pjsp.CONTRIBUTED, pjsp.PAYER_SIGNED):
        assert pjsp.whose_turn(status) in ("payer", "payee")
    assert pjsp.whose_turn(pjsp.CONTRIBUTED) == "payer"
    assert pjsp.whose_turn(pjsp.PAYER_SIGNED) == "payee"


def test_an_open_offer_can_be_withdrawn():
    assert pjsp.can_cancel(pjsp.OPEN)
    assert pjsp.can_cancel(pjsp.CLAIMED)


def test_every_live_state_either_names_a_turn_or_is_open():
    """No state may be reachable and answer neither. That combination is a
    PayJoin nobody can move and nobody is told about."""
    live = (pjsp.OPEN, pjsp.PROPOSED, pjsp.CLAIMED, pjsp.CONTRIBUTED,
            pjsp.PAYER_SIGNED)
    for s in live:
        assert pjsp.whose_turn(s) is not None or pjsp.is_open(s), s


# ── when two assemblies differ, say how ──────────────────────────────────────
#
# Both parties and the coordinator build the transaction independently from one
# row, and a key-path signature commits to every byte of it. When they differ,
# signature verification can only report that it failed — true, and no help at
# all to whoever has to fix it. explain_mismatch turns that into a sentence.


def _hex(tx):
    return tx.serialize().hex()


def test_identical_transactions_are_not_a_mismatch():
    assert pjsp.explain_mismatch(unsigned(), _hex(unsigned())) is None


def test_no_client_transaction_is_not_a_mismatch():
    """An older client sends nothing and still works — it just gets the vaguer
    error from signature verification."""
    assert pjsp.explain_mismatch(unsigned(), "") is None


def test_unparseable_is_reported_as_such():
    assert "not a transaction" in pjsp.explain_mismatch(unsigned(), "not hex")


def test_a_different_output_value_is_named():
    a = amounts()
    other = pjsp.assemble(ALL_INPUTS, {**a, "payment": a["payment"] + 1},
                          PAYMENT_SPK, CHANGE_SPK)
    msg = pjsp.explain_mismatch(unsigned(), _hex(other))
    assert "sats where this PayJoin pays" in msg, msg


def test_a_different_destination_is_named():
    other = pjsp.assemble(ALL_INPUTS, amounts(),
                          bytes([0x51, 0x20]) + bytes([0x99]) * 32, CHANGE_SPK)
    msg = pjsp.explain_mismatch(unsigned(), _hex(other))
    assert "different destination" in msg, msg


def test_a_different_output_count_is_named():
    one = pjsp.assemble(ALL_INPUTS,
                        pjsp.plan(PAYER_INPUTS, PAYEE_INPUTS, 199_400, 2.0),
                        PAYMENT_SPK, None)
    msg = pjsp.explain_mismatch(unsigned(), _hex(one))
    assert "outputs" in msg and "absorbed into the fee" in msg, msg


def test_a_different_input_set_is_named():
    extra = [*ALL_INPUTS, utxo(0x44, 9, 10_000, PAYER_SECRET)]
    other = pjsp.assemble(extra, amounts(), PAYMENT_SPK, CHANGE_SPK)
    msg = pjsp.explain_mismatch(unsigned(), _hex(other))
    assert "inputs" in msg, msg


def test_the_same_inputs_in_a_different_order_says_so():
    """The failure mode worth naming precisely: both sides agree on which
    coins, and disagree on BIP-69. Every signature is then over the wrong
    position, and 'signature does not match' is the least useful way to learn
    it."""
    tx = unsigned()
    reordered = pjsp.assemble(ALL_INPUTS, amounts(), PAYMENT_SPK, CHANGE_SPK)
    reordered.vin = list(reversed(reordered.vin))
    msg = pjsp.explain_mismatch(tx, _hex(reordered))
    assert "different order" in msg and "BIP-69" in msg, msg
