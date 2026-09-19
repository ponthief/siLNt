"""A two-party Silent Payments PayJoin, end to end.

The spike (helpers/_payjoin_sp_check.py) established that this is possible.
These tests hold helpers/payjoin_sp.py to it, and to the properties that decide
whether money moves:

  - each party derives its OWN output from a public input set, and the
    production matcher in scan.py finds it;
  - what each party finds is SPENDABLE, checked with the spend secret that
    party's own scanner never sees;
  - neither party's derivation depends on the other's private keys;
  - the amounts add up, and the fee is the one that was quoted.

Everything is driven through the real module. Where a value could be faked to
make a test pass — the oracle tweak above all — it is computed the way the real
producer computes it instead.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

import coincurve
import pytest
from conftest import scan

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _load(module: str):
    """Load a helpers module for real. conftest stubs helpers.wallet for scan.py;
    payjoin_sp imports the real thing, so it is loaded here under its own name
    with the one host-application import filled in."""
    name = f"{PKG}.helpers._{module}_under_test"
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


# payjoin_sp does `from .wallet import ...`, so the real wallet module has to be
# registered under the package name it expects before it is imported.
_wallet = _load("wallet")
sys.modules[f"{PKG}.helpers.wallet"] = _wallet
pj = _load("payjoin_sp")


class Party:
    """A siLNt wallet, reduced to the four keys that matter here."""

    def __init__(self, seed: int):
        self.scan_secret = bytes([seed]) * 32
        self.spend_secret = bytes([seed + 1]) * 32
        self.spend_pub = coincurve.PublicKey.from_secret(self.spend_secret).format()
        self.labels = scan.create_labels(self.scan_secret, indices=[])
        self.m0 = next(lab for lab in self.labels if lab.m == 0)

    def utxo(self, seed: int, txid: str, vout: int, amount: int) -> pj.PayjoinInput:
        """A UTXO this party owns: an SP output, so its key is b_spend + tweak."""
        tweak = bytes([seed]) * 32
        full = scan.add_private_keys(self.spend_secret, tweak)
        pub = coincurve.PublicKey.from_secret(full).format()[1:]
        return pj.PayjoinInput(
            txid=txid, vout=vout, amount=amount, pub_key=pub, priv_key_tweak=tweak
        )


def oracle_tweak(inputs) -> bytes:
    """input_hash · A_sum — what BlindBit publishes for the transaction.

    Built from payjoin_sp's own digest so the scanner is driven by the same
    input set the module derived against, not by a value chosen to agree.
    """
    a_sum, input_hash = pj.input_digest(pj.canonical(inputs))
    pt = _wallet.point_mul(a_sum, input_hash)
    return bytes([0x02 + (pt[1] % 2)]) + _wallet.ser256(pt[0])


def scan_for(party: Party, inputs, scripts, amount=10_000):
    utxos = [
        {"txid": "cc" * 32, "vout": i, "amount": amount, "pubkey": s[2:].hex(),
         "timestamp": 1}
        for i, s in enumerate(scripts)
    ]
    return scan.sync_block(
        [oracle_tweak(inputs).hex()], utxos,
        party.scan_secret, party.spend_pub, party.labels,
    )


def spendable(party: Party, owned) -> bool:
    full = scan.add_private_keys(party.spend_secret, owned.priv_key_tweak)
    return coincurve.PublicKey.from_secret(full).format()[1:] == owned.pub_key


@pytest.fixture
def parties():
    payer, payee = Party(0x11), Party(0x41)
    payer_in = [payer.utxo(0x21, "aa" * 32, 0, 120_000)]
    payee_in = [payee.utxo(0x51, "bb" * 32, 1, 40_000)]
    return payer, payee, payer_in, payee_in


# ── the whole flow ───────────────────────────────────────────────────────────

def test_each_party_finds_and_can_spend_its_own_output(parties):
    payer, payee, payer_in, payee_in = parties
    inputs = pj.canonical(payer_in + payee_in)

    amounts = pj.plan(payer_in, payee_in, amount=25_000, fee_rate=2)

    # Derived independently, each from its own scan key and the public inputs.
    payment = pj.payment_script(payee.scan_secret, payee.spend_pub, inputs)
    change = pj.change_script(
        payer.scan_secret, payer.spend_pub, payer.m0.pub_key, inputs
    )
    assert payment != change

    payee_found = scan_for(payee, inputs, [payment, change])
    payer_found = scan_for(payer, inputs, [payment, change])

    assert len(payee_found) == 1, "the payee should find exactly the payment"
    assert payee_found[0].pub_key == payment[2:]
    assert len(payer_found) == 1, "the payer should find exactly its change"
    assert payer_found[0].pub_key == change[2:]

    assert spendable(payee, payee_found[0]), "payment detected but not spendable"
    assert spendable(payer, payer_found[0]), "change detected but not spendable"


def test_neither_party_can_derive_the_other_s_output(parties):
    """The property the whole design rests on, stated as a test.

    A party holding only its own scan key derives its own output and nothing
    else. If this ever fails, one party can compute where the other's money
    lands, which is exactly the linkage Silent Payments exist to prevent.
    """
    payer, payee, payer_in, payee_in = parties
    inputs = pj.canonical(payer_in + payee_in)

    payment = pj.payment_script(payee.scan_secret, payee.spend_pub, inputs)
    # The payer, using its own scan key against the payee's spend key — the
    # closest it can get without b_scan.
    guess = pj.payment_script(payer.scan_secret, payee.spend_pub, inputs)
    assert guess != payment


def test_deriving_from_one_party_s_inputs_alone_loses_the_payment(parties):
    """The blocker, kept in the suite so nobody re-introduces it.

    This is what today's single-party builder does if pointed at a PayJoin:
    derive over the inputs you control. The output is well-formed and the payee
    never finds it.
    """
    payer, payee, payer_in, payee_in = parties
    full = pj.canonical(payer_in + payee_in)

    partial = pj.payment_script(payee.scan_secret, payee.spend_pub, pj.canonical(payee_in))
    assert partial != pj.payment_script(payee.scan_secret, payee.spend_pub, full)
    assert scan_for(payee, full, [partial]) == []


def test_an_input_added_after_derivation_invalidates_the_outputs(parties):
    """Why the protocol has to freeze inputs before anyone derives."""
    payer, payee, payer_in, payee_in = parties
    inputs = pj.canonical(payer_in + payee_in)
    payment = pj.payment_script(payee.scan_secret, payee.spend_pub, inputs)

    late = pj.canonical(inputs + [payer.utxo(0x31, "dd" * 32, 0, 5_000)])
    assert scan_for(payee, late, [payment]) == []
    assert len(scan_for(payee, late,
                        [pj.payment_script(payee.scan_secret, payee.spend_pub, late)])) == 1


def test_input_order_does_not_change_the_result(parties):
    """Both sides must land on the same transaction without negotiating one.

    BIP-69 does that, but only if the derivation is order-independent to begin
    with — A_sum is a sum and input_hash uses the minimum outpoint, so it is.
    """
    payer, payee, payer_in, payee_in = parties
    a = pj.payment_script(payee.scan_secret, payee.spend_pub,
                          pj.canonical(payer_in + payee_in))
    b = pj.payment_script(payee.scan_secret, payee.spend_pub,
                          pj.canonical(payee_in + payer_in))
    assert a == b


# ── amounts ──────────────────────────────────────────────────────────────────

def test_the_payee_gets_its_contribution_back_on_top(parties):
    payer, payee, payer_in, payee_in = parties
    a = pj.plan(payer_in, payee_in, amount=25_000, fee_rate=2)
    assert a["payment"] == 25_000 + 40_000, "payee must not fund the payment"
    assert a["payer_in"] == a["amount"] + a["fee"] + a["change"], "sats went missing"


def test_a_dust_payment_is_refused(parties):
    payer, payee, payer_in, payee_in = parties
    with pytest.raises(ValueError, match="dust limit"):
        pj.plan(payer_in, payee_in, amount=100, fee_rate=1)


def test_insufficient_funds_names_the_maximum(parties):
    payer, payee, payer_in, payee_in = parties
    with pytest.raises(ValueError) as e:
        pj.plan(payer_in, payee_in, amount=500_000, fee_rate=1)
    assert "the most they can send is" in str(e.value)


def test_dust_change_is_absorbed_not_created(parties):
    payer, payee, payer_in, payee_in = parties
    _vsize, fee = pj.estimate_fee(2, 2, 2)
    amount = 120_000 - fee - 200          # would leave 200 sats of change
    a = pj.plan(payer_in, payee_in, amount=amount, fee_rate=2)
    assert a["change"] == 0
    assert a["payer_in"] == a["amount"] + a["fee"], "absorbed change must be exact"


def test_both_parties_must_contribute(parties):
    payer, payee, payer_in, payee_in = parties
    with pytest.raises(ValueError, match="both parties"):
        pj.plan(payer_in, [], amount=25_000, fee_rate=2)


# ── signing ──────────────────────────────────────────────────────────────────

def test_signing_key_reproduces_the_input_key(parties):
    payer, _payee, payer_in, _payee_in = parties
    u = payer_in[0]
    key = pj.signing_key(payer.spend_secret, u.priv_key_tweak, u.pub_key)
    point = _wallet.pubkey_point_gen_from_int(int.from_bytes(key.secret, "big"))
    assert _wallet.ser256(point[0]) == u.pub_key
    assert point[1] % 2 == 0, "a taproot signing key must have even Y"


def test_the_wrong_wallet_cannot_sign_an_input(parties):
    """A mismatched spend key is caught here rather than producing a signature
    that fails at broadcast with nothing to point at."""
    _payer, payee, payer_in, _payee_in = parties
    u = payer_in[0]
    with pytest.raises(ValueError, match="does not reproduce"):
        pj.signing_key(payee.spend_secret, u.priv_key_tweak, u.pub_key)


# ── input-set hygiene ────────────────────────────────────────────────────────

def test_a_non_taproot_input_is_refused(parties):
    payer, _payee, payer_in, payee_in = parties
    bad = pj.PayjoinInput(
        txid="ee" * 32, vout=0, amount=1000,
        pub_key=coincurve.PublicKey.from_secret(bytes([9]) * 32).format(),  # 33 bytes
    )
    with pytest.raises(ValueError, match="x-only"):
        pj.input_digest(pj.canonical(payer_in + payee_in + [bad]))


def test_an_empty_input_set_is_refused():
    with pytest.raises(ValueError, match="both parties"):
        pj.input_digest([])
