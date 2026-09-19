"""Does /plain/prepare decide the same spend /plain/spend would have built?

The plain BIP-84 chain used to be spent by posting its private keys and letting
the server sign. The clients now ask plan_plain_spend what the transaction
should be and sign it themselves, which is only an improvement if the plan is
the same spend — same coins, same order, same fee, same refusals. If the two
drift, one of them is quietly pricing or refusing differently from the other,
and the difference shows up as a transaction that will not build or a fee
nobody chose.

build_plain_transaction now calls plan_plain_spend, so these are not two
independent implementations to compare; they are a check that the split did not
lose anything and that the plan really does carry everything a signer needs.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name


def _load(module: str):
    name = f"{PKG}.helpers._{module}_for_plain_tests"
    if name in sys.modules:
        return sys.modules[name]
    for m in ("lnbits", "lnbits.utils", "lnbits.utils.crypto"):
        sys.modules.setdefault(m, types.ModuleType(m))
    if not hasattr(sys.modules["lnbits.utils.crypto"], "AESCipher"):
        sys.modules["lnbits.utils.crypto"].AESCipher = object
    spec = importlib.util.spec_from_file_location(name, ROOT / "helpers" / f"{module}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# wallet first, and registered under its canonical name: conftest puts a stub
# there for scan.py's sake, and plain.py imports the real thing from it. Same
# order, and for the same reason, as test_txsize.py.
wallet = _load("wallet")
sys.modules[f"{PKG}.helpers.wallet"] = wallet
plain = _load("plain")
DUST = plain.DUST_SATS

KEYS = ["d1" * 32, "d2" * 32, "d3" * 32]
CHANGE_KEY = "d4" * 32


def addr(i: int, network: str = "signet") -> str:
    return plain.plain_address_for_key(KEYS[i], network)


def change_addr(network: str = "signet") -> str:
    return plain.plain_address_for_key(CHANGE_KEY, network)


def utxo(i: int, txid: str, vout: int, amount: int, network: str = "signet") -> dict:
    return {"address": addr(i, network), "txid": txid, "vout": vout,
            "amount": amount, "height": 100_000}


def sp_address(network: str = "signet") -> str:
    return wallet.encode_silent_payment_address(
        wallet.pubkey_point_gen_from_int(int("33" * 32, 16)),
        wallet.pubkey_point_gen_from_int(int("44" * 32, 16)),
        "sp" if network == "mainnet" else "tsp",
    )


BECH32 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"


def both(utxos, amount, fee_rate, destination, key_indices, change=None, network="signet"):
    """The plan and the build of the same spend."""
    kwargs = dict(destination=destination, utxos=utxos, fee_rate=fee_rate,
                  network=network, amount=amount, change_address=change)
    return (
        plain.plan_plain_spend(**kwargs),
        plain.build_plain_transaction(keys=[KEYS[i] for i in key_indices], **kwargs),
    )


# ── the plan is the transaction ──────────────────────────────────────────────

@pytest.mark.parametrize("destination", [BECH32, sp_address()])
@pytest.mark.parametrize("amount,change_needed", [(40_000, True), (None, False)])
def test_plan_and_build_agree_on_the_money(destination, amount, change_needed):
    utxos = [utxo(0, "01" * 32, 0, 120_000)]
    p, b = both(utxos, amount, 2, destination, [0],
                change_addr() if change_needed else None)
    assert (p["amount"], p["fee"], p["change"], p["vsize"], p["total_input"]) == (
        b["amount"], b["fee"], b["change"], b["vsize"], b["total_input"]
    )
    assert (p["change"] > 0) is change_needed


def test_the_plans_input_order_is_the_transactions_input_order():
    """A signer that orders inputs differently signs a different transaction.

    Three coins across two addresses, deliberately given out of order.
    """
    utxos = [
        utxo(0, "03" * 32, 1, 90_000),
        utxo(1, "02" * 32, 0, 70_000),
        utxo(0, "04" * 32, 7, 60_000),
    ]
    p, b = both(utxos, 100_000, 4, BECH32, [0, 1], change_addr())
    assert [(u["txid"], u["vout"]) for u in p["utxos"]] == [
        ("02" * 32, 0), ("03" * 32, 1), ("04" * 32, 7)
    ]
    assert b["input_count"] == 3
    # The transaction's inputs, read back off the wire, in the plan's order.
    raw = bytes.fromhex(b["tx_hex"])
    at = 4 + 2 + 1  # version, marker+flag, input count (three fits in one byte)
    seen = []
    for _ in range(3):
        seen.append((raw[at:at + 32][::-1].hex(), int.from_bytes(raw[at + 32:at + 36], "little")))
        at += 32 + 4 + 1 + 4
    assert seen == [(u["txid"], u["vout"]) for u in p["utxos"]]


def test_a_silent_payment_destination_has_no_script_in_the_plan():
    """And an ordinary one always does.

    This is the whole reason the split works: the SP output key comes from the
    input PRIVATE keys, so the server cannot compute it and must not pretend to.
    Its size is fixed, so the fee is still the server's to quote.
    """
    utxos = [utxo(0, "01" * 32, 0, 120_000)]
    sp, _ = both(utxos, 40_000, 2, sp_address(), [0], change_addr())
    assert sp["is_silent_payment"] and sp["destination_script"] is None

    ordinary, _ = both(utxos, 40_000, 2, BECH32, [0], change_addr())
    assert not ordinary["is_silent_payment"]
    assert ordinary["destination_script"] == (
        "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    )


def test_the_change_script_matches_the_change_address():
    utxos = [utxo(0, "01" * 32, 0, 120_000)]
    p, _ = both(utxos, 40_000, 2, BECH32, [0], change_addr())
    from embit import script

    assert p["change_script"] == script.address_to_scriptpubkey(change_addr()).data.hex()
    assert p["change_address"] == change_addr()


def test_absorbed_change_leaves_no_change_address_to_pay():
    """Change under the dust floor goes to the miner, and the plan must say so
    rather than naming an address that gets nothing."""
    vsize = plain.math.ceil(
        plain.OVERHEAD_VBYTES + plain.INPUT_VBYTES + plain.OUTPUT_VBYTES
        + plain.CHANGE_VBYTES
    )
    fee = max(1, plain.math.ceil(vsize * 2))
    p, b = both([utxo(0, "01" * 32, 0, 100_000)], 100_000 - fee - 200, 2,
                sp_address(), [0], change_addr())
    assert p["change"] == 0
    assert p["change_address"] is None and p["change_script"] is None
    assert p["fee"] == fee + 200, "the absorbed remainder must go to the miner"
    assert p["vsize"] == vsize - plain.CHANGE_VBYTES
    assert b["change"] == 0 and b["fee"] == p["fee"]


# ── every refusal is the plan's, so a signing client hits it too ─────────────

def test_a_dust_amount_is_refused():
    utxos = [utxo(0, "01" * 32, 0, 120_000)]
    for amount in (1, 100, 330, DUST - 1):
        with pytest.raises(ValueError, match="at least"):
            plain.plan_plain_spend(BECH32, utxos, 1, "signet", amount, change_addr())


def test_more_than_the_coins_hold_is_refused():
    utxos = [utxo(0, "01" * 32, 0, 10_000)]
    with pytest.raises(ValueError, match="Not enough"):
        plain.plan_plain_spend(BECH32, utxos, 1, "signet", 50_000, change_addr())


def test_sweeping_dust_is_refused():
    """Send-everything on a coin too small to survive its own fee."""
    with pytest.raises(ValueError, match="dust limit"):
        plain.plan_plain_spend(BECH32, [utxo(0, "01" * 32, 0, 600)], 1, "signet", None)


def test_no_coins_is_refused():
    with pytest.raises(ValueError, match="No confirmed coins"):
        plain.plan_plain_spend(BECH32, [], 1, "signet", 10_000, change_addr())


def test_change_must_come_back_to_this_chain():
    """The one rule that stops a malformed request routing the remainder
    somewhere else. It has to live in the plan: a client that signs for itself
    never reaches the builder that used to enforce it."""
    utxos = [utxo(0, "01" * 32, 0, 120_000)]
    with pytest.raises(ValueError, match="native segwit"):
        plain.plan_plain_spend(BECH32, utxos, 1, "signet", 40_000, sp_address())
    with pytest.raises(ValueError, match="native segwit"):
        # A mainnet address on a signet wallet.
        plain.plan_plain_spend(
            BECH32, utxos, 1, "signet", 40_000,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        )
    with pytest.raises(ValueError, match="change address is required"):
        plain.plan_plain_spend(BECH32, utxos, 1, "signet", 40_000, None)


def test_an_unusable_destination_is_refused_before_anything_is_signed():
    utxos = [utxo(0, "01" * 32, 0, 120_000)]
    with pytest.raises(ValueError, match="Invalid destination"):
        plain.plan_plain_spend("not-an-address", utxos, 1, "signet", 40_000, change_addr())
    with pytest.raises(ValueError, match="destination is required"):
        plain.plan_plain_spend("   ", utxos, 1, "signet", 40_000, change_addr())


# ── sizing ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "destination,expected_out_vbytes",
    [
        (BECH32, 31),                                        # P2WPKH
        ("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", 34),           # P2PKH
        ("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc", 32),          # P2SH
        (sp_address(), 43),                                  # P2TR, undeliverable here
    ],
)
def test_the_destination_is_priced_by_its_real_output_size(destination, expected_out_vbytes):
    """A Silent Payments destination is priced without being derived — that is
    what lets the server quote a fee for an output only the client can build."""
    assert plain.destination_vbytes(destination) == expected_out_vbytes
    p = plain.plan_plain_spend(
        destination, [utxo(0, "01" * 32, 0, 500_000)], 1, "signet", 40_000, change_addr()
    )
    assert p["vsize"] == plain.math.ceil(
        plain.OVERHEAD_VBYTES + plain.INPUT_VBYTES + expected_out_vbytes
        + plain.CHANGE_VBYTES
    )


def test_the_quoted_vsize_is_close_to_the_real_one():
    """Never under, and over by less than a vbyte per input.

    68 vB per input assumes the largest signature grinding can leave (71 DER
    bytes plus the sighash byte); a shorter one makes the transaction smaller
    than quoted. Under-quoting would be the real bug — that is a fee below the
    rate the user picked.
    """
    for n in (1, 2, 3):
        utxos = [utxo(i % 3, f"{i + 1:02x}" * 32, i, 200_000) for i in range(n)]
        b = plain.build_plain_transaction(
            keys=KEYS, destination=BECH32, utxos=utxos, fee_rate=3,
            network="signet", amount=100_000, change_address=change_addr(),
        )
        raw = bytes.fromhex(b["tx_hex"])
        # Each P2WPKH witness is 1 item count + (1 + len sig) + (1 + 33) bytes.
        witness = 2 + sum(1 + 1 + s + 1 + 33 for s in _witness_sig_lens(raw, n))
        base = len(raw) - witness
        measured = -(-(base * 3 + len(raw)) // 4)
        assert b["vsize"] >= measured, f"{n} inputs: quoted under the real size"
        assert b["vsize"] - measured < n, f"{n} inputs: quoted {b['vsize'] - measured} vB over"


def _witness_sig_lens(raw: bytes, n_inputs: int) -> list[int]:
    """Signature lengths, read off the serialised witnesses."""
    at = 4 + 2
    at += 1  # input count
    at += n_inputs * (32 + 4 + 1 + 4)
    n_out = raw[at]
    at += 1
    for _ in range(n_out):
        at += 8
        at += 1 + raw[at]
    lens = []
    for _ in range(n_inputs):
        assert raw[at] == 2, "a P2WPKH witness is two items"
        at += 1
        lens.append(raw[at])
        at += 1 + raw[at]
        at += 1 + raw[at]
    return lens
