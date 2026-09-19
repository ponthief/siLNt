"""Are the sizes in helpers/txsize.py the sizes transactions actually are?

The whole point of that module is that the fee matches the rate the user chose,
so checking its arithmetic against more arithmetic would prove nothing. These
build real transactions with the production builder, serialise them, and
measure.

The bug this exists to prevent: the Silent Payments builder priced every output
at 31 vB, which is a P2WPKH output, when every output it creates is P2TR at 43.
A two-output send was 25 vB short and paid about 16% under the chosen rate.
Nothing was lost — the transaction simply missed the block target it paid for.
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
    name = f"{PKG}.helpers._{module}_for_size_tests"
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


txsize = _load("txsize")
wallet = _load("wallet")
sys.modules[f"{PKG}.helpers.wallet"] = wallet

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SPEND = "22" * 32
SCAN = "11" * 32


def _utxo(tweak: str, txid: str, vout: int, amount: int) -> dict:
    full = (int(SPEND, 16) + int(tweak, 16)) % N
    if wallet.pubkey_point_gen_from_int(full)[1] % 2 == 1:
        full = N - full
    import coincurve

    pub = coincurve.PublicKey.from_secret(full.to_bytes(32, "big")).format()[1:]
    return {"txid": txid, "vout": vout, "amount": amount,
            "priv_key_tweak": tweak, "pub_key": pub.hex()}


def _sp_address(network="signet") -> str:
    return wallet.encode_silent_payment_address(
        wallet.pubkey_point_gen_from_int(int("33" * 32, 16)),
        wallet.pubkey_point_gen_from_int(int("44" * 32, 16)),
        "sp" if network == "mainnet" else "tsp",
    )


def measured_vsize(tx_hex: str, n_inputs: int) -> int:
    """vsize from the bytes: (base*3 + total)/4, rounded up.

    Every input here is P2TR key-path, so each witness is exactly 66 bytes —
    1 item count, 1 length, 64 signature — and the marker and flag are 2 more.
    """
    raw = bytes.fromhex(tx_hex)
    witness = 2 + n_inputs * 66
    base = len(raw) - witness
    return -(-(base * 3 + len(raw)) // 4)


def _build(utxos: list[dict], amount: int, fee_rate: float, recipient: str):
    return wallet.build_transaction(
        spend_key_hex=SPEND, scan_secret_hex=SCAN, recipient=recipient,
        amount=amount, fee_rate=fee_rate, utxos=utxos, network="signet",
    )


# ── the quoted size is the real size ─────────────────────────────────────────

@pytest.mark.parametrize("n_inputs", [1, 2, 3, 5])
def test_quoted_vsize_matches_the_serialised_transaction(n_inputs):
    utxos = [
        _utxo(f"{i + 0xa0:02x}" * 32, f"{i + 1:02x}" * 32, i, 200_000)
        for i in range(n_inputs)
    ]
    built = _build(utxos, 150_000, 3, _sp_address())
    assert built["vsize"] == measured_vsize(built["tx_hex"], n_inputs), (
        f"{n_inputs} inputs: quoted {built['vsize']}, actually "
        f"{measured_vsize(built['tx_hex'], n_inputs)}"
    )


@pytest.mark.parametrize("fee_rate", [1, 2, 5, 12, 50])
def test_the_fee_is_the_rate_that_was_asked_for(fee_rate):
    """The bug, stated as the thing a user would notice.

    Pick 12 sat/vB and the transaction should pay 12 sat/vB. Under the old
    formula it paid about 10.
    """
    utxos = [_utxo("aa" * 32, "01" * 32, 0, 5_000_000)]
    built = _build(utxos, 1_000_000, fee_rate, _sp_address())
    actual = measured_vsize(built["tx_hex"], 1)
    assert built["fee"] == -(-(actual * fee_rate) // 1), (
        f"asked {fee_rate} sat/vB, paid {built['fee'] / actual:.2f}"
    )


def test_a_p2wpkh_recipient_is_not_charged_as_taproot():
    """An ordinary bech32 output is 31 vB, not 43. Charging the larger figure
    would be the same mistake in the other direction."""
    utxos = [_utxo("ab" * 32, "02" * 32, 0, 500_000)]
    to_wpkh = _build(utxos, 100_000, 4, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
    to_sp = _build(utxos, 100_000, 4, _sp_address())
    assert to_wpkh["vsize"] == measured_vsize(to_wpkh["tx_hex"], 1)
    assert to_sp["vsize"] - to_wpkh["vsize"] == 12, (
        "a P2TR output is exactly 12 vB more than a P2WPKH one"
    )


def test_absorbed_change_reports_the_one_output_size():
    """When dust change goes to the miner the transaction really is smaller,
    and the quoted vsize should say so rather than describe the two-output
    transaction that was priced."""
    one_output = txsize.estimate_vsize(1, [txsize.TAPROOT_OUTPUT_VBYTES])
    two_outputs = txsize.estimate_vsize(1, [txsize.TAPROOT_OUTPUT_VBYTES] * 2)
    fee = txsize.fee_for(two_outputs, 2)
    total = 100_000
    built = _build([_utxo("ac" * 32, "03" * 32, 0, total)], total - fee - 200, 2, _sp_address())
    assert built["change"] == 0
    assert built["vsize"] == one_output
    assert built["vsize"] == measured_vsize(built["tx_hex"], 1)
    assert built["vsize"] < two_outputs


# ── the constants themselves ─────────────────────────────────────────────────

def test_output_sizes_are_eight_plus_one_plus_the_script():
    for script_len, expected in ((22, 31), (23, 32), (25, 34), (34, 43)):
        assert txsize.output_vbytes(bytes(script_len)) == expected == 8 + 1 + script_len


def test_an_unknown_script_length_is_sized_not_guessed():
    assert txsize.output_vbytes(bytes(80)) == 8 + 1 + 80


def test_vsize_is_rounded_up():
    """57.5 vB per input and 10.5 of overhead make odd input counts fractional.
    Rounding down is how a transaction ends up a satoshi under its rate."""
    odd = txsize.estimate_vsize(1, [txsize.TAPROOT_OUTPUT_VBYTES])
    assert odd == 111 and float(odd).is_integer()
    assert txsize.estimate_vsize(2, [31]) == 157   # 10.5 + 115 + 31 = 156.5 -> 157
    assert txsize.fee_for(111, 0.5) == 56          # 55.5 rounds up


def test_a_fee_is_never_zero():
    assert txsize.fee_for(1, 0.0001) == 1


def test_plain_py_agrees_with_the_shared_module():
    """plain.py had these right all along and is where they came from. If the
    two ever disagree, one spend path prices differently from the other."""
    plain = _load("plain")
    assert plain.OVERHEAD_VBYTES == txsize.OVERHEAD_VBYTES
    assert plain.OUTPUT_VBYTES == txsize.TAPROOT_OUTPUT_VBYTES
    assert plain.INPUT_VBYTES == txsize.P2WPKH_INPUT_VBYTES
    for n in (22, 23, 25, 34, 80):
        assert plain.output_vbytes(bytes(n)) == txsize.output_vbytes(bytes(n))
