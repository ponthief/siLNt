"""
Generate cross-check vectors for client-side signing.

    python3 helpers/_client_signing_fixtures.py > fixtures/client-signing.json

Moving transaction building off the server means the spend key stops being sent
with every send — but it also means a second implementation of the part of this
codebase where a mistake is unrecoverable. src/services/spKeys.ts already took
that bet once for key derivation and settled it with server-generated vectors;
this is the same bet for the sending half, settled the same way.

WHAT IS COMPARED, AND WHY NOT tx_hex. coincurve's sign_schnorr defaults to
random auxiliary data, so two signatures over the same sighash differ and the
serialised transactions never match byte for byte. That is correct BIP-340
behaviour, not a problem to engineer around, so the vectors pin the
deterministic parts instead:

    recipient scriptPubKey     the output BIP-352 says the payment must go to
    change scriptPubKey        the m=0 labelled output the wallet must find later
    fee / change / vsize       the amounts
    unsigned tx serialisation  input order, sequence, output order, versions
    per-input sighash          BIP-341, SIGHASH_DEFAULT

A client that reproduces all five and whose signature verifies against the
sighash has produced a transaction the network and the receiver's scanner will
both accept. Comparing the signature bytes would test the RNG.

The cases cover what actually varies: one input and several, a Silent Payments
recipient and an ordinary bech32 one, change and no change (absorbed into the
fee), and both networks.
"""

from __future__ import annotations

import json
import sys
import types


def _bootstrap():
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    sys.path.insert(0, os.path.dirname(root))

    name = os.path.basename(root)
    pkg = types.ModuleType(name)
    pkg.__path__ = [root]
    sys.modules[name] = pkg

    class _Any(types.ModuleType):
        def __getattr__(self, attr):
            return None

    sys.modules[f"{name}.crud"] = _Any(f"{name}.crud")

    lnbits = types.ModuleType("lnbits")
    utils = types.ModuleType("lnbits.utils")
    crypto = types.ModuleType("lnbits.utils.crypto")

    class AESCipher:
        def __init__(self, key=None):
            pass

    crypto.AESCipher = AESCipher
    utils.crypto = crypto
    lnbits.utils = utils
    sys.modules.setdefault("lnbits", lnbits)
    sys.modules.setdefault("lnbits.utils", utils)
    sys.modules.setdefault("lnbits.utils.crypto", crypto)
    return name


PKG = _bootstrap()

import coincurve  # noqa: E402
from embit.psbt import PSBT  # noqa: E402
from embit.transaction import (  # noqa: E402
    Transaction,
    TransactionInput,
    TransactionOutput,
)

_w = __import__(f"{PKG}.helpers.wallet", fromlist=["*"])

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def utxo(spend_key_hex: str, tweak_hex: str, txid: str, vout: int, amount: int) -> dict:
    """A UTXO the wallet owns, in the shape the API takes.

    pub_key is what sits on chain, so it is derived here the way the scanner
    would have recorded it: b_spend + tweak, forced to even Y.
    """
    full = (
        int(spend_key_hex, 16) + int(tweak_hex, 16)
    ) % N
    if _w.pubkey_point_gen_from_int(full)[1] % 2 == 1:
        full = N - full
    pub = coincurve.PublicKey.from_secret(full.to_bytes(32, "big")).format()[1:]
    return {
        "txid": txid,
        "vout": vout,
        "amount": amount,
        "priv_key_tweak": tweak_hex,
        "pub_key": pub.hex(),
    }


def sp_address_for(scan_hex: str, spend_hex: str, network: str) -> str:
    return _w.encode_silent_payment_address(
        _w.pubkey_point_gen_from_int(int(scan_hex, 16)),
        _w.pubkey_point_gen_from_int(int(spend_hex, 16)),
        "sp" if network == "mainnet" else "tsp",
    )


def expected(case: dict) -> dict:
    """Run the production builder, and re-derive the intermediates it does not
    return. Deliberately calls the same private helpers the endpoint calls, so a
    refactor that changes behaviour changes these vectors too."""
    spend_key = _w.ec.PrivateKey(bytes.fromhex(case["spend_key"]))
    utxos = case["utxos"]

    input_keys, input_scripts = _w._prepare_inputs(spend_key, utxos)
    recipient_script = _w._derive_recipient_script(case["recipient"], spend_key, utxos)
    # The recipient's script sizes its output, exactly as build_transaction
    # passes it. Without this a P2WPKH recipient is priced as P2TR and the
    # vectors would enshrine a 12 vB overcharge.
    total_in, fee, change, vsize = _w._compute_amounts(
        utxos, case["amount"], case["fee_rate"], bytes(recipient_script.data)
    )
    change_script = _w._derive_change_script(
        change, case["scan_secret"], spend_key, utxos, case["network"]
    )
    tx_outputs = _w._assemble_outputs(
        case["amount"], recipient_script, change, change_script, case["recipient"]
    )

    # Rebuild the unsigned transaction exactly as _build_sign_finalize does,
    # stopping before the signatures, and capture each input's sighash.
    paired = [
        (TransactionInput(bytes.fromhex(u["txid"]), int(u.get("vout", 0))),
         input_scripts[i], u["amount"])
        for i, u in enumerate(utxos)
    ]
    paired.sort(key=lambda x: (x[0].txid.hex(), x[0].vout))
    tx = Transaction(vin=[p[0] for p in paired], vout=tx_outputs)
    psbt = PSBT(tx)
    for i, (_vin, spk, val) in enumerate(paired):
        psbt.inputs[i].witness_utxo = TransactionOutput(val, spk[0])

    amounts = [inp.witness_utxo.value for inp in psbt.inputs]
    scripts = [inp.witness_utxo.script_pubkey for inp in psbt.inputs]
    sighashes = [
        _w.taproot_sighash(tx, i, scripts, amounts, sighash_type=0).hex()
        for i in range(len(psbt.inputs))
    ]

    return {
        "recipient_spk": bytes(recipient_script.data).hex(),
        "change_spk": bytes(change_script.data).hex() if change_script else None,
        "total_input": total_in,
        "fee": fee,
        "change": change,
        "vsize": vsize,
        "unsigned_tx": tx.serialize().hex(),
        "input_order": [f"{p[0].txid.hex()}:{p[0].vout}" for p in paired],
        "sighashes": sighashes,
        "output_values": [o.value for o in tx_outputs],
        "output_scripts": [bytes(o.script_pubkey.data).hex() for o in tx_outputs],
    }


SPEND = "22" * 32
SCAN = "11" * 32
PAYEE_SPEND = "44" * 32
PAYEE_SCAN = "33" * 32


def cases() -> list[dict]:
    out = []

    sp_signet = sp_address_for(PAYEE_SCAN, PAYEE_SPEND, "signet")
    sp_main = sp_address_for(PAYEE_SCAN, PAYEE_SPEND, "mainnet")

    out.append({
        "name": "one input, SP recipient, with change",
        "network": "signet",
        "spend_key": SPEND, "scan_secret": SCAN,
        "recipient": sp_signet, "amount": 40_000, "fee_rate": 2,
        "utxos": [utxo(SPEND, "aa" * 32, "01" * 32, 0, 120_000)],
    })
    out.append({
        "name": "three inputs, SP recipient, with change",
        "network": "signet",
        "spend_key": SPEND, "scan_secret": SCAN,
        "recipient": sp_signet, "amount": 150_000, "fee_rate": 5,
        "utxos": [
            utxo(SPEND, "ab" * 32, "03" * 32, 1, 90_000),
            utxo(SPEND, "ac" * 32, "02" * 32, 0, 70_000),
            utxo(SPEND, "ad" * 32, "04" * 32, 7, 60_000),
        ],
    })
    out.append({
        "name": "mainnet, SP recipient",
        "network": "mainnet",
        "spend_key": SPEND, "scan_secret": SCAN,
        "recipient": sp_main, "amount": 250_000, "fee_rate": 12,
        "utxos": [utxo(SPEND, "ae" * 32, "05" * 32, 3, 1_000_000)],
    })
    out.append({
        "name": "ordinary bech32 recipient",
        "network": "signet",
        "spend_key": SPEND, "scan_secret": SCAN,
        "recipient": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "amount": 30_000, "fee_rate": 3,
        "utxos": [utxo(SPEND, "af" * 32, "06" * 32, 0, 100_000)],
    })

    # Change below the dust floor: absorbed into the fee, so the transaction has
    # one output and the change script is never derived. The arithmetic for this
    # lives in _compute_amounts and the client has to agree on it, or it builds
    # a transaction with an output the wallet will never find.
    from siLNt.helpers.txsize import TAPROOT_OUTPUT_VBYTES, estimate_vsize, fee_for
    fee_at_2 = fee_for(
        estimate_vsize(1, [TAPROOT_OUTPUT_VBYTES, TAPROOT_OUTPUT_VBYTES]), 2
    )
    out.append({
        "name": "dust change absorbed into the fee",
        "network": "signet",
        "spend_key": SPEND, "scan_secret": SCAN,
        "recipient": sp_signet,
        "amount": 100_000 - fee_at_2 - 200,
        "fee_rate": 2,
        "utxos": [utxo(SPEND, "b0" * 32, "07" * 32, 2, 100_000)],
    })

    for c in out:
        c["expected"] = expected(c)
    return out


if __name__ == "__main__":
    data = {
        "_comment": (
            "Generated by helpers/_client_signing_fixtures.py from the production "
            "builder in helpers/wallet.py. Regenerate after any change to the "
            "derivation, the fee formula or the output ordering. Signatures are "
            "NOT included: coincurve's sign_schnorr uses random aux data, so the "
            "client is checked by verifying its signature against the sighash "
            "below rather than by comparing signature bytes."
        ),
        "cases": cases(),
    }
    json.dump(data, sys.stdout, indent=2)
    sys.stdout.write("\n")
