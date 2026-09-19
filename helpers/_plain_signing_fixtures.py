"""
Generate cross-check vectors for client-side plain-chain signing.

    python3 helpers/_plain_signing_fixtures.py > fixtures/plain-signing.json

The sibling of _client_signing_fixtures.py, for the other spend path. Moving
the plain BIP-84 chain off /plain/spend stops whole private keys crossing the
network — each one enough on its own to empty the address it belongs to — at
the cost of a second implementation of code where a mistake is unrecoverable.
Same answer as before: vectors from the production builder.

WHAT IS COMPARED. Everything, including tx_hex. Unlike the Silent Payments
vectors — where coincurve's sign_schnorr uses random aux data and no two
signatures match — ECDSA here is RFC 6979, and embit's low-R grinding (retry
with the counter as 32-byte little-endian extra entropy until the DER fits in
70 bytes) is reproducible from the same inputs. So the client has to produce
the identical transaction, byte for byte, or it has a bug.

The cases cover what varies: one input and several, one address and several,
every destination type the sender can type (P2WPKH, P2TR, P2PKH, P2SH and an
sp1…), change and no change, send-everything, and both networks.
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

_p = __import__(f"{PKG}.helpers.plain", fromlist=["*"])
_w = __import__(f"{PKG}.helpers.wallet", fromlist=["*"])

# Four keys on the plain chain, standing in for four m/84'/…/0/i addresses.
KEYS = ["d1" * 32, "d2" * 32, "d3" * 32, "d4" * 32]


def sp_address_for(scan_hex: str, spend_hex: str, network: str) -> str:
    return _w.encode_silent_payment_address(
        _w.pubkey_point_gen_from_int(int(scan_hex, 16)),
        _w.pubkey_point_gen_from_int(int(spend_hex, 16)),
        "sp" if network == "mainnet" else "tsp",
    )


def utxo(key_index: int, txid: str, vout: int, amount: int, network: str) -> dict:
    """One coin, in the shape scan_addresses returns and the builder takes."""
    return {
        "address": _p.plain_address_for_key(KEYS[key_index], network),
        "txid": txid,
        "vout": vout,
        "amount": amount,
        "height": 100_000,
    }


def expected(case: dict) -> dict:
    """Plan it, then build it, with the production code in both halves."""
    plan = _p.plan_plain_spend(
        destination=case["destination"],
        utxos=case["utxos"],
        fee_rate=case["fee_rate"],
        network=case["network"],
        amount=case["amount"],
        change_address=case.get("change_address"),
    )
    built = _p.build_plain_transaction(
        keys=[KEYS[i] for i in case["key_indices"]],
        destination=case["destination"],
        utxos=case["utxos"],
        fee_rate=case["fee_rate"],
        network=case["network"],
        amount=case["amount"],
        change_address=case.get("change_address"),
    )
    return {
        "plan": {
            "destination": plan["destination"],
            "destination_script": plan["destination_script"],
            "is_silent_payment": plan["is_silent_payment"],
            "change_script": plan["change_script"],
            "input_order": [f"{u['txid']}:{u['vout']}" for u in plan["utxos"]],
        },
        "tx_hex": built["tx_hex"],
        "amount": built["amount"],
        "change": built["change"],
        "fee": built["fee"],
        "total_input": built["total_input"],
        "vsize": built["vsize"],
        "input_count": built["input_count"],
        "swept_addresses": built["swept_addresses"],
    }


def cases() -> list[dict]:
    out: list[dict] = []
    # Change always comes back to another address on this same chain.
    change_signet = _p.plain_address_for_key(KEYS[3], "signet")
    change_main = _p.plain_address_for_key(KEYS[3], "mainnet")

    out.append({
        "name": "one input, SP destination, with change",
        "network": "signet",
        "destination": sp_address_for("33" * 32, "44" * 32, "signet"),
        "amount": 40_000, "fee_rate": 2,
        "change_address": change_signet,
        "key_indices": [0],
        "utxos": [utxo(0, "01" * 32, 0, 120_000, "signet")],
    })
    out.append({
        "name": "two addresses, three inputs, bech32 destination",
        "network": "signet",
        "destination": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        "amount": 100_000, "fee_rate": 4,
        "change_address": change_signet,
        "key_indices": [0, 1],
        "utxos": [
            utxo(0, "03" * 32, 1, 90_000, "signet"),
            utxo(1, "02" * 32, 0, 70_000, "signet"),
            utxo(0, "04" * 32, 7, 60_000, "signet"),
        ],
    })
    out.append({
        "name": "send everything, no change output",
        "network": "signet",
        "destination": sp_address_for("33" * 32, "44" * 32, "signet"),
        "amount": None, "fee_rate": 3,
        "key_indices": [0, 1],
        "utxos": [
            utxo(0, "05" * 32, 0, 50_000, "signet"),
            utxo(1, "06" * 32, 2, 25_000, "signet"),
        ],
    })
    out.append({
        "name": "P2TR destination, mainnet",
        "network": "mainnet",
        "destination": "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "amount": 250_000, "fee_rate": 12,
        "change_address": change_main,
        "key_indices": [2],
        "utxos": [utxo(2, "07" * 32, 3, 1_000_000, "mainnet")],
    })
    out.append({
        "name": "P2PKH destination, base58",
        "network": "signet",
        "destination": "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        "amount": 30_000, "fee_rate": 1.5,
        "change_address": change_signet,
        "key_indices": [1],
        "utxos": [utxo(1, "08" * 32, 0, 100_000, "signet")],
    })
    out.append({
        "name": "P2SH destination, base58",
        "network": "signet",
        "destination": "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc",
        "amount": 30_000, "fee_rate": 7,
        "change_address": change_signet,
        "key_indices": [1],
        "utxos": [utxo(1, "09" * 32, 1, 100_000, "signet")],
    })

    # Change under the dust floor is absorbed into the fee, and the transaction
    # is then one output smaller than it was priced at. The client has to agree
    # on this or it signs a different transaction.
    total = 100_000
    vsize_two_out = _p.math.ceil(
        _p.OVERHEAD_VBYTES + _p.INPUT_VBYTES + _p.OUTPUT_VBYTES + _p.CHANGE_VBYTES
    )
    fee_at_2 = max(1, _p.math.ceil(vsize_two_out * 2))
    out.append({
        "name": "dust change absorbed into the fee",
        "network": "signet",
        "destination": sp_address_for("33" * 32, "44" * 32, "signet"),
        "amount": total - fee_at_2 - 200,
        "fee_rate": 2,
        "change_address": change_signet,
        "key_indices": [2],
        "utxos": [utxo(2, "0a" * 32, 2, total, "signet")],
    })

    for c in out:
        c["expected"] = expected(c)
        c["keys"] = {
            _p.plain_address_for_key(KEYS[i], c["network"]): KEYS[i]
            for i in c["key_indices"]
        }
    return out


if __name__ == "__main__":
    data = {
        "_comment": (
            "Generated by helpers/_plain_signing_fixtures.py from the production "
            "builder in helpers/plain.py. Regenerate after any change to the fee "
            "formula, the output ordering or the signing. tx_hex IS compared: "
            "ECDSA here is RFC 6979 with low-R grinding, so the client must "
            "produce the identical transaction byte for byte."
        ),
        "cases": cases(),
    }
    json.dump(data, sys.stdout, indent=2)
    sys.stdout.write("\n")
