"""
Generate cross-check vectors for client-side SP PayJoin derivation.

    python3 helpers/_payjoin_sp_fixtures.py > fixtures/payjoin-sp.json

Same bet, and settled the same way, as fixtures/client-signing.json and
fixtures/plain-signing.json: the client has a second implementation of a
derivation where a mistake is unrecoverable, so it is held to this one.

WHY IT MATTERS MORE HERE THAN FOR AN ORDINARY SEND. In a normal send the
sender derives the recipient's output and a mistake makes a transaction the
recipient's scanner cannot find — bad, but one party's bug. In a PayJoin the
two parties derive different outputs of the SAME transaction from the SAME
frozen input set, and each signs over both. If the client's input_hash or A_sum
disagrees with the server's by one byte, the two sides produce outputs that
belong to nobody, the signatures still verify, and the transaction is accepted
by the network. Detected-and-unspendable, for both parties at once, with no
error anywhere. That is the failure these vectors exist to make impossible.

WHAT IS COMPARED. Everything deterministic, which here is everything except
the signatures:

    a_sum / input_hash    the shared input digest both parties must agree on
    payment_spk           the payee's output, from the payee's scan key
    change_spk            the payer's m=0 labelled change
    plan amounts          payment, change, fee, vsize
    unsigned_tx           canonical input order, BIP-69 outputs, versions
    sighashes             BIP-341, SIGHASH_DEFAULT, one per input

Signatures are not compared, for the reason given in _client_signing_fixtures:
coincurve's sign_schnorr uses random auxiliary data per BIP-340, so two
signatures over one sighash differ. The client is checked by verifying its
signature against the sighash instead.

The secrets in here are fixed test values. They are also the only place in this
repo where a scan key and a spend key sit next to a PayJoin — the flow itself
never has both, by construction.
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

_w = __import__(f"{PKG}.helpers.wallet", fromlist=["*"])
_pj = __import__(f"{PKG}.helpers.payjoin_sp", fromlist=["*"])

N = _pj.SECP256K1_N

# Two parties. Distinct scan and spend keys each, because a bug that used one
# party's scan key for the other's output would still produce a valid-looking
# script if the four values were related.
PAYER_SCAN = "a1" * 32
PAYER_SPEND = "a2" * 32
PAYEE_SCAN = "b1" * 32
PAYEE_SPEND = "b2" * 32


def spend_pub(spend_hex: str) -> str:
    return coincurve.PrivateKey(bytes.fromhex(spend_hex)).public_key.format(
        compressed=True
    ).hex()


def label_pub(scan_hex: str, m: int = 0) -> str:
    """The m-th label's public key, B_m - B_spend = TaggedHash(...)·G.

    change_script takes this as a point to add, rather than an address to
    parse, so it is emitted separately. m=0 is BIP-352's reserved change label.
    """
    tweak = int.from_bytes(
        _w.tagged_hash("BIP0352/Label", bytes.fromhex(scan_hex) + m.to_bytes(4, "big")),
        "big",
    ) % N
    return coincurve.PublicKey.from_secret(tweak.to_bytes(32, "big")).format(
        compressed=True
    ).hex()


def txid_for(seed: int) -> str:
    """A txid that is NOT its own reverse.

    This matters more than it looks. The fixtures used bytes([n]).hex() * 32 —
    "ee" thirty-two times — and a string of one repeated byte is identical to
    its own reversal. So every check here passed while helpers/payjoin_sp.py
    was writing txids to the wire backwards: the transaction was wrong, the
    sighashes were wrong, and nothing could see it. Real txids are not
    palindromes, and neither are these.
    """
    return (f"{seed:02x}" + "11" * 30 + f"{(seed ^ 0xFF):02x}")


def utxo(spend_hex: str, tweak_hex: str, txid: str, vout: int, amount: int) -> dict:
    """One party's coin, in the shape the wire uses plus the tweak its owner
    holds. pub_key is derived the way the scanner recorded it: b_spend + tweak,
    forced to even Y, which is how a taproot key sits on chain."""
    full = (int(spend_hex, 16) + int(tweak_hex, 16)) % N
    if _w.pubkey_point_gen_from_int(full)[1] % 2 == 1:
        full = N - full
    pub = coincurve.PublicKey.from_secret(full.to_bytes(32, "big")).format()[1:]
    return {
        "txid": txid,
        "vout": vout,
        "amount": amount,
        "pub_key": pub.hex(),
        "priv_key_tweak": tweak_hex,
    }


def _inputs(rows: list):
    return [
        _pj.PayjoinInput(
            txid=r["txid"],
            vout=r["vout"],
            amount=r["amount"],
            pub_key=bytes.fromhex(r["pub_key"]),
        )
        for r in rows
    ]


def expected(case: dict) -> dict:
    """Run the production functions. The payee's and the payer's derivations
    are called here with both parties' secrets in one process, which no real
    PayJoin ever has — that is what makes this a cross-check rather than a
    second copy of the protocol."""
    payer_rows = case["payer"]["inputs"]
    payee_rows = case["payee"]["inputs"]
    payer_in = _inputs(payer_rows)
    payee_in = _inputs(payee_rows)
    all_in = payer_in + payee_in

    a_sum, input_hash = _pj.input_digest(all_in)
    amounts = _pj.plan(payer_in, payee_in, case["amount"], case["fee_rate"])

    payment_spk = _pj.payment_script(
        bytes.fromhex(case["payee"]["scan_secret"]),
        bytes.fromhex(spend_pub(case["payee"]["spend_secret"])),
        all_in,
    )
    change_spk = None
    if amounts["change"]:
        change_spk = _pj.change_script(
            bytes.fromhex(case["payer"]["scan_secret"]),
            bytes.fromhex(spend_pub(case["payer"]["spend_secret"])),
            bytes.fromhex(label_pub(case["payer"]["scan_secret"], 0)),
            all_in,
        )

    tx = _pj.assemble(all_in, amounts, payment_spk, change_spk)
    digests = _pj.sighashes(tx, all_in)
    ordered = _pj.canonical(all_in)

    return {
        # A_sum is emitted compressed, the form input_hash is computed over —
        # so a client that agrees on the bytes agrees on the parity too, which
        # is the half of this that silently produces unspendable outputs.
        "a_sum": (bytes([0x02 + (a_sum[1] % 2)]) + _w.ser256(a_sum[0])).hex(),
        "input_hash": input_hash.to_bytes(32, "big").hex(),
        "payment_spk": payment_spk.hex(),
        "change_spk": change_spk.hex() if change_spk else None,
        "payer_in": amounts["payer_in"],
        "payee_in": amounts["payee_in"],
        "payment": amounts["payment"],
        "change": amounts["change"],
        "fee": amounts["fee"],
        "vsize": amounts["vsize"],
        "input_order": [f"{i.txid}:{i.vout}" for i in ordered],
        "unsigned_tx": tx.serialize().hex(),
        "sighashes": [d.hex() for d in digests],
        "output_values": [o.value for o in tx.vout],
        "output_scripts": [bytes(o.script_pubkey.data).hex() for o in tx.vout],
        # Which positions each party signs. A client that got this wrong would
        # sign the counterparty's input and its own not at all.
        "payer_indices": sorted(_pj.owner_indices(all_in, payer_in)),
        "payee_indices": sorted(_pj.owner_indices(all_in, payee_in)),
    }


def party(scan: str, spend: str, rows: list) -> dict:
    return {
        "scan_secret": scan,
        "spend_secret": spend,
        "spend_pub": spend_pub(spend),
        "label_pub_0": label_pub(scan, 0),
        "inputs": rows,
    }


def cases() -> list:
    out = []

    # One each. The payee's txid sorts BEFORE the payer's, so canonical order
    # is not submission order — a client that kept its own order is caught.
    out.append({
        "name": "one input each, change",
        "network": "signet",
        "amount": 100_000,
        "fee_rate": 2,
        "payer": party(PAYER_SCAN, PAYER_SPEND, [
            utxo(PAYER_SPEND, "c0" * 32, txid_for(0xee), 1, 250_000),
        ]),
        "payee": party(PAYEE_SCAN, PAYEE_SPEND, [
            utxo(PAYEE_SPEND, "d0" * 32, txid_for(0x11), 0, 60_000),
        ]),
    })

    # Several on each side: A_sum is a sum, so an ordering or parity mistake in
    # the accumulation only shows up past two points.
    out.append({
        "name": "two payer inputs, two payee inputs, change",
        "network": "mainnet",
        "amount": 150_000,
        "fee_rate": 5,
        "payer": party(PAYER_SCAN, PAYER_SPEND, [
            utxo(PAYER_SPEND, "c1" * 32, txid_for(0xaa), 0, 120_000),
            utxo(PAYER_SPEND, "c2" * 32, txid_for(0x22), 3, 140_000),
        ]),
        "payee": party(PAYEE_SCAN, PAYEE_SPEND, [
            utxo(PAYEE_SPEND, "d1" * 32, txid_for(0x33), 1, 40_000),
            utxo(PAYEE_SPEND, "d2" * 32, txid_for(0xbb), 2, 25_000),
        ]),
    })

    # Change below dust: absorbed into the fee, one output, and no change
    # script is derived at all. 250_000 in, fee at 2 sat/vB for 2-in-1-out.
    payer_in = 250_000
    fee_1out = _pj.estimate_fee(2, 1, 2)[1]
    out.append({
        "name": "dust change absorbed into the fee",
        "network": "signet",
        "amount": payer_in - fee_1out - 100,
        "fee_rate": 2,
        "payer": party(PAYER_SCAN, PAYER_SPEND, [
            utxo(PAYER_SPEND, "c3" * 32, txid_for(0xc3), 7, payer_in),
        ]),
        "payee": party(PAYEE_SCAN, PAYEE_SPEND, [
            utxo(PAYEE_SPEND, "d3" * 32, txid_for(0x44), 0, 30_000),
        ]),
    })

    # A high input count, to price the vsize formula past the small cases.
    out.append({
        "name": "three payer inputs, one payee input",
        "network": "signet",
        "amount": 200_000,
        "fee_rate": 11,
        "payer": party(PAYER_SCAN, PAYER_SPEND, [
            utxo(PAYER_SPEND, "c4" * 32, txid_for(0x55), 0, 90_000),
            utxo(PAYER_SPEND, "c5" * 32, txid_for(0x66), 1, 95_000),
            utxo(PAYER_SPEND, "c6" * 32, txid_for(0x77), 2, 100_000),
        ]),
        "payee": party(PAYEE_SCAN, PAYEE_SPEND, [
            utxo(PAYEE_SPEND, "d4" * 32, txid_for(0x88), 4, 70_000),
        ]),
    })

    for c in out:
        c["expected"] = expected(c)
    return out


if __name__ == "__main__":
    data = {
        "_comment": (
            "Generated by helpers/_payjoin_sp_fixtures.py from the production "
            "functions in helpers/payjoin_sp.py. Regenerate after any change to "
            "the derivation, the fee formula, the input ordering or the output "
            "ordering. Signatures are NOT included: coincurve's sign_schnorr "
            "uses random aux data per BIP-340, so the client is checked by "
            "verifying its signature against the sighash below."
        ),
        "cases": cases(),
    }
    json.dump(data, sys.stdout, indent=2)
    sys.stdout.write("\n")
