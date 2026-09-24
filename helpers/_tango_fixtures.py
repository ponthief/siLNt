"""
Generate cross-check vectors for Tango, the two-party equal-output mix.

    python3 helpers/_tango_fixtures.py > fixtures/tango.json

Same bet as the other three generators, and one extra reason here: Tango's
whole claim is that both mixed outputs are the same. A client whose amounts
drift by one satoshi does not produce a weaker mix — it produces two outputs
an observer can tell apart, which is a PayJoin with nobody being paid, sold as
privacy.

TXIDS ARE NOT PALINDROMES. The PayJoin fixtures used one byte repeated 32
times, which reads the same backwards, and that hid a real byte-order bug
through 200 passing tests until a live transaction failed. Every txid here
differs from its own reverse.

What is compared: the plan (denomination, both changes, both fee shares,
vsize, and `clean`), the four derived scripts, the unsigned transaction,
and every sighash. Not the signatures — BIP-340 uses random aux data, so the
client is checked by verifying its signature against the sighash instead.
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
_t = __import__(f"{PKG}.helpers.tango", fromlist=["*"])

N = _pj.SECP256K1_N

A_SCAN, A_SPEND = "11" * 32, "12" * 32
B_SCAN, B_SPEND = "21" * 32, "22" * 32


def txid_for(seed: int) -> str:
    """Not its own reverse. See the note at the top of this file."""
    return f"{seed:02x}" + "11" * 30 + f"{(seed ^ 0xFF):02x}"


def spend_pub(spend_hex: str) -> str:
    return coincurve.PrivateKey(bytes.fromhex(spend_hex)).public_key.format(
        compressed=True
    ).hex()


def label_pub(scan_hex: str, m: int = 0) -> str:
    tweak = int.from_bytes(
        _w.tagged_hash("BIP0352/Label", bytes.fromhex(scan_hex) + m.to_bytes(4, "big")),
        "big",
    ) % N
    return coincurve.PublicKey.from_secret(tweak.to_bytes(32, "big")).format(
        compressed=True
    ).hex()


def utxo(spend_hex: str, tweak_hex: str, seed: int, vout: int, amount: int) -> dict:
    full = (int(spend_hex, 16) + int(tweak_hex, 16)) % N
    if _w.pubkey_point_gen_from_int(full)[1] % 2 == 1:
        full = N - full
    pub = coincurve.PublicKey.from_secret(full.to_bytes(32, "big")).format()[1:]
    return {
        "txid": txid_for(seed),
        "vout": vout,
        "amount": amount,
        "pub_key": pub.hex(),
        "priv_key_tweak": tweak_hex,
    }


def _inputs(rows: list):
    return [
        _pj.PayjoinInput(txid=r["txid"], vout=r["vout"], amount=r["amount"],
                         pub_key=bytes.fromhex(r["pub_key"]))
        for r in rows
    ]


def expected(case: dict) -> dict:
    a_rows, b_rows = case["a"]["inputs"], case["b"]["inputs"]
    a_in, b_in = _inputs(a_rows), _inputs(b_rows)
    all_in = a_in + b_in
    amounts = _t.plan(a_in, b_in, case["denom"], case["fee_rate"])

    a_mix = _t.payment_script(bytes.fromhex(A_SCAN),
                              bytes.fromhex(spend_pub(A_SPEND)), all_in)
    b_mix = _t.payment_script(bytes.fromhex(B_SCAN),
                              bytes.fromhex(spend_pub(B_SPEND)), all_in)
    a_chg = _t.change_script(bytes.fromhex(A_SCAN), bytes.fromhex(spend_pub(A_SPEND)),
                             bytes.fromhex(label_pub(A_SCAN)), all_in) \
        if amounts["a_change"] else None
    b_chg = _t.change_script(bytes.fromhex(B_SCAN), bytes.fromhex(spend_pub(B_SPEND)),
                             bytes.fromhex(label_pub(B_SCAN)), all_in) \
        if amounts["b_change"] else None

    tx = _t.assemble(all_in, amounts, a_mix, b_mix, a_chg, b_chg)
    digests = _t.sighashes(tx, all_in)
    ordered = _pj.canonical(all_in)

    return {
        **{k: amounts[k] for k in ("denom", "a_in", "b_in", "a_change",
                                   "b_change", "a_fee", "b_fee", "fee",
                                   "vsize", "clean")},
        "a_mix_spk": a_mix.hex(),
        "b_mix_spk": b_mix.hex(),
        "a_change_spk": a_chg.hex() if a_chg else None,
        "b_change_spk": b_chg.hex() if b_chg else None,
        "input_order": [f"{i.txid}:{i.vout}" for i in ordered],
        "unsigned_tx": tx.serialize().hex(),
        "sighashes": [d.hex() for d in digests],
        "output_values": [o.value for o in tx.vout],
        "output_scripts": [bytes(o.script_pubkey.data).hex() for o in tx.vout],
        "a_indices": sorted(_pj.owner_indices(all_in, a_in)),
        "b_indices": sorted(_pj.owner_indices(all_in, b_in)),
    }


def side(scan: str, spend: str, rows: list) -> dict:
    return {"scan_secret": scan, "spend_secret": spend,
            "spend_pub": spend_pub(spend), "label_pub_0": label_pub(scan),
            "inputs": rows}


def cases() -> list:
    out = []

    # Both sides with change: the ordinary case, and the weaker one.
    out.append({
        "name": "one coin each, both with change",
        "denom": 25_000, "fee_rate": 2,
        "a": side(A_SCAN, A_SPEND, [utxo(A_SPEND, "c0" * 32, 0xA1, 1, 400_000)]),
        "b": side(B_SCAN, B_SPEND, [utxo(B_SPEND, "d0" * 32, 0xB1, 0, 300_000)]),
    })

    # A clean round: neither side has change. Two inputs, two identical
    # outputs, nothing for an observer to solve. The shape Tango is for.
    rough = _t.plan(_inputs([utxo(A_SPEND, "c1" * 32, 0xA2, 0, 400_000)]),
                    _inputs([utxo(B_SPEND, "d1" * 32, 0xB2, 0, 400_000)]),
                    25_000, 2)
    out.append({
        "name": "clean: no change on either side",
        "denom": 25_000, "fee_rate": 2,
        "a": side(A_SCAN, A_SPEND,
                  [utxo(A_SPEND, "c1" * 32, 0xA2, 0, 25_000 + rough["a_fee"])]),
        "b": side(B_SCAN, B_SPEND,
                  [utxo(B_SPEND, "d1" * 32, 0xB2, 0, 25_000 + rough["b_fee"])]),
    })

    # Several coins a side: A_sum is a sum, so an ordering or parity mistake in
    # the accumulation only shows past two points.
    out.append({
        "name": "two coins each",
        "denom": 50_000, "fee_rate": 7,
        "a": side(A_SCAN, A_SPEND, [
            utxo(A_SPEND, "c2" * 32, 0xA3, 0, 60_000),
            utxo(A_SPEND, "c3" * 32, 0xA4, 2, 70_000),
        ]),
        "b": side(B_SCAN, B_SPEND, [
            utxo(B_SPEND, "d2" * 32, 0xB3, 1, 55_000),
            utxo(B_SPEND, "d3" * 32, 0xB4, 3, 80_000),
        ]),
    })

    # One side's change is dust and is absorbed; the other's is real. Three
    # outputs, and an uneven fee split that is not the odd-satoshi rule.
    r2 = _t.plan(_inputs([utxo(A_SPEND, "c4" * 32, 0xA5, 0, 400_000)]),
                 _inputs([utxo(B_SPEND, "d4" * 32, 0xB5, 0, 400_000)]),
                 25_000, 3)
    out.append({
        "name": "one side's change is dust and is absorbed",
        "denom": 25_000, "fee_rate": 3,
        "a": side(A_SCAN, A_SPEND,
                  [utxo(A_SPEND, "c4" * 32, 0xA5, 0, 25_000 + r2["a_fee"] + 200)]),
        "b": side(B_SCAN, B_SPEND, [utxo(B_SPEND, "d4" * 32, 0xB5, 0, 400_000)]),
    })

    for c in out:
        c["expected"] = expected(c)
    return out


def labels() -> dict:
    """The coin labels, and the selections a client must refuse.

    Here for the same reason the amounts are: the clients re-implement this,
    and a prefix that drifted by one character would stop refusing anything
    while every other test still passed.
    """
    return {
        "mix": _t.mix_label("alice"),
        "change": _t.change_label("alice"),
        "bare_mix": _t.mix_label(None),
        "bare_change": _t.change_label(""),
        "dated_mix": _t.mix_label("alice", "2026-09-24"),
        "dated_change": _t.change_label("alice", "2026-10-01"),
        "marker_only": _t.mix_label("", "2026-09-24"),
        "date_from_timestamp": _t.change_label("alice", "2026-09-24T13:05:00Z"),
        "cases": [
            {"labels": ls, "undoes": _t.undoes_a_round(ls)}
            for ls in (
                # A share with change: refused, whoever each was with and
                # whenever it happened. The change carries an attribution the
                # share exists to be free of.
                ["Tango mix - alice", "Tango change - alice"],
                ["Tango mix - alice", "Tango change - alice", "rent"],
                ["Tango mix - alice", "Tango change - bob"],
                # The date marker, and the round-id tag it replaced: coins
                # carrying the old one are still in wallets.
                ["Tango mix - alice · 2026-09-24",
                 "Tango change - alice · 2026-10-01"],
                ["Tango mix - alice #7c2e", "Tango change - alice #3f9a"],
                ["Tango mix · 2026-09-24", "Tango change"],
                ["Tango mix #7c2e", "Tango change"],
                ["Tango mix", "Tango change · 2026-09-24"],
                ["Tango mix - alice", "Tango mix - bob", "Tango change - carol"],
                # Not this failure.
                ["Tango mix - alice", "Tango mix - bob"],
                ["Tango mix - alice · 2026-09-24",
                 "Tango mix - alice · 2026-10-01"],
                ["Tango change - alice", "Tango change - bob"],
                # The user's own words, not ours.
                ["my Tango mix - alice", "Tango change - alice"],
                ["Tango mixer fund", "Tango change - alice"],
                ["Tango mix money for alice", "Tango change - alice"],
                ["salary", "Tango", ""],
                [],
            )
        ],
    }


if __name__ == "__main__":
    data = {
        "_comment": (
            "Generated by helpers/_tango_fixtures.py from helpers/tango.py. "
            "Regenerate after any change to the amounts, the output ordering "
            "or the derivation. Signatures are NOT included: BIP-340 uses "
            "random aux data, so the client is checked by verifying its "
            "signature against the sighash below. No txid here is its own "
            "reverse -- palindromic txids hid a byte-order bug once already."
        ),
        "cases": cases(),
        "labels": labels(),
    }
    json.dump(data, sys.stdout, indent=2)
    sys.stdout.write("\n")
