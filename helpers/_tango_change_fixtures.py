#!/usr/bin/env python3
"""Vectors for the routed Tango change output, for the clients to verify against.

A user who gives a Lightning address has their round's change output pay the
INSTANCE's Silent Payments address. The clients cannot re-derive that script —
it needs the instance's scan key, which is the payee's — so instead the round
reveals t_k and each client checks

    script == OP_1 <x(B_spend + t_k·G)>

That check is the only thing standing between a coordinator and a change
output pointed anywhere, because a taproot key-path signature commits to every
output. So the two implementations have to agree exactly, and this is what
pins them.

    python3 helpers/_tango_change_fixtures.py > fixtures/tango-change-payout.json

Then, in thrilla:  npm run check:signing:change
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
_tc = __import__(f"{PKG}.helpers.tangochange", fromlist=["*"])

# The instance's payout wallet. A scan key and a spend key that are NOT
# related, so a verifier that confused the two would not accidentally pass.
INSTANCE_SCAN = "c1" * 32
INSTANCE_SPEND = "c2" * 32

# Two parties' coins, which is what a Tango's input set is. The derivation
# reads only the public side of these.
INPUTS = [
    {
        "txid": "11" * 32,
        "vout": 0,
        "amount": 60_000,
        "pub_key": coincurve.PrivateKey(bytes.fromhex("a1" * 32))
        .public_key.format(compressed=True)
        .hex()[2:],
    },
    {
        "txid": "22" * 32,
        "vout": 3,
        "amount": 40_000,
        "pub_key": coincurve.PrivateKey(bytes.fromhex("a2" * 32))
        .public_key.format(compressed=True)
        .hex()[2:],
    },
    {
        "txid": "33" * 32,
        "vout": 1,
        "amount": 55_000,
        "pub_key": coincurve.PrivateKey(bytes.fromhex("b1" * 32))
        .public_key.format(compressed=True)
        .hex()[2:],
    },
]


def sp_address(scan_hex: str, spend_hex: str, hrp: str = "sp") -> str:
    """encode_silent_payment_address takes POINTS, not compressed bytes."""
    scan = _w.pubkey_point_gen_from_int(int(scan_hex, 16))
    spend = _w.pubkey_point_gen_from_int(int(spend_hex, 16))
    return _w.encode_silent_payment_address(scan, spend, hrp=hrp)


def main() -> int:
    addr = sp_address(INSTANCE_SCAN, INSTANCE_SPEND)
    # PayjoinInput.pub_key is BYTES — the 32-byte x-only key as it sits on
    # chain — while the fixture carries hex for the client to read.
    inputs = [
        _pj.PayjoinInput(
            txid=i["txid"], vout=i["vout"], amount=i["amount"],
            pub_key=bytes.fromhex(i["pub_key"]),
        )
        for i in INPUTS
    ]

    cases = []
    for role in ("a", "b"):
        spk, tweak = _tc.derive_payout_output(
            addr, bytes.fromhex(INSTANCE_SCAN), inputs, role
        )
        cases.append({
            "role": role,
            "k": _tc.payout_k(role),
            "spk": spk.hex(),
            "tweak": tweak.hex(),
            # The verifier's answer on the real pair, which must be true.
            "verifies": _tc.verify_payout_output(addr, tweak, spk),
        })

    # The same output against the OTHER side's tweak must not verify: that is
    # the substitution the check exists to catch, and a verifier that ignored
    # the tweak would pass both.
    crossed = _tc.verify_payout_output(
        addr, bytes.fromhex(cases[1]["tweak"]), bytes.fromhex(cases[0]["spk"])
    )

    # A script paying somebody else entirely, which is the coordinator pointing
    # the change at itself.
    other = sp_address("d1" * 32, "d2" * 32)
    foreign_spk, foreign_tweak = _tc.derive_payout_output(
        other, bytes.fromhex("d1" * 32), inputs, "a"
    )

    # Whether a given scan key really belongs to a given address. Answered
    # here rather than in the test process, where conftest stubs
    # helpers/wallet.py and the real curve code cannot be imported.
    scan_key_match = {
        "right_pair": _tc.scan_key_matches(addr, INSTANCE_SCAN),
        "other_wallets_scan": _tc.scan_key_matches(addr, "d1" * 32),
        # The mistake most likely to be made at a config field with two hex
        # boxes on it.
        "the_spend_key_instead": _tc.scan_key_matches(addr, INSTANCE_SPEND),
        "not_hex": _tc.scan_key_matches(addr, "zz" * 32),
        "too_short": _tc.scan_key_matches(addr, "c1" * 31),
        "too_long": _tc.scan_key_matches(addr, "c1" * 33),
        "zero": _tc.scan_key_matches(addr, "00" * 32),
        "empty": _tc.scan_key_matches(addr, ""),
        "blank": _tc.scan_key_matches(addr, "   "),
        "junk_address": _tc.scan_key_matches("sp1nonsense", INSTANCE_SCAN),
        "empty_address": _tc.scan_key_matches("", INSTANCE_SCAN),
    }

    json.dump(
        {
            "sp_address": addr,
            "scan_secret": INSTANCE_SCAN,
            "inputs": INPUTS,
            "cases": cases,
            "negatives": {
                # Each of these must verify FALSE against sp_address.
                "crossed_tweak": crossed,
                "foreign_spk": foreign_spk.hex(),
                "foreign_tweak": foreign_tweak.hex(),
                "zero_tweak": "00" * 32,
                "short_tweak": "ab" * 31,
            },
            "scan_key_match": scan_key_match,
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
