#!/usr/bin/env python3
"""The chain guard's verdicts, for the clients to be held to.

helpers/chains.py is the authority: the server refuses a cross-chain recipient
whatever the client thinks. The clients mirror it so the refusal arrives while
the address is being typed rather than at Build — and a mirror of a rule is a
second copy of it, which is the thing this repo keeps pinning to fixtures
rather than to good intentions.

    python3 helpers/_chain_guard_fixtures.py > fixtures/chain-guard.json

Then, in thrilla:  npm run check:signing:chains
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys


def _chains():
    """Loaded by path: helpers/chains.py imports nothing, and importing it as
    part of the package would drag in LNbits."""
    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("chains", here / "chains.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Every address family the guard knows, and the ones it deliberately does not.
ADDRESSES = [
    # mainnet
    "sp1qqw508d6qejxtdg4y5r3zarvary0c5xw7k",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    # testnet / signet
    "tsp1qqw508d6qejxtdg4y5r3zarvary0c5xw7k",
    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    "tb1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rus5ss4wd",
    "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
    "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
    # regtest
    "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
    # not this guard's problem, and must not be claimed by it
    "alice@example.com",
    "",
    "   ",
    "garbage",
    "not-an-address",
    "11111",
    "doge1qqqq",
    # case: bech32 is case-insensitive, and a pasted address can be upper
    "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
]

NETWORKS = ["mainnet", "signet", "testnet", "regtest"]


def main() -> int:
    chains = _chains()
    cases = []
    for addr in ADDRESSES:
        for net in NETWORKS:
            cases.append({
                "address": addr,
                "network": net,
                "family": chains.address_chain_family(addr),
                # The message itself, so the clients say the same thing rather
                # than agreeing only on whether to refuse.
                "refusal": chains.recipient_chain_mismatch(addr, net),
            })
    json.dump({"cases": cases}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
