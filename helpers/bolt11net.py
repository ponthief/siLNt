"""Which chain a bolt11 invoice is for, read off the invoice itself.

THE RULE THIS ENFORCES, and it is the oldest one in the payout feature: a
Tango's change must never be paid in real sats when the round that produced it
was on a test chain. Routing a signet round's worthless change to a mainnet
Lightning address buys faucet coins with real money, on repeat, for anyone who
asks.

WHY HERE AND NOT AT THE WALLET. The payout wallet is an LNbits wallet on this
server, running on whatever node LNbits was configured with — a local LND or
Core Lightning, which is the only kind this instance pays from. Nothing in an
extension can ask that node which chain it is on, so for a long time the rule
was stated as a list of chains that may pay out at all, and the list was
("mainnet",). That worked by refusing every other chain outright, which also
refused the case an operator running a signet node actually wants.

The invoice can be asked. BOLT 11 puts the chain in the human-readable part
before the amount — `lnbc…` is mainnet and nothing else is — so the one thing
that must not happen is checkable as a fact, at the only moment it matters:
before a payment leaves. A node on the wrong chain cannot pay an invoice for
another one anyway; it fails, retries and is reported. Money only moves when
the prefix says mainnet, and then only for a mainnet round.

So the guard moved from "which chains may pay out" to "this invoice is for the
chain whose change it is paying", and signet works with a signet node.

NO DEPENDENCIES AND NO DECODING. The prefix is the first few characters of a
string; parsing the rest of an invoice would be a bech32 implementation and a
tagged-field reader for an answer that is already in front of us.
"""

from __future__ import annotations

from typing import Optional


# BOLT 11 §"Human-Readable Part". LONGEST FIRST, and that ordering is the whole
# of the parsing: `lntbs` (signet) starts with `lntb` (testnet), and `lnbcrt`
# (regtest) starts with `lnbc` (MAINNET). Checked shortest-first, every regtest
# invoice in the world reads as mainnet — which is the exact direction that
# spends real money.
#
# `lnsb` is signet as some older implementations wrote it, before `lntbs` was
# settled on. Both are accepted: an invoice this cannot name is refused, and
# refusing a real signet invoice would break the case this exists to allow.
_PREFIXES = (
    ("lnbcrt", "regtest"),
    ("lntbs", "signet"),
    ("lnsb", "signet"),
    ("lntb", "testnet"),
    ("lnbc", "mainnet"),
)


def invoice_network(bolt11: str) -> Optional[str]:
    """The chain this invoice is for, or None if it does not say.

    None is not "probably mainnet". It is an invoice this code cannot read,
    and the caller refuses it — see network_mismatch.
    """
    text = (bolt11 or "").strip().lower()
    for prefix, network in _PREFIXES:
        if text.startswith(prefix):
            return network
    return None


def network_mismatch(bolt11: str, network: str) -> Optional[str]:
    """Why this invoice must not be paid for that chain's change. None when it
    may.

    AN UNREADABLE INVOICE IS A REFUSAL. Treating it as "probably fine" is the
    same mistake as treating a missing prefix as mainnet: the failure being
    guarded against is paying real sats out for test coins, and nothing about
    "we could not tell" argues against it. The cost of being wrong in this
    direction is a payout that does not go; in the other it is money.
    """
    want = (network or "").strip().lower()
    got = invoice_network(bolt11)
    if not want:
        return "No network to check this invoice against."
    if not got:
        return (
            "That Lightning address's provider returned an invoice this "
            "server cannot identify the network of, so it will not be paid."
        )
    if got != want:
        return (
            f"That Lightning address returned a {got} invoice, and this is "
            f"{want} change. Use an address on {want}."
        )
    return None
