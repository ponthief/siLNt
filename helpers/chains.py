"""Which chain an address belongs to.

Split out of send_guards.py so the plain-chain spend planner can use it too:
send_guards reaches into crud, and helpers/plain.py must not. Nothing here
imports anything, which is what keeps that true.
"""

from __future__ import annotations

from typing import Optional


# ── the rule ──
#
# WHY THIS IS A GUARD AND NOT A FORMALITY. Nothing downstream looks at the
# network of a recipient. A BIP-352 address carries its chain in the HRP alone
# — sp1 for mainnet, tsp1 for everything else — and the scan and spend keys
# inside are the same bytes either way, so a mainnet sp1… pasted into a signet
# wallet derives a perfectly valid signet output. embit is no stricter with
# on-chain addresses: script.address_to_scriptpubkey turns bc1q…, tb1q… and
# bcrt1q… into the identical scriptPubKey without a word about which chain
# asked.
#
# So the transaction builds, signs, broadcasts and confirms, and the money is
# gone: the recipient is scanning the other chain and will never see it, and
# there is no bounce and no error anywhere. The only place this can be caught
# is before the build, on the address itself.
#
# signet and testnet are deliberately one family. They share tb1 and they share
# the base58 versions, so no address can tell them apart, and pretending
# otherwise would mean refusing valid recipients.

_BECH32_FAMILY = {
    "bc": "main",
    "sp": "main",
    "tb": "test",
    "tsp": "test",
    "bcrt": "regtest",
}

# base58 version bytes, by leading character. Testnet and regtest share these.
_BASE58_MAIN = ("1", "3")
_BASE58_TEST = ("m", "n", "2")

# A leading character is not enough to call something an address: "11111"
# starts with a 1. base58check addresses are 26–35 characters from this
# alphabet (no 0, O, I or l), and requiring that keeps the guard from claiming
# a chain for a string that is not an address at all.
_BASE58_ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def _looks_base58(address: str) -> bool:
    return 26 <= len(address) <= 35 and all(c in _BASE58_ALPHABET for c in address)


def address_chain_family(address: str) -> Optional[str]:
    """'main', 'test', 'regtest', 'test-or-regtest', or None when unrecognised.

    None means "this guard has nothing to say" — an unknown format is the
    address parser's problem, not this one's, and refusing it here would be
    guessing. It has a better message for it, too.
    """
    a = (address or "").strip().lower()
    if not a:
        return None
    if "1" in a:
        # The bech32 separator is the LAST '1': '1' is not in the data
        # charset, so any earlier one would be part of the HRP.
        fam = _BECH32_FAMILY.get(a.rsplit("1", 1)[0])
        if fam:
            return fam
    raw = address.strip()
    if _looks_base58(raw):
        if raw.startswith(_BASE58_MAIN):
            return "main"
        if raw.startswith(_BASE58_TEST):
            # Indistinguishable by design: testnet, signet and regtest all use
            # these versions.
            return "test-or-regtest"
    return None


def wallet_chain_family(network: str) -> str:
    n = (network or "").strip().lower()
    if n == "mainnet":
        return "main"
    if n == "regtest":
        return "regtest"
    return "test"


def recipient_chain_mismatch(recipient: str, network: str) -> Optional[str]:
    """The message to refuse with, or None when the recipient is on-chain.

    Returns the text rather than raising so the contact endpoints — which are
    not sends — can reuse the same judgement and the same wording.
    """
    addr = (recipient or "").strip()
    if not addr or "@" in addr:
        return None                      # a BitMail is judged once resolved
    theirs = address_chain_family(addr)
    if theirs is None:
        return None
    ours = wallet_chain_family(network)
    if theirs == ours:
        return None
    # A base58 address cannot distinguish these three, so accept it on any.
    if theirs == "test-or-regtest" and ours in ("test", "regtest"):
        return None
    if ours == "regtest" and theirs == "test":
        # tb1/tsp1 on regtest: the same addresses regtest itself hands out for
        # silent payments, so this is not a cross-chain send.
        return None
    names = {"main": "mainnet", "test": "testnet/signet", "regtest": "regtest"}
    return (
        f"That is a {names.get(theirs, theirs)} address and this wallet is on "
        f"{network}. Coins sent to it would be unspendable by the recipient "
        f"and unrecoverable by you."
    )


