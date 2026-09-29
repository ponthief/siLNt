"""A recipient on the other chain, which nothing downstream would notice.

THE REPORT. On a signet wallet, a mainnet `sp1…` pasted into Send went all
the way to the broadcast confirmation, and the same address saved as a contact
without a word.

WHY IT GOT THAT FAR. A BIP-352 address carries its chain in the HRP and
nowhere else — `sp1` for mainnet, `tsp1` for everything else — and the scan
and spend keys inside are the same bytes either way. So a mainnet address
derives a perfectly valid *signet* output. embit is no stricter on the
on-chain side: `script.address_to_scriptpubkey` turns `bc1q…`, `tb1q…` and
`bcrt1q…` into the identical scriptPubKey without asking which chain wanted
it.

WHY IT MATTERS MORE THAN A TYPO. The transaction builds, signs, broadcasts and
confirms. There is no bounce, no error and no failure anywhere: the recipient
is scanning the other chain and simply never sees it. Nothing after the build
can catch this, so the address itself is the only place to catch it.

signet and testnet are deliberately one family here. They share `tb1` and the
base58 versions, so no address distinguishes them, and pretending otherwise
would refuse valid recipients.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _chains():
    """helpers/chains.py imports nothing, which is the point of it existing —
    send_guards reaches into crud and helpers/plain.py must not."""
    spec = importlib.util.spec_from_file_location(
        "silnt_chains_for_tests", ROOT / "helpers" / "chains.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHAINS = _chains()

MAINNET = [
    "sp1qqw508d6qejxtdg4y5r3zarvary0c5xw7k",              # the reported case
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
]

TESTNETTY = [
    "tsp1qqw508d6qejxtdg4y5r3zarvary0c5xw7k",
    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
    "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
]


@pytest.mark.parametrize("addr", MAINNET)
@pytest.mark.parametrize("network", ["signet", "testnet", "regtest"])
def test_a_mainnet_address_is_refused_off_mainnet(addr, network):
    problem = CHAINS.recipient_chain_mismatch(addr, network)
    assert problem, f"{addr} accepted on {network}"
    assert "unrecoverable" in problem, problem


@pytest.mark.parametrize("addr", MAINNET)
def test_a_mainnet_address_is_fine_on_mainnet(addr):
    assert CHAINS.recipient_chain_mismatch(addr, "mainnet") is None


@pytest.mark.parametrize("addr", TESTNETTY)
def test_a_test_address_is_refused_on_mainnet(addr):
    assert CHAINS.recipient_chain_mismatch(addr, "mainnet") is not None


@pytest.mark.parametrize("addr", TESTNETTY)
@pytest.mark.parametrize("network", ["signet", "testnet"])
def test_a_test_address_is_fine_on_signet_and_testnet(addr, network):
    assert CHAINS.recipient_chain_mismatch(addr, network) is None


def test_signet_and_testnet_are_one_family():
    """They share tb1 and they share the base58 versions. Nothing in an
    address tells them apart, so nothing here pretends to."""
    for addr in TESTNETTY:
        assert CHAINS.address_chain_family(addr) in ("test", "test-or-regtest")
    assert CHAINS.wallet_chain_family("signet") == CHAINS.wallet_chain_family("testnet")


def test_regtest_accepts_the_addresses_regtest_hands_out():
    """bcrt1 is its own, and tb1/tsp1 are what regtest produces for segwit and
    for silent payments, so neither is a cross-chain send."""
    for addr in TESTNETTY + ["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]:
        assert CHAINS.recipient_chain_mismatch(addr, "regtest") is None


def test_bcrt_is_refused_everywhere_else():
    for network in ("mainnet", "signet", "testnet"):
        assert CHAINS.recipient_chain_mismatch(
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", network
        ) is not None


def test_a_bitmail_is_judged_after_resolution_not_before():
    """The name says nothing about a chain; the address it resolves to does,
    and resolve_recipient checks that one too."""
    assert CHAINS.recipient_chain_mismatch("alice@example.com", "signet") is None


def test_an_unrecognised_string_is_not_this_guard_s_problem():
    """Refusing it here would be guessing. The address parser says whether it
    is an address at all, and it says so with a better message."""
    for junk in ("", "   ", "garbage", "not-an-address", "11111"):
        assert CHAINS.recipient_chain_mismatch(junk, "signet") is None


def test_the_hrp_is_read_from_the_last_separator():
    """'1' is not in the bech32 data charset, so any earlier one is part of
    the HRP. Reading the first would make `bc1q…1…` unparseable."""
    assert CHAINS.address_chain_family("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == "main"
    # A made-up HRP is unknown rather than guessed at.
    assert CHAINS.address_chain_family("doge1qqqq") is None


# ── and every door it has to be on ──────────────────────────────────────────


def _fn(path: str, name: str) -> str:
    src = (ROOT / path).read_text()
    at = src.index(f"def {name}(")
    nxt = src.find("\nasync def ", at + 10)
    other = src.find("\ndef ", at + 10)
    ends = [i for i in (nxt, other) if i != -1]
    return src[at:min(ends)] if ends else src[at:]


def test_the_send_path_checks_the_address_and_the_resolved_bitmail():
    """Both can be the wrong chain, and by the second one it is what the
    builder will be handed."""
    body = _fn("helpers/send_guards.py", "resolve_recipient")
    assert body.count("require_recipient_network(") == 2, body


def test_both_send_endpoints_pass_the_wallet_s_network():
    """/tx/build and /tx/prepare share resolve_recipient precisely so they
    cannot drift; a default network would have undone that."""
    src = (ROOT / "views_api.py").read_text()
    assert src.count("resolve_recipient(data.recipient, wallet.network)") == 2
    assert "resolve_recipient(data.recipient)" not in src


def test_the_network_argument_is_required():
    """Optional, it would be forgotten at exactly the call site that mattered."""
    body = _fn("helpers/send_guards.py", "resolve_recipient")
    assert "recipient: str, network: str" in body
    assert "network: str = " not in body


def test_saving_a_contact_checks_it_too():
    """A contact is stored per network and only offered on that network, so
    one on the wrong chain is a send that cannot succeed, under a name that
    says it can."""
    assert "require_recipient_network(value, network)" in _fn(
        "views_api.py", "api_sp_contacts_create"
    )


def test_repointing_a_contact_cannot_get_round_it():
    body = _fn("crud.py", "update_sp_contact_value")
    assert "recipient_chain_mismatch(value, row[\"network\"])" in body


def test_the_plain_spend_planner_checks_it_too():
    """It holds every rule for a plain spend so a client that signs for itself
    is held to the same ones."""
    body = _fn("helpers/plain.py", "plan_plain_spend")
    assert "recipient_chain_mismatch(dest, network)" in body


def test_chains_imports_nothing():
    """helpers/plain.py must not reach crud, and send_guards does. That is the
    whole reason this module is separate from it."""
    src = (ROOT / "helpers" / "chains.py").read_text()
    imports = [
        line.strip() for line in src.splitlines()
        if line.startswith(("import ", "from ")) and "__future__" not in line
    ]
    assert imports == ["from typing import Optional"], imports
