"""The Silent Payments key of a BitMail record, and the parser that reads it.

Reported 2026-11-21: Sparrow, on signet, could not pay a WhiSPa BitMail. BIP-321
says a bech32 payment instruction uses its address format's HRP as the parameter
key, so a signet Silent Payments address (tsp1...) goes in ``tsp=``; this
extension wrote ``sp=`` for every network and Sparrow reads ``tsp=`` there.

The module under test is pure (urllib only), so it is loaded by path.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("bip321", ROOT / "helpers" / "bip321.py")
b = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(b)

MAIN = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
SIGNET = "tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"


def test_a_mainnet_address_is_published_under_sp():
    assert b.sp_uri(MAIN) == f"bitcoin:?sp={MAIN}"


def test_a_signet_address_is_published_under_tsp():
    # The reported case: Sparrow looks for tsp= on signet.
    assert b.sp_uri(SIGNET) == f"bitcoin:?tsp={SIGNET}"


def test_the_key_is_the_addresss_own_hrp():
    assert b.sp_param_key(MAIN) == "sp"
    assert b.sp_param_key(SIGNET) == "tsp"
    assert b.sp_param_key("  TSP1Q  ") == "tsp"


def test_both_keys_read_back_to_the_address():
    assert b.sp_from_uri(b.sp_uri(MAIN)) == MAIN
    assert b.sp_from_uri(b.sp_uri(SIGNET)) == SIGNET


def test_a_record_published_before_this_still_resolves():
    # bitcoin:?sp=tsp1... is what every signet BitMail carried until it is
    # rewritten. It must keep working in the meantime.
    assert b.sp_from_uri(f"bitcoin:?sp={SIGNET}") == SIGNET


def test_a_bare_address_passes_through_and_case_does_not_matter():
    assert b.sp_from_uri(SIGNET) == SIGNET
    assert b.sp_from_uri(f"BITCOIN:?TSP={SIGNET}") == SIGNET


def test_the_replace_trap_is_the_bug_this_replaces():
    # What the old parser did to a tsp= record: not an address, a different string.
    old = f"bitcoin:?tsp={SIGNET}".replace("bitcoin:?sp=", "").replace("sp=", "")
    assert old != SIGNET
    assert b.sp_from_uri(f"bitcoin:?tsp={SIGNET}") == SIGNET


def test_an_instruction_with_no_silent_payment_address_yields_nothing():
    # The caller then refuses it rather than paying whatever was left over.
    assert b.sp_from_uri("bitcoin:?lno=lno1bogusoffer") == ""
    assert b.sp_from_uri("bitcoin:bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5nq") == ""
    assert b.sp_from_uri("bitcoin:?sp=notanaddress") == ""
    assert b.sp_from_uri("") == ""
    assert b.sp_from_uri("hello") == ""


def test_an_ambiguous_record_is_refused():
    # BIP-353 refuses ambiguity and so do we.
    assert b.sp_from_uri(f"bitcoin:?sp={MAIN}&sp={MAIN}") == ""
    assert b.sp_from_uri(f"bitcoin:?sp={MAIN}&tsp={SIGNET}") == ""


def test_other_parameters_and_a_fallback_address_are_ignored():
    uri = f"bitcoin:bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5nq?label=x&tsp={SIGNET}"
    assert b.sp_from_uri(uri) == SIGNET


def test_nothing_in_the_extension_parses_the_uri_with_replace_any_more():
    """str.replace is how this went wrong; it must not come back anywhere."""
    pat = re.compile(r"""\.replace\(\s*["'](?:bitcoin:\?)?t?sp=""")
    offenders = []
    for path in list(ROOT.glob("*.py")) + list((ROOT / "helpers").glob("*.py")):
        text = path.read_text()
        # comments and docstrings quote the bug; strip them first
        text = re.sub(r'"""[\s\S]*?"""', "", text)
        text = re.sub(r"#.*", "", text)
        if pat.search(text):
            offenders.append(path.name)
    assert not offenders, offenders


def test_the_tamper_sweep_keeps_a_non_sp_record_visible():
    """An empty parse must not read as 'nothing to compare' in the sweep."""
    text = (ROOT / "views_api.py").read_text()
    i = text.index("tamper sweep: purged stale BitMail records")
    section = text[i : i + 4000]
    assert "sp_from_uri(raw) or raw" in section
