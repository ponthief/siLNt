"""The routed change output: derived by the instance, checked by both clients.

A user who gives a Lightning address has their round's change output pay the
INSTANCE's Silent Payments address instead of their own wallet.

THE PROBLEM, which payjoin_sp.py::payment_script already states about its own
output: "Derived by the PAYEE, who is the only party with the scan key it
needs; the payer cannot compute it and cannot check it." A BIP-352 output is
P_k = B_spend + t_k·G, and t_k needs the payee's scan key or the inputs'
private keys. A client has neither.

That matters because a taproot key-path signature commits to EVERY output. If
a client cannot tell a legitimate change script from one the coordinator
chose, it signs the coin away, and "the server said so" is not a check — that
exact mistake shipped in the PayJoin, comparing the server's value against
itself, and let every substitution through.

THE CHECK THAT IS AVAILABLE: reveal t_k and let each client verify
`script == OP_1 <x(B_spend + t_k·G)>`. That proves the output's private key is
b_spend + t_k, producible only by the holder of b_spend, so the change cannot
be redirected to a third party. It does NOT prove t_k is the real
shared-secret derivative; the money goes to the instance either way, and what
the instance would lose is the ability to find its own coin.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "tango-change-payout.json"


def _fx() -> dict:
    assert FIXTURE.exists(), (
        f"{FIXTURE} is missing. Generate it with:\n"
        f"  python3 helpers/_tango_change_fixtures.py > fixtures/tango-change-payout.json"
    )
    return json.loads(FIXTURE.read_text())


FX = _fx()


def test_the_fixture_covers_both_sides():
    assert len(FX["cases"]) == 2
    assert {c["role"] for c in FX["cases"]} == {"a", "b"}


def test_each_side_verifies_against_its_own_tweak():
    for c in FX["cases"]:
        assert c["verifies"] is True, c["role"]


def test_the_two_sides_get_different_outputs():
    """Both routed changes pay the SAME recipient, so the same k would be one
    address paid twice — one coin rather than two, with the second side's money
    landing on the first side's script."""
    a, b = FX["cases"]
    assert a["spk"] != b["spk"]
    assert a["tweak"] != b["tweak"]


def test_k_is_fixed_by_role_not_by_order():
    """So both clients compute both without negotiating anything."""
    by_role = {c["role"]: c["k"] for c in FX["cases"]}
    assert by_role == {"a": 0, "b": 1}
    src = (ROOT / "helpers" / "tangochange.py").read_text()
    assert 'PAYOUT_K = {"a": 0, "b": 1}' in src


def test_a_crossed_tweak_does_not_verify():
    """The substitution the check exists to catch. A verifier that ignored the
    tweak would pass this and be worthless."""
    assert FX["negatives"]["crossed_tweak"] is False


def test_the_fixture_carries_a_foreign_output_to_reject():
    """The coordinator pointing the change at an address of its own, which is
    the whole attack."""
    neg = FX["negatives"]
    assert neg["foreign_spk"] and neg["foreign_tweak"]
    a = FX["cases"][0]
    assert neg["foreign_spk"] != a["spk"]


def test_the_script_is_a_taproot_output():
    for c in FX["cases"]:
        assert c["spk"].startswith("5120"), c["spk"]
        assert len(c["spk"]) == 68, c["spk"]      # OP_1 OP_PUSH32 + 32 bytes


def test_the_fixture_is_current():
    """Regenerated from the module and compared, so an edit to the derivation
    that nobody re-ran the generator for fails here rather than on a real
    round. Same reason the signing fixtures are checked in."""
    out = subprocess.run(
        [sys.executable, str(ROOT / "helpers" / "_tango_change_fixtures.py")],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    assert json.loads(out.stdout) == FX, (
        "fixtures/tango-change-payout.json is stale. Regenerate it:\n"
        "  python3 helpers/_tango_change_fixtures.py > fixtures/tango-change-payout.json"
    )


# ── the properties the source has to keep ───────────────────────────────────


def _fn(path: str, name: str) -> str:
    """One function's source. Stops at the next def OR the next route
    decorator — an async endpoint followed by another decorated one has no
    bare `def` after it, and an overshooting slice makes every assertion in
    these tests read the rest of the file."""
    src = (ROOT / path).read_text()
    at = src.index(f"def {name}(")
    ends = [
        i for i in (
            src.find("\ndef ", at + 10),
            src.find("\nasync def ", at + 10),
            src.find("\n@silnt_api_router", at + 10),
        ) if i != -1
    ]
    return src[at:min(ends)] if ends else src[at:]


def test_the_verifier_needs_no_secret():
    """Which is the whole point: B_spend comes out of the public address and
    t_k comes with the round."""
    body = _fn("helpers/tangochange.py", "verify_payout_output")
    assert "scan_secret" not in body, body
    assert "parse_sp_address" in body


def test_the_verifier_refuses_a_malformed_tweak_or_script():
    body = _fn("helpers/tangochange.py", "verify_payout_output")
    assert "len(tweak) != 32" in body
    assert "len(script) != 34" in body
    # A tweak of zero or >= N is not a scalar, and point arithmetic on it is
    # either an identity or undefined.
    assert "t_k == 0 or t_k >= SECP256K1_N" in body


def test_the_verifier_never_raises():
    """It is called while deciding whether to sign. An exception there is a
    round that cannot be refused OR accepted."""
    body = _fn("helpers/tangochange.py", "verify_payout_output")
    assert body.count("except Exception:") >= 2
    assert "return False" in body


def test_a_side_without_an_address_keeps_its_own_change():
    body = _fn("helpers/tangochange.py", "payout_change_spks")
    assert "if not routed:" in body and "continue" in body


def test_the_scan_key_is_documented_as_a_view_key():
    """It has to be in config for the instance to derive its own outputs. The
    distinction from a spending key is the reason that is acceptable, so it is
    written down rather than assumed."""
    src = (ROOT / "models.py").read_text()
    at = src.index("tango_change_scan_secret")
    block = src[max(0, at - 700):at]
    assert "VIEW key" in block
    assert "not a spending key" in block.lower() or "not a spending" in block


def test_the_feature_needs_the_scan_key_before_it_will_route():
    """Configured means both the address and the scan key, or neither: without
    the key the instance cannot derive the output it would be paid at."""
    src = (ROOT / "models.py").read_text()
    body = src[src.index("def tango_payout_ready"):]
    body = body[: body.index("\n    def ")]
    assert "tango_change_scan_secret" in body


def test_the_derivation_is_not_in_the_mirrored_module():
    """helpers/tangopayout.py is the fee rule, it is pure, and both clients
    mirror it. The derivation reaches the curve and cannot be mirrored, so
    keeping them apart keeps the mirrored half mirrorable."""
    payout = (ROOT / "helpers" / "tangopayout.py").read_text()
    for forbidden in ("point_add", "point_mul", "curve", "parse_sp_address"):
        assert forbidden not in payout, forbidden


# ── wired into the round ────────────────────────────────────────────────────


def _block(path: str, start: str, end: str) -> str:
    src = (ROOT / path).read_text()
    a = src.index(start)
    return src[a:src.index(end, a)]


def test_each_side_s_intent_is_snapshotted_when_it_joins():
    """A flag re-read between A signing and B signing would change the output
    set, and both signatures commit to it: the two would hold valid signatures
    for different transactions and the round could not be broadcast."""
    src = (ROOT / "views_api.py").read_text()
    # A, at propose.
    assert "a_payout, payout_addr = await _tango_routes_change(uid, wallet.network)" in src
    assert "a_payout=a_payout," in src
    # B, at accept.
    assert "b_payout, b_payout_addr = await _tango_routes_change(uid, rnd.network)" in src
    assert "b_payout=b_payout," in src
    # And A's sign reads the ROUND, not A's current setting.
    sign = _block("views_api.py", 'if role == "a":', "a_mix_spks = _tango_mix_spks")
    assert "rnd.a_payout" in sign
    assert "_tango_routes_change" not in sign, (
        "A's sign must not re-read the setting; the round carries the decision"
    )


def test_a_client_cannot_supply_a_routed_change_script():
    """It pays the instance, and only the payee can derive a BIP-352 output —
    so a client-sent script would be one nobody checked. Refused rather than
    ignored: ignoring it would let a client believe it had chosen."""
    src = (ROOT / "views_api.py").read_text()
    # One wording, used twice: the sentence lived in two places and had already
    # drifted in how it wrapped, which is how two copies become two wordings.
    assert "ROUTED_CHANGE_IS_OURS_TO_DERIVE = (" in src
    assert src.count("detail=ROUTED_CHANGE_IS_OURS_TO_DERIVE,") == 2, (
        "both accept and A's sign have to refuse a client-sent script"
    )


def test_the_address_comes_off_the_round_not_the_live_config():
    """An operator who changes the configured address must not retroactively
    move the output of a round already in flight, which both sides may have
    checked already."""
    body = _fn("views_api.py", "_tango_payout_change_spk")
    assert "rnd.payout_sp_address or cfg.tango_change_sp_address" in body


def test_routing_needs_the_whole_configuration():
    """Address, scan key and a payout wallet. Routing with any of them missing
    takes the coin and has no way to send the value on."""
    body = _fn("views_api.py", "_tango_routes_change")
    assert "cfg.tango_payout_ready(network)" in body
    ready = (ROOT / "models.py").read_text()
    ready = ready[ready.index("def tango_payout_ready"):]
    ready = ready[: ready.index("\n    def ")]
    for field in ("tango_change_sp_address", "tango_change_scan_secret",
                  "tango_change_payout_wallet_id"):
        assert field in ready, field


def test_the_derivation_uses_the_whole_frozen_input_set():
    """A BIP-352 output is derived from EVERY input, both sides' included,
    which is why it cannot be derived before the set is frozen."""
    src = (ROOT / "views_api.py").read_text()
    assert "_pj_payjoin_inputs(a_rows) + _pj_payjoin_inputs(rows)" in src


def test_a_routed_change_is_not_labelled_as_the_user_s_coin():
    """It pays the instance, so it is not in their wallet to label — and
    counting it as missing would have every routed round logging "a script
    this side derived is not in the transaction it signed" forever."""
    src = (ROOT / "views_api.py").read_text()
    assert "None if rnd.a_payout else rnd.a_change_spk" in src
    assert "None if rnd.b_payout else rnd.b_change_spk" in src


def test_the_scan_key_is_not_handed_to_every_user():
    """GET /backend/config returns this model to any authenticated caller,
    which was harmless while nothing in it was a secret. The scan key is the
    first, and it would identify every coin the service has collected."""
    src = (ROOT / "views_api.py").read_text()
    assert '_REDACTED_CONFIG_FIELDS = ("tango_change_scan_secret",)' in src
    body = _fn("views_api.py", "api_get_backend_config")
    assert "is_lnbits_admin(key_info.wallet.user)" in body
    assert "_REDACTED_CONFIG_FIELDS" in body


def test_the_payout_wallet_is_an_id_and_not_a_key():
    """The extension looks the wallet up server-side when it pays, so no
    spending key goes into a config blob."""
    src = (ROOT / "models.py").read_text()
    assert "tango_change_payout_wallet_id: str" in src
    assert "tango_change_payout_adminkey" not in src


# ── the two config values have to be from the same wallet ───────────────────
#
# A MISMATCH IS THE WORST KIND OF WRONG, because nothing notices.
# derive_payout_output uses the SECRET for the shared secret and the address's
# B_SPEND for the point, so a mismatched pair still produces a valid output,
# spendable by the holder of B_spend. verify_payout_output only checks B_spend,
# so both clients accept it and the round completes. And the instance then
# cannot FIND that coin, because it would scan with a key the output was never
# derived against. Money arrives somewhere real and invisible.
#
# The verdicts are computed by the fixture generator rather than here: conftest
# stubs helpers/wallet.py, so the real curve code cannot be imported in the
# test process.


def test_the_real_pair_matches():
    assert FX["scan_key_match"]["right_pair"] is True


@pytest.mark.parametrize(
    "case",
    [
        "other_wallets_scan",
        # The mistake most likely to be made at a config field with two hex
        # boxes on it.
        "the_spend_key_instead",
        "not_hex",
        "too_short",
        "too_long",
        "zero",
        "empty",
        "blank",
        "junk_address",
        "empty_address",
    ],
)
def test_everything_else_is_caught(case):
    assert FX["scan_key_match"][case] is False, case


def test_the_scan_secret_cannot_be_derived_from_the_address():
    """The thing this check exists INSTEAD of. An SP address carries B_scan as
    a PUBLIC key; recovering b_scan from it is the discrete log, and if that
    were possible Silent Payments would be worthless, because anyone could
    scan anyone's payments. So there is no deriving it — only checking a pair.

    Asserted against the module surface so nobody adds a plausible-looking
    derive_scan_key(address) later.
    """
    src = (ROOT / "helpers" / "tangochange.py").read_text()
    assert "def derive_scan_key" not in src
    assert "discrete log" in src, (
        "the reason there is no such function belongs beside the one there is"
    )


def test_the_config_save_refuses_a_mismatched_pair():
    src = (ROOT / "views_api.py").read_text()
    body = src[src.index("async def api_update_backend_config"):]
    body = body[: body.index("\n@silnt_api_router")]
    assert "scan_key_matches(" in body


def test_a_payout_address_can_be_generated_instead_of_typed():
    """The question behind "can the scan key be derived from the address?" —
    which it cannot. Generating both from one seed is the thing that actually
    removes the copying."""
    body = _fn("views_api.py", "api_admin_tango_change_address")
    assert "generate_silent_wallet_address(" in body
    for field in ('"sp_address"', '"scan_secret"', '"mnemonic"'):
        assert field in body, field


def test_the_generator_stores_nothing():
    """The mnemonic is the only way to ever spend what the address collects, so
    it is shown once and kept by the operator. A server that saved it would be
    holding the spend key for every coin it collects."""
    body = _fn("views_api.py", "api_admin_tango_change_address")
    assert "update_backend_config" not in body
    assert "_spend_key" in body, "the spend key is derived and discarded"
    # And it is not in the response.
    assert '"spend' not in body


def test_the_generator_is_admin_only_and_mainnet_only():
    body = _fn("views_api.py", "api_admin_tango_change_address")
    assert "require_admin(key_info)" in body
    assert "payout_offered(net)" in body


def test_the_generated_pair_is_checked_before_it_is_handed_over():
    """Otherwise a mismatch would leave the operator holding a mnemonic for a
    configuration the save will refuse."""
    body = _fn("views_api.py", "api_admin_tango_change_address")
    assert "scan_key_matches(sp_address, scan_key)" in body
