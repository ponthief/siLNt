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
    src = (ROOT / path).read_text()
    at = src.index(f"def {name}(")
    nxt = src.find("\ndef ", at + 10)
    return src[at:nxt] if nxt != -1 else src[at:]


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
