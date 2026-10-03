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

import ast
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


# ── delivering it ───────────────────────────────────────────────────────────
#
# The money is already the instance's by the time any of this runs: the
# round's change output paid our SP address. Every rule here is about an
# obligation already taken on, which is why none of it fails silently.


def _payoutrun():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "silnt_payoutrun_for_tests", ROOT / "helpers" / "tangopayoutrun.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PR = _payoutrun()


@pytest.mark.parametrize(
    "tip,block,want",
    [
        (900_000, 900_000, 1),      # in the tip block: one confirmation
        (900_002, 900_000, 3),
        (900_000, None, 0),         # not mined
        (None, 900_000, 0),         # tip unknown
        (None, None, 0),
        (900_000, 900_005, 0),      # block ahead of the tip: mid-reorg, not negative
    ],
)
def test_confirmations_counts_the_tip_block(tip, block, want):
    assert PR.confirmations(tip, block) == want


def test_a_payout_waits_for_the_configured_depth():
    assert not PR.is_confirmed_enough(900_000, 900_000, 3)
    assert not PR.is_confirmed_enough(900_001, 900_000, 3)
    assert PR.is_confirmed_enough(900_002, 900_000, 3)


def test_zero_confirmations_is_never_enough():
    """A one-confirmation payout can be reversed by a reorg and a Lightning
    payment cannot be clawed back, so a minimum of 0 is read as 1."""
    assert not PR.is_confirmed_enough(900_000, None, 0)
    assert PR.is_confirmed_enough(900_000, 900_000, 0)


def test_the_backoff_grows_then_flattens():
    seen = [PR.backoff_for(n) for n in range(8)]
    assert seen == sorted(seen), seen
    assert seen[-1] == seen[-2], "it should flatten rather than grow forever"
    assert PR.backoff_for(-5) == PR.backoff_for(0)


def test_a_permanent_failure_stops_immediately():
    """"No such user at that domain" does not become true by asking again, and
    five more attempts only delay telling somebody their address is wrong —
    which is the one thing they can act on."""
    assert PR.give_up(attempts=1, permanent=True)
    assert PR.status_after(1, permanent=True) == "unpayable"


def test_a_temporary_failure_is_retried_up_to_a_limit():
    for n in range(1, PR.MAX_ATTEMPTS):
        assert PR.status_after(n, permanent=False) == "pending", n
    assert PR.status_after(PR.MAX_ATTEMPTS, permanent=False) == "failed"


def test_unpayable_and_failed_mean_different_things():
    """One is waiting on the user, the other on the operator, and an operator
    reading the list has to be able to tell at a glance."""
    assert PR.status_after(99, permanent=True) == "unpayable"
    assert PR.status_after(99, permanent=False) == "failed"
    assert PR.failure_body("unpayable") != PR.failure_body("failed")


def test_the_failure_notification_never_mentions_an_amount():
    """It goes through FCM, and therefore Google, in plaintext. CLAUDE.md is
    explicit: push notifications must not mention amounts."""
    import re
    for text in (PR.PAYOUT_FAILED_TITLE, PR.failure_body("unpayable"),
                 PR.failure_body("failed")):
        assert not re.search(r"\d", text), text
        assert "sat" not in text.lower(), text


def test_the_failure_notification_says_what_to_do():
    for status in ("unpayable", "failed"):
        assert "Open WhiSPa" in PR.failure_body(status), status


def test_the_fee_is_stored_not_recomputed_at_payment_time():
    """Recomputing it when the payment goes out would price the same payout
    differently if the operator changed the percentage in between, and the
    figure in the ledger has to be the figure that was charged."""
    body = _fn("views_api.py", "enqueue_tango_payouts")
    assert "payout_plan(" in body
    attempt = _fn("views_api.py", "_attempt_tango_payout")
    assert "payout_plan" not in attempt
    assert 'row["net_sats"]' in attempt


def test_a_payout_is_created_once_per_output():
    """Keyed by (txid, vout) so a rescan, a restart or two overlapping sweeps
    cannot create a second obligation for one coin."""
    body = _fn("views_api.py", "enqueue_tango_payouts")
    assert "await get_tango_payout(rnd.txid, vout)" in body
    crud = (ROOT / "crud.py").read_text()
    assert "PRIMARY KEY (txid, vout)" in (ROOT / "migrations.py").read_text()
    assert "async def create_tango_payout" in crud


def test_a_cleared_address_still_records_the_debt():
    """They changed the setting between the round and the payout. The money is
    still owed, so the row exists and is visible as unpayable rather than
    silently skipped forever."""
    body = _fn("views_api.py", "enqueue_tango_payouts")
    assert "has no Lightning address" in body
    attempt = _fn("views_api.py", "_attempt_tango_payout")
    assert "No Lightning address on record" in attempt


def test_a_change_that_no_longer_clears_the_fee_is_paid_in_full():
    """The round was planned under a different fee. The user is owed the whole
    thing rather than nothing."""
    body = _fn("views_api.py", "enqueue_tango_payouts")
    assert "paying it in full" in body


def test_the_address_sent_to_is_stored_on_the_payout():
    """The setting is a live value they can change or clear. This is where the
    money actually went, which is the question a dispute asks."""
    mig = (ROOT / "migrations.py").read_text()
    body = mig[mig.index("async def m042_tango_change_payouts"):]
    assert "ln_address      TEXT NOT NULL" in body
    assert "we sent it THERE" in body


def test_the_payout_ledger_survives_account_deletion_without_the_identity():
    """It is the instance's financial record as well as the user's data, and
    the txid in it is public chain data either way."""
    crud = (ROOT / "crud.py").read_text()
    assert "async def redact_tango_payouts_for_user" in crud
    body = _fn("crud.py", "redact_tango_payouts_for_user")
    assert "ln_address = ''" in body and "user_id = 'deleted'" in body
    assert "DELETE FROM silnt.tango_change_payouts" not in crud, (
        "the amounts stay; only the identity goes"
    )


def test_fees_are_only_counted_on_payouts_that_went_out():
    """A fee on a payout that never went out is not revenue — the instance is
    holding the whole change, not earning part of it — and counting it would
    overstate earnings by exactly what it failed to deliver."""
    body = _fn("crud.py", "tango_payout_totals")
    assert '"fees_earned_sats": int(paid.get("fee_sats", 0))' in body
    assert "owed_sats" in body


def test_the_admin_list_shows_what_a_dispute_needs():
    body = _fn("views_api.py", "api_admin_tango_payouts")
    assert "require_admin(key_info)" in body
    assert "tango_payout_totals(" in body


def test_a_stopped_payout_can_be_requeued_with_a_fresh_address():
    """The usual reason one is retried is that the user just fixed it, and
    retrying the old address would fail the same way."""
    body = _fn("views_api.py", "api_admin_tango_payout_retry")
    assert "get_tango_ln_address(" in body
    assert "requeue_tango_payout(" in body
    # A paid payout is not retryable, which would be a double payment.
    assert "already been paid" in body


def test_the_requeue_resets_the_backoff():
    body = _fn("crud.py", "requeue_tango_payout")
    assert "attempts = 0" in body
    assert "notified = FALSE" in body


def test_a_user_can_see_their_own_payouts():
    """"Where is my change?" should have an answer in the app, not only in the
    admin console."""
    body = _fn("views_api.py", "api_my_tango_payouts")
    assert "list_tango_payouts_for_user(" in body


def test_one_stuck_payout_does_not_stop_the_others():
    body = _fn("views_api.py", "run_tango_payouts")
    assert "continue" in body


def test_only_rounds_that_actually_routed_are_scanned():
    """Every round ever broadcast would otherwise be read and depth-checked
    over the network once a minute, and almost none of them route."""
    body = _fn("crud.py", "list_broadcast_tango_rounds_with_payouts")
    assert "a_payout = TRUE OR b_payout = TRUE" in body
    assert "status = 'BROADCAST'" in body


def test_a_depth_check_that_fails_delays_rather_than_pays():
    """The safe direction when the alternative is paying out against a
    transaction a reorg removes."""
    body = _fn("views_api.py", "_tango_tx_depth")
    assert body.count("return 0") >= 4


# ── solvency: not offering what we cannot pay ───────────────────────────────


@pytest.mark.parametrize(
    "balance,owed,want",
    [
        (100_000, 0, 100_000),
        (100_000, 90_000, 10_000),
        # THE CASE THE SUBTRACTION EXISTS FOR. A raw-balance check would wave
        # a 20,000 payout through here; only 10,000 is actually free.
        (100_000, 95_000, 5_000),
        (100_000, 200_000, 0),      # overcommitted is nothing available
        (0, 0, 0),
        (None, None, 0),
    ],
)
def test_available_is_the_balance_minus_what_is_already_owed(balance, owed, want):
    assert PR.available_sats(balance, owed) == want


def test_available_is_never_negative():
    """An overcommitted wallet has nothing available, not a debt it can
    spend."""
    for owed in (0, 10, 10_000, 10**9):
        assert PR.available_sats(1_000, owed) >= 0


@pytest.mark.parametrize(
    "available,threshold,want",
    [
        (10_000, 10_000, True),      # exactly on the floor is on it
        (9_999, 10_000, False),
        (0, 0, True),                # no floor set: anything goes
        (0, 1, False),
        (50_000, 10_000, True),
    ],
)
def test_the_floor_decides_whether_a_round_may_route(available, threshold, want):
    assert PR.can_route(available, threshold) is want


def test_the_amount_is_deliberately_not_part_of_the_check():
    """A better question that cannot be asked where it would have to be
    answered: the only place the change is known is at accept, and by then the
    client has already decided whether to send a change script of its own. A
    server-side reversal there leaves a round with change and no script for
    it, which fails at assembly."""
    import inspect
    assert "net_sats" not in inspect.signature(PR.can_route).parameters
    src = (ROOT / "helpers" / "tangopayoutrun.py").read_text()
    assert "fails at assembly" in src, (
        "the reason the amount is not checked belongs next to the check"
    )


def test_the_reason_is_for_an_operator_not_a_user():
    assert PR.liquidity_reason(5_000, 10_000) is not None
    assert PR.liquidity_reason(50_000, 10_000) is None
    src = (ROOT / "helpers" / "tangopayoutrun.py").read_text()
    assert "invitation to work out how low" in src


def test_a_round_does_not_route_when_the_wallet_cannot_pay():
    body = _fn("views_api.py", "_tango_routes_change")
    assert "tango_payout_liquidity(network)" in body
    assert 'if not liq.get("ok")' in body


def test_the_client_is_told_without_being_told_how_low():
    """`ready` folds in liquidity so a depleted server stops offering the
    setting; the reason is not returned, because "the service is low on
    Lightning funds" is an invitation to work out how low."""
    body = _fn("views_api.py", "api_tango_ln_address_get")
    assert "tango_payout_liquidity(network)" in body
    assert '"reason"' not in body


def test_an_unreadable_balance_stops_the_feature_rather_than_risking_it():
    """Not offering it for a few minutes costs a user a privacy improvement.
    Offering it against an unknown balance costs them a coin."""
    body = _fn("views_api.py", "tango_payout_liquidity")
    assert '"ok": False' in body
    assert "could not be read" in body
    assert "No payout wallet is configured." in body


def test_the_alert_fires_on_both_crossings():
    """An operator who topped the wallet up should not have to guess whether
    it took."""
    body = _fn("views_api.py", "check_tango_payout_liquidity")
    assert "notify_service_health_change(" in body
    assert "LIQUIDITY_SERVICE" in body
    src = (ROOT / "helpers" / "tangopayoutrun.py").read_text()
    assert "fires on BOTH transitions" in src


def test_the_liquidity_check_runs_before_anything_can_throw():
    """It is the thing an operator needs to hear about, so it must not be
    skipped by an enqueue that fails."""
    body = _fn("views_api.py", "run_tango_payouts")
    assert body.index("check_tango_payout_liquidity") < body.index(
        "enqueue_tango_payouts"
    )


def test_the_threshold_is_configurable_and_defaulted():
    src = (ROOT / "models.py").read_text()
    assert "tango_change_min_wallet_balance_sats: int = 10_000" in src
    # And the reason a raw balance is the wrong measure is written down.
    at = src.index("tango_change_min_wallet_balance_sats")
    assert "already owed" in src[max(0, at - 600):at]


def test_the_console_shows_the_balance_against_what_is_owed():
    body = _fn("views_api.py", "api_admin_tango_payouts")
    assert "tango_payout_liquidity(" in body


# ── routing is PER SIDE ─────────────────────────────────────────────────────
#
# One party giving a Lightning address must have no bearing on the other. The
# partner who gave none keeps their change on chain, in their own wallet,
# exactly as every round did before this setting existed — and the setting is
# described to users as optional, which is only true if that holds.
#
# The failure this guards against is the expensive direction: a round-wide
# flag would route BOTH change outputs to the instance's SP address, taking a
# coin from somebody who never offered it and owing them nothing over
# Lightning, because no payout row is created for a side that did not route.


def test_each_side_has_its_own_flag_and_its_own_tweak():
    src = (ROOT / "models.py").read_text()
    body = src[src.index("class TangoRound"):]
    for field in ("a_payout", "b_payout", "a_payout_tweak", "b_payout_tweak"):
        assert f"{field}:" in body, field
    # One address, because it is the INSTANCE's and there is only one of those.
    assert "payout_sp_address:" in body


def test_each_sides_flag_is_read_from_that_sides_own_setting():
    """A's at propose, B's at accept, each from its own user id."""
    propose = _fn("views_api.py", "api_tango_propose")
    assert "a_payout, payout_addr = await _tango_routes_change(uid, " in propose
    assert "b_payout" not in propose, (
        "propose must not decide anything about B: B has not joined yet, and "
        "its setting is read when it does"
    )
    accept = _fn("views_api.py", "api_tango_accept")
    assert "b_payout, b_payout_addr = await _tango_routes_change(uid, " in accept
    # And accept must not touch A's, which a signature already depends on.
    assert "a_payout=" not in accept


def test_a_side_that_did_not_route_supplies_its_own_change_script():
    """The whole of "optional". B without an address sends change_spk and it
    is required; B with one is refused for sending it."""
    accept = _fn("views_api.py", "api_tango_accept")
    assert "elif amounts[\"b_change\"] and not data.change_spk:" in accept
    assert "this needs a change script" in accept
    # The routed branch is the one that refuses a client-supplied script.
    assert "ROUTED_CHANGE_IS_OURS_TO_DERIVE" in accept

    sign = _fn("views_api.py", "api_tango_sign")
    assert "if rnd.a_payout:" in sign
    # The else branch is A keeping its change: its own script, validated.
    assert 'validate_spk(data.change_spk or "", "change_spk")' in sign


def test_only_the_routing_side_gets_a_derived_script():
    """Derivation is keyed by role, and the two roles get different outputs —
    PAYOUT_K is 0 for a and 1 for b, so a round where both route does not pay
    the same script twice."""
    # Read from source: importing helpers.tangochange pulls in wallet.py,
    # which imports lnbits — the host application, not a dependency.
    src = (ROOT / "helpers" / "tangochange.py").read_text()
    line = next(ln for ln in src.splitlines() if ln.startswith("PAYOUT_K"))
    k = ast.literal_eval(line.split("=", 1)[1].strip())
    assert k["a"] != k["b"], k
    # BOTH are derived at accept, which is where the input set freezes.
    accept = _fn("views_api.py", "api_tango_accept")
    assert 'if b_payout and amounts["b_change"]:' in accept
    assert '_tango_payout_change_spk(rnd, "b", frozen)' in accept
    assert 'if rnd.a_payout and amounts["a_change"]:' in accept
    assert '_tango_payout_change_spk(rnd, "a", frozen)' in accept
    # And NOT at sign. See test_a_routed_output_exists_before_its_owner_signs.
    sign = _fn("views_api.py", "api_tango_sign")
    assert "_tango_payout_change_spk(" not in sign


def test_a_payout_row_is_created_only_for_the_side_that_routed():
    """Otherwise the instance would owe a Lightning payout to somebody whose
    change went to their own wallet, or — worse — hold a coin it never routed
    and create nothing."""
    body = _fn("views_api.py", "enqueue_tango_payouts")
    assert "(\"a\", rnd.a_payout, rnd.a_change_spk" in body
    assert "(\"b\", rnd.b_payout, rnd.b_change_spk" in body
    assert "if not routed or not spk or not change or not user_id:" in body
    assert "continue" in body


def test_labelling_skips_only_the_routed_sides_change():
    """A routed change is not that side's coin, so there is nothing in their
    wallet to label. The side that kept its change still gets labelled."""
    body = _fn("views_api.py", "_tango_label_change")
    assert "None if rnd.a_payout else rnd.a_change_spk" in body
    assert "None if rnd.b_payout else rnd.b_change_spk" in body


def test_a_routed_output_exists_before_its_owner_signs():
    """A COULD NOT APPROVE ITS OWN ROUND, and would never have been able to.

    A's routed change was derived inside A's own /sign call. A fetches the
    round, verifies it and assembles the transaction BEFORE signing, so at
    that moment a_payout_tweak was still null: the client saw an unrouted
    round, compared it against its own record saying it had asked to route,
    and refused with "This Tango keeps your change in your wallet, but you
    asked for it to be sent over Lightning." Pressing Approve again said the
    same thing, because nothing could change it until A signed — which it
    could not do. A 691 sat change with both sides routing, 2026-10-03.

    Everything the derivation needs exists at accept: the input set freezes
    when B accepts, and a_payout was snapshotted at propose. So both outputs
    are on the round from ACCEPTED, which is what each side reads to verify.
    """
    accept = _fn("views_api.py", "api_tango_accept")
    # Written by the same update that sets ACCEPTED, so a client that fetches
    # the round at any point after it can see both.
    assert "a_change_spk=a_change_spk" in accept
    assert "a_payout_tweak=a_payout_tweak" in accept
    assert "b_payout_tweak=b_payout_tweak" in accept
    # From the frozen set, which is both sides' inputs.
    assert "frozen = _pj_payjoin_inputs(a_rows) + _pj_payjoin_inputs(rows)" in accept


def test_signing_keeps_the_output_it_was_verified_against():
    """A's signature is computed over the outputs as A read them. Re-deriving
    at sign could replace one — a changed instance address, a different tweak
    — under a signature already made over the old one."""
    sign = _fn("views_api.py", "api_tango_sign")
    assert "a_change_spk = rnd.a_change_spk" in sign
    assert "a_payout_tweak = rnd.a_payout_tweak" in sign
    # The refusal of a client-supplied script stays: a routed output is the
    # instance's to derive, and only it can.
    assert "ROUTED_CHANGE_IS_OURS_TO_DERIVE" in sign
