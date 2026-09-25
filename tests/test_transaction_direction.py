"""Which way a transaction went, when the wallet had inputs in it.

"It spent something, therefore it is a send" is true for an ordinary payment
and wrong for everything where both parties put coins in. A PayJoin's payee
contributes a coin of its own and still ends up ahead; a Tango's two sides each
put in and take back the same amount, so the net is only the fee share.

The first produced a row reading "Sent" beside a positive number. The second
produced a true number nobody could read: a 13,000 sat mix showing as -427,
under the label of whichever of its two coins sorted first.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent


# What the stubbed crud returns, per test. transactions.py binds the names at
# import, so they cannot be monkeypatched afterwards — each stub reads this
# instead, and a test fills in only the queries it cares about.
DB: dict = {}


def _stub(fn):
    async def call(*_a, **_k):
        return DB.get(fn, [] if fn.startswith("list_") or "get_wallet_" in fn else {})
    return call


def _load():
    """transactions.py imports ..crud, which needs LNbits, so the package
    parents are stubbed rather than the real ones imported. helpers/ keeps its
    real path: the module under test uses helpers.tango for real."""
    name = f"{ROOT.name}._transactions_for_tests"
    if name in sys.modules:
        return sys.modules[name]
    pkg = types.ModuleType(ROOT.name)
    pkg.__path__ = [str(ROOT)]
    sys.modules.setdefault(ROOT.name, pkg)
    crud = types.ModuleType(f"{ROOT.name}.crud")
    for fn in (
        "get_backend_config", "get_wallet_receives", "get_wallet_sends",
        "get_utxos_for_txid", "get_utxos_spent_in_tx", "get_owned_pubkeys",
        "list_plain_incoming", "clear_plain_incoming",
        "get_tango_txids_for_wallet",
    ):
        setattr(crud, fn, _stub(fn))
    sys.modules[f"{ROOT.name}.crud"] = crud
    helpers = types.ModuleType(f"{ROOT.name}.helpers")
    helpers.__path__ = [str(ROOT / "helpers")]
    sys.modules.setdefault(f"{ROOT.name}.helpers", helpers)

    spec = importlib.util.spec_from_file_location(
        f"{ROOT.name}.helpers.transactions", ROOT / "helpers" / "transactions.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    sys.modules[f"{ROOT.name}.helpers.transactions"] = mod
    spec.loader.exec_module(mod)
    return mod


_mod = _load()
classify = _mod.classify
list_wallet_transactions = _mod.list_wallet_transactions


def test_an_ordinary_payment_is_a_send():
    """100,000 in, 40,000 of change back: 60,000 left, fee included."""
    assert classify(100_000, 40_000) == ("send", -60_000)


def test_a_payment_with_no_change_is_still_a_send():
    assert classify(60_298, 0) == ("send", -60_298)


def test_a_payjoin_payee_is_a_receive():
    """The case that read "Sent" beside a positive number. The payee puts in a
    coin of 10,000 to make the inputs ambiguous and takes 35,000 back — its own
    coin plus the 25,000 it was paid."""
    kind, amount = classify(10_000, 35_000)
    assert kind == "receive"
    assert amount == 25_000


def test_a_tango_costs_only_the_fee_share():
    """The round that prompted this: 13,854 in, a 13,000 share and 427 of
    change back. The 427 that showed in the list was the fee, which happened to
    equal the change — arithmetically right and impossible to read."""
    assert classify(13_854, 13_427) == ("send", -427)


def test_a_clean_tango_costs_only_the_fee_share_too():
    """No change on this side: 13,427 in, the 13,000 share back."""
    assert classify(13_427, 13_000) == ("send", -427)


def test_a_consolidation_to_self_is_a_send_of_its_fee():
    assert classify(100_000, 99_500) == ("send", -500)


def test_a_break_even_transaction_is_a_send():
    """Cannot happen while fees exist, but it must not be called a receive of
    nothing: no coins arrived."""
    assert classify(50_000, 50_000) == ("send", 0)


def test_the_amount_is_signed_so_no_caller_has_to_negate_it():
    """The old code returned a positive net_out and negated it at the call
    site, which is how one branch ended up with the wrong sign."""
    for a, b in ((100_000, 0), (10_000, 35_000), (13_854, 13_427)):
        kind, amount = classify(a, b)
        assert (amount < 0) == (kind == "send"), (a, b)
        assert amount == b - a


# ── what a mix row carries, and what it no longer carries ────────────────────
# The row for signet 61511d8a…d27a as its acceptor saw it: 13,749 in, one
# 13,000 coin back, no change. It read "Mixed −749" beside THREE badges —
# "Tango with alice · 13,000 mixed", "Tango mix - alice · 2026-09-25" and
# "Tango change - alice · 2026-09-25" — which is one fact said three times, two
# of them about a change coin this side does not have.

import asyncio  # noqa: E402

MIX_TXID = "61511d8a53fc2ed4f5c33848547306638d63804feb19a8df917cb68591f6d27a"
PLAIN_TXID = "a" * 64


def rows(**db):
    DB.clear()
    DB.update(db)
    try:
        return asyncio.run(list_wallet_transactions("w1"))
    finally:
        DB.clear()


def mix_round(**over):
    base = {
        "denom_sats": 13_000,
        "partner": "alice",
        "fee_sats": 749,
        "change_sats": 0,
        "dust_to_fee": 322,
    }
    base.update(over)
    return base


def receive(txid, labels, output_sum, count=1):
    return {
        "txid": txid, "output_sum": output_sum, "output_count": count,
        "labels": labels, "timestamp": 1_700_000_000,
    }


def send(txid, input_sum, count=3):
    return {
        "txid": txid, "input_sum": input_sum, "input_count": count,
        "spent_at": 1_700_000_000, "pending_inputs": 0,
    }


def test_a_mix_row_says_it_is_a_mix_and_carries_its_round():
    (row,) = rows(
        get_wallet_receives=[receive(MIX_TXID, ["Tango mix - alice · 2026-09-25"], 13_000)],
        get_wallet_sends=[send(MIX_TXID, 13_749)],
        get_tango_txids_for_wallet={MIX_TXID: mix_round()},
    )
    assert row["kind"] == "tango"
    assert row["tango"]["denom_sats"] == 13_000
    assert row["tango"]["fee_sats"] == 749
    assert row["tango"]["dust_to_fee"] == 322


def test_the_net_is_still_the_truth_underneath():
    """The clients show the denomination now, but the row still reports what
    the balance did — the CSV and the detail view are built from it."""
    (row,) = rows(
        get_wallet_receives=[receive(MIX_TXID, [], 13_000)],
        get_wallet_sends=[send(MIX_TXID, 13_749)],
        get_tango_txids_for_wallet={MIX_TXID: mix_round()},
    )
    assert row["amount_sats"] == -749
    assert row["input_sum"] == 13_749 and row["output_sum"] == 13_000


def test_the_rounds_own_coin_labels_come_off_the_row():
    """Both of them, leaving the row with nothing to repeat."""
    (row,) = rows(
        get_wallet_receives=[receive(
            MIX_TXID,
            ["Tango mix - alice · 2026-09-25", "Tango change - alice · 2026-09-25"],
            16_073, count=2,
        )],
        get_wallet_sends=[send(MIX_TXID, 16_500)],
        get_tango_txids_for_wallet={MIX_TXID: mix_round(fee_sats=427, change_sats=3073,
                                                        dust_to_fee=0)},
    )
    assert row["labels"] == []


def test_a_label_the_user_wrote_on_a_mixed_coin_survives():
    """Dropping our own wording must not drop theirs — it is the only note on
    that coin, and the row is where they would look for it."""
    (row,) = rows(
        get_wallet_receives=[receive(
            MIX_TXID,
            ["Tango mix - alice · 2026-09-25", "rent money"], 13_000,
        )],
        get_wallet_sends=[send(MIX_TXID, 13_749)],
        get_tango_txids_for_wallet={MIX_TXID: mix_round()},
    )
    assert row["labels"] == ["rent money"]


def test_an_ordinary_row_keeps_every_label_it_had():
    """The stripping is scoped to mix rows. A coin labelled "Tango change" by
    hand on an unrelated transaction is not ours to touch."""
    (row,) = rows(
        get_wallet_receives=[receive(PLAIN_TXID, ["Tango change", "groceries"], 40_000)],
        get_wallet_sends=[send(PLAIN_TXID, 100_000)],
        get_tango_txids_for_wallet={},
    )
    assert row["kind"] == "send"
    assert row["labels"] == ["Tango change", "groceries"]


def test_a_round_the_server_never_recorded_a_fee_for_still_renders():
    """Rounds broadcast before those columns existed. The row must still say
    "mix" — the clients treat a missing fee as nothing to show, not as zero."""
    (row,) = rows(
        get_wallet_receives=[receive(MIX_TXID, [], 13_000)],
        get_wallet_sends=[send(MIX_TXID, 13_749)],
        get_tango_txids_for_wallet={
            MIX_TXID: {"denom_sats": 13_000, "partner": "alice"}
        },
    )
    assert row["kind"] == "tango"
    assert "fee_sats" not in row["tango"]
