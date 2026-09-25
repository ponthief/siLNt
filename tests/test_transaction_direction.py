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


def _load():
    """transactions.py imports ..crud, which needs LNbits. Only `classify` is
    under test and it touches none of that, so the package parents are stubbed
    rather than the real ones imported."""
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
        setattr(crud, fn, lambda *a, **k: None)
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


classify = _load().classify


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
