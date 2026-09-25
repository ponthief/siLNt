"""A coin's spend state, and the two ways it used to get stuck.

'unconfirmed_spent' is provisional: the spend is broadcast but not yet in a
block, so it can still be undone if the transaction never lands. Something has
to come back and settle it — reconcile_unconfirmed_spent does, at the end of
every scan.

STUCK THE FIRST WAY. That reconciler is part of a scan, so a coin whose spend
confirmed AFTER the last scan sits provisional indefinitely. The one button
offered for it is Restore, which checks the spending transaction, finds it
confirmed, and refuses — correctly, and without writing down what it just
learned. The coin stays in the wallet as neither spent nor spendable, and the
button keeps refusing.

STUCK THE SECOND WAY, nearly shipped. The Tango guard that repairs a stale
record wrote a placeholder txid when the explorer named no spender. The
reconciler asks the explorer about whatever is in spent_in_txid, would get
nothing back for a placeholder, read that as a spend that never happened, and
restore a genuinely spent coin to spendable — which is worse than the bug it
was added for, and it fails silently.
"""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
VIEWS = (ROOT / "views_api.py").read_text()
SCAN = (ROOT / "helpers" / "scan.py").read_text()


def body_of(src: str, start: str, end: str = "@silnt_api_router") -> str:
    at = src.index(start)
    return src[at : src.index(end, at + len(start))]


def code_of(src: str, start: str, end: str = "@silnt_api_router") -> str:
    """The same, with comments stripped.

    A check for a placeholder txid matched the comment WARNING about the
    placeholder. Prose that names the thing it is avoiding is the point of the
    prose; the assertion has to look at the code.
    """
    return "\n".join(
        line
        for line in body_of(src, start, end).splitlines()
        if not line.lstrip().startswith("#")
    )


# ── restore settles what it discovers ────────────────────────────────────────


def test_restore_records_a_spend_it_finds_confirmed():
    """It already fetched the answer in order to refuse. Not writing it down is
    what leaves the coin provisional forever."""
    body = body_of(VIEWS, "async def api_restore_utxo")
    confirmed = body.index('status.get("confirmed")')
    assert "mark_utxos_confirmed_spent_by_tx(" in body[confirmed:], (
        "restore refuses a confirmed spend without finalising the row"
    )


def test_restore_still_refuses_to_restore_it():
    """Finalising is not restoring. The coin is genuinely gone."""
    body = body_of(VIEWS, "async def api_restore_utxo")
    confirmed = body.index('status.get("confirmed")')
    after = body[confirmed:]
    assert "HTTPStatus.CONFLICT" in after
    assert after.index("HTTPStatus.CONFLICT") > after.index(
        "mark_utxos_confirmed_spent_by_tx("
    ), "the refusal is raised before the row is settled"


def test_restore_leaves_a_pending_spend_alone():
    """Still in the mempool means still undoable: settling it would throw away
    the one state that can be reversed."""
    body = body_of(VIEWS, "async def api_restore_utxo")
    pending = body.index("still pending in the mempool")
    # Between the pending branch and the end, nothing finalises anything.
    assert "mark_utxos_confirmed_spent_by_tx(" not in body[pending:]


def test_the_balance_is_recomputed_when_a_row_is_settled():
    """A coin moving out of 'unconfirmed_spent' does not change the spendable
    total, but the balance column is derived from these rows and drifting it is
    how a wallet starts disagreeing with itself."""
    body = body_of(VIEWS, "async def api_restore_utxo")
    confirmed = body.index('status.get("confirmed")')
    after = body[confirmed : body.index("HTTPStatus.CONFLICT", confirmed)]
    assert "update_balance(" in after


# ── the repair never invents a spender ───────────────────────────────────────


def test_the_tango_repair_only_records_a_real_spending_txid():
    """A placeholder in spent_in_txid is worse than no record: the reconciler
    would read it as a spend that never happened and hand a spent coin back."""
    body = code_of(
        VIEWS,
        "async def _refuse_spent_tango_inputs",
        "async def _refuse_tango_reserved",
    )
    assert '"unknown"' not in body, "a placeholder txid is written"
    assert 'res.get("spent_by")' in body
    assert "spending_txid=spender" in body


def test_a_coin_with_no_named_spender_is_still_refused():
    """Not being able to record it is not a reason to let the round proceed:
    the coin is gone either way."""
    body = body_of(
        VIEWS,
        "async def _refuse_spent_tango_inputs",
        "async def _refuse_tango_reserved",
    )
    # The outpoint joins `mine` before the spender is considered at all.
    assert body.index('mine.append(f"{t}:{v}")') < body.index('res.get("spent_by")')


def test_the_repair_settles_a_spend_that_is_already_in_a_block():
    """Otherwise it creates exactly the stuck row this file is about."""
    body = body_of(
        VIEWS,
        "async def _refuse_spent_tango_inputs",
        "async def _refuse_tango_reserved",
    )
    assert "mark_utxos_confirmed_spent_by_tx(" in body
    assert 'res.get("confirmed")' in body


def test_the_outspend_check_reports_confirmation():
    """Which record to write depends on it, so it has to come back."""
    body = SCAN[SCAN.index("async def get_outspend_status") :][:2000]
    assert '"confirmed"' in body
    assert '(data.get("status") or {}).get("confirmed")' in body
    assert '"spent_by"' in body


def test_an_unanswerable_outpoint_is_left_alone():
    """Not knowing is not evidence. A 404 or a timeout must not refuse a round
    or rewrite a coin's state."""
    body = SCAN[SCAN.index("async def get_outspend_status") :][:2000]
    assert "if r.status_code == 404:" in body
    assert "return None" in body
