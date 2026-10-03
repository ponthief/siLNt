"""A send's own change must not be announced as a payment received.

WHAT HAPPENED. Sending from the phone with change left over produced the
"Payment received" banner. The change output is a new UTXO in the sender's own
wallet, the scan counted it as a find, and both notify sites fired on the find
count. So every send with change told the sender somebody had paid them —
and nothing in the banner could distinguish it from a real payment, because
the push is deliberately generic (no amount, no wallet, no count: it passes
through Google in plaintext).

THE DISTINCTION IS THE LABEL. BIP-352 reserves m=0 for change, and this wallet
also still scans the m=1 it used before that was fixed. An unlabelled output
is a payment to the base address; m>=2 is a sub-address handed out to be paid
at. Only the change label is the wallet paying itself.

Change is still a FIND — it is a spendable coin, the balance counts it and the
UI says so. It is only not a payment anybody made.

Read from source where the module cannot be imported: helpers/scan.py pulls in
wallet.py, which imports lnbits — the host application, not a dependency.
"""

from __future__ import annotations

import pathlib
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _fn(path: str, name: str) -> str:
    src = (ROOT / path).read_text()
    at = src.index(f"def {name}(")
    nxt = src.find("\nasync def ", at + 10)
    other = src.find("\ndef ", at + 10)
    dec = src.find("\n@silnt_api_router", at + 10)
    ends = [i for i in (nxt, other, dec) if i != -1]
    return src[at:min(ends)] if ends else src[at:]


# ── the rule itself, run rather than read ───────────────────────────────────


def _is_own_change():
    """is_own_change, lifted out of scan.py by AST so it can be CALLED.

    Two nodes, exec'd on their own: the frozenset of change label indices and
    the function that reads it. Importing the module is not possible here, and
    asserting on its source text would not catch an inverted comparison.
    """
    import ast

    tree = ast.parse((ROOT / "helpers" / "scan.py").read_text())
    wanted = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "is_own_change":
            wanted.append(node)
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "CHANGE_LABEL_INDICES"
                for t in node.targets
            )
        ):
            wanted.append(node)
    assert len(wanted) == 2, [type(n).__name__ for n in wanted]
    ns: dict = {
        "BIP352_CHANGE_LABEL_INDEX": 0,
        "BIP352_LEGACY_CHANGE_LABEL_INDICES": [1],
    }
    exec(ast.unparse(ast.Module(body=wanted, type_ignores=[])), ns)
    return ns["is_own_change"]


def _owned(m):
    return types.SimpleNamespace(label=None if m is None else types.SimpleNamespace(m=m))


@pytest.mark.parametrize("m", [0, 1])
def test_a_change_label_is_our_own_change(m):
    """m=0 is BIP-352's change label; m=1 is what this wallet used before that
    was corrected, and those coins still exist."""
    assert _is_own_change()(_owned(m)) is True


@pytest.mark.parametrize("m", [None, 2, 3])
def test_everything_else_is_somebody_paying_us(m):
    """No label is the base address. m>=2 is a sub-address given out to be paid
    at. Both are payments, and both must still notify."""
    assert _is_own_change()(_owned(m)) is False


# ── and the wiring, which is where it went wrong ────────────────────────────


def test_the_scan_reports_the_two_counts_apart():
    src = (ROOT / "helpers" / "scan.py").read_text()
    for key in ('"utxos_found"', '"amount_found"',
                '"utxos_incoming"', '"amount_incoming"'):
        assert key in src, key
    # The split is made from the rows that were actually new. Counting every
    # detected output would re-announce a payment on each rescan.
    assert "not in new_keys" in src


def test_insert_says_which_rows_were_new():
    body = _fn("crud.py", "insert_utxos_for_wallet")
    assert "new_keys.add((row[\"txid\"], int(row[\"vout\"])))" in body
    assert "return newly_inserted, newly_amount, new_keys" in body
    # Only on the insert path: a re-detected UTXO is an upsert, not news.
    assert "if not already:" in body


def test_both_notify_sites_use_the_incoming_count():
    """There are two — the interactive scan on app open and the background
    sweep — and the bug was in both, because they were written from each
    other."""
    src = (ROOT / "views_api.py").read_text()
    hits = [
        ln for ln in src.splitlines()
        if "_notify_payment_found(" in ln and "async def" not in ln
    ]
    assert len(hits) == 2, hits
    # The guard above each one reads the incoming count.
    assert src.count('"utxos_incoming", 0') == 2, src.count('"utxos_incoming", 0')
    assert src.count('.get("amount_incoming")') == 2
    # And neither notifies on the raw find count any more.
    for ln in src.splitlines():
        if "utxos_found" in ln and not ln.strip().startswith("#"):
            pytest.fail(f"views_api still reads utxos_found: {ln.strip()}")


def test_the_push_still_says_nothing_about_the_money():
    """Unchanged, and worth keeping checked while this code is being edited:
    FCM carries the title and body through Google in plaintext."""
    body = _fn("views_api.py", "_notify_payment_found")
    assert '"Payment received"' in body
    for leak in ("new_found", "amount_sats", "{wallet"):
        assert f"{leak}}}" not in body, leak
