"""The tamper sweep does not watch a BitMail its owner has removed.

Removing a BitMail deletes its DNS record on purpose and leaves the approved
request row (it keeps the wallet's lifetime cap and reserves the username). The
sweep walked every approved row whose wallet still existed, so each removed name
was resolved on every pass, found nothing published, and said so in the log -
two lines per sweep for two removed names (reported 2026-11-21). Nothing was
wrong; the sweep was checking something that is meant to be gone.

Read from source: importing views_api needs the host application.
"""

from __future__ import annotations

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _sweep() -> str:
    text = (ROOT / "views_api.py").read_text(encoding="utf-8")
    tree = ast.parse(text)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)
              and n.name == "_run_bitmail_tamper_sweep_inner")
    src = ast.get_source_segment(text, fn)
    return re.sub(r"#.*", "", src)


def test_the_row_carries_the_address_it_was_issued_for():
    sql = (ROOT / "crud.py").read_text(encoding="utf-8")
    i = sql.index("async def list_approved_bitmails")
    assert "address_id" in sql[i : i + 700]


def test_a_removed_bitmail_is_skipped_before_it_is_resolved():
    src = _sweep()
    skip = src.index("carried.strip().lower() != bitmail.lower()")
    resolve = src.index("bip353_resolve(bitmail)")
    assert skip < resolve, "the liveness check must come before the DNS lookup"
    assert "continue" in src[skip : skip + 120]


def test_liveness_is_read_from_the_address_or_the_wallet():
    src = _sweep()
    assert "get_wallet_address(aid)" in src          # a labeled address
    assert 'getattr(owner, "hr_address"' in src       # the base address


def test_doubt_keeps_checking_rather_than_skipping():
    """If liveness cannot be established the name is still verified: a skipped
    check is the one thing this sweep must not do quietly."""
    src = _sweep()
    assert "carried = bitmail" in src
