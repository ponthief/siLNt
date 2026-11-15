"""Starting a different authenticator must not kill the one that works.

Reported 2026-11-15: after turning 2FA off, pressing "Use a different app"
left no way back to the screen for the existing app. The UI had no route back,
but the server had a worse problem under it: `start_twofa_totp` overwrote
`totp_secret` and reset `totp_confirmed` the moment the option was pressed, so
the existing app's codes were already dead and there was nothing to go back TO.

The real crud functions run here against a real SQLite, because every failure
is a round-trip: a secret that was overwritten still "exists", and only reading
it back after the sequence tells you whether it is the one that was confirmed.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
import sqlite3
import time
from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent


class _Db:
    """The two calls crud makes, over sqlite with a `silnt` schema attached."""

    def __init__(self):
        self.c = sqlite3.connect(":memory:")
        self.c.row_factory = sqlite3.Row
        self.c.execute("ATTACH DATABASE ':memory:' AS silnt")
        self.c.execute(
            """CREATE TABLE silnt.twofa (
                 user_id TEXT PRIMARY KEY, totp_secret TEXT,
                 totp_confirmed INTEGER NOT NULL DEFAULT 0,
                 enabled INTEGER NOT NULL DEFAULT 0, last_counter BIGINT,
                 created_at INTEGER NOT NULL, pending_secret TEXT)"""
        )
        self.c.execute(
            "CREATE TABLE silnt.twofa_sessions (token_hash TEXT PRIMARY KEY, "
            "user_id TEXT, expires_at INTEGER)"
        )
        self.c.execute(
            "CREATE TABLE silnt.twofa_codes (user_id TEXT PRIMARY KEY, "
            "code_hash TEXT, expires_at INTEGER, attempts INTEGER)"
        )

    async def execute(self, sql, params=None):
        return self.c.execute(sql, params or {})

    async def fetchone(self, sql, params=None):
        return self.c.execute(sql, params or {}).fetchone()


def _crud():
    src = (ROOT / "crud.py").read_text()
    block = src[src.index("async def get_twofa("):src.index("# ── Sessions")]
    ns = {"db": _Db(), "time": time, "Optional": Optional}
    exec(block, ns)
    return ns


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _confirmed_and_off(ns, secret="OLDAPP"):
    run(ns["start_twofa_totp"]("u", secret))
    run(ns["confirm_twofa_totp"]("u", 100))
    run(ns["disable_twofa"]("u"))
    row = run(ns["get_twofa"]("u"))
    assert row["totp_secret"] == secret and row["totp_confirmed"] and not row["enabled"]


def test_starting_a_different_app_leaves_the_confirmed_one_alone():
    ns = _crud()
    _confirmed_and_off(ns)
    run(ns["start_twofa_totp"]("u", "NEWAPP"))
    row = run(ns["get_twofa"]("u"))
    # The reported failure: this was NEWAPP and unconfirmed.
    assert row["totp_secret"] == "OLDAPP"
    assert row["totp_confirmed"] is True
    assert row["pending_secret"] == "NEWAPP"
    assert row["enabled"] is False


def test_going_back_to_the_existing_app_still_works():
    ns = _crud()
    _confirmed_and_off(ns)
    run(ns["start_twofa_totp"]("u", "NEWAPP"))
    # A code from the EXISTING app confirms against totp_secret, and the
    # abandoned replacement is dropped so a stale QR cannot be confirmed later.
    run(ns["confirm_twofa_totp"]("u", 200))
    row = run(ns["get_twofa"]("u"))
    assert row["enabled"] is True
    assert row["totp_secret"] == "OLDAPP"
    assert row["pending_secret"] is None


def test_confirming_the_replacement_makes_it_the_secret():
    ns = _crud()
    _confirmed_and_off(ns)
    run(ns["start_twofa_totp"]("u", "NEWAPP"))
    run(ns["confirm_twofa_totp"]("u", 300, promote=True))
    row = run(ns["get_twofa"]("u"))
    assert (row["totp_secret"], row["pending_secret"]) == ("NEWAPP", None)
    assert row["enabled"] is True and row["totp_confirmed"] is True
    assert row["last_counter"] == 300


def test_promoting_with_nothing_pending_changes_nothing():
    ns = _crud()
    _confirmed_and_off(ns)
    run(ns["confirm_twofa_totp"]("u", 400, promote=True))
    row = run(ns["get_twofa"]("u"))
    assert row["enabled"] is False
    assert row["totp_secret"] == "OLDAPP"


def test_first_time_setup_is_unchanged():
    """No confirmed app yet: the secret goes in `totp_secret`, unconfirmed, as
    it always did, and starting twice replaces the abandoned attempt."""
    ns = _crud()
    run(ns["start_twofa_totp"]("u", "FIRST"))
    run(ns["start_twofa_totp"]("u", "SECOND"))
    row = run(ns["get_twofa"]("u"))
    assert row["totp_secret"] == "SECOND"
    assert row["totp_confirmed"] is False and row["pending_secret"] is None


def test_a_secret_in_force_is_still_not_rotated_from_under_the_user():
    ns = _crud()
    run(ns["start_twofa_totp"]("u", "LIVE"))
    run(ns["confirm_twofa_totp"]("u", 1))
    try:
        run(ns["start_twofa_totp"]("u", "ATTACKER"))
    except ValueError:
        pass
    else:
        raise AssertionError("a live second factor was replaceable")
    row = run(ns["get_twofa"]("u"))
    assert row["totp_secret"] == "LIVE" and row["pending_secret"] is None


def test_the_endpoint_says_which_app_a_code_is_for():
    src = (ROOT / "views_api.py").read_text()
    at = src.index("async def api_twofa_totp_confirm")
    body = src[at:src.index("\n@silnt_api_router", at)]
    assert 'payload or {}).get("replace")' in body
    assert 'row["pending_secret"]' in body
    assert "promote=replace" in body


def test_the_migration_exists_and_is_idempotent():
    src = (ROOT / "migrations.py").read_text()
    nums = [int(m) for m in re.findall(r"^async def m(\d+)_", src, re.M)]
    assert 46 in nums and len(nums) == len(set(nums))
    body = src[src.index("async def m046_twofa_pending_secret"):]
    assert "ADD COLUMN IF NOT EXISTS pending_secret TEXT" in body


def test_the_admin_health_reads_do_not_walk_around_the_second_factor():
    """require_trusted_device_admin says a factor the admin surface walks
    around is a factor on the read paths only, and these two used the bare key
    check."""
    src = (ROOT / "views_api.py").read_text()
    for name in ("api_blindbit_health", "api_fulcrum_health"):
        at = src.index("async def " + name)
        head = src[at:src.index("):", at)]
        assert "Depends(require_trusted_device_admin)" in head, name
        assert "Depends(require_admin_key)" not in head, name
