"""A TIMESTAMP column is written by the database, never bound as a value.

WHY. `silnt.sp_contacts.last_used_at` is a TIMESTAMP, and `touch_sp_contact`
bound `int(time.time())` to it. SQLite stores whatever it is handed, so the
tests passed and a SQLite instance worked. Postgres refused every write:

    asyncpg.exceptions.DataError: invalid input for query argument $1:
    1790619858 (expected a datetime.date or datetime.datetime instance,
    got 'int')

and because the only caller is a best-effort `try/except` after a broadcast,
nothing surfaced. Sends went through, a warning went to the log, and saved
contacts silently never reordered — on every send, for as long as the column
existed.

migrations.py already states the convention in two places: TIMESTAMP columns
get `db.timestamp_now` (as a DEFAULT or in a `SET`), and anything computed in
Python is stored as epoch seconds in an INTEGER/BIGINT column. The bug was one
line that did neither.

Read from source rather than by running queries, for the same reason
test_migrations_fstrings.py does: the failure only ever appears on Postgres,
and CI has no Postgres. The point is to fail here instead.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

# SQL identifier characters, for the word boundaries below. `\b` is not enough:
# it would match `last_used_at` inside `wallet_last_used_at`.
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def _timestamp_columns() -> dict[str, set[str]]:
    """{table: {column, …}} for every column declared TIMESTAMP/TIMESTAMPTZ."""
    src = (ROOT / "migrations.py").read_text(encoding="utf-8")
    out: dict[str, set[str]] = {}

    for m in re.finditer(r"CREATE TABLE (?:IF NOT EXISTS )?(silnt\.\w+)\s*\(", src):
        # Balance the parentheses: a column type can carry its own, and the
        # table body is whatever sits inside the outermost pair.
        depth, i = 1, m.end()
        while i < len(src) and depth:
            depth += (src[i] == "(") - (src[i] == ")")
            i += 1
        for line in src[m.end():i - 1].splitlines():
            line = line.split("--")[0].strip().rstrip(",")
            parts = line.split()
            if len(parts) >= 2 and parts[1].upper().startswith("TIMESTAMP"):
                out.setdefault(m.group(1), set()).add(parts[0].strip('"'))

    for m in re.finditer(
        rf"ALTER TABLE (silnt\.\w+) ADD COLUMN\s+(?:IF NOT EXISTS\s+)?\"?({_IDENT})\"?\s+(\w+)",
        src,
    ):
        if m.group(3).upper().startswith("TIMESTAMP"):
            out.setdefault(m.group(1), set()).add(m.group(2))

    return out


def _sources() -> list[pathlib.Path]:
    return [
        p for p in sorted(ROOT.rglob("*.py"))
        if "__pycache__" not in p.parts
        and p.name != "migrations.py"          # declares the columns
        and "tests" not in p.parts             # this file quotes the bad SQL
    ]


def test_the_migrations_declare_some_timestamp_columns():
    """The guard below is vacuous if the parse finds nothing, and a rewritten
    migrations.py would make it vacuous silently."""
    cols = _timestamp_columns()
    assert "silnt.sp_contacts" in cols, cols
    assert "last_used_at" in cols["silnt.sp_contacts"]
    assert len(cols) >= 10, sorted(cols)


def _bound_param_offenders(paths) -> list[str]:
    every = {c for cols in _timestamp_columns().values() for c in cols}
    offenders = []
    for path in paths:
        src = path.read_text(encoding="utf-8", errors="replace")
        for col in sorted(every):
            for m in re.finditer(rf"(?<![A-Za-z0-9_]){col}\s*=\s*:(\w+)", src):
                line = src[: m.start()].count("\n") + 1
                offenders.append(f"{path.name}:{line}: {m.group(0)}")
    return offenders


def test_no_timestamp_column_is_set_from_a_bound_parameter():
    offenders = _bound_param_offenders(_sources())
    assert not offenders, (
        "a TIMESTAMP column is being assigned a bound parameter:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse f\"… SET col = {db.timestamp_now} …\" instead. Postgres wants "
        "a datetime and rejects an int; SQLite accepts either, so this passes "
        "locally and fails only in production."
    )


def test_the_check_would_have_caught_the_real_bug(tmp_path):
    """The guard is only worth having if it fails on the line that shipped.

    Verbatim from crud.py before the fix.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(
        'SQL = ("UPDATE silnt.sp_contacts SET last_used_at = :ts "\n'
        '       "WHERE user_id = :uid AND network = :net AND value_sha256 = :h")\n',
        encoding="utf-8",
    )
    offenders = _bound_param_offenders([probe])
    assert offenders == ["probe.py:1: last_used_at = :ts"], offenders


def test_the_check_is_not_fooled_by_a_longer_column_name(tmp_path):
    """`\\b` matches `last_used_at` inside `wallet_last_used_at`, which is a
    different column with a different type — and a guard that cries wolf is a
    guard that gets suppressed."""
    probe = tmp_path / "probe.py"
    probe.write_text(
        'SQL = "UPDATE t SET wallet_last_used_at = :ts, xcreated_at = :a"\n',
        encoding="utf-8",
    )
    assert _bound_param_offenders([probe]) == []


def test_no_timestamp_column_is_inserted_as_a_value():
    """The same mistake in an INSERT would not even be silent — it would take
    the whole statement down rather than a best-effort bump."""
    tables = _timestamp_columns()
    offenders = []
    for path in _sources():
        src = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"INSERT INTO\s+(silnt\.\w+)\s*\(([^)]*)\)", src, re.S):
            named = set(re.findall(_IDENT, m.group(2)))
            for col in sorted(tables.get(m.group(1), set()) & named):
                line = src[: m.start()].count("\n") + 1
                offenders.append(
                    f"{path.relative_to(ROOT)}:{line}: {m.group(1)}.{col}"
                )
    assert not offenders, (
        "a TIMESTAMP column is named in an INSERT column list:\n  "
        + "\n  ".join(offenders)
        + "\n\nLeave it out and let its DEFAULT db.timestamp_now fill it."
    )


def test_touch_sp_contact_lets_the_database_write_the_time():
    """The specific line this file exists for."""
    src = (ROOT / "crud.py").read_text(encoding="utf-8")
    body = src[src.index("async def touch_sp_contact"):]
    body = body[: body.index("\nasync def ", 10)]
    assert "SET last_used_at = {db.timestamp_now}" in body
    # And no value is bound for it. Read from the argument dict rather than the
    # whole function, whose comment quotes the old line on purpose.
    values = body[body.index("await db.execute("):]
    assert '"ts"' not in values


# ── the log line that said nothing ──────────────────────────────────────────


def _errors_module():
    spec = importlib.util.spec_from_file_location(
        "silnt_errors_for_tests", ROOT / "helpers" / "errors.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_an_exception_with_no_message_still_names_itself():
    """`str(httpx.ConnectTimeout())` is "", which is how production logged
    `[silnt] auto-refund loop error:` and nothing else."""
    exc_text = _errors_module().exc_text

    class ConnectTimeout(Exception):
        pass

    assert exc_text(ConnectTimeout()) == "ConnectTimeout"


def test_a_message_is_passed_through_with_its_type():
    exc_text = _errors_module().exc_text
    assert exc_text(ValueError("bad input")) == "ValueError: bad input"


def test_a_message_that_names_its_own_type_is_not_prefixed_twice():
    exc_text = _errors_module().exc_text

    class DataError(Exception):
        pass

    assert exc_text(DataError("DataError: invalid input")) == "DataError: invalid input"


def test_a_broken_repr_does_not_become_the_error():
    """It is called from except-blocks whose job is to not raise."""
    exc_text = _errors_module().exc_text

    class Awkward(Exception):
        def __str__(self):
            raise RuntimeError("nope")

    assert exc_text(Awkward()) == "Awkward"


def test_the_background_loops_use_it():
    src = (ROOT / "__init__.py").read_text(encoding="utf-8")
    assert "from .helpers.errors import exc_text" in src
    # Every loop, not just the refund one that showed up in the logs.
    assert "loop error: {exc}" not in src, "a loop still formats the raw exception"
    assert src.count("exc_text(exc)") >= 5


# ── a third party being down is not a 500 ───────────────────────────────────


def test_the_confirmation_poll_answers_when_mempool_is_unreachable():
    """It is polled every few seconds by every open app. An unhandled
    httpx.ConnectTimeout there wrote a full ASGI traceback with an Exception ID
    for what is mempool.space being slow."""
    src = (ROOT / "views_api.py").read_text(encoding="utf-8")
    body = src[src.index("async def api_tx_confirmation"):]
    body = body[: body.index("\n@silnt_api_router")]
    assert "except httpx.TimeoutException:" in body
    assert "except httpx.HTTPError as e:" in body
    assert "GATEWAY_TIMEOUT" in body and "BAD_GATEWAY" in body


def test_the_refund_pass_survives_an_unreachable_chain_height():
    src = (ROOT / "boltz_refund_api.py").read_text(encoding="utf-8")
    body = src[src.index("async def refund_due_swaps"):]
    assert "except httpx.HTTPError as exc:" in body
    # Returns rather than raises: the loop retries on its own schedule, and
    # nothing can be decided about refundability without a height anyway.
    guard = body[body.index("try:"): body.index("for state in")]
    assert "return results" in guard
