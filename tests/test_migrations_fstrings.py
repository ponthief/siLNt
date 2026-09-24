"""Every migration's SQL is an f-string. A stray brace is therefore code.

This is not hypothetical and not subtle in hindsight. m031 carried a comment
reading

    -- The frozen input set: JSON arrays of {txid, vout, pub_key,
    -- amount}, public data only.

and because the whole CREATE TABLE is an f-string, Python read that as a set
literal and the migration died with `NameError: name 'txid' is not defined`.
LNbits does not start when a migration raises, so one brace in a comment took
the extension down. A second one, `JSON {index: hex}`, was waiting behind it.

Nothing catches this before the migration runs. It is valid Python — ast.parse
is happy, the module imports, the tests that do not execute migrations all
pass — and it only fails at the moment a real deployment applies it, which is
the worst possible time to find out.

So: every interpolation in every migration must be an attribute of `db`
(db.big_int, db.timestamp_now, db.reference_str …). That is the only thing
these statements legitimately interpolate, and anything else is either a brace
that escaped or a value that should not be pasted into SQL in the first place.

Read as source rather than by running the migrations, because running them
needs a database and the point is to fail in CI without one.
"""

from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _offenders(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for part in node.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            e = part.value
            is_db_attr = (
                isinstance(e, ast.Attribute)
                and isinstance(e.value, ast.Name)
                and e.value.id == "db"
            )
            if not is_db_attr:
                bad.append(f"line {part.lineno}: {ast.unparse(e)!r}")
    return bad


def test_migrations_only_interpolate_db_attributes():
    bad = _offenders(ROOT / "migrations.py")
    assert not bad, (
        "migrations.py interpolates something other than a db.* attribute:\n  "
        + "\n  ".join(bad)
        + "\n\nIf this is a brace inside an SQL comment, reword the comment — "
        "the statement is an f-string, so the brace is executed. If it is a "
        "real value, it should not be pasted into SQL."
    )


def test_the_check_would_have_caught_the_real_bug():
    """The guard is only worth having if it fails on the thing that happened.

    Same construct, same place: a JSON shape written into an SQL comment
    inside an f-string.
    """
    src = '''
async def m999(db):
    await db.execute(
        f"""
        CREATE TABLE x (
            -- inputs are JSON arrays of {txid, vout}
            a {db.big_int}
        );
        """
    )
'''
    tmp = ROOT / "tests" / "_fstring_probe.py"
    tmp.write_text(src, encoding="utf-8")
    try:
        bad = _offenders(tmp)
        assert bad, "the guard did not notice a brace in an SQL comment"
        assert any("txid" in b for b in bad), bad
    finally:
        tmp.unlink()


# ── and actually run them ────────────────────────────────────────────────────
#
# The AST check above catches a brace that became code. This catches the rest:
# any migration that raises when applied. Both are worth having, because the
# failure they prevent only ever surfaces on a real deployment — LNbits does
# not start when a migration raises, so the first person to find out is whoever
# restarted it.
#
# The stub records SQL and answers every query with nothing, which is enough
# for migrations that create, alter and drop. It is NOT a database: this says
# a migration executes, not that its SQL is valid on Postgres or SQLite.

import asyncio
import importlib.util
import sys
import types


class _FakeDB:
    """Just the surface the migrations use."""

    big_int = "BIGINT"
    timestamp_now = "CURRENT_TIMESTAMP"

    def __init__(self):
        self.sql: list[str] = []

    async def execute(self, q, *a, **k):
        self.sql.append(q)

    async def fetchall(self, *a, **k):
        return []

    async def fetchone(self, *a, **k):
        return None


def _load_migrations():
    for m in ("lnbits", "lnbits.utils", "lnbits.utils.crypto", "lnbits.db",
              "lnbits.helpers"):
        sys.modules.setdefault(m, types.ModuleType(m))
    sys.modules["lnbits.utils.crypto"].AESCipher = object
    sys.modules["lnbits.db"].Database = object
    sys.modules["lnbits.helpers"].urlsafe_short_hash = lambda: "x"
    name = "silnt_migrations_for_tests"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "migrations.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _migration_names(mod) -> list[str]:
    import inspect

    return sorted(
        n for n, f in vars(mod).items()
        if n.startswith("m") and inspect.iscoroutinefunction(f)
    )


def test_every_migration_runs():
    mod = _load_migrations()
    names = _migration_names(mod)
    assert len(names) >= 29, f"only found {names}"
    failures = []
    for n in names:
        try:
            asyncio.run(getattr(mod, n)(_FakeDB()))
        except Exception as e:  # noqa: BLE001 — the point is to report any of them
            failures.append(f"{n}: {type(e).__name__}: {e}")
    assert not failures, "migrations that raise:\n  " + "\n  ".join(failures)


def test_m031_creates_the_payjoin_table_and_its_indexes():
    """The one this file was written for. Named explicitly so a rename or an
    accidental deletion shows up as a missing test rather than a silent pass
    over 28 other migrations."""
    mod = _load_migrations()
    db = _FakeDB()
    asyncio.run(mod.m031_payjoin_sp_requests(db))
    joined = "\n".join(db.sql)
    assert "CREATE TABLE silnt.payjoin_sp_requests" in joined
    # The db attributes really were substituted, so a future migration that
    # hardcodes BIGINT instead of db.big_int is visible here.
    assert "BIGINT" in joined and "CURRENT_TIMESTAMP" in joined
    for idx in ("idx_payjoin_sp_payee", "idx_payjoin_sp_payer",
                "idx_payjoin_sp_status"):
        assert idx in joined, idx


def test_m034_clears_the_label_flag_on_broadcast_rounds_only():
    """It exists so the sweeper revisits rounds it already labelled, under the
    current wording. Scoped to BROADCAST: clearing the flag on a cancelled or
    still-running round would have the sweeper hunting for coins that do not
    exist."""
    mod = _load_migrations()
    db = _FakeDB()
    asyncio.run(mod.m034_relabel_tango_coins(db))
    joined = " ".join(" ".join(db.sql).split())
    assert "UPDATE silnt.tango_rounds" in joined
    assert "change_labelled = FALSE" in joined
    assert "WHERE status = 'BROADCAST'" in joined
    # Never a DELETE: the point is to redo work, not to drop rounds.
    assert "DELETE" not in joined.upper()
