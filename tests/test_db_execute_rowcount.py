"""`db.execute` returns a CursorResult, not a number.

WHY THIS EXISTS. Sign-out threw on a live instance (2026-11-10):

    File ".../views_api.py", line 3124, in api_twofa_session_revoke
        return {"revoked": int(removed or 0)}
    TypeError: int() argument must be a string, a bytes-like object or a
    real number, not 'CursorResult'

`revoke_twofa_session` was written as `return await db.execute(...)` under an
`-> int` annotation. The annotation is a comment to Python, so nothing
complained; the first caller that did arithmetic on the result raised, and the
handler it raised in was the one that revokes a verified 2FA session.

THE CONSEQUENCE WAS NOT THE 500. The exception fired after
`clear_session_cookie`, so the Set-Cookie was discarded with the response the
handler never returned, and the row was never deleted either. Signing out
therefore left BOTH halves of the verified session alive server-side while the
client cleared its own copy — so the next sign-in in that browser would find
the cookie still valid and never ask for a code. A sign-out that does not sign
the second factor out is the one thing that endpoint is for.

The repo's own pattern, in `revoke_trusted_device` two hundred lines above the
offender, is `getattr(result, "rowcount", 0) or 0`. This pins it, and pins the
annotation that made the mistake invisible.

Narrow on purpose: a `return await db.execute(...)` is only wrong when the
caller wants a count, but it is never RIGHT — `db.execute` has nothing else
worth returning — so the shape is banned outright rather than inferred.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

SOURCES = ["crud.py", "views_api.py"] + [
    f"helpers/{p.name}" for p in sorted((ROOT / "helpers").glob("*.py"))
]


def _sources():
    for rel in SOURCES:
        path = ROOT / rel
        if path.exists():
            yield path


def test_nothing_returns_a_cursorresult():
    """THE REPORTED BUG, as a shape."""
    offenders = []
    for path in _sources():
        src = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"return\s+await\s+db\.execute\s*\(", src):
            offenders.append(f"{path.name}:{src[: m.start()].count(chr(10)) + 1}")
    assert not offenders, (
        "a function returns db.execute's CursorResult:\n  "
        + "\n  ".join(offenders)
        + '\n\nUse `result = await db.execute(...)` then '
        '`return getattr(result, "rowcount", 0) or 0`, as '
        "revoke_trusted_device does. An `-> int` annotation does not convert it, "
        "and the first caller that does arithmetic on it raises TypeError."
    )


def test_the_two_fa_revokes_count_rows_the_house_way():
    """Not just absent — written the way its neighbours are."""
    src = (ROOT / "crud.py").read_text(encoding="utf-8")
    for fn in (
        "revoke_twofa_session",
        "revoke_all_twofa_sessions",
        "purge_expired_twofa_sessions",
    ):
        body = src[src.index(f"async def {fn}(") :]
        body = body[: body.index("\nasync def ", 10)]
        assert 'getattr(result, "rowcount", 0)' in body, fn


def test_the_pattern_it_copies_is_still_there():
    """The guard is only meaningful while the thing it points at exists — a
    renamed `revoke_trusted_device` would leave the advice naming nothing."""
    src = (ROOT / "crud.py").read_text(encoding="utf-8")
    body = src[src.index("async def revoke_trusted_device(") :]
    body = body[: body.index("\nasync def ", 10)]
    assert 'getattr(result, "rowcount", 0) or 0' in body


def test_the_check_would_have_caught_the_real_line(tmp_path):
    """Verbatim from crud.py before the fix. A guard that does not fail on the
    line that shipped is a guard that proves nothing."""
    probe = tmp_path / "crud.py"
    probe.write_text(
        "async def revoke_twofa_session(user_id: str, token: str) -> int:\n"
        "    if not token:\n"
        "        return 0\n"
        "    return await db.execute(\n"
        '        "DELETE FROM silnt.twofa_sessions WHERE token_hash = :th",\n'
        '        {"th": token},\n'
        "    )\n",
        encoding="utf-8",
    )
    found = re.findall(r"return\s+await\s+db\.execute\s*\(", probe.read_text())
    assert len(found) == 1


def test_it_does_not_flag_an_awaited_execute_whose_result_is_dropped(tmp_path):
    """Most callers want nothing back, and `await db.execute(...)` on its own
    line is correct everywhere in this tree. A guard that cried wolf on those
    would be suppressed within a day."""
    probe = tmp_path / "crud.py"
    probe.write_text(
        "async def touch(uid: str) -> None:\n"
        '    await db.execute("UPDATE t SET a = 1 WHERE id = :uid", {"uid": uid})\n',
        encoding="utf-8",
    )
    assert not re.findall(r"return\s+await\s+db\.execute\s*\(", probe.read_text())
