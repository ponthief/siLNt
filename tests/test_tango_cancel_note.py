"""An optional line from whoever cancelled a Tango.

WHY IT IS A SECOND COLUMN. reject_reason is state: "cancelled by a",
"expired", "connection removed", parsed by helpers/tango.who_cancelled and
again by the clients' tangoTurns.ts so the same stored value reads "You
cancelled it" to one party and "alice cancelled it" to the other. A sentence
somebody typed in there would make who_cancelled return None on both sides at
once, and the round would read "Cancelled — ran out of time" to everybody.

TWO THINGS THIS GUARDS, and they pull in opposite directions:

 * The cancellation must land even if the note does not. Cancelling is what
   gives both sides' coins back — a live round holds them out of the next
   Tango — so the status is written on its own and the note follows.
 * The note must not go in the push. A push carries its title and body
   through Google in plaintext, which is why no amount is ever in one; the
   other party's sentence about a mix is no more ours to send that way.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _pure(*names):
    """Named functions out of helpers/tango.py, by AST, so they can be RUN.

    The module cannot be imported here — it pulls in wallet.py, which imports
    lnbits, the host application. test_tango.py builds a loader for that; this
    file needs three pure functions and their literal constants, so it takes
    those nodes and nothing else. Asserting on source text instead would not
    catch an inverted comparison or an off-by-one cap.
    """
    tree = ast.parse((ROOT / "helpers" / "tango.py").read_text())
    body = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and all(
            isinstance(t, ast.Name) for t in node.targets
        ):
            try:
                ast.literal_eval(node.value)
            except ValueError:
                continue
            body.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            body.append(node)
    got = {n.name for n in body if isinstance(n, ast.FunctionDef)}
    assert got == set(names), got
    ns: dict = {"Optional": object}
    exec(ast.unparse(ast.Module(body=body, type_ignores=[])), ns)
    return ns


def _clean():
    ns = _pure("clean_cancel_note")
    return ns["clean_cancel_note"], ns["CANCEL_NOTE_MAX"]


def _fn(path: str, name: str) -> str:
    src = (ROOT / path).read_text()
    at = src.index(f"def {name}(")
    nxt = src.find("\nasync def ", at + 10)
    other = src.find("\ndef ", at + 10)
    dec = src.find("\n@silnt_api_router", at + 10)
    ends = [i for i in (nxt, other, dec) if i != -1]
    return src[at:min(ends)] if ends else src[at:]


@pytest.mark.parametrize("empty", [None, "", "   ", "\n\n", "\t "])
def test_nothing_to_say_stores_nothing(empty):
    """The field is optional, and a blank one must not write an empty string —
    the clients show the note only when there is one."""
    clean, _ = _clean()
    assert clean(empty) is None


def test_a_note_is_kept_as_one_line():
    clean, _ = _clean()
    assert clean("  changed my\n\n mind  ") == "changed my mind"


def test_whitespace_is_collapsed_before_the_cap():
    """Otherwise a note padded with newlines pushes its own words past the cap
    and arrives truncated to nothing, and a note can lay out lines of its own
    in the other party's round list."""
    clean, cap = _clean()
    out = clean(("\n" * 500) + "sorry")
    assert out == "sorry"
    out = clean("x " * 400)
    assert len(out) <= cap


def test_the_cap_is_short_on_purpose():
    _, cap = _clean()
    assert 0 < cap <= 300, cap


def test_a_long_note_is_cut_not_refused():
    """Refusing it would fail a cancellation over a sentence."""
    clean, cap = _clean()
    out = clean("a" * (cap + 50))
    assert out == "a" * cap


# ── the endpoint ────────────────────────────────────────────────────────────


def test_the_body_is_optional():
    """A client that predates the field, and one whose user left it empty,
    both POST nothing at all."""
    body = _fn("views_api.py", "api_tango_cancel")
    assert "data: Optional[CancelTangoData] = Body(None)" in body
    assert "data.note if data else None" in body


def test_the_cancellation_lands_before_the_note():
    """The status frees both sides' coins. The note is worth nothing beside
    that, so it is a second statement and its failure is survivable."""
    body = _fn("views_api.py", "api_tango_cancel")
    status_at = body.index('status="CANCELLED"')
    note_at = body.index("cancel_note=note")
    assert status_at < note_at, "the note must not share the status update"
    assert "except Exception" in body[note_at:]
    # Said out loud. This repo has a case of a best-effort write failing
    # silently on Postgres for weeks.
    assert "logger.warning" in body[note_at:]


def test_the_note_never_goes_in_the_push():
    body = _fn("views_api.py", "api_tango_cancel")
    push = body[body.index("_notify_tango("):]
    assert "note" not in push.split(")")[0], push.split(")")[0]
    assert '"The other side cancelled a Tango."' in push


def test_reject_reason_still_says_only_who():
    """If the note ever leaked into it, who_cancelled would stop working on
    both the server and the two clients at once."""
    body = _fn("views_api.py", "api_tango_cancel")
    assert "reject_reason=cancelled_by(role)" in body
    assert "reject_reason=note" not in body
    # And the parser is unchanged: a bare side, nothing more.
    ns = _pure("cancelled_by", "who_cancelled")
    cancelled_by, who_cancelled = ns["cancelled_by"], ns["who_cancelled"]
    for role in ("a", "b"):
        assert who_cancelled(cancelled_by(role)) == role
    assert who_cancelled("cancelled by a: ran out of time") is None


def test_the_column_is_nullable_and_separate():
    src = (ROOT / "migrations.py").read_text()
    body = src[src.index("async def m039_tango_cancel_note"):]
    assert "ADD COLUMN IF NOT EXISTS cancel_note TEXT" in body
    assert "NOT NULL" not in body.split("await db.execute")[1]
    # The collision with the Lightning branch's m039 was resolved by keeping
    # this number and moving those up; the reasoning stays where somebody
    # renumbering again would see it.
    assert "MERGE NOTE, now resolved" in body
    # And IF NOT EXISTS, because an instance that ran the OLD numbering is
    # already past 039 and arrives at these in a different order.
    assert "IF NOT EXISTS" in body


def test_the_migration_numbers_are_unique_and_in_order():
    """THE THING THAT SILENTLY BREAKS A DATABASE.

    LNbits records the migration NUMBER, not its name. Two functions sharing
    one number means whichever an instance runs first makes the other
    unreachable on that instance forever — no error, no log, just a column or
    a table that never appears. That is what merging this branch's
    m039_tango_cancel_note with the Lightning work's m039_tango_ln_address
    would have done, and it is why those moved to m040–m043.

    Gaps are not the same hazard and this repo has two of them (18 and 29,
    from migrations removed long ago): LNbits runs the functions that exist,
    in order, and records the highest. A number used TWICE is the problem.
    """
    import re

    src = (ROOT / "migrations.py").read_text()
    nums = [int(m) for m in re.findall(r"^async def m(\d+)_", src, re.M)]
    assert nums, "no migrations found"
    assert len(nums) == len(set(nums)), (
        f"duplicate migration numbers: "
        f"{sorted(n for n in nums if nums.count(n) > 1)}"
    )
    assert nums == sorted(nums), "migrations are out of order in the file"


def test_the_column_is_guaranteed_whatever_order_an_instance_arrived_in():
    """The repair for a hazard that already happened.

    m039 adds cancel_note, but an instance that ran the Lightning branch's own
    m039 is already past 039 and never runs it. The column is then missing for
    good there: the note write fails every time and the reason somebody typed
    is dropped without a word. m044 adds it above the whole range, IF NOT
    EXISTS, so every instance reaches it and the ones that already have it pay
    nothing.
    """
    src = (ROOT / "migrations.py").read_text()
    body = src[src.index("async def m044_tango_cancel_note_backfill"):]
    assert "ADD COLUMN IF NOT EXISTS cancel_note TEXT" in body
    # Above everything else, or an instance past that number skips it too.
    import re
    nums = [int(m) for m in re.findall(r"^async def m(\d+)_", src, re.M)]
    assert max(nums) == 44, nums
    # And m039 stays: an instance that ran it must not run it again.
    assert "async def m039_tango_cancel_note" in src


def test_a_note_that_could_not_be_stored_is_reported():
    """Not only logged. Somebody who types a reason and is told the round was
    cancelled has every reason to think the reason went with it."""
    body = _fn("views_api.py", "api_tango_cancel")
    assert "note_saved = True" in body
    assert "note_saved = False" in body
    assert '"note_saved": note_saved' in body
    # The cancellation itself still succeeds — it is what frees the coins.
    assert "raise" not in body.split("note_saved = False")[1]
