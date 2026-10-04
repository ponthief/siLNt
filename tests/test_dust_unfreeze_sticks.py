"""Unfreezing a dust coin has to survive the next scan.

Reported 2026-10-04 as "updating the mobile app causes unfrozen coins to get
frozen again". The update was incidental. What follows an update is a restart
and a catch-up scan, and `_scan_wallet` ends by calling
`evaluate_dust_for_wallet` — which is where the coin went back under the lock.

The mechanism was a shadowed name. crud.py defined
`clear_utxo_freeze_manual` TWICE: once writing the override marker
(`freeze_reason = 'manual_unfrozen'`), and again, 27 lines later, writing
`freeze_reason = NULL`. Python keeps the later definition, so the endpoint
imported the one that erased the marker. The unfreeze itself worked — the coin
showed unfrozen, which is why this looked like it had stuck — and then the
next dust eval saw a below-threshold UTXO whose reason was NULL, read that as
"nobody has an opinion about this one", and auto-froze it.

Nothing about that is visible at the call site: both defs had the right name,
the right signature and a docstring saying the right thing. So the first test
here is not about dust at all. It is about the file containing one of each.

The marker is the whole mechanism — the dust classification does not change
when a user unfreezes a 400-sat coin, it is still dust, and the evaluator is
still right about that. `manual_unfrozen` is the record that the user was
asked and answered. Erase it and the answer is re-asked, silently, on every
scan.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
CRUD = (ROOT / "crud.py").read_text()
DUST = (ROOT / "helpers" / "dust_check.py").read_text()

FREEZE_HELPERS = (
    "set_utxo_freeze_auto",
    "set_utxo_freeze_manual",
    "clear_utxo_freeze_auto",
    "clear_utxo_freeze_manual",
    "normalize_unfrozen_override",
    "get_utxo_freeze_reason",
)


def _fn(src: str, name: str) -> str:
    """The body of one def, up to the next top-level def/class.

    `rindex`, not `index`: where a name is defined twice, the LAST one is what
    the importer gets, so that is the one these tests have to read. With
    `index` every assertion below passed against the broken file — they were
    reading the good definition while the endpoint called the bad one.
    """
    at = src.rindex(f"async def {name}(")
    ends = [
        i
        for i in (
            src.find("\nasync def ", at + 10),
            src.find("\ndef ", at + 10),
            src.find("\nclass ", at + 10),
        )
        if i != -1
    ]
    return src[at : min(ends)] if ends else src[at:]


def _code(src: str) -> str:
    """Drop `#` lines and the leading docstring of each def.

    The surviving `clear_utxo_freeze_manual` QUOTES the removed duplicate's
    `freeze_reason = NULL` in its docstring to explain what went wrong, and a
    bare grep matched that and reported the bug as still present.

    Only a docstring in the FIRST statement position is dropped: the SQL in
    this file is written as triple-quoted strings too, and a stripper that
    toggled on every `\"\"\"` would eat every UPDATE in the module.
    """
    out = []
    expect_doc = False
    in_doc = False
    quote = ""
    for line in src.split("\n"):
        stripped = line.strip()
        if in_doc:
            if quote in stripped:
                in_doc = False
            continue
        if stripped.startswith("#"):
            continue
        if expect_doc and stripped[:3] in ('"""', "'''"):
            expect_doc = False
            quote = stripped[:3]
            rest = stripped[3:]
            if quote not in rest:
                in_doc = True
            continue
        if stripped:
            expect_doc = bool(re.match(r"(async )?def .*:$", stripped))
        out.append(line)
    return "\n".join(out)


def test_each_freeze_helper_is_defined_exactly_once():
    """The bug, stated generally. A second def of any of these shadows the
    first with no error anywhere, and the caller cannot tell which it got."""
    for name in FREEZE_HELPERS:
        found = len(re.findall(rf"^async def {name}\(", CRUD, re.M))
        assert found == 1, f"{name} defined {found} times in crud.py"


def test_unfreezing_records_the_override():
    body = _code(_fn(CRUD, "clear_utxo_freeze_manual"))
    assert "freeze_reason = 'manual_unfrozen'" in body, body
    assert "frozen = FALSE" in body
    # Not NULL: NULL is "no opinion", which is what the evaluator auto-freezes.
    assert "freeze_reason = NULL" not in body, body


def test_unfreezing_clears_whoever_set_it():
    """An auto-freeze and a manual freeze both yield to the user. The UPDATE
    is keyed on the outpoint alone — no `AND freeze_reason = ...` — or a coin
    the dust eval froze could not be unfrozen from the app at all."""
    body = _code(_fn(CRUD, "clear_utxo_freeze_manual"))
    where = body[body.index("WHERE") :]
    assert "freeze_reason" not in where, where


def test_the_evaluator_leaves_an_overridden_coin_alone():
    """Still dust, still classified as dust — and not re-frozen."""
    body = _code(_fn(DUST, "evaluate_dust_for_wallet"))
    assert 'current_reason not in ("manual", "manual_unfrozen")' in body, body
    # The guard has to sit between reading the reason and setting the freeze,
    # not somewhere after it.
    read = body.index("get_utxo_freeze_reason(")
    guard = body.index("manual_unfrozen")
    freeze = body.index("set_utxo_freeze_auto(")
    assert read < guard < freeze, (read, guard, freeze)


def test_the_auto_freeze_refuses_on_its_own_too():
    """Second line of defence, in SQL. Even called unguarded,
    `set_utxo_freeze_auto` must not touch a coin carrying a user's answer:
    the evaluator's check is one `if` away from being edited out."""
    body = _code(_fn(CRUD, "set_utxo_freeze_auto"))
    where = body[body.index("WHERE") :]
    assert "freeze_reason IS NULL OR freeze_reason = 'auto'" in where, where


def test_the_override_is_dropped_only_when_the_coin_stops_being_dust():
    """The marker is not permanent — a coin that grows past the threshold (or
    a threshold that drops below it) has nothing left to override, and keeping
    the marker would exempt it from a LATER, legitimate auto-freeze."""
    normalize = _code(_fn(CRUD, "normalize_unfrozen_override"))
    assert "freeze_reason = 'manual_unfrozen'" in normalize[normalize.index("WHERE") :]

    body = _code(_fn(DUST, "evaluate_dust_for_wallet"))
    # It lives in the `else` — the not-dust branch — after the auto-freeze
    # release, never in the branch that freezes.
    branch = body[body.index("else:") :]
    assert "normalize_unfrozen_override(" in branch
    assert "normalize_unfrozen_override(" not in body[: body.index("else:")]


def test_the_endpoint_uses_the_recording_unfreeze():
    """And not a hand-rolled UPDATE beside it, which is how the duplicate got
    written in the first place."""
    api = _code((ROOT / "views_api.py").read_text())
    at = api.index("async def api_set_utxo_frozen(")
    body = api[at : at + 2000]
    assert "clear_utxo_freeze_manual(txid, vout)" in body, body
    assert "UPDATE silnt.utxos" not in body, body
