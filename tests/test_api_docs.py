"""The API reference is generated, and the generation is the thing to pin.

A hand-kept endpoint list is wrong the first time somebody adds a route and
nobody notices, and a reference that is quietly wrong is worse than none
because it is believed. These assert the half that decides what an operator
reads — grouping, summarising, access badges, ordering — without needing
FastAPI or a running app.
"""

import ast
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _apidocs():
    spec = importlib.util.spec_from_file_location(
        "silnt_apidocs_for_tests", ROOT / "helpers" / "apidocs.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


D = _apidocs()


def _fn(filename: str, name: str) -> str:
    """One function's source, by AST, so a module importing lnbits can still
    be read here."""
    tree = ast.parse((ROOT / filename).read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == name:
                return ast.get_source_segment((ROOT / filename).read_text(), node)
    raise AssertionError(f"{name} not found in {filename}")


# ── grouping ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path,want",
    [
        ("/api/v1/tango/rounds", "tango"),
        ("/api/v1/tango/rounds/{rid}/accept", "tango"),
        ("/api/v1/admin/api-docs", "admin"),
        ("/api/v1/wallet", "wallet"),
        ("/api/v1/bip353/name", "bip353"),
    ],
)
def test_the_group_is_the_segment_after_the_version(path, want):
    assert D.group_for(path) == want


def test_an_odd_path_still_lands_somewhere():
    """A route missing from the reference is the failure this exists to
    prevent. An odd heading is a much cheaper way to notice it."""
    assert D.group_for("/health") == "health"
    assert D.group_for("") == "other"
    assert D.group_for("/api/v1") == "other"
    assert D.group_for("/api/v1/") == "other"


def test_an_unknown_group_gets_a_readable_title_rather_than_disappearing():
    """So a new prefix shows up in the docs the day it is added, instead of
    waiting for somebody to update the table."""
    assert D.group_title("tango") == "Tango — the two-party mix"
    assert D.group_title("widgets") == "Widgets"
    assert D.group_title("cold-storage") == "Cold storage"


def test_every_ordered_group_has_a_title():
    for g in D.GROUP_ORDER:
        assert g in D.GROUP_TITLES, g


# ── summarising ────────────────────────────────────────────────────────────


def test_the_summary_is_the_first_paragraph_not_the_first_line():
    """These docstrings wrap at 79 columns, so cutting at the newline gives
    half a sentence."""
    doc = """What is saved, and what this instance would
    do with it.

    Returns the configuration alongside the address.
    """
    summary, rest = D.summarise(doc)
    assert summary == "What is saved, and what this instance would do with it."
    assert rest == "Returns the configuration alongside the address."


def test_the_rest_keeps_its_paragraphs():
    """The detail is mostly reasoning, which falls apart when it is
    reflowed."""
    doc = "One.\n\nTwo is a point.\n\nThree is another."
    summary, rest = D.summarise(doc)
    assert summary == "One."
    assert rest.count("\n\n") == 1
    assert "Two is a point." in rest and "Three is another." in rest


def test_no_docstring_is_empty_not_an_error():
    assert D.summarise(None) == ("", "")
    assert D.summarise("") == ("", "")
    assert D.summarise("   \n  ") == ("", "")


def test_a_one_line_docstring_has_no_rest():
    assert D.summarise("Just this.") == ("Just this.", "")


# ── who may call it ────────────────────────────────────────────────────────


def test_the_access_badges_say_who_may_call_it():
    assert D.auth_badges(["require_trusted_device"]) == ["trusted device"]
    assert D.auth_badges(["require_trusted_device_admin"]) == ["admin device"]


def test_plumbing_dependencies_are_not_shown():
    """Listing every dependency would bury the three that matter."""
    assert D.auth_badges(["get_db", "some_helper"]) == []


def test_admin_reads_first_when_a_route_has_both():
    """The decorator guard is declared before the parameter, and a route
    guarded by both should read as the stricter one."""
    got = D.auth_badges(["require_trusted_device_admin", "require_trusted_device"])
    assert got[0] == "admin device"


def test_a_badge_is_not_repeated():
    got = D.auth_badges(["require_admin", "check_admin", "require_admin"])
    assert got == ["admin"]


def test_nothing_at_all_is_an_empty_list():
    assert D.auth_badges(None) == []
    assert D.auth_badges([]) == []


# ── assembling ─────────────────────────────────────────────────────────────


def _row(method, path, name="x", summary="", auth=None):
    return {
        "method": method, "path": path, "name": name,
        "summary": summary, "detail": "", "auth": auth or [],
    }


def test_build_groups_counts_and_orders():
    out = D.build([
        _row("GET", "/api/v1/admin/api-docs"),
        _row("POST", "/api/v1/tango/rounds"),
        _row("GET", "/api/v1/tango/rounds"),
        _row("GET", "/api/v1/auth/me"),
    ])
    assert out["count"] == 4
    names = [g["group"] for g in out["groups"]]
    # auth before tango before admin, per GROUP_ORDER.
    assert names == ["auth", "tango", "admin"]
    tango = next(g for g in out["groups"] if g["group"] == "tango")
    assert tango["count"] == 2
    # GET before POST on the same path: the order they are read in.
    assert [r["method"] for r in tango["routes"]] == ["GET", "POST"]


def test_an_unlisted_group_sorts_after_the_known_ones():
    out = D.build([
        _row("GET", "/api/v1/zebra/x"),
        _row("GET", "/api/v1/admin/y"),
        _row("GET", "/api/v1/auth/z"),
    ])
    assert [g["group"] for g in out["groups"]] == ["auth", "admin", "zebra"]


def test_nothing_in_is_nothing_out_rather_than_a_crash():
    assert D.build([])["count"] == 0
    assert D.build(None)["groups"] == []


# ── read off the live router, not a list somebody keeps ────────────────────


def test_the_rows_come_from_the_router_that_is_serving():
    """The only way for the docs to be out of date should be for the server
    to be."""
    body = _fn("views_api.py", "_api_doc_rows")
    assert "silnt_api_router" in body
    assert '"routes"' in body or "routes" in body


def test_one_row_per_method_not_per_route():
    """A path registered for both GET and DELETE is two different things to
    whoever is reading."""
    body = _fn("views_api.py", "_api_doc_rows")
    assert "for method in" in body
    assert '"HEAD"' in body and '"OPTIONS"' in body, (
        "FastAPI adds those and nobody is looking them up"
    )


def test_both_places_a_dependency_can_hide_are_read():
    """`dependencies=[Depends(...)]` on the decorator AND `Depends(...)` as a
    parameter default. This extension uses both, often on one endpoint."""
    body = _fn("views_api.py", "_route_dependency_names")
    assert "route, \"dependencies\"" in body or 'route, "dependencies"' in body
    assert "signature(" in body
    assert "param.default" in body or "default = param.default" in body


def test_the_endpoint_is_admin_only():
    body = _fn("views_api.py", "api_admin_api_docs")
    assert "require_trusted_device_admin" in body
    assert "require_admin(key_info)" in body
