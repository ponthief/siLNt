"""Which background loops siLNt_start actually starts.

WHY THIS IS WORTH A TEST. The refund loop is paused deliberately — Boltz is
offline, so it spent every two minutes deciding nothing, and it is the loop
that filled the 2026-09-28 log. Pausing it means commenting out two lines in
the middle of a function that starts four other loops, and the repo has a
documented case of a comment-out taking more with it than was meant
(.github/workflows/build-ios.yml, deleted on a misreading).

So this pins the other four. If the scan loop stops starting, nobody finds
out by reading the diff — they find out because received payments stop being
noticed, days later.

Read from source. Importing __init__.py executes `from lnbits.tasks import
…` at module scope, and LNbits is the host application, not a dependency
this package can install.
"""

from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _started() -> dict[str, str]:
    """{task name: loop function} for each create_permanent_unique_task call
    that is really code. A commented-out call does not parse, which is the
    whole point."""
    tree = ast.parse((ROOT / "__init__.py").read_text(encoding="utf-8"))
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "siLNt_start"
    )
    out = {}
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "create_permanent_unique_task"
            and len(node.args) == 2
        ):
            out[ast.literal_eval(node.args[0])] = ast.unparse(node.args[1])
    return out


def test_the_loops_that_must_keep_running_still_start():
    started = _started()
    for name, loop in {
        "ext_silnt_bgscan": "_background_scan_loop",   # finds received payments
        "ext_silnt_tango": "_tango_sweep_loop",        # frees coins a dead round holds
        # Delivers routed Tango change. The money is already the instance's by
        # the time this runs, so a loop that stops starting is users owed
        # money and nothing trying to send it.
        "ext_silnt_tango_payout": "_tango_payout_loop",
        "ext_silnt_tamper": "_tamper_sweep_loop",      # BitMail hijack detection
        "ext_silnt_health": "_health_monitor_loop",    # BlindBit/Fulcrum alerts
    }.items():
        assert started.get(name) == loop, (
            f"{name} is no longer started by siLNt_start(): {started}"
        )


def test_every_started_task_has_a_distinct_name():
    """create_permanent_unique_task keys on the name, so two loops sharing one
    would silently leave a loop unstarted."""
    tree = ast.parse((ROOT / "__init__.py").read_text(encoding="utf-8"))
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "siLNt_start"
    )
    names = [
        ast.literal_eval(n.args[0])
        for n in ast.walk(fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "create_permanent_unique_task"
        and len(n.args) == 2
    ]
    assert len(names) == len(set(names)), names


def test_the_refund_loop_is_paused_on_purpose_and_says_so():
    """Not started, but not deleted either — and the reason is in the file, so
    whoever finds it is not left guessing whether it was an accident."""
    src = (ROOT / "__init__.py").read_text(encoding="utf-8")
    assert "ext_silnt" not in _started(), "the refund loop is running again"
    assert "PAUSED" in src
    assert "_refund_loop" in src, "the loop itself must stay, so resuming is one edit"
    # Resuming has to be findable.
    assert 'create_permanent_unique_task("ext_silnt", _refund_loop)' in src


def test_pausing_the_loop_did_not_unmount_the_refund_endpoints():
    """A swap past its timeout can still be refunded by hand. Removing the
    manual path as well would strand funds, which is a different decision from
    switching off a timer."""
    src = (ROOT / "__init__.py").read_text(encoding="utf-8")
    assert "siLNt_ext.include_router(silnt_refund_router)" in src
    api = (ROOT / "boltz_refund_api.py").read_text(encoding="utf-8")
    for route in (
        '@silnt_refund_router.get("/api/v1/swap/refundable")',
        '@silnt_refund_router.post("/api/v1/swap/{swap_id}/refund")',
    ):
        assert route in api, route
    # And the function the loop called is untouched, so resuming needs no
    # rewrite of the thing being resumed.
    assert "async def refund_due_swaps" in api
