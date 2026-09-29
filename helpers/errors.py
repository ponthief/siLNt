"""Rendering an exception for a log line.

WHY THIS EXISTS. Several of the background loops log `f"…error: {exc}"`, and
on 2026-09-28 production produced:

    ERROR | siLNt:_refund_loop - [silnt] auto-refund loop error:

with nothing after the colon, then a traceback. The exception was
`httpx.ConnectTimeout`, and httpx raises its timeout and network errors with
no message at all — `str(httpx.ConnectTimeout())` is `""`. So the one line a
reader greps for said only that something went wrong, and the class of
failure (a third party being unreachable, which is not a bug) was
indistinguishable from a real one.

`exc_text` puts the type in front whenever the message is empty, so the log
line carries the one fact that identifies the failure.
"""

from __future__ import annotations


def exc_text(exc: BaseException) -> str:
    """`"ConnectTimeout"` rather than `""`; otherwise the message unchanged.

    Kept deliberately dull: it is called from except-blocks whose whole job is
    to not raise, so it must not raise either — a `__str__` that throws is
    rendered as the type name rather than becoming the error being reported.
    """
    try:
        text = str(exc).strip()
    except Exception:  # noqa: BLE001 — a broken __str__ must not escape here
        text = ""
    name = type(exc).__name__
    if not text:
        return name
    # A message that already names its own class needs no prefix.
    return text if name in text else f"{name}: {text}"
