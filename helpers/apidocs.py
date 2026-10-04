"""The API, described from the API.

WHY THIS IS GENERATED AND NOT WRITTEN. A hand-kept list of endpoints is wrong
the first time somebody adds one and nobody notices for a month — and a
reference that is quietly wrong is worse than none, because it is believed.
Everything here comes from the router that is actually serving requests, so
the only way for the docs to be out of date is for the server to be.

WHAT IS PURE AND WHAT IS NOT. Reading FastAPI's route objects needs FastAPI and
a built app; grouping, titling, summarising and ordering do not. The second
half is here and is testable without either, which is the half that decides
what an operator reads.

NOT A REPLACEMENT FOR OpenAPI. FastAPI already produces a schema and this does
not try to repeat it — no request bodies, no response models, no types. What it
gives is the thing a schema buries: what each endpoint is for, in the sentence
the person who wrote it left behind, and who is allowed to call it.
"""

from __future__ import annotations

from typing import Optional


# The segment after /api/v1/, mapped to something an operator reads. A group
# with no entry here falls back to its own name, so a new prefix appears in the
# docs the day it is added rather than waiting for this table.
GROUP_TITLES = {
    "auth": "Accounts and sessions",
    "devices": "Trusted devices",
    "user": "The signed-in user",
    "wallet": "Wallets",
    "utxos": "Coins",
    "tx": "Transactions",
    "plain": "Plain (BIP-84) sending",
    "payjoin": "PayJoin",
    "tango": "Tango — the two-party mix",
    "contacts": "Saved addresses",
    "bip": "BIP-353 / BitMail names",
    "fcm": "Push notifications",
    "ntfy": "Operator alerts",
    "cloudflare": "Cloudflare DNS",
    "backend": "Backend configuration",
    "oracle": "BlindBit oracle",
    "fees": "Fee estimates",
    "rate": "Exchange rate",
    "invite": "Invites",
    "admin": "Admin",
}

# Order the groups are shown in: the things a reader is most likely to be
# looking for first, admin last because it is the smallest audience. Anything
# not listed sorts after these, alphabetically, rather than vanishing.
GROUP_ORDER = [
    "auth", "devices", "user", "wallet", "utxos", "tx", "plain", "payjoin",
    "tango", "contacts", "bip", "fcm", "ntfy", "fees", "rate", "oracle",
    "invite", "cloudflare", "backend", "admin",
]

# Dependency names that mean something about who may call an endpoint, mapped
# to a short badge. A dependency not in here is not shown: most of them are
# plumbing, and listing every one would bury the three that matter.
AUTH_BADGES = {
    "require_trusted_device_admin": "admin device",
    "require_trusted_device": "trusted device",
    "require_admin": "admin",
    "check_admin": "admin",
    "get_key_type": "api key",
    "require_invoice_key": "invoice key",
    "require_admin_key": "admin key",
}

METHOD_ORDER = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}


def group_for(path: str) -> str:
    """Which group an endpoint belongs to: the segment after /api/v1/.

    Paths that do not look like that get "other" rather than being dropped —
    a route missing from the reference is the failure this file exists to
    prevent, and an odd heading is a far cheaper way to notice it.
    """
    parts = [p for p in (path or "").split("/") if p]
    try:
        i = parts.index("v1")
    except ValueError:
        return parts[0] if parts else "other"
    return parts[i + 1] if len(parts) > i + 1 else "other"


def group_title(group: str) -> str:
    return GROUP_TITLES.get(group, group.replace("-", " ").capitalize())


def summarise(doc: Optional[str]) -> tuple[str, str]:
    """(summary, rest) from a docstring.

    The summary is the first PARAGRAPH, rewrapped to one line — not the first
    line, because these docstrings wrap at 79 columns and cutting at the
    newline gives half a sentence. The rest is kept verbatim, paragraph breaks
    and all, because the detail in them is mostly reasoning that falls apart
    when it is reflowed.
    """
    text = (doc or "").strip()
    if not text:
        return "", ""
    blocks = text.split("\n\n")
    summary = " ".join(line.strip() for line in blocks[0].splitlines()).strip()
    rest = "\n\n".join(b.rstrip() for b in blocks[1:]).strip()
    return summary, rest


def auth_badges(dependency_names) -> list:
    """The access badges for one endpoint, de-duplicated, order preserved.

    Order matters: a route guarded by both the admin dependency and the
    ordinary one should read as admin, and the admin one is declared first.
    """
    out = []
    for name in dependency_names or []:
        badge = AUTH_BADGES.get(name)
        if badge and badge not in out:
            out.append(badge)
    return out


def sort_key(row: dict):
    """Within a group: by path, then by method in the order they are read."""
    return (row.get("path") or "", METHOD_ORDER.get(row.get("method"), 9))


def build(rows: list) -> dict:
    """Group, title, order and count. `rows` are already-extracted dicts, so
    this needs neither FastAPI nor a running app."""
    groups: dict = {}
    for row in rows or []:
        g = group_for(row.get("path") or "")
        groups.setdefault(g, []).append(row)

    ordered = []
    known = [g for g in GROUP_ORDER if g in groups]
    extra = sorted(g for g in groups if g not in GROUP_ORDER)
    for g in known + extra:
        ordered.append({
            "group": g,
            "title": group_title(g),
            "count": len(groups[g]),
            "routes": sorted(groups[g], key=sort_key),
        })
    return {
        "count": sum(len(v) for v in groups.values()),
        "groups": ordered,
    }
