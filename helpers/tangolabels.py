"""What a Tango writes on a coin, and how to read it back.

SEPARATE FROM tango.py FOR THE SAME REASON tangoTurns.ts IS SEPARATE FROM
tango.ts ON THE CLIENT. Everything here is string work — no curve, no
transaction, no arithmetic beyond comparing a value to a denomination — but
tango.py reaches payjoin_sp, which reaches wallet.py and coincurve. So the
transaction list, which wants one predicate to decide whether a label is one of
ours, was importing the entire signing stack to get it.

The split is not only about weight. tests/conftest.py stubs helpers/wallet.py,
so importing tango.py from a test that has not arranged otherwise fails on
DUST_SATS — and the one place it appeared to work, it worked because another
test module happened to be collected first and replace the stub. A pure module
has no such ordering to get wrong.

tango.py re-exports all of it, so every existing caller and test is unaffected.
"""

from __future__ import annotations

from typing import Optional


MIX_LABEL = "Tango mix"
CHANGE_LABEL = "Tango change"


def day_marker(when) -> str:
    """The day a coin was made, for the label: "· 2026-09-24".

    WHY A DATE AND NOT A ROUND ID. Two rounds with the same person produce two
    coins whose labels would otherwise read identically, so something has to
    separate them. This was four characters of the round id, which separated
    them and told the owner nothing — "#fagk" is noise in a coin list.

    ISO order rather than "24 Sep": it needs no locale to read, it sorts, and
    it is the same width every time. The year is included because the label is
    written once and never revised, so leaving it out would make a coin from
    last September indistinguishable from one from this September.

    Two rounds with one person ON THE SAME DAY still collide. They are
    distinguishable by amount in the list beside it, and the refusal that reads
    these labels does not use the marker at all — it goes by kind.

    Accepts a date, a datetime, or a string already in this shape.
    """
    if not when:
        return ""
    if isinstance(when, str):
        text = when.strip()[:10]
        return f"· {text}" if text else ""
    try:
        return "· " + when.strftime("%Y-%m-%d")
    except (AttributeError, ValueError):
        return ""


def _named(prefix: str, other_username: Optional[str], when) -> str:
    parts = [prefix]
    who = (other_username or "").strip()
    if who:
        parts.append(f"- {who}")
    mark = day_marker(when)
    if mark:
        parts.append(mark)
    return " ".join(parts)


def mix_label(other_username: Optional[str], when=None) -> str:
    """The mixed share: "Tango mix - alice · 2026-09-24"."""
    return _named(MIX_LABEL, other_username, when)


def change_label(other_username: Optional[str], when=None) -> str:
    """A change coin: "Tango change - alice · 2026-09-24"."""
    return _named(CHANGE_LABEL, other_username, when)


# The markers this module has written: the date, and the round-id tag it
# replaced. Both have to be recognised — coins carrying the old one are in
# wallets right now, and a rule that stopped seeing them would stop refusing
# them silently.
_MARKERS = (" · ", " #")


def _strip_marker(rest: str) -> str:
    for sep in _MARKERS:
        if sep in rest:
            return rest[: rest.rindex(sep)].strip()
    return rest


def _party(label: str, prefix: str) -> Optional[str]:
    """The counterparty named in one of our labels, or None if it is not one.

    Matched from the start and only up to a separator we wrote, never as a
    substring: a coin the user named "my Tango mix money" is theirs, not ours,
    and refusing to spend it would be us reading our own meaning into their
    words.

    Accepts every shape this has written: the bare prefix, the prefix with
    either marker, and the prefix with a name and an optional marker.
    """
    text = (label or "").strip()
    if text == prefix:
        return ""
    if not text.startswith(f"{prefix} "):
        return None
    rest = text[len(prefix) + 1 :].strip()
    if rest.startswith("- "):
        rest = rest[2:].strip()
    elif rest.startswith("#") or rest.startswith("·"):
        return ""
    else:
        # "Tango mix something we never wrote" is the user's own text.
        return None
    return _strip_marker(rest)


def coin_labels(
    tx_outputs: dict,
    denom: int,
    scripts,
    other_username: Optional[str],
    when=None,
) -> dict:
    """Which of this side's coins is the share and which is the change, decided
    by what each one is WORTH in the broadcast transaction.

    WHY NOT JUST TRUST THE COLUMNS. a_mix_spk and a_change_spk say which is
    which, and a label written from them is wrong in exactly the way that is
    hardest to notice if either the client or the server ever puts them the
    wrong way round: the wallet then calls the change coin a share, the send
    guard refuses the safe pair and allows the dangerous one, and the label
    reads plausibly throughout.

    The transaction cannot be wrong about it. Both shares are worth the
    denomination — that is the whole privacy claim, checked on both devices
    before either signs — so an output of this side's worth exactly `denom` is
    its share and anything else is its change. Reading it off the chain makes
    the label true whatever the columns say, and disagreement becomes visible
    rather than silent.

    `tx_outputs` maps scriptPubKey hex to value; case and surrounding space are
    ignored on both sides, since one comes off the wire and the other out of a
    column. Scripts not in it are left out: the caller knows how many it asked
    about and can say so.
    """
    outs = {
        (k or "").strip().lower(): v for k, v in (tx_outputs or {}).items()
    }
    out = {}
    for spk in scripts:
        key = (spk or "").strip().lower()
        if not key or key not in outs:
            continue
        value = int(outs[key])
        naming = mix_label if value == int(denom) else change_label
        out[key] = naming(other_username, when)
    return out


def wrote_label(label: str) -> bool:
    """Whether this label is one this module wrote.

    So the transaction list can drop them. A round's row already says "Tango
    with alice", and the two coin labels underneath it repeat the same fact
    twice more — three badges on one row, where one is enough. They stay on the
    coins themselves, which is where a per-coin label belongs and where the
    send guard reads them.

    Uses _party rather than a prefix test, so a coin the user named "Tango mix
    money" keeps its label: that is their text, not ours.
    """
    text = label or ""
    return (
        _party(text, MIX_LABEL) is not None
        or _party(text, CHANGE_LABEL) is not None
    )


def undoes_a_round(labels) -> Optional[str]:
    """The round(s) a selection of coins would undo, named, or None.

    ANY TANGO SHARE WITH ANY TANGO CHANGE. Not only a share with its own
    round's change, which is what this used to check and was too narrow.

    The reasoning that led there was that the two have to add up — a round's
    change plus its share is what that side put in, so the arithmetic resolves
    which of the two identical shares was theirs. True, and not the only way
    it goes wrong. A Tango change coin is attributable BY CONSTRUCTION: its
    value plus a share equals an input total, so an observer can tie it to the
    coins its owner brought, which is exactly the history that owner had before
    the mix. A share is the opposite: it is the coin that history was cut off
    from. Put the two in one transaction and the cut is repaired — the share
    inherits the change's attribution — whoever the round was with and whenever
    it happened. Change from the alice round reconnects a share from the bob
    round just as well.

    So the rule is by KIND, not by round, and the marker in the label is for
    the human reading it rather than for this.

    Returns the counterparty of the share(s) at risk, since the share is what
    loses its protection. None when the selection is safe.
    """
    mixed = set()
    has_change = False
    for raw in labels:
        who = _party(raw or "", MIX_LABEL)
        if who is not None:
            mixed.add(who or "someone")
            continue
        if _party(raw or "", CHANGE_LABEL) is not None:
            has_change = True
    if not mixed or not has_change:
        return None
    return " and ".join(sorted(mixed))
