"""The Tango board: offers to mix, posted where connections (or anyone) can see.

AN OFFER IS AN ADVERT, NOT A ROUND, and that is the decision everything else
rests on (2026-11-25, chosen over posting with coins). It names a denomination
and a coin split and holds NO coins. A taker answers it by proposing an
ordinary round to the maker, so the maker's coins are locked only from the
moment the maker accepts — never by being on the board, and never by a stranger
proposing. What a flood of takers can cost the maker is inbox noise, which the
caps below bound, not coins held out of their own wallet.

WHAT THE BOARD DOES NOT CHANGE. The signing protocol, what each side verifies on
its own device before signing, and the fact that the counterparty in a Tango
always learns which outputs are yours. Matching with a stranger moves that
knowledge to the stranger; `visibility` defaults to connections for that
reason, and "anyone" is a per-offer choice, never a default.

This module is pure: no database, no clock of its own, nothing to mock. The
clients mirror the lists below by reading them from the server
(`GET /tango/offers`), never by copying them.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Optional

# A FIXED LIST, not a free field. A mix output of an odd amount is recognisable
# on chain for ever; a small set of shared denominations puts everybody's
# outputs into the same pools. The list is the authority — the endpoint refuses
# anything else, and the clients render whatever the server sends.
#
# EVERY ONE IS A MULTIPLE OF 6, and that is not taste. Every output in a Tango
# has to be the same size (helpers/tango.py::plan refuses an amount that does
# not divide into the coin split), and the board offers splits of 1, 2 and 3:
# 1-2-5 steps, the obvious ladder, divide by 2 and never by 3, so the three-coin
# split would have been unavailable at every amount.
DENOMINATIONS = (12_000, 30_000, 60_000, 120_000, 300_000, 600_000, 1_200_000)

# How many equal coins each side takes its share back as. The protocol allows 4
# (ProposeTangoData); the board offers 1-3. Each extra piece is another 86
# vbytes and the gain is log2(C(2p, p)): about 1, 2.6 and 4.3 bits.
PIECES = (1, 2, 3)

# An offer lives 21 hours (the user's number), under the round's own 24, so a
# proposal made in an offer's last minute still has most of a day to be
# answered. Answered proposals keep their own clock: an offer expiring does not
# cancel what was already proposed against it.
OFFER_TTL_SECONDS = 21 * 60 * 60

VISIBILITY_CONNECTIONS = "connections"
VISIBILITY_ANYONE = "anyone"
VISIBILITIES = (VISIBILITY_CONNECTIONS, VISIBILITY_ANYONE)
DEFAULT_VISIBILITY = VISIBILITY_CONNECTIONS

# The caps that stand in for "locking" worries. All three bound what a stranger
# can do to somebody who has done nothing but post an advert.
MAX_OPEN_OFFERS = 3               # per user per network
MAX_PROPOSALS_PER_OFFER = 3       # live PROPOSED rounds against one offer
MAX_BOARD_PROPOSALS_PER_TAKER = 3  # live PROPOSED rounds a taker has out

# Rejection reasons written to a round's reject_reason, mirrored by
# services/tangoTurns.ts. Machine-readable state, like EXPIRED beside them.
OFFER_TAKEN = "offer taken"
OFFER_WITHDRAWN = "offer withdrawn"

# The maker's coins are checked at post and at proposal so the board does not
# fill with offers nobody could honour. This is a SANITY check, not a guarantee:
# the real fee depends on how many coins each side brings, and the maker still
# chooses their coins at accept.
FUNDING_MARGIN_SATS = 2_000

# A board proposal's fee rate is bounded, because the proposer sets it and the
# maker pays half. Before the board the partner was somebody you had connected
# to; a stranger can type any number. Twice the fastest recommended tier, with a
# floor so a quiet mempool does not forbid a normal rate.
FEE_CAP_MULTIPLE = 2.0
FEE_CAP_FLOOR = 5.0


def validate_offer(denom_sats: int, pieces: int, visibility: str) -> None:
    """Raise ValueError, with a sentence a person can read, if this is not
    something the board takes."""
    if denom_sats not in DENOMINATIONS:
        raise ValueError(
            "That amount is not one the board offers. Pick one of: "
            + ", ".join(f"{d:,}" for d in DENOMINATIONS)
            + " sats."
        )
    if pieces not in PIECES:
        raise ValueError(
            "The coin split has to be " + ", ".join(str(p) for p in PIECES) + "."
        )
    if visibility not in VISIBILITIES:
        raise ValueError("Visibility has to be connections or anyone.")


def expires_at_for(now: int) -> int:
    return int(now) + OFFER_TTL_SECONDS


def is_open(expires_at: Optional[int], now: int) -> bool:
    """An offer with no expiry is not open: it could never have been posted by
    this code, so reading it as eternal would only keep a broken row alive."""
    if not expires_at:
        return False
    return int(expires_at) > int(now)


def visible_to(visibility: str, viewer_is_connected: bool) -> bool:
    """Whether a viewer who is not the maker may see or take this offer."""
    if visibility == VISIBILITY_ANYONE:
        return True
    return bool(viewer_is_connected)


def fee_cap(recommended: Optional[dict]) -> float:
    """The highest fee rate (sat/vB) a board proposal may carry."""
    fastest = 0.0
    try:
        fastest = float((recommended or {}).get("fastestFee") or 0)
    except (TypeError, ValueError):
        fastest = 0.0
    return max(FEE_CAP_FLOOR, fastest * FEE_CAP_MULTIPLE)


def sats_spendable(rows: list, reserved: set) -> int:
    """Sum of the coins a maker could actually put in: unspent, unfrozen (the
    caller's query), and not already held by a live round."""
    from .tango import outpoint_key

    total = 0
    for r in rows:
        if outpoint_key(r["txid"], r["vout"]) in reserved:
            continue
        total += int(r["amount"])
    return total


def can_fund(spendable: int, denom_sats: int) -> bool:
    return int(spendable) >= int(denom_sats) + FUNDING_MARGIN_SATS


class RateLimiter:
    """A per-key sliding window, in memory.

    In memory like the other limiters here: a restart clears everybody's
    counters, which during an incident clears an abuser's too. It exists to
    stop a scripted board being hammered, not to be an accounting system.
    """

    def __init__(self, limit: int, window_seconds: int, clock=time.time):
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self._clock()
        q = self._hits[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True
