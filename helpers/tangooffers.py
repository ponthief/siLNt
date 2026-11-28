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
#
# 60k to 6M sats (2026-11-25: the first list started at 12k and 30k, and the user
# judged those too small at today's price to be worth a mix once the miner fee
# and the two-sided coordination are paid). The floor is one number in this
# tuple; the clients render whatever the server sends.
DENOMINATIONS = (60_000, 120_000, 300_000, 600_000, 1_200_000, 3_000_000, 6_000_000)

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

# A proposal made against an offer has to be ANSWERED, and quickly. The taker's
# coins lock the moment they propose — the maker's do not — so a maker who posts
# and goes quiet holds other people's coins for as long as the round's clock
# allows. A board proposal therefore expires after this, instead of after the
# round's 24 hours, and accepting it gives the round its full day back.
ANSWER_WINDOW_SECONDS = 2 * 60 * 60

# A proposal that expires unanswered is a strike against the maker. This many in
# the window and they cannot post, and what they have up comes down. Answering
# is what clears the record: declining counts, because declining is an answer.
STRIKE_LIMIT = 3
STRIKE_WINDOW_SECONDS = 24 * 60 * 60

# Offers that one wallet's SP address may have up across ALL accounts. The same
# seed imported into several accounts passes the funding check in every one of
# them, so the per-account cap alone bounds nothing against someone willing to
# make accounts.
MAX_OPEN_PER_ADDRESS = MAX_OPEN_OFFERS

# Rejection reasons written to a round's reject_reason, mirrored by
# services/tangoTurns.ts. Machine-readable state, like EXPIRED beside them.
OFFER_TAKEN = "offer taken"
OFFER_WITHDRAWN = "offer withdrawn"
# A proposal its acceptor can no longer fund, because the coins went into another
# round they matched first. Cancelled for them rather than left to expire: the
# proposer's coins are locked until it does, and nobody can answer it.
OUT_OF_COINS = "out of coins"

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


def suspended_for(strike_times: list, now: int) -> int:
    """Seconds until this maker may post again; 0 if they may now.

    `strike_times` are when their unanswered proposals expired. Only those inside
    the window count, and they may post again as soon as enough of them have aged
    out to leave fewer than STRIKE_LIMIT.
    """
    inside = sorted(
        int(t) for t in strike_times if int(t) > int(now) - STRIKE_WINDOW_SECONDS
    )
    if len(inside) < STRIKE_LIMIT:
        return 0
    # The strike that has to age out to leave STRIKE_LIMIT - 1.
    must_expire = inside[len(inside) - STRIKE_LIMIT]
    return max(0, must_expire + STRIKE_WINDOW_SECONDS - int(now))


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
