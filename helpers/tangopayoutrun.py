"""Delivering a routed Tango change: when to try, and how long to keep trying.

The money is already the instance's by the time this runs — the round's change
output paid our Silent Payments address — and the user is owed the net over
Lightning. Everything here is about an obligation we have already taken on,
which is why nothing in it fails silently.

WHAT IS PURE AND WHAT IS NOT. The policy is here and is testable without a
network, a node or a database: when a payout becomes due, how long to wait
after a failure, when to stop trying, and whether a given error is worth
retrying at all. The doing — resolving the address, asking for an invoice,
paying it — is in views_api so it sits beside the config and the push it has
to send. Splitting them that way is what makes the retry rules assertable;
they are the part that would otherwise only be exercised by a real failure
against a real provider.
"""

from __future__ import annotations

from typing import Optional


# A payout is created only after the round's transaction has this many
# confirmations, which BackendConfig can raise. One confirmation can be
# reversed by a reorg and a Lightning payment cannot be clawed back, so the
# default leaves room.
DEFAULT_MIN_CONFIRMATIONS = 3

# How many times to try before telling the user it did not work.
#
# Six, with the backoff below, is a little over two hours of trying. Long
# enough to ride out a provider restart or a routing failure that clears, short
# enough that somebody owed money hears about it the same day rather than
# finding out when they look.
MAX_ATTEMPTS = 6

# Seconds to wait before attempt n+1, indexed by attempts already made.
# Roughly exponential and then flat: a provider that has been down for twenty
# minutes is not likely to be fixed by asking faster.
BACKOFF_SECONDS = (60, 300, 900, 1800, 3600)


def confirmations(tip_height: Optional[int], block_height: Optional[int]) -> int:
    """How many confirmations a transaction in `block_height` has at `tip`.

    A transaction in the tip block has one. Unconfirmed, or either height
    unknown, is zero — never a negative, and never a guess that something is
    deeper than it is.
    """
    if not tip_height or not block_height:
        return 0
    if block_height > tip_height:
        # A tip we read before the block we are asking about, or an explorer
        # mid-reorg. Not deeper than zero.
        return 0
    return int(tip_height) - int(block_height) + 1


def is_confirmed_enough(
    tip_height: Optional[int],
    block_height: Optional[int],
    minimum: int = DEFAULT_MIN_CONFIRMATIONS,
) -> bool:
    return confirmations(tip_height, block_height) >= max(1, int(minimum))


def backoff_for(attempts: int) -> int:
    """Seconds to wait after `attempts` failures."""
    n = max(0, int(attempts))
    if n >= len(BACKOFF_SECONDS):
        return BACKOFF_SECONDS[-1]
    return BACKOFF_SECONDS[n]


def next_attempt_at(now: int, attempts: int) -> int:
    return int(now) + backoff_for(attempts)


def give_up(attempts: int, permanent: bool) -> bool:
    """Should this stop being retried?

    A permanent failure stops immediately. "No such user at that domain" does
    not become true by asking again, and five more attempts only delay telling
    somebody their address is wrong — which is the one thing they can act on.
    """
    return bool(permanent) or int(attempts) >= MAX_ATTEMPTS


def status_after(attempts: int, permanent: bool) -> str:
    """'pending' while it is still worth trying, else why it stopped.

    'unpayable' and 'failed' are deliberately different words. Unpayable is
    about the destination — a bad address, a provider that refuses the amount —
    and the user can fix it by changing their address. Failed is everything
    else, which is ours: no route, no liquidity, a node that would not answer
    six times. An operator reading the list should be able to tell at a glance
    which ones are waiting on the user and which are waiting on them.
    """
    if not give_up(attempts, permanent):
        return "pending"
    return "unpayable" if permanent else "failed"


# What the user is told when a payout stops. NO AMOUNT: this goes through FCM
# and Google in plaintext, and CLAUDE.md is explicit that push notifications
# must not mention amounts. It says what to do rather than only what happened,
# because the actionable half differs by status.
PAYOUT_FAILED_TITLE = "Tango change not sent"

PAYOUT_UNPAYABLE_BODY = (
    "Your Tango change could not be sent to your Lightning address. "
    "Open WhiSPa to check it."
)
PAYOUT_FAILED_BODY = (
    "Your Tango change could not be sent over Lightning. Open WhiSPa — it "
    "will be retried, and you can change the address."
)


def failure_body(status: str) -> str:
    return PAYOUT_UNPAYABLE_BODY if status == "unpayable" else PAYOUT_FAILED_BODY


# ── Solvency: can this server actually pay what it is about to take on? ─────
#
# A routed change output becomes the instance's the moment the round confirms,
# and the net is then owed over Lightning. Offering that when the payout wallet
# cannot cover it is taking people's coins on a promise, so the rules are here
# and are checked before a round routes rather than after it has.

# Below this much headroom the feature stops being offered. Configurable; the
# default is a working buffer rather than a meaningful amount of money.
DEFAULT_MIN_WALLET_BALANCE_SATS = 10_000


def available_sats(balance_sats: int, owed_sats: int) -> int:
    """What the payout wallet could actually spend on a NEW obligation.

    THE SUBTRACTION IS THE POINT. A raw balance is not the answer: a wallet
    holding 100,000 with 90,000 already owed on undelivered payouts can cover
    one more payout of 10,000 and not of 20,000, and a check against the
    balance alone would wave both through. What is owed is money with
    somebody's name on it already.

    Never negative — an overcommitted wallet has nothing available, not a
    debt it can spend.
    """
    return max(0, int(balance_sats or 0) - int(owed_sats or 0))


def can_route(
    available: int,
    threshold: int = DEFAULT_MIN_WALLET_BALANCE_SATS,
) -> bool:
    """May a new change output be routed?

    THE AMOUNT IS NOT PART OF THIS, and that was a deliberate reversal. An
    amount-aware version — "would this particular payout leave us above the
    floor" — is a better question and cannot be asked where it would have to
    be answered. The only place the change is known is at accept, and by then
    the client has ALREADY decided whether to send a change script of its own,
    on the strength of what the server said was available before it asked.
    Flipping the decision server-side at that point leaves a round with change
    and no script for it, which fails at assembly.

    So the floor is checked without the amount, at propose and at accept
    alike. That is what a buffer is for: a single payout dipping into it is
    survivable, the obligation is recorded either way, and the retry plus the
    ntfy handle the rest.
    """
    return int(available or 0) >= max(0, int(threshold or 0))


def liquidity_reason(
    available: int,
    threshold: int = DEFAULT_MIN_WALLET_BALANCE_SATS,
) -> Optional[str]:
    """Why not, for an operator. None when it can route.

    Deliberately not shown to users: what they get is the setting quietly not
    being offered, because "the service is low on Lightning funds" is an
    invitation to work out how low.
    """
    if can_route(available, threshold):
        return None
    return (
        f"The payout wallet has {available} sats available against a "
        f"{threshold} sat floor."
    )


# The ntfy service name. notify_service_health_change dedups per service and
# fires on BOTH transitions, so recovery is announced too — an operator who
# topped the wallet up should not have to guess whether it took.
LIQUIDITY_SERVICE = "tango_payout_liquidity"
