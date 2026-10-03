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


# ── Deferral: not every failure is worth an attempt ─────────────────────────
#
# MAX_ATTEMPTS and the backoff above are sized for a Lightning failure: a
# provider restart, a route that is not there this minute. Six tries over two
# hours is the right shape for that, and the wrong shape for an empty payout
# wallet, which clears when a human notices and tops it up. Spending the whole
# retry budget on a balance that cannot cover the payment means the row reaches
# 'failed' — and the user is pushed "could not be sent" — over a problem that
# was never theirs and that nobody was asked to fix any faster by trying again.
#
# So a payout the wallet demonstrably cannot fund is deferred instead: pushed
# out without consuming an attempt, leaving the full budget for real Lightning
# failures once there is money to attempt with.

# How long to wait before looking again. The liquidity check runs on the same
# two-minute pass, so this only has to be long enough not to re-read the wallet
# for every row on every pass.
DEFER_SECONDS = 300

# …but not forever. A payout nobody can fund is still a payout somebody is
# waiting on, and silence stops being kind at about a day. Past this the row
# goes through the ordinary attempt path so it can reach 'failed' and say so.
DEFER_MAX_SECONDS = 86_400

DEFER_REASON = (
    "Waiting on the payout wallet: its balance does not cover this payout."
)


def owed_age_seconds(created_at, now: int) -> int:
    """How long a payout has been owed, from whatever `created_at` came back as.

    The column is a TIMESTAMP rather than epoch seconds — it is defaulted by
    the database, not computed in Python — so it arrives as a datetime on one
    backend, a string on another, and a number if it was ever written by hand.

    AN UNREADABLE VALUE RETURNS THE CAP, not zero. The age is only ever used to
    stop deferring, so a value nothing can parse falls back to the behaviour
    there was before deferral existed: attempt, fail, and tell the user. The
    alternative — treating unknown as brand new — defers forever on a column
    that cannot be read, which is the one outcome nobody is told about.
    """
    import datetime as _dt

    if created_at is None:
        return DEFER_MAX_SECONDS
    stamp = None
    if isinstance(created_at, (int, float)):
        stamp = float(created_at)
    elif isinstance(created_at, _dt.datetime):
        at = created_at
        if at.tzinfo is None:
            at = at.replace(tzinfo=_dt.timezone.utc)
        stamp = at.timestamp()
    elif isinstance(created_at, str):
        try:
            at = _dt.datetime.fromisoformat(created_at.strip().replace("Z", "+00:00"))
        except ValueError:
            return DEFER_MAX_SECONDS
        if at.tzinfo is None:
            at = at.replace(tzinfo=_dt.timezone.utc)
        stamp = at.timestamp()
    if stamp is None:
        return DEFER_MAX_SECONDS
    # Never negative: a clock that disagrees with the database is not a payout
    # owed from the future.
    return max(0, int(now) - int(stamp))


def should_defer(
    balance_sats: Optional[int],
    net_sats: int,
    owed_for_seconds: int = 0,
) -> bool:
    """Hold this payout back instead of attempting it?

    ONLY WHEN WE KNOW. An unreadable balance is None and does NOT defer: a
    wallet lookup that is broken while payments work would otherwise stall
    every payout indefinitely, and the attempt it skips is the thing that would
    have delivered the money. Failing open costs an attempt; failing closed
    costs the delivery.

    THERE IS NO FEE RESERVE IN THIS. A balance below the amount cannot pay,
    full stop. A balance above the amount but short of the routing fee is a
    genuine Lightning failure — one the backoff and the attempt count are for —
    and guessing a reserve here would defer payouts that would have gone
    through.
    """
    if balance_sats is None:
        return False
    if int(owed_for_seconds or 0) >= DEFER_MAX_SECONDS:
        return False
    return int(balance_sats) < int(net_sats or 0)


def next_deferral_at(now: int) -> int:
    return int(now) + DEFER_SECONDS


# ── Recovery: putting stopped payouts back in the queue ─────────────────────


def requeue_on_recovery(was_ok: Optional[bool], now_ok: bool) -> bool:
    """Did the payout wallet just come back up?

    A genuine down→up only. `was_ok is None` means no state was ever recorded —
    a first run, or a fresh database — and that is not a recovery: treating it
    as one would requeue every stopped payout on the first pass after a
    restart, including the ones that stopped for reasons a top-up does not fix.
    """
    return was_ok is False and bool(now_ok)


# Which stopped payouts a top-up should revive. 'failed' only: 'unpayable' is
# about the destination — an address that does not resolve, a provider refusing
# the amount — and no amount of money in the payout wallet makes it payable.
# Requeueing those would burn six more attempts and push the user a second
# "could not be sent" for a thing they already have to fix themselves.
REQUEUE_STATUS = "failed"


# ── Telling the operator a payout stopped ──────────────────────────────────
#
# Distinct from LIQUIDITY_SERVICE below, and deliberately NOT routed through
# notify_service_health_change: that dedups on a service's up/down state, so an
# operator who has already been told the wallet is low hears nothing more when
# the payouts underneath it start stopping. These are rare by construction —
# a payout reaches a stop once — so there is nothing to dedup against.

PAYOUT_STOPPED_TITLE = "Tango payout stopped"


# ── …and what the USER is told about the same row ──────────────────────────
#
# `last_error` is written for an operator: a raw provider exception, or
# DEFER_REASON, which says the payout wallet is short. The user's own payout
# list used to hand that straight back, which is the same mistake
# liquidity_reason exists to avoid — "the service is low on Lightning funds" is
# an invitation to work out how low, and a user who knows their own payout
# amount already has a lower bound. So the user endpoint shows this instead:
# the status, in a sentence, and never the operator's reason.

_USER_STATUS_TEXT = {
    "pending": "Waiting to be sent.",
    "paid": "Sent.",
    # True since a top-up requeues these automatically; before that it was a
    # promise only an operator pressing a button could keep.
    "failed": "Could not be sent yet. It will be retried.",
    "unpayable": (
        "Could not be sent to your Lightning address. Check that it is right."
    ),
}


def user_facing_error(status: str) -> Optional[str]:
    """What a user sees in place of `last_error`. None when nothing is wrong."""
    if status == "paid" or status == "pending":
        return None
    return _USER_STATUS_TEXT.get(status, _USER_STATUS_TEXT["failed"])


def operator_alert(
    status: str, txid: str, vout: int, attempts: int, net_sats: int, error: str
) -> str:
    """What an operator needs: which payout, how much, and whose move it is.

    The amount is in it. This goes to the operator's own ntfy topic, not
    through FCM — and the figure is already public, since it is the value of
    `txid:vout` on chain. The Lightning address is NOT in it: that is the
    user's, it is stored encrypted, and an operator who needs it has the admin
    console.
    """
    who = (
        "The destination refused it — the user has to correct their Lightning "
        "address."
        if status == "unpayable"
        else "Check the payout wallet, then retry it from the admin console."
    )
    tail = f" Last error: {error.strip()}" if (error or "").strip() else ""
    return (
        f"{txid[:12]}…:{vout} — {int(net_sats)} sats not sent after "
        f"{int(attempts)} attempts ({status}). {who}{tail}"
    )


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
