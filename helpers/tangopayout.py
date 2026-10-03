"""What a Tango's change is worth once it is paid out over Lightning.

THE ARRANGEMENT. A round's change output normally lands in its owner's wallet,
where it is the strongest remaining linkability problem in Tango: its value is
fixed by the round's arithmetic, so spending it later — to anyone, on its own,
months afterwards — shows which of the two identical shares were theirs. A user
who supplies a Lightning address instead has that output paid to the
INSTANCE's Silent Payments address, and the value sent to their Lightning
address, minus a service fee.

Optional, per user. No address, no routing, and the change lands in their
wallet exactly as it does today.

WHY THE FEE IS CHARGED ON THE CHANGE AND NOT ON THE ROUND. The specification
was 0.5% of the total transaction, and that does not fit inside the change.
The two are unrelated quantities: the denomination is what the two sides
agreed to mix, the change is whatever their coin selection happened to leave
over. A big round with a small change is the normal case, not an edge case —
at 1,000,000 sats a side, 0.5% of the round is 10,000 sats charged against a
750-sat change, and the user is owed minus 9,250.

So the percentage is charged on the amount being moved, which is the change —
the same basis Boltz uses for a swap. `min(change - DUST_SATS, ...)` then makes
it arithmetically impossible to charge more than the change can carry,
whatever anyone configures.

WHY THERE IS A FLOOR. 0.5% of a realistic change collects almost nothing:
3.75 sats on 750, 12.5 on 2,500. Delivering it costs a Lightning routing fee
plus, eventually, 57.5 vB to spend the collected output — 58 sats at 1 sat/vB,
575 at 10. The percentage is revenue and the floor is cost recovery, and
without the floor every payout loses money.

NO PROJECT IMPORTS beyond the dust limit: this is the authority the clients mirror so
they can show the net before anyone signs, and it has to be a pure function to
be worth mirroring.
"""

from __future__ import annotations

import math
from typing import Optional

from .wallet import DUST_SATS


# Defaults for the BackendConfig keys of the same name. Both configurable; the
# floor especially, since what it has to cover is a fee rate the operator can
# see and this module cannot.
DEFAULT_FEE_PCT = 0.005          # 0.5%
DEFAULT_FEE_FLOOR_SATS = 100     # a routing fee plus a low-fee-rate sweep


# WHICH CHAINS CAN PAY OUT, and it is one.
#
# A Lightning address is not network-scoped — satoshi@coinos.io is a mainnet
# endpoint, and there is no signet equivalent anyone runs. A signet round's
# change is worthless test coin. Route it and the instance pays real sats for
# faucet money, which every signet user could do on repeat.
#
# So the setting is not offered off mainnet and the backend refuses to route
# there, rather than relying on an operator not to enable it. The two clients
# mirror this to decide whether to show the setting at all: a field that
# silently cannot work is worse than no field.
PAYOUT_NETWORKS = ("mainnet",)


def payout_offered(network: str) -> bool:
    """Whether this chain can pay a Tango's change over Lightning at all.

    Deliberately not configurable. See PAYOUT_NETWORKS — the failure it
    prevents is the instance funding a faucet, and that is not a preference.
    """
    return (network or "").strip().lower() in PAYOUT_NETWORKS


class PayoutPlan:
    """What one side's change becomes. Deliberately dull and total: every
    refusal names itself, because "no payout happened" is the one outcome a
    user will ask about and a boolean cannot answer."""

    __slots__ = ("gross_sats", "fee_sats", "net_sats", "routed", "reason")

    def __init__(
        self,
        gross_sats: int,
        fee_sats: int,
        net_sats: int,
        routed: bool,
        reason: Optional[str],
    ):
        self.gross_sats = gross_sats
        self.fee_sats = fee_sats
        self.net_sats = net_sats
        self.routed = routed
        self.reason = reason

    def dict(self) -> dict:
        return {
            "gross_sats": self.gross_sats,
            "fee_sats": self.fee_sats,
            "net_sats": self.net_sats,
            "routed": self.routed,
            "reason": self.reason,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging only
        return f"PayoutPlan({self.dict()})"


def _not_routed(gross: int, reason: str) -> PayoutPlan:
    return PayoutPlan(
        gross_sats=max(0, int(gross)), fee_sats=0, net_sats=0,
        routed=False, reason=reason,
    )


def payout_plan(
    change_sats: int,
    *,
    fee_pct: float = DEFAULT_FEE_PCT,
    fee_floor_sats: int = DEFAULT_FEE_FLOOR_SATS,
) -> PayoutPlan:
    """The gross, the fee and the net for one side's change.

    `routed=False` means the change stays in its owner's wallet, which is
    today's behaviour and never an error. The reason says which rule declined
    it, so the clients can say so rather than showing a silent nothing.

    Rounding is always in the instance's favour by at most one sat: the fee is
    rounded up. A user who is short a sat has not noticed; an instance that is
    short a sat on every payout has a slow leak.
    """
    change = int(change_sats or 0)

    if change <= 0:
        # The common, good case: the round came out clean. plan() also folds a
        # sub-dust change into the miner fee, so this covers that too.
        return _not_routed(0, "no change to pay out")

    if change < DUST_SATS:
        # plan() should have folded it already; if one ever reaches here it is
        # below the floor the instance's address is allowed to accumulate.
        return _not_routed(change, f"change below the {DUST_SATS} sat floor")

    pct = max(0.0, float(fee_pct))
    floor = max(0, int(fee_floor_sats))

    # Round the percentage up, then take whichever of the two is larger. The
    # percentage is revenue and the floor is cost recovery, so on a small
    # change the floor is the whole fee and on a large one the percentage is.
    fee = max(math.ceil(change * pct) if pct else 0, floor)

    # THE FEE EITHER FITS OR THERE IS NO PAYOUT, and this is the reason the
    # function is not one line.
    #
    # An earlier cut capped the fee at `change - DUST_SATS` instead. That is
    # arithmetically safe and economically backwards: on a 600-sat change it
    # quietly charged 54 sats — below the floor, which exists precisely because
    # under it the payout loses money — and routed anyway. A cap that discounts
    # is a subsidy nobody chose.
    #
    # So the fee is never reduced. If it does not leave a payout worth sending,
    # the change simply stays in its owner's wallet, which is today's behaviour
    # and not an error. This also makes a misconfigured percentage (>= 1.0)
    # safe by the same path: the fee exceeds the change, nothing is routed, and
    # nobody is owed a negative amount.
    net = change - fee
    if net < DUST_SATS:
        return _not_routed(
            change,
            f"too small to pay out: a {fee} sat fee would leave less than "
            f"{DUST_SATS} sats",
        )

    return PayoutPlan(
        gross_sats=change, fee_sats=fee, net_sats=net, routed=True, reason=None,
    )


def min_change_to_route(
    fee_pct: float = DEFAULT_FEE_PCT,
    fee_floor_sats: int = DEFAULT_FEE_FLOOR_SATS,
) -> Optional[int]:
    """The smallest change worth routing, for the setting to state plainly.

    `None` when no change is large enough, which a percentage of 1.0 or more
    guarantees. None rather than a number, because a setting that names a
    threshold nothing can reach should say nothing.

    The answer is confirmed by asking `payout_plan` rather than returned from
    the arithmetic directly: the two cannot then disagree, and a stated
    threshold that disagrees with the rule is worse than an unstated one.
    """
    pct = max(0.0, float(fee_pct))
    floor = max(0, int(fee_floor_sats))
    if pct >= 1.0:
        return None

    def routes(change: int) -> bool:
        return payout_plan(change, fee_pct=pct, fee_floor_sats=floor).routed

    # DOUBLE, THEN BISECT, and no arithmetic shortcut.
    #
    # Two closed forms were tried and both were wrong. Scanning `floor` steps
    # up from the dust limit finds nothing when the floor is 0 and the
    # percentage is what holds the payout back. And `ceil(DUST / (1 - pct))`
    # is off by one at pct = 0.9, because 1.0 - 0.9 is 0.09999999999999998 and
    # the division lands just above an integer.
    #
    # `routes` is monotone — a sat added to the change adds one sat and at most
    # one sat of fee, so the net never decreases — which is what makes a
    # bisection exact where the algebra was not.
    lo = DUST_SATS
    if routes(lo):
        return lo
    hi = lo + max(1, floor)
    for _ in range(64):
        if routes(hi):
            break
        lo, hi = hi, hi * 2
    else:
        return None

    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if routes(mid):
            hi = mid
        else:
            lo = mid
    return hi


# ── pinning the instance's change address outside the database ──────────────
#
# WHAT THIS DEFENDS AGAINST. A round's routed change pays the address in
# `tango_change_sp_address`, which lives as plain JSON in silnt.backend_config.
# Anyone who can WRITE that row redirects every future routed change to
# themselves, and nothing downstream notices: the clients verify the output
# against `payout_sp_address` taken from the same round, so the tweak check
# passes perfectly against the attacker's address. A client has no independent
# idea what this instance's address ought to be.
#
# Encryption does not help. The threat is substitution, not reading, and the
# key is wherever the application can reach it.
#
# So the address is also kept somewhere a database write cannot reach: the
# process environment. A mismatch stops routing — the coins stay in their
# owners' wallets, which is the state every round had before this feature.
#
# UNSET IS NOT A MISMATCH. An instance that has never set it keeps working
# exactly as before, because failing closed on a value nobody has configured
# would turn a security improvement into an outage. The admin page says the pin
# is not set, which is the honest version of "no protection here".
PAYOUT_ADDRESS_PIN_ENV = "SILNT_TANGO_CHANGE_SP_ADDRESS"

# The ntfy service name for the pin. notify_service_health_change dedups per
# service and fires on BOTH transitions, so a mismatch is reported once rather
# than on every round, and an operator who fixed a stale environment variable
# is told it took.
TANGO_ADDRESS_PIN_SERVICE = "tango_change_address_pin"


def payout_address_pin(configured: str, pinned: str) -> tuple[str, Optional[str]]:
    """Compare the stored change address with the pinned one.

    Returns (state, reason) where state is:

      'unpinned'  nothing is pinned, so nothing is checked
      'ok'        the database agrees with the environment
      'mismatch'  they differ — the database may have been written to

    Case-folded and stripped, because a bech32m address is canonically lower
    case and an operator pasting one with different case has made a typo, not
    an attack. Comparing raw would turn that into a silent outage.
    """
    want = (pinned or "").strip().lower()
    have = (configured or "").strip().lower()
    if not want:
        return "unpinned", (
            f"{PAYOUT_ADDRESS_PIN_ENV} is not set, so a write to the backend "
            f"config could change where routed change is paid"
        )
    if want == have:
        return "ok", None
    return "mismatch", (
        f"the configured change address does not match "
        f"{PAYOUT_ADDRESS_PIN_ENV}. Routing is refused until they agree: "
        f"either the environment is stale, or the stored configuration was "
        f"changed by something other than the admin page"
    )
