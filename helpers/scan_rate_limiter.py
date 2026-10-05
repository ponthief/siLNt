"""
Rate limiting for the scan endpoint.

BIP-352 scanning is expensive — each block needs tweaks + UTXOs fetched from
BlindBit and EC math per output. Without limits, a single user (intentionally
or via bug) can hammer the oracle.

Limits enforced:
  1. Per-wallet cooldown: same wallet can't be scanned more often than every N seconds
  2. Concurrent scans per user: only one active scan at a time per user
  3. Per-IP scan starts per hour
  4. Per-user blocks-scanned budget per hour
"""

import time
from collections import defaultdict
from http import HTTPStatus
from typing import Optional

from fastapi import HTTPException, Request
from loguru import logger


# ── Configurable limits (could live in BackendConfig if you want admin UI control)
WALLET_COOLDOWN_SECONDS    = 60           # 1 minute between scans of same wallet
MAX_CONCURRENT_PER_USER    = 1            # only one active scan per user
MAX_SCAN_STARTS_PER_IP_HR  = 30           # 30 scan-starts/hour per IP
MAX_BLOCKS_PER_USER_HR     = 500_000      # ~half a million blocks/hour per user

# The plain/SegWit address preview. A different cost from a BIP-352 scan — one
# Fulcrum socket and a listunspent per address, no EC math — but it is the one
# read in the app with NO limit of any kind, and it opens a connection to the
# chain index on every call.
#
# Legitimate traffic is small and known: the card walks on mount, the
# foreground watcher polls every five minutes, the wallet screen's
# pull-to-refresh, and once after a send. Thirty a minute is far above all of
# that together and still caps a client holding a button down.
#
# The Refresh button came off the phone's card on 2026-10-05 over exactly this
# worry, and removing a button is not the fix: anyone can call the endpoint
# directly. The limit is.
MAX_PLAIN_PREVIEWS_PER_USER_MIN = 30


# ── State (in-memory — fine for single-process LNbits) ───────────────────────
_last_scan_time:   dict     = {}                     # wallet_id -> ts
_active_scans:     dict     = defaultdict(set)       # user_id -> {wallet_id, ...}
_ip_scan_log:      dict     = defaultdict(list)      # ip -> [ts, ts, ...]
_user_blocks_log:  dict     = defaultdict(list)      # user_id -> [(ts, count), ...]
_plain_preview_log: dict    = defaultdict(list)      # user_id -> [ts, ts, ...]


def _prune_old(entries: list, age_seconds: int) -> list:
    """Drop entries older than age_seconds. Entries are timestamps or (ts, *) tuples."""
    cutoff = time.time() - age_seconds
    return [
        e for e in entries
        if (e[0] if isinstance(e, tuple) else e) >= cutoff
    ]


def check_scan_allowed(
    user_id: str,
    wallet_id: str,
    ip: str,
    estimated_blocks: int,
) -> None:
    """
    Raise HTTPException(429) if any rate limit would be violated by this scan.
    Call this BEFORE starting the scan. Increments counters as side effects.
    """
    now = time.time()

    # ── 1. Per-wallet cooldown ────────────────────────────────────────────────
    last_ts = _last_scan_time.get(wallet_id, 0)
    if now - last_ts < WALLET_COOLDOWN_SECONDS:
        wait = int(WALLET_COOLDOWN_SECONDS - (now - last_ts))
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail=f"Wallet was scanned recently. Try again in {wait} seconds.",
        )

    # ── 2. Concurrent scans per user ──────────────────────────────────────────
    if len(_active_scans[user_id]) >= MAX_CONCURRENT_PER_USER:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail="Another scan is already running on your account. Wait for it to finish.",
        )

    # ── 3. Per-IP scan starts per hour ────────────────────────────────────────
    _ip_scan_log[ip] = _prune_old(_ip_scan_log[ip], 3600)
    if len(_ip_scan_log[ip]) >= MAX_SCAN_STARTS_PER_IP_HR:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail="Too many scan attempts from this IP. Try again later.",
        )

    # ── 4. Per-user blocks budget per hour ────────────────────────────────────
    _user_blocks_log[user_id] = _prune_old(_user_blocks_log[user_id], 3600)
    consumed = sum(count for _ts, count in _user_blocks_log[user_id])
    if consumed + estimated_blocks > MAX_BLOCKS_PER_USER_HR:
        remaining = MAX_BLOCKS_PER_USER_HR - consumed
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail=(
                f"Hourly scan budget exceeded ({MAX_BLOCKS_PER_USER_HR:,} blocks/hour). "
                f"You have {remaining:,} blocks remaining this hour. "
                f"Try a smaller range or wait."
            ),
        )

    # All checks passed — record this scan
    _last_scan_time[wallet_id] = now
    _active_scans[user_id].add(wallet_id)
    _ip_scan_log[ip].append(now)
    _user_blocks_log[user_id].append((now, estimated_blocks))

    logger.info(
        f"Scan allowed: user={user_id[:8]} wallet={wallet_id[:8]} "
        f"blocks={estimated_blocks} ip={ip}"
    )


def check_plain_preview_allowed(user_id: str) -> None:
    """Raise 429 if this user is asking about their SegWit addresses too fast.

    Per user rather than per wallet: the cost is the chain-index connection,
    and one account can have a wallet on each network.
    """
    now = time.time()
    _plain_preview_log[user_id] = _prune_old(_plain_preview_log[user_id], 60)
    if len(_plain_preview_log[user_id]) >= MAX_PLAIN_PREVIEWS_PER_USER_MIN:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail="Checking those addresses too often. Try again in a minute.",
        )
    _plain_preview_log[user_id].append(now)


def mark_scan_finished(
    user_id: str,
    wallet_id: str,
    actual_blocks: Optional[int] = None,
    estimated_blocks: Optional[int] = None,
    reset_wallet_cooldown: bool = False,
) -> None:
    """
    Release the concurrent-scan slot once a scan finishes (success/failure/stop).

    If actual_blocks and estimated_blocks are given, reconcile the per-user block
    budget: at start we debited the ESTIMATE; here we refund the difference so the
    user is only charged for blocks ACTUALLY scanned (oracle load done).

    If reset_wallet_cooldown is True (user explicitly stopped), clear the per-wallet
    cooldown so they can retry immediately — the block budget is the real oracle-load
    guard, and a self-initiated stop isn't the rapid-rescan case the cooldown targets.
    """
    _active_scans[user_id].discard(wallet_id)

    # Reconcile the block budget: replace the most recent estimate-debit for this
    # user with the actual count (refund the unscanned remainder).
    if actual_blocks is not None and estimated_blocks is not None:
        log = _user_blocks_log.get(user_id)
        if log:
            # Find the most recent entry matching the estimate we debited and
            # correct it to the actual blocks scanned.
            for i in range(len(log) - 1, -1, -1):
                ts, count = log[i]
                if count == estimated_blocks:
                    log[i] = (ts, max(0, int(actual_blocks)))
                    break

    if reset_wallet_cooldown:
        _last_scan_time.pop(wallet_id, None)


def clear_wallet_limits(wallet_id: str, user_id: Optional[str] = None) -> None:
    """Drop the per-wallet limiter state for a wallet that no longer exists.

    Wallet ids are reproducible from the seed, so deleting a wallet and
    importing the same recovery phrase again yields the SAME id. Without this,
    the new wallet starts life inside the old one's cooldown, and — if the old
    wallet was deleted mid-scan — inside a concurrency slot that is never
    released, so every scan on the account is refused with "another scan is
    already running".

    The per-IP and per-user block budgets are deliberately left alone: those
    measure oracle load that really did happen, and deleting a wallet is not a
    way to buy more of it.
    """
    _last_scan_time.pop(wallet_id, None)
    if user_id is not None:
        _active_scans[user_id].discard(wallet_id)
    else:
        for wallets in _active_scans.values():
            wallets.discard(wallet_id)