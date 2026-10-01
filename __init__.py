import asyncio
import time
from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles
from loguru import logger
from lnbits.tasks import create_permanent_unique_task

from .crud import db
from .views import silnt_generic_router
from .views_api import (
    silnt_api_router,
    run_bitmail_tamper_sweep,
    run_health_probes,
    run_background_scans,
    background_tip_advanced,
    run_send_confirmation_checks,
    run_tango_labelling,
    run_tango_sweep,
    run_tango_payouts,
    BACKGROUND_SCAN_POLL_SECONDS,
    BACKGROUND_SCAN_INTERVAL_SECONDS,
)
from .boltz_swap import silnt_boltz_router
from .boltz_refund_api import silnt_refund_router
from .boltz_refund_api import refund_due_swaps
from .helpers.errors import exc_text


siLNt_static_files = [
    {
        "path": "/siLNt/static",
        "app": StaticFiles(packages=[("lnbits", "extensions/siLNt/static")]),
        "name": "siLNt_static",
    }
]

siLNt_ext: APIRouter = APIRouter(prefix="/siLNt", tags=["siLNt"])
siLNt_ext.include_router(silnt_generic_router)
siLNt_ext.include_router(silnt_api_router)
siLNt_ext.include_router(silnt_boltz_router)
siLNt_ext.include_router(silnt_refund_router)


scheduled_tasks: list[asyncio.Task] = []

async def _tamper_sweep_loop():
    while True:
        try:
            res = await run_bitmail_tamper_sweep()
            if res and res.get("mismatches"):
                logger.warning(f"[silnt] tamper sweep: {res}")
        except Exception as exc:
            logger.error(f"[silnt] tamper sweep loop error: {exc_text(exc)}")
        await asyncio.sleep(300)   # every 5 min

async def _refund_loop():
    while True:
        try:            
            results = await refund_due_swaps()
            if results:
                logger.info(f"[silnt] auto-refund pass: {results}")
        except Exception as exc:
            logger.error(f"[silnt] auto-refund loop error: {exc_text(exc)}")
        await asyncio.sleep(120)   # every 2 min; tune as you like

async def _health_monitor_loop():
    # Probe BlindBit Oracle  Fulcrum on a timer so a down (or recovery) fires an
    # ntfy even when no admin has the dashboard open. State-change dedup is inside
    # notify_service_health_change, so this won't spam while a service stays down.
    while True:
        try:
            await run_health_probes()
        except Exception as exc:
            logger.error(f"[silnt] health monitor loop error: {exc_text(exc)}")
        await asyncio.sleep(60)   # every 2 min

async def _background_scan_loop():
    # Scan opt-in wallets as soon as a new block appears, rather than on a fixed
    # timer — so a received payment is detected (and pushed) within ~a block
    # instead of up to the fallback interval. A cheap per-network chain-tip poll
    # gates the actual sweep; a periodic forced sweep still runs as a safety net
    # (newly opted-in wallets, a missed tip update, a server restart).
    last_tip_by_network: dict = {}
    last_sweep = 0.0
    while True:
        try:
            advanced = await background_tip_advanced(last_tip_by_network)
            now = time.monotonic()
            due_fallback = (now - last_sweep) >= BACKGROUND_SCAN_INTERVAL_SECONDS
            if advanced or due_fallback:
                # Confirmations first, and for every wallet with a pending send
                # — not only background-scan opt-ins. Checking a send needs no
                # scan key, just a public txid lookup, and this is the path that
                # reaches a user whose app is closed. Kept ahead of the scan so
                # a slow sweep can't delay it.
                await run_send_confirmation_checks()
                await run_background_scans()
                # Name Tango coins the scans just found. Their round finished
                # before they existed, and the send guard reads labels — an
                # unlabelled share is one it cannot refuse. The five-minute
                # sweep is the backstop, not the mechanism.
                try:
                    await run_tango_labelling()
                except Exception as exc:
                    logger.warning(f"[silnt] tango labelling after scans: {exc_text(exc)}")
                last_sweep = time.monotonic()
        except Exception as exc:
            logger.error(f"[silnt] background scan loop error: {exc_text(exc)}")
        await asyncio.sleep(BACKGROUND_SCAN_POLL_SECONDS)

async def _tango_payout_loop():
    # Delivering routed Tango change. The money is already the instance's by
    # the time this runs — the round's change output paid our SP address — so
    # every pass is work on an obligation already taken on, and a pass that
    # does nothing is a user still waiting.
    #
    # Every two minutes: the backoff inside a payout decides when IT is next
    # tried, so this only has to come round often enough not to add delay of
    # its own.
    while True:
        try:
            res = await run_tango_payouts()
            if res and any(res.values()):
                logger.info(f"[silnt] tango payouts: {res}")
        except Exception as exc:
            logger.error(f"[silnt] tango payout loop error: {exc_text(exc)}")
        await asyncio.sleep(120)

async def _tango_sweep_loop():
    # Closes rounds that ran out of time, which is what gives both sides' coins
    # back — a live round holds a claim on them, and the side who would close
    # it is the side that stopped. Also names change coins the scanner has
    # since found: they do not exist when the round finishes, and nobody
    # reopens a finished round to trigger it.
    while True:
        try:
            res = await run_tango_sweep()
            if res and (res.get("expired") or res.get("labelled")):
                logger.info(f"[silnt] tango sweep: {res}")
        except Exception as exc:
            logger.error(f"[silnt] tango sweep loop error: {exc_text(exc)}")
        await asyncio.sleep(300)   # every 5 min


# in async def silnt_start() / wherever the ext starts its tasks:
def siLNt_start():
    # PAUSED 2026-09-29 — _refund_loop is not started.
    #
    # It exists for Boltz submarine swaps, and Boltz is offline, so every pass
    # was a round trip to a chain-height source to decide nothing: there are no
    # live swaps for it to act on. It is the loop that produced
    # `[silnt] auto-refund loop error:` every two minutes in the 2026-09-28
    # logs.
    #
    # WHAT IS STILL THERE, because pausing the timer is not removing the
    # feature: _refund_loop and refund_due_swaps are unchanged, and all four
    # endpoints on silnt_refund_router stay mounted —
    #   GET    /api/v1/swap/refundable
    #   POST   /api/v1/swap/{swap_id}/refund
    #   GET    /api/v1/swap/list
    #   DELETE /api/v1/swap/{swap_id}
    # so a swap that is past its timeout can still be refunded, by hand,
    # whenever someone asks for it.
    #
    # WHAT IS NOT: nothing refunds a timed-out swap on its own any more. If a
    # lockup is sitting out there with a refund address on record, it now waits
    # for a person. Check GET /api/v1/swap/refundable before assuming there is
    # nothing to collect.
    #
    # TO RESUME when Boltz is back: uncomment the two lines below. Nothing else
    # changed.
    # task = create_permanent_unique_task("ext_silnt", _refund_loop)
    # scheduled_tasks.append(task)
    tamper_task = create_permanent_unique_task("ext_silnt_tamper", _tamper_sweep_loop)
    scheduled_tasks.append(tamper_task)
    health_task = create_permanent_unique_task("ext_silnt_health", _health_monitor_loop)
    scheduled_tasks.append(health_task)
    bgscan_task = create_permanent_unique_task("ext_silnt_bgscan", _background_scan_loop)
    scheduled_tasks.append(bgscan_task)
    tango_task = create_permanent_unique_task("ext_silnt_tango", _tango_sweep_loop)
    scheduled_tasks.append(tango_task)
    payout_task = create_permanent_unique_task(
        "ext_silnt_tango_payout", _tango_payout_loop
    )
    scheduled_tasks.append(payout_task)

# in the ext stop hook:
def siLNt_stop():
    for t in scheduled_tasks:
        try:
            t.cancel()
        except Exception as ex:
            logger.warning(ex)

__all__ = ["siLNt_ext", "siLNt_static_files", "db", "siLNt_start", "siLNt_stop"]