import asyncio
from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles
from loguru import logger
from lnbits.tasks import create_permanent_unique_task

from .crud import db
from .views import silnt_generic_router
from .views_api import silnt_api_router, run_bitmail_tamper_sweep, run_health_probes
from .boltz_swap import silnt_boltz_router
from .boltz_refund_api import silnt_refund_router
from .boltz_refund_api import refund_due_swaps


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
            logger.error(f"[silnt] tamper sweep loop error: {exc}")
        await asyncio.sleep(300)   # every 5 min

async def _refund_loop():
    while True:
        try:            
            results = await refund_due_swaps()
            if results:
                logger.info(f"[silnt] auto-refund pass: {results}")
        except Exception as exc:
            logger.error(f"[silnt] auto-refund loop error: {exc}")
        await asyncio.sleep(120)   # every 2 min; tune as you like

async def _health_monitor_loop():
    # Probe BlindBit Oracle  Fulcrum on a timer so a down (or recovery) fires an
    # ntfy even when no admin has the dashboard open. State-change dedup is inside
    # notify_service_health_change, so this won't spam while a service stays down.
    while True:
        try:
            await run_health_probes()
        except Exception as exc:
            logger.error(f"[silnt] health monitor loop error: {exc}")
        await asyncio.sleep(60)   # every 2 min

# in async def silnt_start() / wherever the ext starts its tasks:
def siLNt_start():
    task = create_permanent_unique_task("ext_silnt", _refund_loop)
    scheduled_tasks.append(task)
    tamper_task = create_permanent_unique_task("ext_silnt_tamper", _tamper_sweep_loop)
    scheduled_tasks.append(tamper_task)
    health_task = create_permanent_unique_task("ext_silnt_health", _health_monitor_loop)
    scheduled_tasks.append(health_task)

# in the ext stop hook:
def siLNt_stop():
    for t in scheduled_tasks:
        try:
            t.cancel()
        except Exception as ex:
            logger.warning(ex)

__all__ = ["siLNt_ext", "siLNt_static_files", "db", "siLNt_start", "siLNt_stop"]