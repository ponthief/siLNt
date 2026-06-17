import asyncio
from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles
from loguru import logger
from lnbits.tasks import create_permanent_unique_task

from .crud import db
from .views import silnt_generic_router
from .views_api import silnt_api_router
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

async def _refund_loop():
    while True:
        try:            
            results = await refund_due_swaps()
            if results:
                logger.info(f"[silnt] auto-refund pass: {results}")
        except Exception as exc:
            logger.error(f"[silnt] auto-refund loop error: {exc}")
        await asyncio.sleep(120)   # every 2 min; tune as you like

# in async def silnt_start() / wherever the ext starts its tasks:
def siLNt_start():
    task = create_permanent_unique_task("ext_silnt", _refund_loop)
    scheduled_tasks.append(task)

# in the ext stop hook:
def siLNt_stop():
    for t in scheduled_tasks:
        try:
            t.cancel()
        except Exception as ex:
            logger.warning(ex)

__all__ = ["siLNt_ext", "siLNt_static_files", "db", "siLNt_start", "siLNt_stop"]