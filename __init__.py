import asyncio
from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles

from .crud import db
from .views import silnt_generic_router
from .views_api import silnt_api_router

silnt_static_files = [
    {
        "path": "/siLNt/static",
        "app": StaticFiles(packages=[("lnbits", "extensions/siLNt/static")]),
        "name": "silnt_static",
    }
]

siLNt_ext: APIRouter = APIRouter(prefix="/silnt", tags=["silnt"])
siLNt_ext.include_router(silnt_generic_router)
siLNt_ext.include_router(silnt_api_router)

scheduled_tasks: list[asyncio.Task] = []

def silnt_start():
    from lnbits.tasks import create_permanent_unique_task    
    task = create_permanent_unique_task("ext_silnt", wait_for_paid_invoices)
    scheduled_tasks.append(task)
       
def silnt_stop():    
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception as ex:
            logger.warning(ex)
__all__ = ["silnt_start", "silnt_stop", "siLNt_ext", "silnt_static_files", "db"]
