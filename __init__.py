import asyncio
from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles

from .crud import db
from .views import silnt_generic_router
from .views_api import silnt_api_router

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

__all__ = ["siLNt_ext", "siLNt_static_files", "db"]
