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

silnt_ext: APIRouter = APIRouter(prefix="/silnt", tags=["silnt"])
silnt_ext.include_router(silnt_generic_router)
silnt_ext.include_router(silnt_api_router)

__all__ = ["siLNt_ext", "silnt_static_files", "db"]
