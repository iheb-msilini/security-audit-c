import logging
import os
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    audits,
    connectors,
    dashboard,
    findings,
    manual_audits,
    reports,
    scoring,
)
from app.core.config import get_settings
from app.db.bootstrap import ensure_schema
from app.db.session import engine

settings = get_settings()
app = FastAPI(title=settings.app_name)
logger = logging.getLogger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup() -> None:
    if os.getenv("APP_SKIP_DB_INIT") == "1" or os.getenv("PYTEST_CURRENT_TEST") or "pytest" in sys.modules:
        return

    try:
        async with engine.begin() as conn:
            await conn.run_sync(ensure_schema)
    except Exception as exc:
        logger.warning("Database initialization skipped: %s", exc)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


app.include_router(audits.router, prefix=settings.api_prefix)
app.include_router(manual_audits.router, prefix=settings.api_prefix)
app.include_router(connectors.router, prefix=settings.api_prefix)
app.include_router(reports.router, prefix=settings.api_prefix)
app.include_router(scoring.router, prefix=settings.api_prefix)
app.include_router(dashboard.router, prefix=settings.api_prefix)
app.include_router(findings.router, prefix=settings.api_prefix)
