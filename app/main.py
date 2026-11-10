from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.callbacks import router as callbacks_router
from app.api.management import router as management_router
from app.api.proxy import close_http_client
from app.api.proxy import router as proxy_router
from app.api.webhooks import router as webhooks_router
from app.core.config import get_settings
from app.services.database import close_database, get_database
from app.services.redis_pubsub import close_redis

log = logging.getLogger(__name__)


def _configure_logging() -> None:
    # Uvicorn only configures its own loggers; without a handler, app INFO logs (incl. app.audit) are dropped.
    app_log = logging.getLogger("app")
    if not app_log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        app_log.addHandler(handler)
        app_log.setLevel(logging.INFO)


_configure_logging()
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.database_url is None:
        log.error("DATABASE_URL is not set; proxy and management requests will return 503")
    else:
        await get_database(settings)
        log.info("Database ready")
    yield
    await close_http_client()
    await close_redis()
    await close_database()


app = FastAPI(title="Agentic IAM Proxy", lifespan=lifespan)
app.include_router(webhooks_router)
app.include_router(proxy_router)
app.include_router(callbacks_router)
app.include_router(management_router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
