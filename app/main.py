from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.callbacks import router as callbacks_router
from app.api.management import router as management_router
from app.api.proxy import close_http_client
from app.api.proxy import router as proxy_router
from app.api.webhooks import router as webhooks_router
from app.core.config import get_settings
from app.core.licensing import LicenseMiddleware, LicenseValidator
from app.services.redis_pubsub import close_redis

log = logging.getLogger(__name__)

try:
    from ee.api import router as ee_router
except ImportError as exc:
    ee_router = None
    # Silent only when ee/ is absent; a broken Enterprise install should be visible.
    if not (isinstance(exc, ModuleNotFoundError) and exc.name in ("ee", "ee.api")):
        log.warning("Enterprise Edition failed to import, running Community Edition: %r", exc)

EDITION = "community" if ee_router is None else "enterprise"

settings = get_settings()
license_validator = LicenseValidator(settings)


@asynccontextmanager
async def lifespan(app: FastAPI):
    lic = await license_validator.current()
    log.info("License: %s (%s)", lic.tier.name.lower(), lic.reason)
    yield
    await license_validator.aclose()
    await close_http_client()
    await close_redis()


app = FastAPI(title="Agentic IAM Proxy", lifespan=lifespan)
app.add_middleware(
    LicenseMiddleware,
    validator=license_validator,
    enforce=settings.license_enforcement,
    upgrade_url=settings.upgrade_url,
)
app.include_router(webhooks_router)
app.include_router(proxy_router)
app.include_router(callbacks_router)
app.include_router(management_router)

if ee_router is not None:
    app.include_router(ee_router)


@app.get("/health")
async def health() -> dict:
    lic = await license_validator.current()
    return {"status": "ok", "edition": EDITION, "license_tier": lic.tier.name.lower()}
