from __future__ import annotations

import asyncio
import logging
import posixpath
import re
import time
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Callable, Optional, Tuple

import httpx
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import Settings

log = logging.getLogger(__name__)

VALIDATE_PATH = "/v1/customer-portal/license-keys/validate"
RETRY_AFTER_FAILURE_SECONDS = 60


class Tier(IntEnum):
    COMMUNITY = 0
    PRO = 1
    ENTERPRISE = 2


# Path prefix -> minimum tier. Everything else is Community.
PREMIUM_ROUTES: Tuple[Tuple[str, Tier], ...] = (
    ("/api/v1/audit-logs", Tier.ENTERPRISE),
    ("/api/v1/sso", Tier.ENTERPRISE),
    ("/api/v1/dashboard", Tier.PRO),
)


@dataclass(frozen=True)
class License:
    tier: Tier
    reason: str
    expires_at: Optional[float] = None


def normalize_path(path: str) -> str:
    # Collapse "//" first: posixpath.normpath preserves a leading double slash.
    path = posixpath.normpath(re.sub(r"/+", "/", "/" + path))
    return path.lower()


def required_tier(path: str) -> Optional[Tier]:
    path = normalize_path(path)
    for prefix, tier in PREMIUM_ROUTES:
        if path == prefix or path.startswith(prefix + "/"):
            return tier
    return None


def _parse_timestamp(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


class LicenseValidator:
    """Validates this deployment's Polar license key, with caching and an outage grace period."""

    def __init__(
        self,
        settings: Settings,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._clock = clock
        self._benefit_tiers = {
            benefit: Tier[name.upper()] for benefit, name in settings.polar_benefit_tiers.items()
        }
        self._client: Optional[httpx.AsyncClient] = None
        self._lock: Optional[asyncio.Lock] = None
        self._current: Optional[License] = None
        self._next_check = 0.0
        self._last_good: Optional[License] = None
        self._last_good_at = 0.0

    async def current(self) -> License:
        s = self._settings
        if not (s.polar_license_key and s.polar_organization_id):
            return License(Tier.COMMUNITY, "no license key configured")
        if self._is_fresh():
            return self._current
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if not self._is_fresh():
                await self._refresh()
            return self._current

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _is_fresh(self) -> bool:
        now = self._clock()
        return self._current is not None and now < self._next_check and not self._expired(self._current, now)

    @staticmethod
    def _expired(lic: License, now: float) -> bool:
        return lic.expires_at is not None and now >= lic.expires_at

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._settings.polar_api_url, timeout=5.0, transport=self._transport
            )
        return self._client

    async def _refresh(self) -> None:
        s = self._settings
        try:
            resp = await self._http().post(
                VALIDATE_PATH,
                json={"key": s.polar_license_key, "organization_id": s.polar_organization_id},
            )
        except httpx.HTTPError as exc:
            self._on_unreachable(f"Polar unreachable ({type(exc).__name__})")
            return

        if resp.status_code in (400, 404, 422):
            self._on_answer(License(Tier.COMMUNITY, "license key is invalid, revoked or expired"))
            return
        if resp.status_code != 200:
            self._on_unreachable(f"Polar returned HTTP {resp.status_code}")
            return
        try:
            data = resp.json()
            granted = data.get("status") == "granted"
            expires_at = _parse_timestamp(data.get("expires_at"))
            tier = self._benefit_tiers.get(data.get("benefit_id"))
        except (ValueError, AttributeError, TypeError):
            self._on_unreachable("malformed response from Polar")
            return

        if not granted:
            self._on_answer(License(Tier.COMMUNITY, "license key is not granted"))
        elif expires_at is not None and expires_at <= self._clock():
            self._on_answer(License(Tier.COMMUNITY, "license key has expired"))
        elif tier is None:
            self._on_answer(License(Tier.COMMUNITY, "license benefit is not mapped to a tier"))
        else:
            self._on_answer(License(tier, "valid license", expires_at))

    def _on_answer(self, lic: License) -> None:
        now = self._clock()
        self._current = lic
        self._next_check = now + self._settings.license_cache_ttl_seconds
        if lic.tier > Tier.COMMUNITY:
            self._last_good, self._last_good_at = lic, now

    def _on_unreachable(self, reason: str) -> None:
        now = self._clock()
        good = self._last_good
        if (
            good is not None
            and now - self._last_good_at < self._settings.license_grace_seconds
            and not self._expired(good, now)
        ):
            log.warning("%s; using last valid license (grace period)", reason)
            self._current = good
        else:
            log.error("%s; no valid cached license, falling back to Community", reason)
            self._current = License(Tier.COMMUNITY, reason)
        self._next_check = now + RETRY_AFTER_FAILURE_SECONDS


class LicenseMiddleware:
    """Returns 402 Payment Required for premium routes the current license doesn't cover."""

    def __init__(
        self, app: ASGIApp, validator: LicenseValidator, enforce: bool = True, upgrade_url: str = ""
    ) -> None:
        self.app = app
        self._validator = validator
        self._enforce = enforce
        self._upgrade_url = upgrade_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._enforce:
            await self.app(scope, receive, send)
            return
        needed = required_tier(scope["path"])
        if needed is None:
            await self.app(scope, receive, send)
            return
        lic = await self._validator.current()
        if lic.tier >= needed:
            await self.app(scope, receive, send)
            return
        response = JSONResponse(
            status_code=402,
            content={
                "error": "payment_required",
                "detail": f"This feature requires the {needed.name.title()} plan.",
                "required_tier": needed.name.lower(),
                "current_tier": lic.tier.name.lower(),
                "reason": lic.reason,
                "upgrade_url": self._upgrade_url,
            },
        )
        await response(scope, receive, send)
