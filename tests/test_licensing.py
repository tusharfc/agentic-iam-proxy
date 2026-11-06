from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.licensing import LicenseMiddleware, LicenseValidator, Tier, required_tier

ORG = "11111111-1111-4111-8111-111111111111"
ENTERPRISE_BENEFIT = "22222222-2222-4222-8222-222222222222"
PRO_BENEFIT = "33333333-3333-4333-8333-333333333333"


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


class Polar:
    """Fake Polar API; set .response to a dict (200), an int status, or an exception."""

    def __init__(self, response) -> None:
        self.response = response
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if isinstance(self.response, Exception):
            raise self.response
        if isinstance(self.response, int):
            return httpx.Response(self.response, json={"error": "x", "detail": "x"})
        return httpx.Response(200, json=self.response)


def granted(benefit: str = ENTERPRISE_BENEFIT, expires_at=None) -> dict:
    return {"status": "granted", "benefit_id": benefit, "expires_at": expires_at}


def make_client(polar: Polar, key="key_abc", clock=None, **overrides) -> TestClient:
    settings = Settings(
        _env_file=None,
        polar_organization_id=ORG,
        polar_license_key=key,
        polar_benefit_tiers={ENTERPRISE_BENEFIT: "enterprise", PRO_BENEFIT: "pro"},
        **overrides,
    )
    validator = LicenseValidator(settings, transport=httpx.MockTransport(polar), clock=clock or Clock())
    app = FastAPI()
    app.add_middleware(LicenseMiddleware, validator=validator, enforce=settings.license_enforcement)

    @app.get("/api/v1/audit-logs")
    async def audit_logs():
        return {"logs": []}

    @app.get("/api/v1/dashboard")
    async def dashboard():
        return {"ok": True}

    @app.get("/api/v1/tools")
    async def tools():
        return {"ok": True}

    return TestClient(app)


def test_valid_enterprise_key_passes():
    client = make_client(Polar(granted()))
    assert client.get("/api/v1/audit-logs").status_code == 200
    assert client.get("/api/v1/dashboard").status_code == 200


def test_pro_key_cannot_reach_enterprise_routes():
    client = make_client(Polar(granted(PRO_BENEFIT)))
    assert client.get("/api/v1/dashboard").status_code == 200
    resp = client.get("/api/v1/audit-logs")
    assert resp.status_code == 402
    assert resp.json()["required_tier"] == "enterprise"
    assert resp.json()["current_tier"] == "pro"


def test_no_key_gets_402_without_calling_polar():
    polar = Polar(granted())
    client = make_client(polar, key=None)
    assert client.get("/api/v1/audit-logs").status_code == 402
    assert polar.calls == 0


def test_revoked_key_gets_402():
    assert make_client(Polar(404)).get("/api/v1/audit-logs").status_code == 402


def test_unmapped_benefit_is_community():
    client = make_client(Polar(granted("44444444-4444-4444-8444-444444444444")))
    assert client.get("/api/v1/dashboard").status_code == 402


def test_expired_key_gets_402():
    clock = Clock()
    client = make_client(Polar(granted(expires_at="2020-01-01T00:00:00.000000Z")), clock=clock)
    assert client.get("/api/v1/audit-logs").status_code == 402


def test_free_routes_untouched():
    polar = Polar(404)
    client = make_client(polar)
    assert client.get("/api/v1/tools").status_code == 200
    assert polar.calls == 0


@pytest.mark.parametrize(
    "path",
    ["/api/v1/audit-logs/", "/api/v1//audit-logs", "/API/v1/Audit-Logs", "/api/v1/x/../audit-logs",
     "/api/v1/audit-logs/export"],
)
def test_path_variants_are_gated(path):
    assert make_client(Polar(404)).get(path).status_code == 402


def test_leading_double_slash_is_gated():
    # An HTTP client would read "//api/..." as a host, so check the matcher directly.
    assert required_tier("//api/v1/audit-logs") == Tier.ENTERPRISE
    assert required_tier("/api/v1/audit-logsx") is None


def test_results_are_cached_until_ttl():
    polar, clock = Polar(granted()), Clock()
    client = make_client(polar, clock=clock, license_cache_ttl_seconds=3600)
    client.get("/api/v1/audit-logs")
    client.get("/api/v1/audit-logs")
    assert polar.calls == 1
    clock.now += 3601
    client.get("/api/v1/audit-logs")
    assert polar.calls == 2


def test_license_revoked_after_ttl():
    polar, clock = Polar(granted()), Clock()
    client = make_client(polar, clock=clock)
    assert client.get("/api/v1/audit-logs").status_code == 200
    polar.response = 404
    clock.now += 3601
    assert client.get("/api/v1/audit-logs").status_code == 402


def test_polar_outage_without_cache_fails_closed():
    client = make_client(Polar(httpx.ConnectError("down")))
    assert client.get("/api/v1/audit-logs").status_code == 402


def test_polar_outage_uses_grace_period_then_fails_closed():
    polar, clock = Polar(granted()), Clock()
    client = make_client(polar, clock=clock)
    assert client.get("/api/v1/audit-logs").status_code == 200

    polar.response = 503
    clock.now += 3601
    assert client.get("/api/v1/audit-logs").status_code == 200

    clock.now += 72 * 3600
    assert client.get("/api/v1/audit-logs").status_code == 402


def test_failed_check_is_not_retried_on_every_request():
    polar = Polar(httpx.ConnectError("down"))
    client = make_client(polar)
    for _ in range(5):
        client.get("/api/v1/audit-logs")
    assert polar.calls == 1


def test_enforcement_can_be_disabled():
    client = make_client(Polar(404), license_enforcement=False)
    assert client.get("/api/v1/audit-logs").status_code == 200
