from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid

import fakeredis
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.callbacks import router as callbacks_router
from app.core.config import Settings
from app.services import notification, redis_pubsub
from app.services.notification import WebhookError, send_generic_webhook, sign_payload
from app.services.supabase_client import get_supabase

SECRET = "whsec_dashboard_secret"
URL = "https://dash.example/hooks/approvals"
DETAILS = {"target_url": "https://api.stripe.com/v1/refunds", "method": "POST", "tenant_id": "t1", "expires_at": 1}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def receiver(monkeypatch):
    """Captures outgoing webhook requests; set .status to control the response."""
    state = {"requests": [], "status": 200, "error": None}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        if state["error"]:
            raise state["error"]
        return httpx.Response(state["status"])

    real_client = httpx.AsyncClient

    def client_factory(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(notification.httpx, "AsyncClient", client_factory)
    return state


def settings(**overrides):
    return Settings(_env_file=None, custom_webhook_url=URL, custom_webhook_secret=SECRET, **overrides)


def verify(secret: str, header: str, body: bytes, tolerance: int = 300) -> bool:
    """What a receiving dashboard does; documented in the README."""
    parts = dict(p.split("=", 1) for p in header.split(","))
    timestamp = int(parts["t"])
    expected = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return abs(time.time() - timestamp) <= tolerance and hmac.compare_digest(expected, parts["v1"])


# send_generic_webhook

@pytest.mark.anyio
async def test_sends_signed_clean_json(receiver):
    assert await send_generic_webhook("tok_abc", DETAILS, settings=settings()) is True
    (req,) = receiver["requests"]
    assert str(req.url) == URL
    assert req.headers["content-type"] == "application/json"
    assert json.loads(req.content) == {"approval_token": "tok_abc", "action": "requires_approval", **DETAILS}
    assert verify(SECRET, req.headers["x-signature"], req.content)
    assert not verify("wrong-secret", req.headers["x-signature"], req.content)
    assert not verify(SECRET, req.headers["x-signature"], req.content.replace(b"POST", b"GET!"))


def test_signature_format_is_stripe_style():
    assert sign_payload("s", b"{}", 1700000000) == (
        "t=1700000000,v1=" + hmac.new(b"s", b"1700000000.{}", hashlib.sha256).hexdigest()
    )


@pytest.mark.anyio
async def test_unconfigured_is_noop(receiver):
    assert await send_generic_webhook("tok", DETAILS, settings=Settings(_env_file=None)) is False
    assert receiver["requests"] == []


@pytest.mark.anyio
async def test_url_without_secret_refuses_to_send_unsigned(receiver):
    with pytest.raises(WebhookError):
        await send_generic_webhook("tok", DETAILS, settings=Settings(_env_file=None, custom_webhook_url=URL))
    assert receiver["requests"] == []


@pytest.mark.anyio
@pytest.mark.parametrize("url, allowed", [
    ("http://dash.example/hook", False),
    ("http://localhost:3000/hook", True),
    ("http://127.0.0.1:3000/hook", True),
])
async def test_plain_http_only_for_localhost(receiver, url, allowed):
    s = Settings(_env_file=None, custom_webhook_url=url, custom_webhook_secret=SECRET)
    if allowed:
        assert await send_generic_webhook("tok", DETAILS, settings=s) is True
    else:
        with pytest.raises(WebhookError):
            await send_generic_webhook("tok", DETAILS, settings=s)
        assert receiver["requests"] == []


@pytest.mark.anyio
@pytest.mark.parametrize("status, error", [(500, None), (302, None), (200, httpx.ConnectError("refused"))])
async def test_delivery_failures_raise_without_leaking_url_or_secret(receiver, status, error):
    receiver["status"], receiver["error"] = status, error
    with pytest.raises(WebhookError) as excinfo:
        await send_generic_webhook("tok_secret", DETAILS, settings=settings())
    for leaked in (URL, SECRET, "tok_secret"):
        assert leaked not in str(excinfo.value)


def test_empty_env_values_mean_unconfigured(tmp_path):
    env = tmp_path / ".env"
    env.write_text("CUSTOM_WEBHOOK_URL=\nCUSTOM_WEBHOOK_SECRET=\n")
    s = Settings(_env_file=str(env))
    assert s.custom_webhook_url is None and s.custom_webhook_secret is None


# Approval tokens + /approve, /deny

@pytest.fixture
async def fake_redis(monkeypatch):
    client = fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr(redis_pubsub, "_client", client)
    yield client
    await client.aclose()


@pytest.mark.anyio
async def test_only_token_hash_is_stored(fake_redis):
    rid = str(uuid.uuid4())
    token = await redis_pubsub.create_approval_token(rid, TENANT_A, 60)
    assert len(token) >= 43
    keys = [k async for k in fake_redis.scan_iter("approval_token:*")]
    assert keys == [f"approval_token:{TENANT_A}:" + hashlib.sha256(token.encode()).hexdigest()]
    assert token not in str(keys)
    assert 0 < await fake_redis.ttl(keys[0]) <= 60


@pytest.mark.anyio
async def test_token_is_single_use_and_validated(fake_redis):
    rid = str(uuid.uuid4())
    await fake_redis.set(f"approval:{rid}:pending", "1")
    token = await redis_pubsub.create_approval_token(rid, TENANT_A, 60)
    assert await redis_pubsub.publish_decision_by_token("not-a-real-token-xxxxxxxx", "approved", TENANT_A) is None
    assert await redis_pubsub.publish_decision_by_token(token, "denied", TENANT_A) is True
    assert await redis_pubsub.publish_decision_by_token(token, "approved", TENANT_A) is None
    assert await fake_redis.get(f"approval:{rid}:decision") == "denied"


@pytest.mark.anyio
async def test_other_tenant_cannot_use_or_burn_token(fake_redis):
    rid = str(uuid.uuid4())
    await fake_redis.set(f"approval:{rid}:pending", "1")
    token = await redis_pubsub.create_approval_token(rid, TENANT_A, 60)
    assert await redis_pubsub.publish_decision_by_token(token, "approved", TENANT_B) is None
    assert await fake_redis.get(f"approval:{rid}:decision") is None
    assert await redis_pubsub.publish_decision_by_token(token, "denied", TENANT_A) is True


TENANT_A = "aaaaaaaa-0000-4000-8000-000000000001"
TENANT_B = "bbbbbbbb-0000-4000-8000-000000000002"
MGMT_A, MGMT_B = "mgmt-token-tenant-a", "mgmt-token-tenant-b"


class FakeManagementTokens:
    """management_tokens lookup: .table().select().eq().limit().execute()."""

    rows = {hashlib.sha256(MGMT_A.encode()).hexdigest(): TENANT_A, hashlib.sha256(MGMT_B.encode()).hexdigest(): TENANT_B}

    def table(self, name):
        assert name == "management_tokens"
        filters = {}
        rows = self.rows

        class Query:
            def select(self, cols):
                return self

            def eq(self, col, value):
                filters[col] = value
                return self

            def limit(self, n):
                return self

            async def execute(self):
                tenant = rows.get(filters.get("token_hash"))
                return type("Resp", (), {"data": [{"tenant_id": tenant}] if tenant else []})()

        return Query()


def callbacks_app():
    app = FastAPI()
    app.include_router(callbacks_router)
    app.dependency_overrides[get_supabase] = lambda: FakeManagementTokens()
    return TestClient(app)


@pytest.fixture
def callbacks(monkeypatch):
    calls = []
    outcome = {"value": True}

    async def fake_publish(token, decision, tenant_id):
        calls.append((token, decision, tenant_id))
        if isinstance(outcome["value"], Exception):
            raise outcome["value"]
        return outcome["value"]

    monkeypatch.setattr(redis_pubsub, "publish_decision_by_token", fake_publish)
    return callbacks_app(), calls, outcome


TOKEN = "t" * 43
AUTH_A = {"X-Management-Token": MGMT_A}


@pytest.mark.parametrize("path, action", [("approve", "approved"), ("deny", "denied")])
def test_callbacks_publish_decision_for_callers_tenant(callbacks, path, action):
    client, calls, _ = callbacks
    resp = client.post(f"/api/v1/callbacks/{path}", json={"approval_token": TOKEN}, headers=AUTH_A)
    assert resp.status_code == 200
    assert resp.json() == {"status": "success", "action": action}
    assert calls == [(TOKEN, action, TENANT_A)]


@pytest.mark.parametrize("path", ["approve", "deny"])
@pytest.mark.parametrize("headers", [{}, {"X-Management-Token": ""}, {"X-Management-Token": "wrong"}])
def test_callbacks_require_management_token(callbacks, path, headers):
    client, calls, _ = callbacks
    assert client.post(f"/api/v1/callbacks/{path}", json={"approval_token": TOKEN}, headers=headers).status_code == 401
    assert calls == []


@pytest.mark.parametrize("value, status", [(None, 404), (False, 409)])
def test_callback_unknown_or_already_decided(callbacks, value, status):
    client, _, outcome = callbacks
    outcome["value"] = value
    assert client.post("/api/v1/callbacks/approve", json={"approval_token": TOKEN}, headers=AUTH_A).status_code == status


def test_callback_redis_down_is_503(callbacks):
    from redis.exceptions import ConnectionError as RedisConnectionError

    client, _, outcome = callbacks
    outcome["value"] = RedisConnectionError("down")
    assert client.post("/api/v1/callbacks/deny", json={"approval_token": TOKEN}, headers=AUTH_A).status_code == 503


@pytest.mark.parametrize("body", [{}, {"approval_token": ""}, {"approval_token": "short"}, {"approval_token": "x" * 300}, {"token": TOKEN}])
def test_callback_rejects_malformed_bodies(callbacks, body):
    client, calls, _ = callbacks
    assert client.post("/api/v1/callbacks/approve", json=body, headers=AUTH_A).status_code == 422
    assert calls == []


@pytest.mark.anyio
async def test_cross_tenant_callback_is_404_and_token_survives(fake_redis):
    rid = str(uuid.uuid4())
    await fake_redis.set(f"approval:{rid}:pending", "1")
    token = await redis_pubsub.create_approval_token(rid, TENANT_A, 60)
    app = FastAPI()
    app.include_router(callbacks_router)
    app.dependency_overrides[get_supabase] = lambda: FakeManagementTokens()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        wrong = await client.post("/api/v1/callbacks/approve", json={"approval_token": token}, headers={"X-Management-Token": MGMT_B})
        right = await client.post("/api/v1/callbacks/deny", json={"approval_token": token}, headers=AUTH_A)
    assert wrong.status_code == 404
    assert right.json() == {"status": "success", "action": "denied"}
    assert await fake_redis.get(f"approval:{rid}:decision") == "denied"
