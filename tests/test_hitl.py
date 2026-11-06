from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import shutil
import socket
import subprocess
import time
import uuid
from urllib.parse import urlencode

import fakeredis
import pytest
import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from app.api.callbacks import router as callbacks_router
from app.core.config import Settings, get_settings
from app.services import redis_pubsub, slack_service

SIGNING_SECRET = "slack-signing-secret"
RESPONSE_URL = "https://hooks.slack.com/actions/T1/123/abc"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def fake_redis(monkeypatch):
    client = fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr(redis_pubsub, "_client", client)
    return client


async def wait_until_pending(r, request_id):
    for _ in range(200):
        if await r.exists(f"approval:{request_id}:pending"):
            return
        await asyncio.sleep(0.01)
    raise AssertionError("request never became pending")


def slack_body(decision="approved", request_id=None, action_id=None, value=None, user=None, response_url=None) -> bytes:
    """A block_actions payload as Slack sends it for a click on one of our Approve/Deny buttons."""
    request_id = request_id or str(uuid.uuid4())
    action = {
        "action_id": action_id or ("deny_action" if decision == "denied" else "approve_action"),
        "value": f"{request_id}:{decision}" if value is None else value,
    }
    payload = {"type": "block_actions", "user": user or {"id": "U1", "username": "alice"}, "actions": [action]}
    if response_url is not None:
        payload["response_url"] = response_url
    return urlencode({"payload": json.dumps(payload)}).encode()


def slack_headers(body: bytes, secret=SIGNING_SECRET, ts=None) -> dict:
    ts = str(int(time.time()) if ts is None else ts)
    sig = hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return {
        "content-type": "application/x-www-form-urlencoded",
        "x-slack-request-timestamp": ts,
        "x-slack-signature": f"v0={sig}",
    }


# redis_pubsub

@pytest.mark.anyio
@pytest.mark.parametrize("decision", ["approved", "denied"])
async def test_decision_wakes_waiter(fake_redis, decision):
    rid = str(uuid.uuid4())
    waiter = asyncio.ensure_future(redis_pubsub.wait_for_approval(rid, timeout=5))
    await wait_until_pending(fake_redis, rid)
    assert await redis_pubsub.publish_decision(rid, decision) is True
    assert await asyncio.wait_for(waiter, 2) == decision
    assert not await fake_redis.exists(f"approval:{rid}:pending")


@pytest.mark.anyio
async def test_timeout_then_late_click_rejected(fake_redis):
    rid = str(uuid.uuid4())
    assert await redis_pubsub.wait_for_approval(rid, timeout=0.2) == "timeout"
    assert await redis_pubsub.publish_decision(rid, "approved") is False


@pytest.mark.anyio
async def test_first_decision_wins(fake_redis):
    rid = str(uuid.uuid4())
    waiter = asyncio.ensure_future(redis_pubsub.wait_for_approval(rid, timeout=5))
    await wait_until_pending(fake_redis, rid)
    assert await redis_pubsub.publish_decision(rid, "denied") is True
    assert await redis_pubsub.publish_decision(rid, "approved") is False
    assert await waiter == "denied"


@pytest.mark.anyio
async def test_decision_recorded_before_subscribe_is_seen(fake_redis):
    rid = str(uuid.uuid4())
    await fake_redis.set(f"approval:{rid}:decision", "approved")
    assert await redis_pubsub.wait_for_approval(rid, timeout=1) == "approved"


@pytest.mark.anyio
async def test_unknown_request_not_recorded(fake_redis):
    assert await redis_pubsub.publish_decision(str(uuid.uuid4()), "approved") is False


@pytest.mark.anyio
async def test_invalid_decision_rejected(fake_redis):
    with pytest.raises(ValueError):
        await redis_pubsub.publish_decision(str(uuid.uuid4()), "maybe")


# Slack callback

@pytest.fixture
def callback_client(monkeypatch):
    calls = []
    state = {"recorded": True, "updates": []}

    async def fake_publish(request_id, decision):
        calls.append((request_id, decision))
        return state["recorded"]

    async def fake_resolve(response_url, text):
        state["updates"].append((response_url, text))

    monkeypatch.setattr(redis_pubsub, "publish_decision", fake_publish)
    monkeypatch.setattr(slack_service, "resolve_message", fake_resolve)
    settings = Settings(_env_file=None, slack_signing_secret=SIGNING_SECRET)
    app = FastAPI()
    app.include_router(callbacks_router)
    app.dependency_overrides[get_settings] = lambda: settings
    client = TestClient(app)
    client.state = state
    return client, calls, settings


@pytest.mark.parametrize("decision", ["approved", "denied"])
def test_signed_click_publishes_decision(callback_client, decision):
    client, calls, _ = callback_client
    rid = str(uuid.uuid4())
    body = slack_body(decision, rid)
    resp = client.post("/api/v1/callbacks/slack", content=body, headers=slack_headers(body))
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "recorded": True}
    assert calls == [(rid, decision)]


@pytest.mark.parametrize("decision, text", [("approved", "Action Approved by <@U1>"), ("denied", "Action Denied by <@U1>")])
def test_click_replaces_message_without_buttons(callback_client, decision, text):
    client, _, _ = callback_client
    body = slack_body(decision, response_url=RESPONSE_URL)
    assert client.post("/api/v1/callbacks/slack", content=body, headers=slack_headers(body)).status_code == 200
    assert client.state["updates"] == [(RESPONSE_URL, text)]


def test_stale_click_says_so(callback_client):
    client, _, _ = callback_client
    client.state["recorded"] = False
    body = slack_body(response_url=RESPONSE_URL)
    resp = client.post("/api/v1/callbacks/slack", content=body, headers=slack_headers(body))
    assert resp.json() == {"ok": True, "recorded": False}
    assert "no longer pending" in client.state["updates"][0][1]


def test_unusual_user_id_is_not_rendered(callback_client):
    client, _, _ = callback_client
    body = slack_body(response_url=RESPONSE_URL, user={"id": "!channel", "username": "<!here>"})
    client.post("/api/v1/callbacks/slack", content=body, headers=slack_headers(body))
    assert client.state["updates"] == [(RESPONSE_URL, "Action Approved by user")]


@pytest.mark.parametrize("response_url", [
    "http://hooks.slack.com/actions/T1/1/a",
    "https://hooks.slack.com.evil.example/actions",
    "https://evil.example/actions",
    "https://169.254.169.254/latest/meta-data",
    "https://hooks.slack.com:8443/actions",
    "https://user:pw@hooks.slack.com/actions",
    "not a url",
])
def test_response_url_outside_slack_is_never_called(callback_client, response_url):
    client, calls, settings = callback_client
    settings.slack_signing_secret = None
    settings.slack_allow_unsigned_callbacks = True
    body = slack_body(response_url=response_url)
    resp = client.post("/api/v1/callbacks/slack", content=body, headers={"content-type": "application/x-www-form-urlencoded"})
    assert resp.status_code == 200
    assert len(calls) == 1
    assert client.state["updates"] == []


@pytest.mark.parametrize("headers", [
    lambda b: slack_headers(b, secret="wrong"),
    lambda b: slack_headers(b, ts=int(time.time()) - 3600),
    lambda b: {"content-type": "application/x-www-form-urlencoded"},
])
def test_bad_signature_rejected(callback_client, headers):
    client, calls, _ = callback_client
    body = slack_body()
    assert client.post("/api/v1/callbacks/slack", content=body, headers=headers(body)).status_code == 401
    assert calls == []


def test_tampered_body_rejected(callback_client):
    client, calls, _ = callback_client
    body = slack_body("denied")
    headers = slack_headers(body)
    tampered = body.replace(b"denied", b"approved").replace(b"deny_action", b"approve_action")
    assert client.post("/api/v1/callbacks/slack", content=tampered, headers=headers).status_code == 401
    assert calls == []


def test_missing_secret_fails_closed(callback_client):
    client, calls, settings = callback_client
    settings.slack_signing_secret = None
    body = slack_body()
    assert client.post("/api/v1/callbacks/slack", content=body, headers=slack_headers(body)).status_code == 503
    assert calls == []


def test_unsigned_allowed_only_in_dev_mode(callback_client):
    client, calls, settings = callback_client
    settings.slack_signing_secret = None
    settings.slack_allow_unsigned_callbacks = True
    body = slack_body()
    resp = client.post("/api/v1/callbacks/slack", content=body, headers={"content-type": "application/x-www-form-urlencoded"})
    assert resp.status_code == 200
    assert len(calls) == 1


@pytest.mark.parametrize("body", [
    b"",
    b"payload=not-json",
    urlencode({"payload": json.dumps({"actions": []})}).encode(),
    slack_body("escalated"),
    slack_body(value="not-a-uuid:approved"),
    slack_body(value=str(uuid.uuid4())),  # no decision
    slack_body("approved", action_id="deny_action"),  # button and value disagree
    slack_body("approved", action_id="approve"),  # old-style action_id
    urlencode({"payload": json.dumps({"actions": [{"action_id": "approve_action", "value": 42}]})}).encode(),
])
def test_malformed_payload_rejected(callback_client, body):
    client, calls, _ = callback_client
    assert client.post("/api/v1/callbacks/slack", content=body, headers=slack_headers(body)).status_code == 400
    assert calls == []


def test_redis_down_returns_503(callback_client, monkeypatch):
    client, _, _ = callback_client

    async def broken(request_id, decision):
        raise RedisConnectionError("down")

    monkeypatch.setattr(redis_pubsub, "publish_decision", broken)
    body = slack_body()
    assert client.post("/api/v1/callbacks/slack", content=body, headers=slack_headers(body)).status_code == 503


# Real Redis (skipped when redis-server isn't installed)

@pytest.fixture
async def real_redis(monkeypatch):
    if shutil.which("redis-server") is None:
        pytest.skip("redis-server not installed")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        ["redis-server", "--port", str(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL,
    )
    client = redis.Redis(port=port, decode_responses=True)
    monkeypatch.setattr(redis_pubsub, "_client", client)
    yield client
    proc.terminate()
    proc.wait()


@pytest.mark.anyio
async def test_real_redis_roundtrip(real_redis):
    for _ in range(100):
        try:
            await real_redis.ping()
            break
        except RedisConnectionError:
            await asyncio.sleep(0.05)
    rid = str(uuid.uuid4())
    waiter = asyncio.ensure_future(redis_pubsub.wait_for_approval(rid, timeout=5))
    await wait_until_pending(real_redis, rid)
    assert await redis_pubsub.publish_decision(rid, "approved") is True
    assert await asyncio.wait_for(waiter, 2) == "approved"
    assert await redis_pubsub.wait_for_approval(str(uuid.uuid4()), timeout=0.3) == "timeout"
    await real_redis.aclose()
