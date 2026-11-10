from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.webhooks import router
from app.core.config import Settings, get_settings
from app.services.database import get_database

SECRET = "whsec_" + base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
TENANT = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"
PRO_PRODUCT = "prod-pro"
ENTERPRISE_PRODUCT = "prod-ent"


class FakeDatabase:
    """Records Database.apply_polar_subscription() calls."""

    def __init__(self) -> None:
        self.calls = []

    async def apply_polar_subscription(self, **params):
        self.calls.append(params)
        return "applied"


def subscription_event(event_type="subscription.updated", product=PRO_PRODUCT, status="active",
                       external_id=TENANT, metadata=None) -> dict:
    return {
        "type": event_type,
        "timestamp": "2026-11-06T10:00:00Z",
        "data": {
            "id": "sub_1",
            "status": status,
            "product_id": product,
            "customer_id": "cus_1",
            "created_at": "2026-11-01T00:00:00Z",
            "modified_at": "2026-11-06T10:00:00Z",
            "current_period_end": "2026-12-01T00:00:00Z",
            "cancel_at_period_end": False,
            "metadata": metadata or {},
            "customer": {"id": "cus_1", "external_id": external_id},
        },
    }


def sign(body: bytes, key: bytes, msg_id="msg_1", ts=None) -> dict:
    ts = str(int(time.time()) if ts is None else ts)
    sig = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest())
    return {"webhook-id": msg_id, "webhook-timestamp": ts, "webhook-signature": "v1," + sig.decode()}


STANDARD_KEY = base64.b64decode(SECRET[len("whsec_"):])
LEGACY_KEY = SECRET.encode()


@pytest.fixture
def setup():
    db = FakeDatabase()
    settings = Settings(
        _env_file=None,
        polar_webhook_secret=SECRET,
        polar_product_tiers={PRO_PRODUCT: "pro", ENTERPRISE_PRODUCT: "enterprise"},
    )
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_database] = lambda: db
    return TestClient(app), db, settings


def post(client, payload, key=STANDARD_KEY, **sign_kwargs):
    body = json.dumps(payload).encode()
    headers = {"content-type": "application/json", **sign(body, key, **sign_kwargs)}
    return client.post("/api/v1/webhooks/polar", content=body, headers=headers)


@pytest.mark.parametrize("key", [STANDARD_KEY, LEGACY_KEY], ids=["standard", "legacy"])
def test_valid_event_updates_tier(setup, key):
    client, db, _ = setup
    resp = post(client, subscription_event(product=ENTERPRISE_PRODUCT), key=key)
    assert resp.status_code == 202
    assert resp.json() == {"result": "applied"}
    (params,) = db.calls
    assert params["tenant_id"] == TENANT
    assert params["tier"] == "enterprise"
    assert params["status"] == "active"
    assert params["event_id"] == "msg_1"
    # asyncpg binds timestamptz from aware datetimes, not strings.
    assert params["modified_at"] == datetime(2026, 11, 6, 10, tzinfo=timezone.utc)
    assert params["current_period_end"] == datetime(2026, 12, 1, tzinfo=timezone.utc)


def test_subscription_created_is_handled(setup):
    client, db, _ = setup
    assert post(client, subscription_event("subscription.created")).status_code == 202
    assert db.calls[0]["tier"] == "pro"


def test_bad_signature_rejected(setup):
    client, db, _ = setup
    assert post(client, subscription_event(), key=b"wrong").status_code == 403
    assert db.calls == []


def test_tampered_body_rejected(setup):
    client, db, _ = setup
    body = json.dumps(subscription_event(product=PRO_PRODUCT)).encode()
    headers = sign(body, STANDARD_KEY)
    tampered = body.replace(PRO_PRODUCT.encode(), ENTERPRISE_PRODUCT.encode())
    resp = client.post("/api/v1/webhooks/polar", content=tampered, headers=headers)
    assert resp.status_code == 403
    assert db.calls == []


def test_missing_headers_rejected(setup):
    client, db, _ = setup
    resp = client.post("/api/v1/webhooks/polar", json=subscription_event())
    assert resp.status_code == 403
    assert db.calls == []


def test_replayed_old_timestamp_rejected(setup):
    client, db, _ = setup
    assert post(client, subscription_event(), ts=int(time.time()) - 3600).status_code == 403
    assert db.calls == []


def test_unconfigured_secret_rejects_everything(setup):
    client, db, settings = setup
    settings.polar_webhook_secret = None
    assert post(client, subscription_event()).status_code == 503
    assert db.calls == []


def test_other_event_types_ignored(setup):
    client, db, _ = setup
    resp = post(client, {"type": "order.created", "data": {"id": "o_1"}})
    assert resp.status_code == 202
    assert resp.json() == {"result": "ignored"}
    assert db.calls == []


def test_unknown_product_ignored(setup):
    client, db, _ = setup
    assert post(client, subscription_event(product="prod-other")).json() == {"result": "unknown_product"}
    assert db.calls == []


def test_missing_tenant_ignored(setup):
    client, db, _ = setup
    assert post(client, subscription_event(external_id=None)).json() == {"result": "no_tenant"}
    assert post(client, subscription_event(external_id="not-a-uuid")).json() == {"result": "no_tenant"}
    assert db.calls == []


def test_tenant_from_metadata_fallback(setup):
    client, db, _ = setup
    post(client, subscription_event(external_id=None, metadata={"tenant_id": TENANT}))
    assert db.calls[0]["tenant_id"] == TENANT


def test_malformed_subscription_rejected(setup):
    client, db, _ = setup
    assert post(client, {"type": "subscription.updated", "data": {"id": "sub_1"}}).status_code == 400
    assert db.calls == []
