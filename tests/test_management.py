from __future__ import annotations

import hashlib
import logging

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import proxy
from app.api.management import router as management_router
from app.core.config import Settings, get_settings
from app.services.database import get_database
from app.services.policy_service import PolicyService, get_policy_service
from tests.test_policy_service import FakePolicyTable

TENANT = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"
OTHER_TENANT = "9d1b2c3e-4f50-4a61-8b72-c3d4e5f60718"
MGMT_TOKEN = "mgmt-token-for-tenant"
AGENT_TOKEN = "existing-agent-token"
RAW_KEY = "sk_live_NEVER_ECHO_ME_42"


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class FakeDatabase:
    """In-memory tables behind the Database methods the management API and proxy use."""

    def __init__(self) -> None:
        self.tables = {
            "management_tokens": [{"tenant_id": TENANT, "token_hash": sha(MGMT_TOKEN)}],
            "agent_identities": [{"id": "agent-0", "tenant_id": TENANT, "name": "old", "agent_token": sha(AGENT_TOKEN)}],
            "tenant_api_keys": [],
        }

    def _find(self, table, **match):
        return [r for r in self.tables[table] if all(r.get(k) == v for k, v in match.items())]

    async def tenant_for_management_token_hash(self, token_hash):
        rows = self._find("management_tokens", token_hash=token_hash)
        return rows[0]["tenant_id"] if rows else None

    async def agent_for_token_hash(self, token_hash):
        rows = self._find("agent_identities", agent_token=token_hash)
        return {"tenant_id": rows[0]["tenant_id"], "name": rows[0]["name"], "tenant_name": None} if rows else None

    async def create_agent(self, tenant_id, name, token_hash):
        agents = self.tables["agent_identities"]
        agents.append({"id": f"agent-{len(agents)}", "tenant_id": tenant_id, "name": name, "agent_token": token_hash})
        return agents[-1]["id"]

    async def store_api_key(self, tenant_id, service_name, encrypted_api_key):
        keys = self.tables["tenant_api_keys"]
        keys[:] = [r for r in keys if (r["tenant_id"], r["service_name"]) != (tenant_id, service_name)]
        keys.append({"tenant_id": tenant_id, "service_name": service_name, "encrypted_api_key": encrypted_api_key})

    async def encrypted_api_key(self, tenant_id, service_name):
        rows = self._find("tenant_api_keys", tenant_id=tenant_id, service_name=service_name)
        return rows[0]["encrypted_api_key"] if rows else None


@pytest.fixture
def setup(monkeypatch):
    db = FakeDatabase()
    settings = Settings(_env_file=None, vault_encryption_key=Fernet.generate_key().decode())
    app = FastAPI()
    app.include_router(management_router)
    app.include_router(proxy.router)
    app.dependency_overrides[get_database] = lambda: db
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_policy_service] = lambda: PolicyService(FakePolicyTable([]))
    monkeypatch.setattr(proxy, "_http_client", None)
    return app, TestClient(app), db, settings


MGMT = {"X-Management-Token": MGMT_TOKEN}


# Authentication

@pytest.mark.parametrize("headers", [{}, {"X-Management-Token": ""}, {"X-Management-Token": "wrong"}])
def test_management_requires_valid_token(setup, headers):
    _, client, db, _ = setup
    assert client.post("/api/v1/manage/agents", json={"agent_name": "a"}, headers=headers).status_code == 401
    assert len(db.tables["agent_identities"]) == 1


def test_agent_token_cannot_manage(setup):
    _, client, _, _ = setup
    resp = client.post("/api/v1/manage/agents", json={"agent_name": "a"}, headers={"X-Management-Token": AGENT_TOKEN})
    assert resp.status_code == 401


def test_management_token_cannot_proxy(setup):
    _, client, _, _ = setup
    resp = client.get("/api/v1/proxy/", headers={"Authorization": f"Bearer {MGMT_TOKEN}", "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 401


# Agents

def test_create_agent_returns_token_once_and_stores_only_hash(setup):
    _, client, db, _ = setup
    resp = client.post("/api/v1/manage/agents", json={"agent_name": "  billing-bot  "}, headers=MGMT)
    assert resp.status_code == 201
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["agent_name"] == "billing-bot"
    token = body["token"]
    assert len(token) >= 43

    row = db.tables["agent_identities"][-1]
    assert row == {"tenant_id": TENANT, "name": "billing-bot", "agent_token": sha(token), "id": body["id"]}
    assert token not in str(db.tables)


def test_tokens_are_unique(setup):
    _, client, _, _ = setup
    tokens = {client.post("/api/v1/manage/agents", json={"agent_name": "a"}, headers=MGMT).json()["token"] for _ in range(5)}
    assert len(tokens) == 5


@pytest.mark.parametrize("payload", [{}, {"agent_name": ""}, {"agent_name": "   "}, {"agent_name": "x" * 101}])
def test_invalid_agent_name_rejected(setup, payload):
    _, client, _, _ = setup
    assert client.post("/api/v1/manage/agents", json=payload, headers=MGMT).status_code == 422


def test_tenant_comes_from_token_not_body(setup):
    _, client, db, _ = setup
    client.post("/api/v1/manage/agents", json={"agent_name": "a", "tenant_id": OTHER_TENANT}, headers=MGMT)
    assert db.tables["agent_identities"][-1]["tenant_id"] == TENANT


# Vault keys

def test_add_vault_key_stores_ciphertext_and_never_returns_key(setup, caplog):
    _, client, db, _ = setup
    with caplog.at_level(logging.DEBUG):
        resp = client.post("/api/v1/manage/vault/keys", json={"service_name": "stripe", "raw_api_key": RAW_KEY}, headers=MGMT)
    assert resp.status_code == 200
    assert resp.json() == {"service_name": "stripe", "status": "stored"}
    assert RAW_KEY not in resp.text
    assert RAW_KEY not in caplog.text

    (row,) = db.tables["tenant_api_keys"]
    assert row["tenant_id"] == TENANT and row["service_name"] == "stripe"
    assert RAW_KEY not in row["encrypted_api_key"]


def test_add_vault_key_upserts(setup):
    _, client, db, _ = setup
    for key in ("sk_old_1", "sk_new_2"):
        client.post("/api/v1/manage/vault/keys", json={"service_name": "stripe", "raw_api_key": key}, headers=MGMT)
    assert len(db.tables["tenant_api_keys"]) == 1


def test_unknown_service_rejected(setup):
    _, client, db, _ = setup
    resp = client.post("/api/v1/manage/vault/keys", json={"service_name": "aws", "raw_api_key": RAW_KEY}, headers=MGMT)
    assert resp.status_code == 422
    assert "stripe" in resp.json()["detail"]
    assert db.tables["tenant_api_keys"] == []


@pytest.mark.parametrize("bad", ["has space", "line\r\nX-Evil: 1", ""])
def test_header_unsafe_key_rejected_without_echo(setup, bad):
    _, client, db, _ = setup
    resp = client.post("/api/v1/manage/vault/keys", json={"service_name": "stripe", "raw_api_key": bad}, headers=MGMT)
    assert resp.status_code == 422
    if bad:
        assert bad not in resp.text
    assert db.tables["tenant_api_keys"] == []


def test_vault_not_configured_is_503(setup):
    _, client, db, settings = setup
    settings.vault_encryption_key = None
    resp = client.post("/api/v1/manage/vault/keys", json={"service_name": "stripe", "raw_api_key": RAW_KEY}, headers=MGMT)
    assert resp.status_code == 503
    assert db.tables["tenant_api_keys"] == []


# Round trip: management API -> proxy

def test_created_agent_and_stored_key_work_through_proxy(setup):
    app, client, _, _ = setup
    sent = []

    def downstream(request):
        sent.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    app.dependency_overrides[proxy.get_http_client] = lambda: httpx.AsyncClient(transport=httpx.MockTransport(downstream))
    token = client.post("/api/v1/manage/agents", json={"agent_name": "bot"}, headers=MGMT).json()["token"]
    client.post("/api/v1/manage/vault/keys", json={"service_name": "stripe", "raw_api_key": RAW_KEY}, headers=MGMT)

    resp = client.get("/api/v1/proxy/v1/charges", headers={"Authorization": f"Bearer {token}", "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 200
    assert sent[0].headers["authorization"] == f"Bearer {RAW_KEY}"
