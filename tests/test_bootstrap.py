from __future__ import annotations

import asyncio
import hashlib
import uuid

import pytest

import bootstrap

EXISTING = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"


class FakeDatabase:
    """Stand-in for the Database methods bootstrap uses."""

    def __init__(self) -> None:
        self.tables = {"tenants": [{"id": EXISTING, "name": "Acme"}], "management_tokens": []}
        self.closed = False

    async def create_tenant(self, name):
        self.tables["tenants"].append({"id": str(uuid.uuid4()), "name": name})
        return self.tables["tenants"][-1]["id"]

    async def tenant_exists(self, tenant_id):
        return any(t["id"] == tenant_id for t in self.tables["tenants"])

    async def create_management_token(self, tenant_id, token_hash, name):
        self.tables["management_tokens"].append({"tenant_id": tenant_id, "token_hash": token_hash, "name": name})

    async def close(self):
        self.closed = True


def run(db, *args):
    return asyncio.run(bootstrap.bootstrap(db, *args))


def test_creates_tenant_and_stores_only_hash():
    db = FakeDatabase()
    tenant_id, token = run(db, None, "Startup", "admin")
    assert {"id": tenant_id, "name": "Startup"} in db.tables["tenants"]
    (row,) = db.tables["management_tokens"]
    assert row["tenant_id"] == tenant_id
    assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in str(db.tables)
    assert len(token) >= 43


def test_uses_existing_tenant():
    db = FakeDatabase()
    tenant_id, _ = run(db, EXISTING, "ignored", "ci")
    assert tenant_id == EXISTING
    assert len(db.tables["tenants"]) == 1
    assert db.tables["management_tokens"][0]["name"] == "ci"


def test_unknown_tenant_aborts_without_token():
    db = FakeDatabase()
    with pytest.raises(SystemExit):
        run(db, str(uuid.uuid4()), "x", "admin")
    assert db.tables["management_tokens"] == []


def test_main_prints_token_banner(monkeypatch, capsys):
    from app.core.config import Settings
    from app.services import database

    db = FakeDatabase()

    async def connect(dsn):
        assert dsn == "postgresql://u:p@db:5432/iam"
        return db

    monkeypatch.setattr(bootstrap, "get_settings", lambda: Settings(
        _env_file=None, database_url="postgresql://u:p@db:5432/iam"
    ))
    monkeypatch.setattr(database.Database, "connect", staticmethod(connect))
    bootstrap.main([])
    out = capsys.readouterr().out
    token_hash = db.tables["management_tokens"][0]["token_hash"]
    token = out.split("✅ Admin Token Generated: ", 1)[1].split()[0]
    assert hashlib.sha256(token.encode()).hexdigest() == token_hash
    assert "⚠️ SAVE THIS NOW. It will never be shown again and is required to hit the /api/v1/manage endpoints." in out
    assert db.closed


def test_main_requires_database_url(monkeypatch):
    from app.core.config import Settings

    monkeypatch.setattr(bootstrap, "get_settings", lambda: Settings(_env_file=None))
    with pytest.raises(SystemExit) as excinfo:
        bootstrap.main([])
    assert "DATABASE_URL" in str(excinfo.value)
