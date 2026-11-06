from __future__ import annotations

import hashlib
import uuid

import pytest

import bootstrap

EXISTING = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"


class FakeClient:
    """Sync supabase client stand-in: tenants + management_tokens."""

    def __init__(self) -> None:
        self.tables = {"tenants": [{"id": EXISTING, "name": "Acme"}], "management_tokens": []}

    def table(self, name):
        fake, state = self, {"filters": {}}

        class Query:
            def insert(self, row):
                state["insert"] = row
                return self

            def select(self, cols):
                return self

            def eq(self, col, value):
                state["filters"][col] = value
                return self

            def limit(self, n):
                return self

            def execute(self):
                rows = fake.tables[name]
                if "insert" in state:
                    row = dict(state["insert"])
                    row.setdefault("id", str(uuid.uuid4()))
                    rows.append(row)
                    data = [row]
                else:
                    data = [r for r in rows if all(r.get(k) == v for k, v in state["filters"].items())]
                return type("Resp", (), {"data": data})()

        return Query()


def test_creates_tenant_and_stores_only_hash():
    client = FakeClient()
    tenant_id, token = bootstrap.bootstrap(client, None, "Startup", "admin")
    assert {"id": tenant_id, "name": "Startup"} in client.tables["tenants"]
    (row,) = client.tables["management_tokens"]
    assert row["tenant_id"] == tenant_id
    assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in str(client.tables)
    assert len(token) >= 43


def test_uses_existing_tenant():
    client = FakeClient()
    tenant_id, _ = bootstrap.bootstrap(client, EXISTING, "ignored", "ci")
    assert tenant_id == EXISTING
    assert len(client.tables["tenants"]) == 1
    assert client.tables["management_tokens"][0]["name"] == "ci"


def test_unknown_tenant_aborts_without_token():
    client = FakeClient()
    with pytest.raises(SystemExit):
        bootstrap.bootstrap(client, str(uuid.uuid4()), "x", "admin")
    assert client.tables["management_tokens"] == []


def test_main_prints_token_banner(monkeypatch, capsys):
    from app.core.config import Settings

    client = FakeClient()
    monkeypatch.setattr(bootstrap, "get_settings", lambda: Settings(
        _env_file=None, supabase_url="https://x.supabase.co", supabase_service_role_key="service-role"
    ))
    monkeypatch.setattr("supabase.create_client", lambda url, key: client)
    bootstrap.main([])
    out = capsys.readouterr().out
    token_hash = client.tables["management_tokens"][0]["token_hash"]
    token = out.split("✅ Admin Token Generated: ", 1)[1].split()[0]
    assert hashlib.sha256(token.encode()).hexdigest() == token_hash
    assert "⚠️ SAVE THIS NOW. It will never be shown again and is required to hit the /api/v1/manage endpoints." in out


def test_main_requires_supabase_config(monkeypatch):
    from app.core.config import Settings

    monkeypatch.setattr(bootstrap, "get_settings", lambda: Settings(_env_file=None))
    with pytest.raises(SystemExit) as excinfo:
        bootstrap.main([])
    assert "SUPABASE_URL" in str(excinfo.value)
