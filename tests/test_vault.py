from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from app.core.config import Settings
from app.services.vault_service import VaultError, VaultService

TENANT = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"
OTHER_TENANT = "9d1b2c3e-4f50-4a61-8b72-c3d4e5f60718"
API_KEY = "sk_live_51HxSECRET"


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakeSupabase:
    """Stores tenant_api_keys rows; supports .table().select().eq().eq().limit().execute()."""

    def __init__(self) -> None:
        self.rows = []
        self.queries = []

    def table(self, name):
        fake, filters = self, {}

        class Query:
            def select(self, cols):
                filters["_select"] = cols
                return self

            def eq(self, col, value):
                filters[col] = value
                return self

            def limit(self, n):
                return self

            async def execute(self):
                fake.queries.append((name, dict(filters)))
                rows = [
                    {"encrypted_api_key": r["encrypted_api_key"]} for r in fake.rows
                    if r["tenant_id"] == filters.get("tenant_id") and r["service_name"] == filters.get("service_name")
                ]
                return type("Resp", (), {"data": rows})()

        return Query()


@pytest.fixture
def vault():
    supabase = FakeSupabase()
    service = VaultService(SecretStr(Fernet.generate_key().decode()), supabase)

    def store(tenant_id, service_name, ciphertext):
        supabase.rows.append({"tenant_id": tenant_id, "service_name": service_name, "encrypted_api_key": ciphertext})

    return service, supabase, store


@pytest.mark.anyio
async def test_roundtrip(vault):
    service, supabase, store = vault
    ciphertext = service.encrypt_api_key(TENANT, "stripe", API_KEY)
    assert API_KEY not in ciphertext
    store(TENANT, "stripe", ciphertext)
    assert await service.get_decrypted_key(TENANT, "stripe") == API_KEY
    assert supabase.queries == [(
        "tenant_api_keys", {"_select": "encrypted_api_key", "tenant_id": TENANT, "service_name": "stripe"},
    )]


@pytest.mark.anyio
async def test_missing_key_returns_none(vault):
    service, _, _ = vault
    assert await service.get_decrypted_key(TENANT, "stripe") is None


@pytest.mark.anyio
async def test_row_copied_to_other_tenant_is_rejected(vault):
    service, _, store = vault
    store(OTHER_TENANT, "stripe", service.encrypt_api_key(TENANT, "stripe", API_KEY))
    with pytest.raises(VaultError):
        await service.get_decrypted_key(OTHER_TENANT, "stripe")


@pytest.mark.anyio
async def test_row_moved_to_other_service_is_rejected(vault):
    service, _, store = vault
    store(TENANT, "github", service.encrypt_api_key(TENANT, "stripe", API_KEY))
    with pytest.raises(VaultError):
        await service.get_decrypted_key(TENANT, "github")


@pytest.mark.anyio
@pytest.mark.parametrize("ciphertext", ["not-a-token", Fernet(Fernet.generate_key()).encrypt(b"{}").decode()])
async def test_undecryptable_rows_raise_without_leaking(vault, ciphertext):
    service, _, store = vault
    store(TENANT, "stripe", ciphertext)
    with pytest.raises(VaultError) as excinfo:
        await service.get_decrypted_key(TENANT, "stripe")
    assert excinfo.value.__cause__ is None
    assert ciphertext not in str(excinfo.value)


@pytest.mark.anyio
async def test_tampered_ciphertext_rejected(vault):
    service, _, store = vault
    token = service.encrypt_api_key(TENANT, "stripe", API_KEY)
    store(TENANT, "stripe", token[:-6] + ("A" if token[-6] != "A" else "B") + token[-5:])
    with pytest.raises(VaultError):
        await service.get_decrypted_key(TENANT, "stripe")


@pytest.mark.parametrize("bad_key", ["sk live", "sk_live\r\nX-Evil: 1", "", "ключ"])
def test_header_unsafe_keys_cannot_be_stored(vault, bad_key):
    service, _, _ = vault
    with pytest.raises(VaultError):
        service.encrypt_api_key(TENANT, "stripe", bad_key)


@pytest.mark.anyio
@pytest.mark.parametrize("key", [None, SecretStr("too-short"), SecretStr("")])
async def test_bad_vault_config_raises(key):
    service = VaultService(key, FakeSupabase())
    with pytest.raises(VaultError) as excinfo:
        await service.get_decrypted_key(TENANT, "stripe")
    assert "VAULT_ENCRYPTION_KEY" in str(excinfo.value)


def test_empty_env_values_mean_unset(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SLACK_SIGNING_SECRET=\nPOLAR_WEBHOOK_SECRET=\nVAULT_ENCRYPTION_KEY=\n")
    settings = Settings(_env_file=str(env))
    assert settings.slack_signing_secret is None
    assert settings.polar_webhook_secret is None
    assert settings.vault_encryption_key is None
