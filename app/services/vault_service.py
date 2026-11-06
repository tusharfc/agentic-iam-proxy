from __future__ import annotations

import json
import re
import uuid
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends
from pydantic import SecretStr
from supabase import AsyncClient

from app.core.config import Settings, get_settings
from app.services.supabase_client import get_supabase

# Printable ASCII without spaces: anything else could break or inject into an HTTP header.
_VALID_API_KEY = re.compile(r"[\x21-\x7e]+")


class VaultError(Exception):
    """Vault misconfiguration or an undecryptable record. Messages never contain key material."""


class VaultConfigError(VaultError):
    """VAULT_ENCRYPTION_KEY is missing or malformed."""


class VaultService:
    def __init__(self, encryption_key: Optional[SecretStr], supabase: AsyncClient) -> None:
        self._encryption_key = encryption_key
        self._supabase = supabase
        self._fernet: Optional[Fernet] = None

    def _cipher(self) -> Fernet:
        if self._fernet is None:
            if self._encryption_key is None:
                raise VaultConfigError("VAULT_ENCRYPTION_KEY is not set")
            try:
                self._fernet = Fernet(self._encryption_key.get_secret_value())
            except (ValueError, TypeError):
                raise VaultConfigError("VAULT_ENCRYPTION_KEY must be a url-safe base64-encoded 32-byte key") from None
        return self._fernet

    def encrypt_api_key(self, tenant_id: str, service_name: str, api_key: str) -> str:
        if not _VALID_API_KEY.fullmatch(api_key):
            raise VaultError("API key must be printable ASCII without whitespace")
        # Binding tenant and service into the ciphertext stops a copied row from working elsewhere.
        plaintext = json.dumps({"tenant_id": str(uuid.UUID(tenant_id)), "service": service_name, "key": api_key})
        return self._cipher().encrypt(plaintext.encode()).decode()

    async def get_decrypted_key(self, tenant_id: str, service_name: str) -> str | None:
        cipher = self._cipher()
        result = await (
            self._supabase.table("tenant_api_keys")
            .select("encrypted_api_key")
            .eq("tenant_id", tenant_id)
            .eq("service_name", service_name)
            .limit(1)
            .execute()
        )
        if not result.data:
            return None
        try:
            record = json.loads(cipher.decrypt(result.data[0]["encrypted_api_key"].encode()))
            api_key = record["key"]
            bound = record["tenant_id"] == str(uuid.UUID(tenant_id)) and record["service"] == service_name
        except (InvalidToken, ValueError, KeyError, TypeError, AttributeError):
            raise VaultError(f"stored {service_name} key could not be decrypted") from None
        if not bound:
            raise VaultError(f"stored {service_name} key belongs to a different tenant or service")
        if not isinstance(api_key, str) or not _VALID_API_KEY.fullmatch(api_key):
            raise VaultError(f"stored {service_name} key is not a valid header value")
        return api_key


def get_vault_service(
    settings: Settings = Depends(get_settings), supabase: AsyncClient = Depends(get_supabase)
) -> VaultService:
    return VaultService(settings.vault_encryption_key, supabase)
