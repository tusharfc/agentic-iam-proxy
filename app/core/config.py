from __future__ import annotations

from functools import lru_cache
from typing import Dict, Literal, Optional

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Empty values (e.g. `SLACK_SIGNING_SECRET=` copied from .env.example) must mean "unset", not an empty secret.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)

    polar_webhook_secret: Optional[SecretStr] = None
    # JSON object mapping Polar product_id -> "pro" | "enterprise".
    polar_product_tiers: Dict[str, Literal["pro", "enterprise"]] = {}

    # Any Postgres 14+, e.g. postgresql://user:password@host:5432/dbname. Tables are created at startup.
    database_url: Optional[SecretStr] = None

    proxy_timeout_seconds: float = 60.0
    # Local development only: lets agents reach localhost/private-network targets.
    proxy_allow_private_targets: bool = False

    redis_url: str = "redis://localhost:6379/0"
    hitl_timeout_seconds: int = 300
    # Incoming webhook of the Slack app whose Interactivity URL points at /api/v1/callbacks/slack.
    slack_webhook_url: Optional[SecretStr] = None
    slack_signing_secret: Optional[SecretStr] = None
    # Local development only: accept unsigned callbacks when no signing secret is set.
    slack_allow_unsigned_callbacks: bool = False

    # Headless approvals: signed JSON webhook to your own backend/dashboard.
    custom_webhook_url: Optional[SecretStr] = None
    custom_webhook_secret: Optional[SecretStr] = None

    # Fernet key (url-safe base64, 32 bytes) encrypting tenant_api_keys.encrypted_api_key.
    vault_encryption_key: Optional[SecretStr] = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
