from __future__ import annotations

from functools import lru_cache
from typing import Dict, Literal, Optional

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Empty values (e.g. `SLACK_SIGNING_SECRET=` copied from .env.example) must mean "unset", not an empty secret.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)

    polar_api_url: str = "https://api.polar.sh"
    polar_organization_id: Optional[str] = None
    polar_license_key: Optional[str] = None
    # JSON object mapping Polar benefit_id -> "pro" | "enterprise".
    polar_benefit_tiers: Dict[str, str] = {}

    license_enforcement: bool = True
    license_cache_ttl_seconds: int = 3600
    # How long a previously valid license keeps working while Polar is unreachable.
    license_grace_seconds: int = 72 * 3600
    upgrade_url: str = "https://polar.sh/your-org"

    polar_webhook_secret: Optional[SecretStr] = None
    # JSON object mapping Polar product_id -> "pro" | "enterprise".
    polar_product_tiers: Dict[str, Literal["pro", "enterprise"]] = {}

    supabase_url: Optional[str] = None
    supabase_service_role_key: Optional[SecretStr] = None

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

    # Fernet key (url-safe base64, 32 bytes) encrypting tenant_api_keys.encrypted_api_key.
    vault_encryption_key: Optional[SecretStr] = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
