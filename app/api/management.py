from __future__ import annotations

import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import APIKeyHeader
from postgrest.types import ReturnMethod
from supabase import AsyncClient

from app.api.proxy import SERVICE_HOSTS
from app.core.security import hash_token, tenant_for_token
from app.models.schemas import AgentCreate, AgentCreated, VaultKeyCreate, VaultKeyStored
from app.services.supabase_client import get_supabase
from app.services.vault_service import VaultConfigError, VaultError, VaultService, get_vault_service

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/manage", tags=["management"])

_management_token = APIKeyHeader(name="X-Management-Token", auto_error=False)


async def get_current_tenant(
    token: Optional[str] = Depends(_management_token), supabase: AsyncClient = Depends(get_supabase)
) -> str:
    if not token:
        raise HTTPException(401, "X-Management-Token header is required")
    tenant_id = await tenant_for_token(supabase, "management_tokens", "token_hash", token)
    if tenant_id is None:
        raise HTTPException(401, "invalid management token")
    return tenant_id


@router.post("/agents", status_code=201, response_model=AgentCreated)
async def create_agent(
    body: AgentCreate,
    response: Response,
    tenant_id: str = Depends(get_current_tenant),
    supabase: AsyncClient = Depends(get_supabase),
) -> AgentCreated:
    token = secrets.token_urlsafe(32)
    result = await supabase.table("agent_identities").insert(
        {"tenant_id": tenant_id, "name": body.agent_name, "agent_token": hash_token(token)}
    ).execute()
    row = result.data[0]
    log.info("Tenant %s created agent %s (%s)", tenant_id, row["id"], body.agent_name)
    response.headers["Cache-Control"] = "no-store"
    return AgentCreated(id=row["id"], agent_name=row["name"], token=token)


@router.post("/vault/keys", response_model=VaultKeyStored)
async def add_vault_key(
    body: VaultKeyCreate,
    tenant_id: str = Depends(get_current_tenant),
    supabase: AsyncClient = Depends(get_supabase),
    vault: VaultService = Depends(get_vault_service),
) -> VaultKeyStored:
    services = sorted(set(SERVICE_HOSTS.values()))
    if body.service_name not in services:
        raise HTTPException(422, f"service_name must be one of: {', '.join(services)}")
    try:
        ciphertext = vault.encrypt_api_key(tenant_id, body.service_name, body.raw_api_key.get_secret_value())
    except VaultConfigError as exc:
        log.error("Cannot store vault key: %s", exc)
        raise HTTPException(503, "vault is not configured")
    except VaultError as exc:
        raise HTTPException(422, str(exc))
    await supabase.table("tenant_api_keys").upsert(
        {"tenant_id": tenant_id, "service_name": body.service_name, "encrypted_api_key": ciphertext},
        on_conflict="tenant_id,service_name",
        returning=ReturnMethod.minimal,
    ).execute()
    log.info("Tenant %s stored a %s key", tenant_id, body.service_name)
    return VaultKeyStored(service_name=body.service_name)
