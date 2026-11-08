from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from supabase import AsyncClient


@dataclass(frozen=True)
class AgentIdentity:
    tenant_id: str
    agent_name: Optional[str] = None
    tenant_name: Optional[str] = None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def agent_for_token(supabase: AsyncClient, token: str) -> Optional[AgentIdentity]:
    """Resolves an agent token (by SHA-256 hash) to its tenant plus display names, in one query."""
    result = await (
        supabase.table("agent_identities").select("tenant_id, name, tenants(name)")
        .eq("agent_token", hash_token(token)).limit(1).execute()
    )
    if not result.data:
        return None
    row = result.data[0]
    tenant = row.get("tenants") if isinstance(row.get("tenants"), dict) else {}
    return AgentIdentity(row["tenant_id"], row.get("name"), tenant.get("name"))


async def tenant_for_token(supabase: AsyncClient, table: str, column: str, token: str) -> Optional[str]:
    """Returns the tenant owning `token`, looked up by its SHA-256 hash in `table.column`."""
    result = await supabase.table(table).select("tenant_id").eq(column, hash_token(token)).limit(1).execute()
    return result.data[0]["tenant_id"] if result.data else None
