from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from app.services.database import Database


@dataclass(frozen=True)
class AgentIdentity:
    tenant_id: str
    agent_name: Optional[str] = None
    tenant_name: Optional[str] = None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def agent_for_token(db: "Database", token: str) -> Optional[AgentIdentity]:
    """Resolves an agent token (by SHA-256 hash) to its tenant plus display names, in one query."""
    row = await db.agent_for_token_hash(hash_token(token))
    if row is None:
        return None
    return AgentIdentity(row["tenant_id"], row.get("name"), row.get("tenant_name"))


async def tenant_for_management_token(db: "Database", token: str) -> Optional[str]:
    return await db.tenant_for_management_token_hash(hash_token(token))
