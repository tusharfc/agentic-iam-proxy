from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import asyncpg
from fastapi import Depends, HTTPException

from app.core.config import Settings, get_settings

log = logging.getLogger(__name__)

SCHEMA_SQL = (Path(__file__).resolve().parent.parent / "db" / "schema.sql").read_text()
# Serialises schema setup when several replicas start at once.
_SCHEMA_LOCK_ID = 7_211_003


class Database:
    """Every query the proxy runs. Values are always bound parameters, never formatted into SQL."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    @classmethod
    async def connect(cls, dsn: str) -> "Database":
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=10)
        db = cls(pool)
        try:
            await db.apply_schema()
        except BaseException:
            await pool.close()
            raise
        return db

    async def close(self) -> None:
        await self._pool.close()

    async def apply_schema(self) -> None:
        async with self._pool.acquire() as conn, conn.transaction():
            await conn.execute("select pg_advisory_xact_lock($1)", _SCHEMA_LOCK_ID)
            await conn.execute(SCHEMA_SQL)

    # Tokens

    async def agent_for_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        row = await self._pool.fetchrow(
            "select a.tenant_id::text as tenant_id, a.name, t.name as tenant_name"
            " from agent_identities a join tenants t on t.id = a.tenant_id"
            " where a.agent_token = $1",
            token_hash,
        )
        return dict(row) if row else None

    async def tenant_for_management_token_hash(self, token_hash: str) -> Optional[str]:
        return await self._pool.fetchval(
            "select tenant_id::text from management_tokens where token_hash = $1", token_hash
        )

    # Management

    async def create_tenant(self, name: str) -> str:
        return await self._pool.fetchval("insert into tenants (name) values ($1) returning id::text", name)

    async def tenant_exists(self, tenant_id: str) -> bool:
        return await self._pool.fetchval("select exists (select 1 from tenants where id = $1::uuid)", tenant_id)

    async def create_management_token(self, tenant_id: str, token_hash: str, name: str) -> None:
        await self._pool.execute(
            "insert into management_tokens (tenant_id, token_hash, name) values ($1::uuid, $2, $3)",
            tenant_id, token_hash, name,
        )

    async def create_agent(self, tenant_id: str, name: str, token_hash: str) -> str:
        return await self._pool.fetchval(
            "insert into agent_identities (tenant_id, name, agent_token) values ($1::uuid, $2, $3) returning id::text",
            tenant_id, name, token_hash,
        )

    async def create_policy(
        self, tenant_id: str, name: str, priority: int, method: str, url_pattern: str, action: str
    ) -> str:
        return await self._pool.fetchval(
            "insert into tenant_policies (tenant_id, name, priority, method, url_pattern, action)"
            " values ($1::uuid, $2, $3, $4, $5, $6) returning id::text",
            tenant_id, name, priority, method, url_pattern, action,
        )

    # Vault

    async def store_api_key(self, tenant_id: str, service_name: str, encrypted_api_key: str) -> None:
        await self._pool.execute(
            "insert into tenant_api_keys (tenant_id, service_name, encrypted_api_key) values ($1::uuid, $2, $3)"
            " on conflict (tenant_id, service_name) do update set encrypted_api_key = excluded.encrypted_api_key",
            tenant_id, service_name, encrypted_api_key,
        )

    async def encrypted_api_key(self, tenant_id: str, service_name: str) -> Optional[str]:
        return await self._pool.fetchval(
            "select encrypted_api_key from tenant_api_keys where tenant_id = $1::uuid and service_name = $2",
            tenant_id, service_name,
        )

    # Policies

    async def policies(self, tenant_id: str) -> List[Dict[str, Any]]:
        rows = await self._pool.fetch(
            "select id::text as id, name, priority, method, url_pattern, action"
            " from tenant_policies where tenant_id = $1::uuid order by priority",
            tenant_id,
        )
        return [dict(r) for r in rows]

    # Billing

    async def apply_polar_subscription(
        self,
        *,
        event_id: str,
        event_type: str,
        tenant_id: str,
        subscription_id: str,
        customer_id: Optional[str],
        product_id: str,
        tier: str,
        status: str,
        current_period_end: Optional[datetime],
        cancel_at_period_end: bool,
        modified_at: datetime,
    ) -> str:
        return await self._pool.fetchval(
            "select apply_polar_subscription($1, $2, $3::uuid, $4, $5, $6, $7::tenant_tier, $8, $9, $10, $11)",
            event_id, event_type, tenant_id, subscription_id, customer_id, product_id,
            tier, status, current_period_end, cancel_at_period_end, modified_at,
        )


_db: Optional[Database] = None
_lock: Optional[asyncio.Lock] = None


async def get_database(settings: Settings = Depends(get_settings)) -> Database:
    global _db, _lock
    if _db is None:
        if settings.database_url is None:
            raise HTTPException(status_code=503, detail="Database is not configured")
        if _lock is None:
            _lock = asyncio.Lock()
        async with _lock:
            if _db is None:
                _db = await Database.connect(settings.database_url.get_secret_value())
    return _db


async def close_database() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None
