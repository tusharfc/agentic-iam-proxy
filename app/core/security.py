from __future__ import annotations

import hashlib
from typing import Optional

from supabase import AsyncClient


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def tenant_for_token(supabase: AsyncClient, table: str, column: str, token: str) -> Optional[str]:
    """Returns the tenant owning `token`, looked up by its SHA-256 hash in `table.column`."""
    result = await supabase.table(table).select("tenant_id").eq(column, hash_token(token)).limit(1).execute()
    return result.data[0]["tenant_id"] if result.data else None
