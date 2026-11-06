from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException
from supabase import AsyncClient, acreate_client

from app.core.config import Settings, get_settings

_client: Optional[AsyncClient] = None


async def get_supabase(settings: Settings = Depends(get_settings)) -> AsyncClient:
    """Service-role client: bypasses RLS, so only use it for backend-owned writes."""
    global _client
    if _client is None:
        if not (settings.supabase_url and settings.supabase_service_role_key):
            raise HTTPException(status_code=503, detail="Supabase is not configured")
        _client = await acreate_client(
            settings.supabase_url, settings.supabase_service_role_key.get_secret_value()
        )
    return _client
