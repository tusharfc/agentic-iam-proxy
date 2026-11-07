from __future__ import annotations

import asyncio
import hashlib
import secrets
from typing import Awaitable, Callable, Optional

import redis.asyncio as redis
from redis.asyncio.client import PubSub

from app.core.config import get_settings

APPROVED, DENIED, TIMEOUT = "approved", "denied", "timeout"
DECISIONS = frozenset({APPROVED, DENIED})
DECISION_TTL_SECONDS = 3600

_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _channel(request_id: str) -> str:
    return f"approval:{request_id}"


def _pending_key(request_id: str) -> str:
    return f"approval:{request_id}:pending"


def _decision_key(request_id: str) -> str:
    return f"approval:{request_id}:decision"


def _token_key(tenant_id: str, approval_token: str) -> str:
    # Tenant-scoped, so another tenant's lookup misses instead of consuming the token.
    return f"approval_token:{tenant_id}:" + hashlib.sha256(approval_token.encode()).hexdigest()


async def _next_decision(pubsub: PubSub) -> str:
    async for message in pubsub.listen():
        if message["type"] == "message" and message["data"] in DECISIONS:
            return message["data"]
    raise ConnectionError("Redis subscription closed")


async def wait_for_approval(
    request_id: str, timeout: int = 300, on_pending: Optional[Callable[[], Awaitable[None]]] = None
) -> str:
    """Blocks until a human decides; returns 'approved', 'denied' or 'timeout'.

    `on_pending` runs once the request is pending and subscribed, so approvers notified there
    can answer instantly without their decision being rejected as "not pending".
    """
    r = get_redis()
    await r.set(_pending_key(request_id), "1", ex=int(timeout) + 60)
    pubsub = r.pubsub()
    try:
        await pubsub.subscribe(_channel(request_id))
        if on_pending is not None:
            await on_pending()
        # The decision may have been published before the subscription was active.
        decision = await r.get(_decision_key(request_id))
        if decision is None:
            try:
                decision = await asyncio.wait_for(_next_decision(pubsub), timeout)
            except asyncio.TimeoutError:
                # Record the timeout so a late click can't count; if a click just won the race, honour it.
                if await r.set(_decision_key(request_id), TIMEOUT, nx=True, ex=DECISION_TTL_SECONDS):
                    return TIMEOUT
                decision = await r.get(_decision_key(request_id))
        return decision if decision in DECISIONS else TIMEOUT
    finally:
        await pubsub.unsubscribe()
        await pubsub.aclose()
        await r.delete(_pending_key(request_id))


async def publish_decision(request_id: str, decision: str) -> bool:
    """Records and broadcasts a decision. False if the request isn't waiting or was already decided."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    r = get_redis()
    if not await r.exists(_pending_key(request_id)):
        return False
    if not await r.set(_decision_key(request_id), decision, nx=True, ex=DECISION_TTL_SECONDS):
        return False
    await r.publish(_channel(request_id), decision)
    return True


async def create_approval_token(request_id: str, tenant_id: str, ttl_seconds: int) -> str:
    """Issues an unguessable, single-use token for headless approval. Only its hash is stored."""
    token = secrets.token_urlsafe(32)
    await get_redis().set(_token_key(tenant_id, token), request_id, ex=ttl_seconds)
    return token


async def publish_decision_by_token(approval_token: str, decision: str, tenant_id: str) -> Optional[bool]:
    """Like publish_decision, keyed by approval token. None if the token is unknown, used, expired
    or belongs to a different tenant."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    request_id = await get_redis().getdel(_token_key(tenant_id, approval_token))
    if request_id is None:
        return None
    return await publish_decision(request_id, decision)
