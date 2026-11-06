from __future__ import annotations

import asyncio
from typing import Optional

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


async def _next_decision(pubsub: PubSub) -> str:
    async for message in pubsub.listen():
        if message["type"] == "message" and message["data"] in DECISIONS:
            return message["data"]
    raise ConnectionError("Redis subscription closed")


async def wait_for_approval(request_id: str, timeout: int = 300) -> str:
    """Blocks until a human decides; returns 'approved', 'denied' or 'timeout'."""
    r = get_redis()
    await r.set(_pending_key(request_id), "1", ex=int(timeout) + 60)
    pubsub = r.pubsub()
    try:
        await pubsub.subscribe(_channel(request_id))
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
