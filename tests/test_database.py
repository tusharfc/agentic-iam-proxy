"""Runs the real schema and queries against Postgres. Skipped unless TEST_DATABASE_URL is set.

    TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:55432/iam_test pytest tests/test_database.py

The database's public schema is dropped and recreated for every test.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from app.services.database import Database

DSN = os.environ.get("TEST_DATABASE_URL")
pytestmark = [pytest.mark.anyio, pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")]

HASH_A = "a" * 64
HASH_B = "b" * 64


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def db():
    conn = await asyncpg.connect(DSN)
    await conn.execute("drop schema public cascade; create schema public;")
    await conn.close()
    database = await Database.connect(DSN)
    yield database
    await database.close()


async def test_schema_is_idempotent_even_when_replicas_start_together(db):
    await db.apply_schema()
    others = await asyncio.gather(*(Database.connect(DSN) for _ in range(3)))
    for other in others:
        await other.close()


async def test_agent_lookup_returns_tenant_and_names(db):
    tenant = await db.create_tenant("Demo Co")
    agent_id = await db.create_agent(tenant, "billing-bot", HASH_A)
    assert await db.agent_for_token_hash(HASH_A) == {
        "tenant_id": tenant, "name": "billing-bot", "tenant_name": "Demo Co",
    }
    assert await db.agent_for_token_hash(HASH_B) is None
    assert len(agent_id) == 36


async def test_management_token_lookup(db):
    tenant = await db.create_tenant("Demo Co")
    await db.create_management_token(tenant, HASH_B, "admin")
    assert await db.tenant_for_management_token_hash(HASH_B) == tenant
    assert await db.tenant_for_management_token_hash(HASH_A) is None
    assert await db.tenant_exists(tenant)
    assert not await db.tenant_exists("00000000-0000-0000-0000-000000000000")


async def test_token_columns_only_accept_sha256_hex(db):
    tenant = await db.create_tenant("Demo Co")
    with pytest.raises(asyncpg.CheckViolationError):
        await db.create_agent(tenant, "bot", "plaintext-token")


async def test_api_keys_upsert_and_stay_per_tenant(db):
    t1, t2 = await db.create_tenant("One"), await db.create_tenant("Two")
    await db.store_api_key(t1, "stripe", "cipher-old")
    await db.store_api_key(t1, "stripe", "cipher-new")
    assert await db.encrypted_api_key(t1, "stripe") == "cipher-new"
    assert await db.encrypted_api_key(t2, "stripe") is None
    assert await db.encrypted_api_key(t1, "github") is None


async def test_policies_ordered_by_priority_and_per_tenant(db):
    t1, t2 = await db.create_tenant("One"), await db.create_tenant("Two")
    await db.create_policy(t1, "later", 20, "*", "refunds", "deny")
    await db.create_policy(t1, "first", 10, "POST", "refunds", "requires_approval")
    await db.create_policy(t2, "other tenant", 1, "*", ".*", "deny")
    rules = await db.policies(t1)
    assert [(r["name"], r["priority"], r["method"], r["action"]) for r in rules] == [
        ("first", 10, "POST", "requires_approval"),
        ("later", 20, "*", "deny"),
    ]


async def test_polar_subscription_is_applied_once_and_in_order(db):
    tenant = await db.create_tenant("Demo Co")
    now = datetime.now(timezone.utc)
    event = dict(
        event_id="msg_1", event_type="subscription.created", tenant_id=tenant, subscription_id="sub_1",
        customer_id="cus_1", product_id="prod_1", tier="pro", status="active",
        current_period_end=now + timedelta(days=30), cancel_at_period_end=False, modified_at=now,
    )
    assert await db.apply_polar_subscription(**event) == "applied"
    assert await db.apply_polar_subscription(**event) == "duplicate"
    older = dict(event, event_id="msg_0", status="canceled", modified_at=now - timedelta(minutes=5))
    assert await db.apply_polar_subscription(**older) == "stale"
    missing = dict(event, event_id="msg_2", tenant_id="00000000-0000-0000-0000-000000000000")
    assert await db.apply_polar_subscription(**missing) == "unknown_tenant"
    assert await db._pool.fetchval("select tier::text from tenants where id = $1::uuid", tenant) == "pro"
