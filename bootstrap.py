"""Create a tenant (or use an existing one) and print a one-time admin token for /api/v1/manage."""
from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
import uuid
from typing import Optional, Tuple

from app.core.config import get_settings
from app.core.security import hash_token


async def bootstrap(db, tenant_id: Optional[str], tenant_name: str, token_name: str) -> Tuple[str, str]:
    if tenant_id is None:
        tenant_id = await db.create_tenant(tenant_name)
    elif not await db.tenant_exists(tenant_id):
        raise SystemExit(f"Tenant {tenant_id} does not exist.")

    token = secrets.token_urlsafe(32)
    await db.create_management_token(tenant_id, hash_token(token), token_name)
    return tenant_id, token


async def _run(dsn: str, tenant_id: Optional[str], tenant_name: str, token_name: str) -> Tuple[str, str]:
    from app.services.database import Database

    db = await Database.connect(dsn)
    try:
        return await bootstrap(db, tenant_id, tenant_name, token_name)
    finally:
        await db.close()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", type=uuid.UUID, help="existing tenant (default: create a new one)")
    parser.add_argument("--tenant-name", default="Default", help="name for a new tenant (default: Default)")
    parser.add_argument("--token-name", default="admin", help="label stored with the token (default: admin)")
    args = parser.parse_args(argv)

    settings = get_settings()
    if settings.database_url is None:
        sys.exit("DATABASE_URL must be set (see .env.example).")

    tenant_id, token = asyncio.run(_run(
        settings.database_url.get_secret_value(),
        str(args.tenant_id) if args.tenant_id else None, args.tenant_name, args.token_name,
    ))

    bar = "=" * 78
    print(f"\n{bar}\n")
    print(f"  Tenant: {tenant_id}\n")
    print(f"✅ Admin Token Generated: {token}\n")
    print("⚠️ SAVE THIS NOW. It will never be shown again and is required to hit the /api/v1/manage endpoints.")
    print(f"\n{bar}\n")


if __name__ == "__main__":
    main()
