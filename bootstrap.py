"""Create a tenant (or use an existing one) and print a one-time admin token for /api/v1/manage."""
from __future__ import annotations

import argparse
import secrets
import sys
import uuid
from typing import Optional, Tuple

from app.core.config import get_settings
from app.core.security import hash_token


def bootstrap(client, tenant_id: Optional[str], tenant_name: str, token_name: str) -> Tuple[str, str]:
    if tenant_id is None:
        tenant_id = client.table("tenants").insert({"name": tenant_name}).execute().data[0]["id"]
    elif not client.table("tenants").select("id").eq("id", tenant_id).limit(1).execute().data:
        raise SystemExit(f"Tenant {tenant_id} does not exist.")

    token = secrets.token_urlsafe(32)
    client.table("management_tokens").insert(
        {"tenant_id": tenant_id, "token_hash": hash_token(token), "name": token_name}
    ).execute()
    return tenant_id, token


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", type=uuid.UUID, help="existing tenant (default: create a new one)")
    parser.add_argument("--tenant-name", default="Default", help="name for a new tenant (default: Default)")
    parser.add_argument("--token-name", default="admin", help="label stored with the token (default: admin)")
    args = parser.parse_args(argv)

    settings = get_settings()
    if not (settings.supabase_url and settings.supabase_service_role_key):
        sys.exit("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set (see .env.example).")

    from supabase import create_client

    client = create_client(settings.supabase_url, settings.supabase_service_role_key.get_secret_value())
    tenant_id, token = bootstrap(
        client, str(args.tenant_id) if args.tenant_id else None, args.tenant_name, args.token_name
    )

    bar = "=" * 78
    print(f"\n{bar}\n")
    print(f"  Tenant: {tenant_id}\n")
    print(f"✅ Admin Token Generated: {token}\n")
    print("⚠️ SAVE THIS NOW. It will never be shown again and is required to hit the /api/v1/manage endpoints.")
    print(f"\n{bar}\n")


if __name__ == "__main__":
    main()
