"""One-time demo setup: tenant, admin token, agent, vaulted Stripe test key, refund policy,
and a Stripe test customer with a $49.99 charge for the agent to refund.

Needs .env (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, VAULT_ENCRYPTION_KEY) and a Stripe
*test* key in STRIPE_TEST_KEY. Writes the generated tokens to demo/.demo.env (gitignored).

    STRIPE_TEST_KEY=sk_test_... .venv-demo/bin/python demo/setup_demo.py
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings  # noqa: E402
from app.core.security import hash_token  # noqa: E402
from app.services.vault_service import VaultService  # noqa: E402
from bootstrap import bootstrap  # noqa: E402

DEMO_ENV = Path(__file__).with_name(".demo.env")
REFUND_POLICY = {
    "name": "Refunds need human approval",
    "priority": 10,
    "method": "POST",
    "url_pattern": r"^https://api\.stripe\.com/v1/refunds",
    "action": "requires_approval",
}


def stripe(key: str, path: str, data: dict) -> dict:
    resp = httpx.post(f"https://api.stripe.com{path}", data=data, auth=(key, ""), timeout=20)
    if resp.is_error:
        sys.exit(f"Stripe {path} failed: HTTP {resp.status_code} {resp.json().get('error', {}).get('message')}")
    return resp.json()


def create_demo_charge(stripe_key: str) -> tuple:
    customer = stripe(stripe_key, "/v1/customers", {"name": "Jane Demo", "email": "jane.demo@example.com"})
    payment = stripe(stripe_key, "/v1/payment_intents", {
        "amount": 4999, "currency": "usd", "customer": customer["id"], "payment_method": "pm_card_visa",
        "confirm": "true", "description": "Pro plan - monthly",
        "automatic_payment_methods[enabled]": "true", "automatic_payment_methods[allow_redirects]": "never",
    })
    return customer["id"], payment["latest_charge"]


def setup(client, vault: VaultService, stripe_key: str) -> dict:
    tenant_id, admin_token = bootstrap(client, None, "Demo Co", "demo-admin")

    agent_token = secrets.token_urlsafe(32)
    client.table("agent_identities").insert(
        {"tenant_id": tenant_id, "name": "billing-bot", "agent_token": hash_token(agent_token)}
    ).execute()

    client.table("tenant_api_keys").upsert(
        {"tenant_id": tenant_id, "service_name": "stripe",
         "encrypted_api_key": vault.encrypt_api_key(tenant_id, "stripe", stripe_key)},
        on_conflict="tenant_id,service_name",
    ).execute()

    client.table("tenant_policies").insert({"tenant_id": tenant_id, **REFUND_POLICY}).execute()
    return {"DEMO_TENANT_ID": tenant_id, "DEMO_ADMIN_TOKEN": admin_token, "AGENTIC_IAM_AGENT_TOKEN": agent_token}


def main() -> None:
    stripe_key = os.environ.get("STRIPE_TEST_KEY", "")
    if not stripe_key.startswith(("sk_test_", "rk_test_")):
        sys.exit("Set STRIPE_TEST_KEY to a Stripe *test-mode* key (sk_test_...). Live keys are refused.")
    settings = get_settings()
    if not (settings.supabase_url and settings.supabase_service_role_key and settings.vault_encryption_key):
        sys.exit("Fill SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY and VAULT_ENCRYPTION_KEY in .env first.")

    from supabase import create_client

    client = create_client(settings.supabase_url, settings.supabase_service_role_key.get_secret_value())
    values = setup(client, VaultService(settings.vault_encryption_key, None), stripe_key)
    customer_id, charge_id = create_demo_charge(stripe_key)
    values.update(DEMO_CUSTOMER_ID=customer_id, DEMO_CHARGE_ID=charge_id)

    DEMO_ENV.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    DEMO_ENV.chmod(0o600)
    print(f"Tenant {values['DEMO_TENANT_ID']}: agent, vaulted Stripe key and refund policy created.")
    print(f"Stripe test customer {customer_id} with a $49.99 charge {charge_id}.")
    print(f"Tokens saved to {DEMO_ENV.relative_to(Path.cwd()) if DEMO_ENV.is_relative_to(Path.cwd()) else DEMO_ENV}.")


if __name__ == "__main__":
    main()
