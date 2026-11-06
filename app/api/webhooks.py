from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import List, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from supabase import AsyncClient

from app.core.config import Settings, get_settings
from app.models.schemas import PolarSubscription, PolarSubscriptionEvent
from app.services.supabase_client import get_supabase

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

SUBSCRIPTION_EVENTS = {"subscription.created", "subscription.updated"}
TIMESTAMP_TOLERANCE_SECONDS = 300
MAX_BODY_BYTES = 1_000_000


def _signing_keys(secret: str) -> List[bytes]:
    # Polar secrets from before 2026-09-08 sign with the raw "whsec_..." bytes;
    # newer ones are Standard Webhooks secrets (base64 after the prefix).
    keys = [secret.encode()]
    if secret.startswith("whsec_"):
        try:
            keys.append(base64.b64decode(secret[len("whsec_"):], validate=True))
        except binascii.Error:
            pass
    return keys


def verify_signature(secret: str, headers: Mapping[str, str], body: bytes, now: float) -> bool:
    """Standard Webhooks verification: HMAC-SHA256 over "{id}.{timestamp}.{body}"."""
    msg_id = headers.get("webhook-id")
    timestamp = headers.get("webhook-timestamp")
    signatures = headers.get("webhook-signature")
    if not (msg_id and timestamp and signatures):
        return False
    try:
        if abs(now - int(timestamp)) > TIMESTAMP_TOLERANCE_SECONDS:
            return False
    except ValueError:
        return False

    signed = f"{msg_id}.{timestamp}.".encode() + body
    expected = [
        base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()) for key in _signing_keys(secret)
    ]
    for entry in signatures.split():
        version, _, signature = entry.partition(",")
        if version == "v1" and any(hmac.compare_digest(signature.encode(), e) for e in expected):
            return True
    return False


def _tenant_id(sub: PolarSubscription) -> Optional[str]:
    # Checkout must set customer_external_id (or metadata.tenant_id) to our tenant UUID.
    candidate = (sub.customer.external_id if sub.customer else None) or sub.metadata.get("tenant_id")
    try:
        return str(uuid.UUID(str(candidate)))
    except ValueError:
        return None


async def read_limited_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="payload too large")
    return bytes(body)


@router.post("/polar", status_code=202)
async def polar_webhook(
    request: Request,
    settings: Settings = Depends(get_settings),
    supabase: AsyncClient = Depends(get_supabase),
) -> dict:
    if settings.polar_webhook_secret is None:
        raise HTTPException(status_code=503, detail="webhook secret not configured")

    body = await read_limited_body(request)
    secret = settings.polar_webhook_secret.get_secret_value()
    if not verify_signature(secret, request.headers, body, time.time()):
        raise HTTPException(status_code=403, detail="invalid signature")

    try:
        envelope = json.loads(body)
        event_type = envelope.get("type")
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="invalid JSON payload")
    if event_type not in SUBSCRIPTION_EVENTS:
        return {"result": "ignored"}

    try:
        sub = PolarSubscriptionEvent.model_validate(envelope).data
    except ValidationError:
        raise HTTPException(status_code=400, detail="invalid subscription payload")

    tenant_id = _tenant_id(sub)
    if tenant_id is None:
        log.warning("Polar subscription %s has no tenant ID; ignoring", sub.id)
        return {"result": "no_tenant"}
    tier = settings.polar_product_tiers.get(sub.product_id)
    if tier is None:
        log.warning("Polar product %s is not mapped to a tier; ignoring", sub.product_id)
        return {"result": "unknown_product"}

    response = await supabase.rpc(
        "apply_polar_subscription",
        {
            "p_event_id": request.headers["webhook-id"],
            "p_event_type": event_type,
            "p_tenant_id": tenant_id,
            "p_subscription_id": sub.id,
            "p_customer_id": sub.customer_id,
            "p_product_id": sub.product_id,
            "p_tier": tier,
            "p_status": sub.status,
            "p_current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
            "p_cancel_at_period_end": sub.cancel_at_period_end,
            "p_modified_at": (sub.modified_at or sub.created_at).isoformat(),
        },
    ).execute()
    log.info("Polar %s for tenant %s: %s", event_type, tenant_id, response.data)
    return {"result": response.data}
