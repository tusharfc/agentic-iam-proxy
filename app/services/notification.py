from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional

import httpx

from app.core.config import Settings, get_settings

TIMEOUT_SECONDS = 10.0
SIGNATURE_HEADER = "X-Signature"
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


class WebhookError(Exception):
    """Delivery failed or is misconfigured. Never includes the URL or secret."""


def sign_payload(secret: str, body: bytes, timestamp: int) -> str:
    """Stripe-style signature: HMAC-SHA256 over "{timestamp}.{body}", sent as "t=...,v1=..."."""
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


async def send_generic_webhook(
    approval_token: str, request_details: Dict[str, Any], settings: Optional[Settings] = None
) -> bool:
    """POSTs a signed approval request to CUSTOM_WEBHOOK_URL. False when it isn't configured."""
    settings = settings or get_settings()
    if settings.custom_webhook_url is None:
        return False
    if settings.custom_webhook_secret is None:
        raise WebhookError("CUSTOM_WEBHOOK_SECRET must be set when CUSTOM_WEBHOOK_URL is")
    url = httpx.URL(settings.custom_webhook_url.get_secret_value())
    # The approval token is a credential: never send it in plain text off this machine.
    if url.scheme != "https" and not (url.scheme == "http" and url.host in _LOCAL_HOSTS):
        raise WebhookError("CUSTOM_WEBHOOK_URL must use https")

    body = json.dumps(
        {"approval_token": approval_token, "action": "requires_approval", **request_details},
        separators=(",", ":"),
    ).encode()
    headers = {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: sign_payload(settings.custom_webhook_secret.get_secret_value(), body, int(time.time())),
    }
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await client.post(url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        raise WebhookError(f"request failed: {type(exc).__name__}") from None
    if response.is_error or response.is_redirect:
        raise WebhookError(f"HTTP {response.status_code}")
    return True
