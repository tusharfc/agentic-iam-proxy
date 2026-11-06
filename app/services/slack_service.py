from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

from app.core.config import Settings, get_settings

log = logging.getLogger(__name__)

APPROVE_ACTION, DENY_ACTION = "approve_action", "deny_action"
TIMEOUT_SECONDS = 10.0
# Section fields allow 2000 characters; escaping can grow text up to 5x.
_MAX_FIELD_CHARS = 350


class SlackError(Exception):
    """Slack rejected or never received a message. Never includes the webhook URL, which is a secret."""


def _escape(text: str) -> str:
    # Agent-controlled text must not render as links or <!channel>-style mentions in front of the approver.
    if len(text) > _MAX_FIELD_CHARS:
        text = text[: _MAX_FIELD_CHARS - 1] + "…"
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def approval_message(request_id: str, target_url: str, tenant_id: str) -> Dict[str, Any]:
    return {
        "text": "🚨 AI Agent requesting high-risk action.",  # shown in notifications
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": "🚨 AI Agent requesting high-risk action."}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target URL:*\n{_escape(target_url)}", "verbatim": True},
                    {"type": "mrkdwn", "text": f"*Tenant ID:*\n{_escape(tenant_id)}", "verbatim": True},
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": APPROVE_ACTION,
                        "value": f"{request_id}:approved",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "style": "danger",
                        "action_id": DENY_ACTION,
                        "value": f"{request_id}:denied",
                    },
                ],
            },
        ],
    }


async def _post(url: str, payload: Dict[str, Any]) -> None:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        raise SlackError(f"request failed: {type(exc).__name__}") from None
    if response.is_error:
        raise SlackError(f"HTTP {response.status_code}: {response.text[:200]}")


async def send_approval_message(
    request_id: str, target_url: str, tenant_id: str, settings: Optional[Settings] = None
) -> bool:
    """Posts the Approve/Deny message. False when no webhook is configured (local development)."""
    webhook = (settings or get_settings()).slack_webhook_url
    if webhook is None:
        log.warning(
            "SLACK_WEBHOOK_URL is not set; approve or deny request %s via POST /api/v1/callbacks/slack", request_id
        )
        return False
    await _post(webhook.get_secret_value(), approval_message(request_id, target_url, tenant_id))
    return True


async def resolve_message(response_url: str, text: str) -> None:
    """Replaces the approval message with `text`, dropping the buttons so they can't be clicked twice."""
    payload = {
        "replace_original": True,
        "text": text,
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    }
    try:
        await _post(response_url, payload)
    except SlackError as exc:
        log.warning("Could not update the Slack approval message: %s", exc)
