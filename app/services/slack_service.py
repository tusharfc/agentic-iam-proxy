from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx

from app.core.config import Settings, get_settings
from app.services.approval_details import ApprovalDetails

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


def _code(text: str) -> str:
    return "`" + _escape(text).replace("`", "'") + "`"


_VERBS = {"GET": "read", "POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}
_SERVICE_NAMES = {"github": "GitHub", "openai": "OpenAI"}


def action_summary(method: str, target_url: str) -> str:
    """Plain-English guess at the action, e.g. "create refund" or "delete customer cus_123"."""
    segments = [s for s in urlsplit(target_url).path.split("/") if s and not re.fullmatch(r"v\d+(\.\d+)?", s)]
    ident = segments.pop() if len(segments) > 1 and re.search(r"\d", segments[-1]) else None
    resource = (segments[-1] if segments else "resource").replace("_", " ").replace("-", " ")
    if resource.endswith("s") and not resource.endswith("ss"):
        resource = resource[:-1]
    return f"{_VERBS.get(method.upper(), method.lower())} {resource}" + (f" {ident}" if ident else "")


def approval_message(request_id: str, details: ApprovalDetails) -> Dict[str, Any]:
    agent = details.agent_name or "An AI agent"
    service = _SERVICE_NAMES.get(details.service or "", (details.service or "an API").title())
    headline = f"{agent} wants to {action_summary(details.method, details.target_url)} on {service}"
    minutes = max(1, round(details.expires_in_seconds / 60))
    return {
        "text": f"🚨 Approval needed: {headline}",  # shown in notifications
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"🚨 Approval needed: {headline}"[:150]}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent:*\n{_escape(agent)}", "verbatim": True},
                    {"type": "mrkdwn", "text": f"*Workspace:*\n{_escape(details.tenant_name or details.tenant_id)}", "verbatim": True},
                    {"type": "mrkdwn", "text": f"*Request:*\n{_code(details.method + ' ' + details.endpoint)}", "verbatim": True},
                    {"type": "mrkdwn", "text": f"*Paused by policy:*\n{_escape(details.policy_name or 'Requires approval')}", "verbatim": True},
                ],
            },
            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"⏱ Automatically denied in {minutes} min if nobody responds · request `{request_id[:8]}`",
                    "verbatim": True,
                }],
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
    request_id: str, details: ApprovalDetails, settings: Optional[Settings] = None
) -> bool:
    """Posts the Approve/Deny message. False when no webhook is configured (local development)."""
    webhook = (settings or get_settings()).slack_webhook_url
    if webhook is None:
        log.warning(
            "SLACK_WEBHOOK_URL is not set; approve or deny request %s via POST /api/v1/callbacks/slack", request_id
        )
        return False
    await _post(webhook.get_secret_value(), approval_message(request_id, details))
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
