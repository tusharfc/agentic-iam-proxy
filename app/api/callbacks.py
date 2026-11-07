from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
import uuid
from typing import Mapping, Optional
from urllib.parse import parse_qs

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from redis.exceptions import RedisError

from app.api.management import get_current_tenant
from app.api.webhooks import read_limited_body
from app.core.config import Settings, get_settings
from app.services import redis_pubsub, slack_service

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/callbacks", tags=["callbacks"])

TIMESTAMP_TOLERANCE_SECONDS = 300
# Each button's value is "<request_id>:<decision>"; its action_id must agree with that decision.
ACTION_DECISIONS = {
    slack_service.APPROVE_ACTION: redis_pubsub.APPROVED,
    slack_service.DENY_ACTION: redis_pubsub.DENIED,
}
SLACK_RESPONSE_HOST = "hooks.slack.com"
_SLACK_USER_ID = re.compile(r"[UW][A-Z0-9]+")


def verify_slack_signature(secret: str, headers: Mapping[str, str], body: bytes, now: float) -> bool:
    timestamp = headers.get("x-slack-request-timestamp")
    signature = headers.get("x-slack-signature")
    if not (timestamp and signature):
        return False
    try:
        if abs(now - int(timestamp)) > TIMESTAMP_TOLERANCE_SECONDS:
            return False
    except ValueError:
        return False
    digest = hmac.new(secret.encode(), f"v0:{timestamp}:".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"v0={digest}", signature)


def _slack_response_url(payload: dict) -> Optional[str]:
    # Only ever post back to Slack itself: in unsigned dev mode the payload is attacker-controlled.
    raw = payload.get("response_url")
    if not isinstance(raw, str):
        return None
    try:
        url = httpx.URL(raw)
    except httpx.InvalidURL:
        return None
    if url.scheme != "https" or url.host != SLACK_RESPONSE_HOST or url.port not in (None, 443) or url.userinfo:
        return None
    return raw


def _outcome_text(decision: str, recorded: bool, user: dict) -> str:
    if not recorded:
        return "Request is no longer pending (already decided or timed out); nothing was changed."
    user_id = user.get("id")
    who = f"<@{user_id}>" if isinstance(user_id, str) and _SLACK_USER_ID.fullmatch(user_id) else "user"
    return f"Action {decision.capitalize()} by {who}"


@router.post("/slack")
async def slack_callback(
    request: Request, background: BackgroundTasks, settings: Settings = Depends(get_settings)
) -> dict:
    body = await read_limited_body(request)
    if settings.slack_signing_secret is not None:
        secret = settings.slack_signing_secret.get_secret_value()
        if not verify_slack_signature(secret, request.headers, body, time.time()):
            raise HTTPException(401, "invalid Slack signature")
    elif not settings.slack_allow_unsigned_callbacks:
        raise HTTPException(503, "SLACK_SIGNING_SECRET is not configured")

    try:
        payload = json.loads(parse_qs(body.decode())["payload"][0])
        action = payload["actions"][0]
        raw_id, separator, decision = action["value"].rpartition(":")
        request_id = str(uuid.UUID(raw_id))
        if not separator or ACTION_DECISIONS.get(action["action_id"]) != decision:
            raise ValueError("button value and action_id disagree")
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        raise HTTPException(400, "expected a Slack block_actions payload with an approve/deny button")

    try:
        recorded = await redis_pubsub.publish_decision(request_id, decision)
    except RedisError:
        log.exception("Could not publish decision for %s", request_id)
        raise HTTPException(503, "approval service unavailable")

    user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
    log.info(
        "Request %s %s by Slack user %s (%s)%s", request_id, decision, user.get("id"), user.get("username"),
        "" if recorded else " - ignored: not pending or already decided",
    )
    # Slack wants the 200 within 3 s; the message edit happens after the response is sent.
    response_url = _slack_response_url(payload)
    if response_url is not None:
        background.add_task(slack_service.resolve_message, response_url, _outcome_text(decision, recorded, user))
    return {"ok": True, "recorded": recorded}


class ApprovalDecisionRequest(BaseModel):
    approval_token: str = Field(min_length=16, max_length=256)


async def _decide_by_token(body: ApprovalDecisionRequest, decision: str, tenant_id: str) -> dict:
    try:
        recorded = await redis_pubsub.publish_decision_by_token(body.approval_token, decision, tenant_id)
    except RedisError:
        log.exception("Could not publish a headless %s decision", decision)
        raise HTTPException(503, "approval service unavailable")
    if recorded is None:
        raise HTTPException(404, "approval token is invalid, already used or expired")
    if not recorded:
        raise HTTPException(409, "request is no longer pending (already decided or timed out)")
    log.info("Request %s via headless callback by tenant %s", decision, tenant_id)
    return {"status": "success", "action": decision}


@router.post("/approve")
async def approve(body: ApprovalDecisionRequest, tenant_id: str = Depends(get_current_tenant)) -> dict:
    return await _decide_by_token(body, redis_pubsub.APPROVED, tenant_id)


@router.post("/deny")
async def deny(body: ApprovalDecisionRequest, tenant_id: str = Depends(get_current_tenant)) -> dict:
    return await _decide_by_token(body, redis_pubsub.DENIED, tenant_id)
