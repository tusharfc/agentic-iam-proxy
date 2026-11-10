from __future__ import annotations

import ipaddress
import json
import logging
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import quote

import anyio
import httpcore
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from redis.exceptions import RedisError
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse

from app.core.config import Settings, get_settings
from app.core.security import AgentIdentity, agent_for_token
from app.services import notification, redis_pubsub, slack_service
from app.services.approval_details import ApprovalDetails
from app.services.database import Database, get_database
from app.services.policy_service import DENY, REQUIRES_APPROVAL, PolicyService, get_policy_service
from app.services.vault_service import VaultError, VaultService, get_vault_service

log = logging.getLogger(__name__)
audit_log = logging.getLogger("app.audit")

PREFIX = "/api/v1/proxy"
TARGET_HEADER = "x-target-url"
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})
# The agent's proxy token must never reach the downstream API.
NOT_FORWARDED = HOP_BY_HOP | {"host", "authorization", TARGET_HEADER}

# Exact hostnames only: substring matching would send the Stripe key to https://evil.example/?api.stripe.com.
# AWS is deliberately absent: it needs SigV4 request signing, not a bearer header.
SERVICE_HOSTS = {
    "api.stripe.com": "stripe",
    "api.github.com": "github",
    "api.openai.com": "openai",
    "slack.com": "slack",
}

router = APIRouter(prefix=PREFIX, tags=["proxy"])


class BlockedTargetError(Exception):
    pass


class ApprovalChannelError(Exception):
    """Every configured approval channel failed to deliver."""


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    return ip.is_global and not ip.is_multicast


class _GuardedBackend(httpcore.AsyncNetworkBackend):
    """Checks resolved addresses at connect time, so DNS rebinding can't reach internal hosts."""

    def __init__(self, allow_private: bool) -> None:
        self._allow_private = allow_private
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            with anyio.fail_after(timeout):
                infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(str(exc)) from exc
        except OSError as exc:
            raise httpcore.ConnectError(str(exc)) from exc

        addresses = list(dict.fromkeys(info[4][0] for info in infos))
        if not self._allow_private and not all(_is_public(a) for a in addresses):
            raise BlockedTargetError(host)

        error: Optional[Exception] = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except httpcore.ConnectError as exc:
                error = exc
        raise error or httpcore.ConnectError(f"no addresses for {host}")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise BlockedTargetError(path)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


_http_client: Optional[httpx.AsyncClient] = None


def get_http_client(settings: Settings = Depends(get_settings)) -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        transport = httpx.AsyncHTTPTransport(retries=0)
        # httpx has no public network_backend option; swap it on the httpcore pool.
        transport._pool._network_backend = _GuardedBackend(settings.proxy_allow_private_targets)
        _http_client = httpx.AsyncClient(
            transport=transport,
            timeout=settings.proxy_timeout_seconds,
            follow_redirects=False,
            trust_env=False,  # an env-configured proxy would bypass the address check
        )
    return _http_client


async def close_http_client() -> None:
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


def record_audit(identity: AgentIdentity, target_url: str, method: str, status_code: int) -> None:
    """One JSON line per proxied request. Never includes headers, bodies or query strings."""
    audit_log.info(json.dumps({
        "event": "proxy_request",
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "tenant_id": identity.tenant_id,
        "agent": identity.agent_name,
        "method": method,
        "target_url": target_url,
        "status": status_code,
    }))


async def _authenticate(request: Request, db: Database) -> AgentIdentity:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    identity = await agent_for_token(db, token)
    if identity is None:
        raise HTTPException(401, "invalid agent token", headers={"WWW-Authenticate": "Bearer"})
    return identity


def _target_url(request: Request, path: str) -> httpx.URL:
    raw = request.headers.get(TARGET_HEADER)
    if not raw:
        raise HTTPException(400, "X-Target-Url header is required")
    try:
        url = httpx.URL(raw)
    except httpx.InvalidURL:
        raise HTTPException(400, "X-Target-Url is not a valid URL")
    if url.scheme not in ("http", "https") or not url.host:
        raise HTTPException(400, "X-Target-Url must be an absolute http(s) URL")
    if url.userinfo:
        raise HTTPException(400, "X-Target-Url must not contain credentials")

    # Use the undecoded path so encoded characters like %2F survive.
    raw_path = request.scope.get("raw_path", b"").decode("latin-1")
    suffix = raw_path[len(PREFIX) + 1:] if raw_path.startswith(PREFIX + "/") else quote(path)
    target_path = url.raw_path.split(b"?", 1)[0].decode("ascii")
    if suffix:
        target_path = target_path.rstrip("/") + "/" + suffix

    query = "&".join(q for q in (url.query.decode("ascii"), request.url.query) if q)
    return url.copy_with(raw_path=(target_path + ("?" + query if query else "")).encode("ascii"))


def _filter_headers(raw: List[Tuple[bytes, bytes]], excluded: frozenset) -> List[Tuple[bytes, bytes]]:
    drop = set(excluded)
    for name, value in raw:
        if name.lower() == b"connection":
            drop.update(t.strip().lower() for t in value.decode("latin-1").split(","))
    return [(k.lower(), v) for k, v in raw if k.decode("latin-1").lower() not in drop]


def service_for(target: httpx.URL) -> Optional[str]:
    return SERVICE_HOSTS.get(target.host.lower().rstrip("."))


@router.api_route("/{path:path}", methods=METHODS)
async def proxy(
    path: str,
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Database = Depends(get_database),
    client: httpx.AsyncClient = Depends(get_http_client),
    vault: VaultService = Depends(get_vault_service),
    policies: PolicyService = Depends(get_policy_service),
):
    identity = await _authenticate(request, db)
    tenant_id = identity.tenant_id
    method = request.method
    try:
        target = _target_url(request, path)
    except HTTPException as exc:
        record_audit(identity, request.headers.get(TARGET_HEADER, "").split("?", 1)[0], method, exc.status_code)
        raise
    audit_url = str(target.copy_with(query=None))

    headers = _filter_headers(request.headers.raw, NOT_FORWARDED)
    has_body = "content-length" in request.headers or "transfer-encoding" in request.headers

    service_name = service_for(target)
    if service_name is None:
        record_audit(identity, audit_url, method, 403)
        raise HTTPException(403, "Egress denied: Host not in approved service allowlist.")
    if target.scheme != "https":
        record_audit(identity, audit_url, method, 400)
        raise HTTPException(400, f"{service_name} credentials are only sent over https")
    try:
        decision_rule = await policies.match_request(tenant_id, method, str(target))
    except Exception:
        log.exception("Policy evaluation failed for tenant %s", tenant_id)
        record_audit(identity, audit_url, method, 503)
        raise HTTPException(503, "policy service unavailable")
    action = decision_rule.action
    if action == DENY:
        record_audit(identity, audit_url, method, 403)
        raise HTTPException(403, "Action denied by tenant security policy")
    # Before any approval request: never ask a human to approve a call that can't be authenticated.
    try:
        api_key = await vault.get_decrypted_key(tenant_id, service_name)
    except VaultError as exc:
        log.error("Vault lookup for tenant %s, service %s failed: %s", tenant_id, service_name, exc)
        api_key = None
    if api_key is None:
        record_audit(identity, audit_url, method, 500)
        raise HTTPException(500, "Missing downstream credentials for this service.")
    # Bearer suits every service in SERVICE_HOSTS; some APIs (e.g. Anthropic) expect `x-api-key` instead.
    headers.append((b"authorization", f"Bearer {api_key}".encode()))

    if action == REQUIRES_APPROVAL:
        request_id = str(uuid.uuid4())
        details = ApprovalDetails(
            method=method,
            target_url=str(target),
            tenant_id=tenant_id,
            service=service_name,
            tenant_name=identity.tenant_name,
            agent_name=identity.agent_name,
            policy_name=decision_rule.rule_name,
            expires_in_seconds=settings.hitl_timeout_seconds,
        )

        async def notify_approvers() -> None:
            delivered, failures = 0, []
            try:
                delivered += await slack_service.send_approval_message(request_id, details, settings=settings)
            except slack_service.SlackError as exc:
                failures.append(f"Slack: {exc}")
            if settings.custom_webhook_url is not None:
                ttl = settings.hitl_timeout_seconds + 60
                token = await redis_pubsub.create_approval_token(request_id, tenant_id, ttl)
                payload = {
                    "target_url": str(target),
                    "method": method,
                    "tenant_id": tenant_id,
                    "tenant_name": identity.tenant_name,
                    "agent_name": identity.agent_name,
                    "policy_name": decision_rule.rule_name,
                    "expires_at": int(time.time()) + settings.hitl_timeout_seconds,
                }
                try:
                    delivered += await notification.send_generic_webhook(token, payload, settings=settings)
                except notification.WebhookError as exc:
                    failures.append(f"custom webhook: {exc}")
            for failure in failures:
                log.error("Approval notification for %s failed: %s", request_id, failure)
            if failures and not delivered:
                # Nobody was asked, so waiting could only end in a timeout.
                raise ApprovalChannelError("; ".join(failures))

        try:
            decision = await redis_pubsub.wait_for_approval(
                request_id, settings.hitl_timeout_seconds, on_pending=notify_approvers
            )
        except ApprovalChannelError:
            record_audit(identity, audit_url, method, 503)
            raise HTTPException(503, "approval service unavailable")
        except RedisError:
            log.exception("Approval wait failed for %s", request_id)
            record_audit(identity, audit_url, method, 503)
            raise HTTPException(503, "approval service unavailable")
        if decision != redis_pubsub.APPROVED:
            record_audit(identity, audit_url, method, 403)
            if decision == redis_pubsub.DENIED:
                raise HTTPException(403, "Action denied by human overseer")
            raise HTTPException(403, "Approval timed out; action not executed")

    upstream_request = client.build_request(
        method, target, headers=headers, content=request.stream() if has_body else None
    )
    try:
        upstream = await client.send(upstream_request, stream=True)
    except BlockedTargetError:
        record_audit(identity, audit_url, method, 403)
        raise HTTPException(403, "X-Target-Url resolves to a private or reserved address")
    except httpx.TimeoutException:
        record_audit(identity, audit_url, method, 504)
        raise HTTPException(504, "downstream API timed out")
    except httpx.HTTPError as exc:
        log.warning("Proxy request to %s failed: %r", audit_url, exc)
        record_audit(identity, audit_url, method, 502)
        raise HTTPException(502, "downstream API request failed")

    async def finish() -> None:
        await upstream.aclose()
        record_audit(identity, audit_url, method, upstream.status_code)

    response = StreamingResponse(
        upstream.aiter_raw(), status_code=upstream.status_code, background=BackgroundTask(finish)
    )
    # Raw headers keep duplicates (e.g. Set-Cookie); body is relayed still-encoded, so lengths match.
    response.raw_headers = _filter_headers(upstream.headers.raw, HOP_BY_HOP)
    return response
