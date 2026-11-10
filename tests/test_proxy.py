from __future__ import annotations

import hashlib
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import proxy
from app.api.callbacks import router as callbacks_router
from app.api.management import get_current_tenant
from app.core.config import Settings, get_settings
from app.services import redis_pubsub
from app.services.database import get_database
from app.services.policy_service import PolicyService, get_policy_service
from app.services.vault_service import VaultError, get_vault_service
from tests.test_policy_service import FakePolicyTable, rule

TOKEN = "agent-secret-token"
TENANT = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
STRIPE_KEY = "sk_live_DO_NOT_LEAK_51Hx"
ACME_KEY = "acme_key_123"


class FakeVault:
    def __init__(self, keys=None, error=None) -> None:
        default = {(TENANT, "stripe"): STRIPE_KEY, (TENANT, "acme"): ACME_KEY, (TENANT, "beta"): "beta_key"}
        self.keys = default if keys is None else keys
        self.error = error
        self.lookups = []

    async def get_decrypted_key(self, tenant_id, service_name):
        self.lookups.append((tenant_id, service_name))
        if self.error is not None:
            raise self.error
        return self.keys.get((tenant_id, service_name))


class FakeAgentDB:
    """Stand-in for Database.agent_for_token_hash()."""

    def __init__(self, agents_by_hash) -> None:
        self.agents_by_hash = agents_by_hash
        self.lookups = []

    async def agent_for_token_hash(self, token_hash):
        self.lookups.append(token_hash)
        return self.agents_by_hash.get(token_hash)


class Downstream:
    def __init__(self, handler=None) -> None:
        self.requests = []
        self.handler = handler or (lambda req: httpx.Response(200, json={"ok": True}))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        request.read()
        self.requests.append(request)
        built = self.handler(request)
        # Response(content=...) is pre-read; real transports return an unread stream.
        return httpx.Response(built.status_code, headers=built.headers, stream=httpx.ByteStream(built.content))


@pytest.fixture(autouse=True)
def reset_proxy_state(monkeypatch):
    monkeypatch.setattr(proxy, "_http_client", None)
    # Test-only allowlisted hosts; real ones (api.stripe.com, ...) stay in place.
    for host, service in (("a.example", "acme"), ("api.example.com", "acme"), ("b.example", "beta")):
        monkeypatch.setitem(proxy.SERVICE_HOSTS, host, service)


def make_app(downstream=None, vault=None, policies=None, **settings_overrides):
    db = FakeAgentDB({hashlib.sha256(TOKEN.encode()).hexdigest(): {
        "tenant_id": TENANT, "name": "billing-bot", "tenant_name": "Demo Co",
    }})
    settings = Settings(_env_file=None, **settings_overrides)
    app = FastAPI()
    app.include_router(proxy.router)
    app.include_router(callbacks_router)
    app.dependency_overrides[get_database] = lambda: db
    app.dependency_overrides[get_settings] = lambda: settings
    vault = FakeVault() if vault is None else vault
    app.dependency_overrides[get_vault_service] = lambda: vault
    # Default tenant rule mirrors the old hardcoded check: refunds and deletes need approval.
    rules = [rule("(?i)refund|delete", "requires_approval")] if policies is None else policies
    app.dependency_overrides[get_policy_service] = lambda: PolicyService(FakePolicyTable(rules))
    if downstream is not None:
        app.dependency_overrides[proxy.get_http_client] = lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(downstream)
        )
    return app, db


def make_client(downstream=None, vault=None, policies=None, **settings_overrides):
    app, db = make_app(downstream, vault, policies, **settings_overrides)
    return TestClient(app), db


# Authentication

def test_missing_token_is_401():
    client, db = make_client(Downstream())
    resp = client.get("/api/v1/proxy/", headers={"X-Target-Url": "https://api.example.com"})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"
    assert db.lookups == []


@pytest.mark.parametrize("header", ["Basic abc", "Bearer ", "Bearer", TOKEN])
def test_malformed_authorization_is_401(header):
    client, _ = make_client(Downstream())
    assert client.get("/api/v1/proxy/", headers={"Authorization": header}).status_code == 401


def test_unknown_token_is_401():
    downstream = Downstream()
    client, _ = make_client(downstream)
    resp = client.get("/api/v1/proxy/", headers={"Authorization": "Bearer nope", "X-Target-Url": "https://a.example"})
    assert resp.status_code == 401
    assert downstream.requests == []


def test_lookup_uses_sha256_of_token():
    client, db = make_client(Downstream())
    client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://api.example.com"})
    assert db.lookups == [hashlib.sha256(TOKEN.encode()).hexdigest()]


# Forwarding

def test_forwards_method_body_query_and_headers():
    downstream = Downstream(lambda req: httpx.Response(
        201, content=b"created", headers=[("X-Up", "1"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]
    ))
    client, _ = make_client(downstream)
    resp = client.post(
        "/api/v1/proxy/v1/charges?amount=5",
        headers={**AUTH, "X-Target-Url": "https://api.example.com/base?version=2", "X-Custom": "keep"},
        content=b'{"x": 1}',
    )
    assert resp.status_code == 201
    assert resp.content == b"created"
    assert resp.headers["x-up"] == "1"
    assert resp.headers.get_list("set-cookie") == ["a=1", "b=2"]

    sent = downstream.requests[0]
    assert sent.method == "POST"
    assert str(sent.url) == "https://api.example.com/base/v1/charges?version=2&amount=5"
    assert sent.content == b'{"x": 1}'
    assert sent.headers["x-custom"] == "keep"
    assert sent.headers["host"] == "api.example.com"
    assert sent.headers.get_list("authorization") == [f"Bearer {ACME_KEY}"]
    assert "x-target-url" not in sent.headers


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE"])
def test_all_methods_forwarded(method):
    downstream = Downstream()
    client, _ = make_client(downstream)
    assert client.request(method, "/api/v1/proxy/x", headers={**AUTH, "X-Target-Url": "https://a.example"}).status_code == 200
    assert downstream.requests[0].method == method


def test_get_without_body_is_not_chunked():
    downstream = Downstream()
    client, _ = make_client(downstream)
    client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example/items"})
    sent = downstream.requests[0]
    assert "transfer-encoding" not in sent.headers
    assert sent.content == b""


def test_encoded_slash_in_path_preserved():
    downstream = Downstream()
    client, _ = make_client(downstream)
    client.get("/api/v1/proxy/repos/a%2Fb/contents", headers={**AUTH, "X-Target-Url": "https://a.example"})
    assert downstream.requests[0].url.raw_path == b"/repos/a%2Fb/contents"


def test_connection_listed_headers_not_forwarded():
    downstream = Downstream()
    client, _ = make_client(downstream)
    client.get("/api/v1/proxy/", headers={
        **AUTH, "X-Target-Url": "https://a.example", "Connection": "x-secret-hop", "X-Secret-Hop": "1",
    })
    assert "x-secret-hop" not in downstream.requests[0].headers


@pytest.mark.parametrize("target, status", [
    (None, 400),
    ("not a url", 400),
    ("ftp://a.example/file", 400),
    ("file:///etc/passwd", 400),
    ("https://user:pass@a.example", 400),
])
def test_invalid_target_rejected(target, status):
    downstream = Downstream()
    client, _ = make_client(downstream)
    headers = dict(AUTH)
    if target:
        headers["X-Target-Url"] = target
    assert client.get("/api/v1/proxy/", headers=headers).status_code == status
    assert downstream.requests == []


def test_downstream_errors_map_to_502_and_504():
    def boom(req):
        raise httpx.ConnectError("refused")

    def slow(req):
        raise httpx.ReadTimeout("slow")

    for handler, status in ((boom, 502), (slow, 504)):
        client, _ = make_client(Downstream(handler))
        assert client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example"}).status_code == status


# SSRF guard (real HTTP client, no mocks). The allowlist already rejects these hosts at the
# endpoint, so the guard is tested directly as the second line of defence (e.g. DNS changes).

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("target", [
    "http://127.0.0.1:9/",
    "http://localhost:9/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:9/",
    "http://10.0.0.1:9/",
    "http://0.0.0.0:9/",
    "https://127.0.0.1:9/",
])
async def test_guard_blocks_private_addresses(target):
    client = proxy.get_http_client(Settings(_env_file=None))
    with pytest.raises(proxy.BlockedTargetError):
        await client.get(target)
    await proxy.close_http_client()


def test_allowlisted_host_resolving_to_private_address_is_403(monkeypatch):
    monkeypatch.setitem(proxy.SERVICE_HOSTS, "localhost", "acme")
    client, _ = make_client()
    resp = client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://localhost:9"})
    assert resp.status_code == 403
    assert "private or reserved" in resp.json()["detail"]


@pytest.fixture
def local_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = f"path={self.path}".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.mark.anyio
async def test_guard_allows_private_in_dev_mode(local_server):
    client = proxy.get_http_client(Settings(_env_file=None, proxy_allow_private_targets=True))
    resp = await client.get(local_server + "/hello?q=1")
    assert resp.status_code == 200
    assert resp.text == "path=/hello?q=1"
    await proxy.close_http_client()


@pytest.mark.anyio
async def test_guard_blocks_local_server_by_default(local_server):
    client = proxy.get_http_client(Settings(_env_file=None))
    with pytest.raises(proxy.BlockedTargetError):
        await client.get(local_server)
    await proxy.close_http_client()


# Audit logging

@pytest.fixture
def audit(caplog):
    """(tenant, url, method, status) of every JSON line written to the app.audit logger."""
    caplog.set_level(logging.INFO, logger="app.audit")

    class Audit:
        @property
        def events(self):
            return [json.loads(r.getMessage()) for r in caplog.records if r.name == "app.audit"]

        @property
        def calls(self):
            return [(e["tenant_id"], e["target_url"], e["method"], e["status"]) for e in self.events]

    return Audit()


def test_audit_line_is_json_with_agent_and_without_query(audit):
    client, _ = make_client(Downstream(lambda req: httpx.Response(201)))
    client.post("/api/v1/proxy/v1/charges?customer=cus_1", headers={**AUTH, "X-Target-Url": "https://a.example"})
    (event,) = audit.events
    assert {k: v for k, v in event.items() if k != "ts"} == {
        "event": "proxy_request", "tenant_id": TENANT, "agent": "billing-bot", "method": "POST",
        "target_url": "https://a.example/v1/charges", "status": 201,
    }
    assert event["ts"].endswith("+00:00")


def test_audit_logs_success_and_failure(audit):
    client, _ = make_client(Downstream(lambda req: httpx.Response(404)))
    client.delete("/api/v1/proxy/v1/x?secret=1", headers={**AUTH, "X-Target-Url": "https://a.example"})

    def boom(req):
        raise httpx.ConnectError("refused")

    client, _ = make_client(Downstream(boom))
    client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://b.example"})

    assert audit.calls == [
        (TENANT, "https://a.example/v1/x", "DELETE", 404),
        (TENANT, "https://b.example/", "GET", 502),
    ]


def test_unauthenticated_requests_are_not_audited(audit):
    client, _ = make_client(Downstream())
    client.get("/api/v1/proxy/", headers={"X-Target-Url": "https://a.example"})
    assert audit.calls == []


# Human-in-the-loop

@pytest.fixture
def decision(monkeypatch):
    state = {"value": "approved", "waited": [], "events": [], "slack_error": None, "slack_sent": True,
             "webhook_error": None}

    async def fake_send(request_id, details, settings=None):
        state["events"].append(("slack", request_id, details.target_url, details.tenant_id))
        state["slack_details"] = details
        if state["slack_error"] is not None:
            raise state["slack_error"]
        return state["slack_sent"]

    async def fake_token(request_id, tenant_id, ttl_seconds):
        state["events"].append(("token", request_id, tenant_id, ttl_seconds))
        return "tok_" + request_id

    async def fake_webhook(approval_token, request_details, settings=None):
        state["events"].append(("webhook", approval_token, request_details))
        if state["webhook_error"] is not None:
            raise state["webhook_error"]
        return True

    async def fake_wait(request_id, timeout=300, on_pending=None):
        state["events"].append(("wait", request_id))
        state["waited"].append((request_id, timeout))
        if on_pending is not None:
            await on_pending()
        if isinstance(state["value"], Exception):
            raise state["value"]
        return state["value"]

    monkeypatch.setattr(proxy.slack_service, "send_approval_message", fake_send)
    monkeypatch.setattr(redis_pubsub, "wait_for_approval", fake_wait)
    monkeypatch.setattr(redis_pubsub, "create_approval_token", fake_token)
    monkeypatch.setattr(proxy.notification, "send_generic_webhook", fake_webhook)
    return state


@pytest.mark.parametrize("target", [
    "https://api.stripe.com/v1/refunds",
    "https://a.example/users/7/delete",
    "https://a.example/x/DELETE",
])
def test_high_risk_asks_slack_then_waits_then_forwards(decision, target):
    downstream = Downstream()
    client, _ = make_client(downstream, hitl_timeout_seconds=42)
    resp = client.post("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": target}, content=b"{}")
    assert resp.status_code == 200
    assert len(downstream.requests) == 1
    request_id, timeout = decision["waited"][0]
    assert timeout == 42
    assert decision["events"] == [("wait", request_id), ("slack", request_id, target, TENANT)]


def test_slack_failure_fails_closed(decision):
    from app.services.slack_service import SlackError

    decision["slack_error"] = SlackError("HTTP 404: no_service")
    downstream = Downstream()
    client, _ = make_client(downstream)
    resp = client.post("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example/refund"})
    assert resp.status_code == 503
    assert [e[0] for e in decision["events"]] == ["wait", "slack"]
    assert downstream.requests == []


@pytest.mark.parametrize("outcome, detail", [
    ("denied", "Action denied by human overseer"),
    ("timeout", "Approval timed out; action not executed"),
])
def test_high_risk_not_approved_is_403(decision, outcome, detail):
    decision["value"] = outcome
    downstream = Downstream()
    client, _ = make_client(downstream)
    resp = client.post("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example/refund"})
    assert resp.status_code == 403
    assert resp.json() == {"detail": detail}
    assert downstream.requests == []


def test_redis_unavailable_fails_closed(decision):
    from redis.exceptions import ConnectionError as RedisConnectionError

    decision["value"] = RedisConnectionError("down")
    downstream = Downstream()
    client, _ = make_client(downstream)
    resp = client.post("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example/refund"})
    assert resp.status_code == 503
    assert downstream.requests == []


def test_low_risk_does_not_wait(decision):
    client, _ = make_client(Downstream())
    assert client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example/charges"}).status_code == 200
    assert decision["waited"] == []


def test_denied_request_is_audited(decision, audit):
    decision["value"] = "denied"
    client, _ = make_client(Downstream())
    client.post("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example/refund"})
    assert audit.calls == [(TENANT, "https://a.example/refund", "POST", 403)]


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("choice, status", [("approved", 201), ("denied", 403)])
async def test_end_to_end_slack_click_resumes_request(monkeypatch, choice, status):
    import asyncio
    import fakeredis
    from tests.test_hitl import SIGNING_SECRET, slack_body, slack_headers, wait_until_pending

    r = fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr(redis_pubsub, "_client", r)
    downstream = Downstream(lambda req: httpx.Response(201, json={"refund": "re_1"}))
    app, _ = make_app(downstream, slack_signing_secret=SIGNING_SECRET, hitl_timeout_seconds=5)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        agent = asyncio.ensure_future(client.post(
            "/api/v1/proxy/v1/refunds",
            headers={**AUTH, "X-Target-Url": "https://api.stripe.com"},
            content=b'{"charge": "ch_1"}',
        ))
        keys = []
        for _ in range(200):
            keys = [k async for k in r.scan_iter("approval:*:pending")]
            if keys:
                break
            await asyncio.sleep(0.01)
        request_id = keys[0].split(":")[1]
        await wait_until_pending(r, request_id)
        assert downstream.requests == []

        body = slack_body(choice, request_id)
        click = await client.post("/api/v1/callbacks/slack", content=body, headers=slack_headers(body))
        assert click.json() == {"ok": True, "recorded": True}

        resp = await asyncio.wait_for(agent, 3)
    assert resp.status_code == status
    assert len(downstream.requests) == (1 if choice == "approved" else 0)


# Downstream credential injection

def test_vault_key_injected_for_known_service():
    downstream = Downstream()
    vault = FakeVault()
    client, _ = make_client(downstream, vault)
    resp = client.post(
        "/api/v1/proxy/v1/charges",
        headers={**AUTH, "X-Target-Url": "https://api.stripe.com"},
        content=b"amount=5",
    )
    assert resp.status_code == 200
    assert vault.lookups == [(TENANT, "stripe")]
    sent = downstream.requests[0]
    assert sent.headers.get_list("authorization") == [f"Bearer {STRIPE_KEY}"]
    assert TOKEN not in str(sent.headers)


def test_missing_key_is_500_and_not_forwarded():
    downstream = Downstream()
    client, _ = make_client(downstream, FakeVault(keys={}))
    resp = client.get("/api/v1/proxy/v1/charges", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Missing downstream credentials for this service."}
    assert downstream.requests == []


def test_vault_failure_is_500_and_not_forwarded():
    downstream = Downstream()
    client, _ = make_client(downstream, FakeVault(error=VaultError("stored stripe key could not be decrypted")))
    resp = client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Missing downstream credentials for this service."}
    assert downstream.requests == []


def test_key_never_sent_over_plain_http():
    downstream = Downstream()
    vault = FakeVault()
    client, _ = make_client(downstream, vault)
    assert client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "http://api.stripe.com"}).status_code == 400
    assert vault.lookups == []
    assert downstream.requests == []


@pytest.mark.parametrize("target", [
    "https://evil.example/?next=api.stripe.com",
    "https://api.stripe.com.evil.example/",
    "https://evil.example/api.stripe.com/v1",
    "https://notapi.stripe.com/",
])
def test_lookalike_hosts_are_egress_denied(target):
    downstream = Downstream()
    vault = FakeVault()
    client, _ = make_client(downstream, vault)
    resp = client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": target})
    assert resp.status_code == 403
    assert vault.lookups == []
    assert downstream.requests == []


def test_hostname_match_is_case_and_trailing_dot_insensitive():
    vault = FakeVault()
    client, _ = make_client(Downstream(), vault)
    client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://API.Stripe.com./"})
    assert vault.lookups == [(TENANT, "stripe")]


def test_unknown_host_is_egress_denied(audit):
    downstream = Downstream()
    vault = FakeVault()
    client, _ = make_client(downstream, vault)
    resp = client.get("/api/v1/proxy/v1/x?k=1", headers={**AUTH, "X-Target-Url": "https://unknown.example"})
    assert resp.status_code == 403
    assert resp.json() == {"detail": "Egress denied: Host not in approved service allowlist."}
    assert vault.lookups == []
    assert downstream.requests == []
    assert audit.calls == [(TENANT, "https://unknown.example/v1/x", "GET", 403)]


def test_missing_key_fails_before_asking_slack(decision):
    downstream = Downstream()
    client, _ = make_client(downstream, FakeVault(keys={}))
    resp = client.post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 500
    assert resp.json() == {"detail": "Missing downstream credentials for this service."}
    assert decision["events"] == []
    assert downstream.requests == []


def test_egress_denied_before_asking_slack(decision):
    client, _ = make_client(Downstream())
    resp = client.post("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://unknown.example/refund"})
    assert resp.status_code == 403
    assert decision["events"] == []


def test_decrypted_key_never_logged_or_audited(audit, caplog, capsys):
    def boom(req):
        raise httpx.ConnectError(f"refused {req.headers}")

    with caplog.at_level(logging.DEBUG):
        for handler in (None, boom):
            client, _ = make_client(Downstream(handler))
            client.get("/api/v1/proxy/v1/charges?x=1", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    captured = capsys.readouterr()
    assert len(audit.calls) == 2
    for text in (caplog.text, captured.out, captured.err, repr(audit.calls)):
        assert STRIPE_KEY not in text


# Policy engine

def test_policy_deny_is_403_before_vault_and_slack(decision):
    downstream, vault = Downstream(), FakeVault()
    client, _ = make_client(downstream, vault, policies=[rule(r"/v1/refunds", "deny")])
    resp = client.post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 403
    assert resp.json() == {"detail": "Action denied by tenant security policy"}
    assert vault.lookups == []
    assert decision["events"] == []
    assert downstream.requests == []


def test_policy_allow_skips_approval(decision):
    downstream = Downstream()
    client, _ = make_client(downstream, policies=[rule(r"/v1/refunds", "allow")])
    resp = client.post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 200
    assert decision["events"] == []
    assert len(downstream.requests) == 1


def test_no_policies_means_allow(decision):
    downstream = Downstream()
    client, _ = make_client(downstream, policies=[])
    assert client.delete("/api/v1/proxy/v1/refunds/re_1", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"}).status_code == 200
    assert decision["events"] == []


def test_policy_method_scoping(decision):
    policies = [rule(r"/v1/customers", "deny", method="DELETE")]
    client, _ = make_client(Downstream(), policies=policies)
    target = {**AUTH, "X-Target-Url": "https://api.stripe.com"}
    assert client.get("/api/v1/proxy/v1/customers/cus_1", headers=target).status_code == 200
    assert client.delete("/api/v1/proxy/v1/customers/cus_1", headers=target).status_code == 403


def test_encoded_path_cannot_dodge_policy(decision):
    downstream = Downstream()
    client, _ = make_client(downstream, policies=[rule(r"^https://api\.stripe\.com/v1/refunds$", "deny")])
    resp = client.post("/api/v1/proxy/v1/re%66unds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 403
    assert downstream.requests == []


def test_policy_backend_failure_fails_closed(decision, audit):
    class Broken:
        async def match_request(self, *args):
            raise RuntimeError("database down")

    downstream = Downstream()
    app, _ = make_app(downstream)
    app.dependency_overrides[get_policy_service] = lambda: Broken()
    resp = TestClient(app).post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 503
    assert downstream.requests == []
    assert audit.calls == [(TENANT, "https://api.stripe.com/v1/refunds", "POST", 503)]


# Headless (generic webhook) approvals

WEBHOOK = {"custom_webhook_url": "https://dash.example/hooks/approvals", "custom_webhook_secret": "whsec_test"}


def test_both_channels_notified_after_pending(decision):
    downstream = Downstream()
    client, _ = make_client(downstream, hitl_timeout_seconds=42, **WEBHOOK)
    resp = client.post("/api/v1/proxy/v1/refunds?x=1", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 200
    request_id = decision["waited"][0][0]
    kinds = [e[0] for e in decision["events"]]
    assert kinds == ["wait", "slack", "token", "webhook"]
    _, token, details = decision["events"][3]
    assert token == "tok_" + request_id
    assert decision["events"][2] == ("token", request_id, TENANT, 42 + 60)
    assert details["target_url"] == "https://api.stripe.com/v1/refunds?x=1"
    assert details["method"] == "POST"
    assert details["tenant_id"] == TENANT
    assert isinstance(details["expires_at"], int)


def test_webhook_not_called_when_unconfigured(decision):
    client, _ = make_client(Downstream())
    client.post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert [e[0] for e in decision["events"]] == ["wait", "slack"]


def test_one_channel_failing_still_waits_for_the_other(decision):
    from app.services.slack_service import SlackError

    decision["slack_error"] = SlackError("HTTP 500")
    downstream = Downstream()
    client, _ = make_client(downstream, **WEBHOOK)
    assert client.post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"}).status_code == 200
    assert len(downstream.requests) == 1


def test_webhook_only_setup(decision):
    decision["slack_sent"] = False
    client, _ = make_client(Downstream(), **WEBHOOK)
    assert client.post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"}).status_code == 200


@pytest.mark.parametrize("slack_sent", [True, False])
def test_all_configured_channels_failing_is_503(decision, slack_sent):
    from app.services.notification import WebhookError
    from app.services.slack_service import SlackError

    if slack_sent:
        decision["slack_error"] = SlackError("HTTP 500")
    else:
        decision["slack_sent"] = False
    decision["webhook_error"] = WebhookError("HTTP 502")
    downstream = Downstream()
    client, _ = make_client(downstream, **WEBHOOK)
    resp = client.post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 503
    assert downstream.requests == []


@pytest.mark.anyio
@pytest.mark.parametrize("decision_path, status", [("approve", 201), ("deny", 403)])
async def test_end_to_end_headless_approval(monkeypatch, decision_path, status):
    import asyncio
    import fakeredis

    r = fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr(redis_pubsub, "_client", r)
    tokens = asyncio.Queue()

    async def capture(approval_token, request_details, settings=None):
        await tokens.put(approval_token)
        return True

    async def no_slack(*args, **kwargs):
        return False

    monkeypatch.setattr(proxy.notification, "send_generic_webhook", capture)
    monkeypatch.setattr(proxy.slack_service, "send_approval_message", no_slack)
    downstream = Downstream(lambda req: httpx.Response(201, json={"id": "re_1"}))
    app, _ = make_app(downstream, hitl_timeout_seconds=5, **WEBHOOK)
    app.dependency_overrides[get_current_tenant] = lambda: TENANT

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        agent = asyncio.ensure_future(client.post(
            "/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"}, content=b"charge=ch_1",
        ))
        token = await asyncio.wait_for(tokens.get(), 3)
        assert downstream.requests == []
        click = await client.post(f"/api/v1/callbacks/{decision_path}", json={"approval_token": token})
        assert click.json() == {"status": "success", "action": "approved" if decision_path == "approve" else "denied"}
        resp = await asyncio.wait_for(agent, 3)
        reuse = await client.post("/api/v1/callbacks/approve", json={"approval_token": token})
    assert resp.status_code == status
    assert len(downstream.requests) == (1 if decision_path == "approve" else 0)
    assert reuse.status_code == 404
    assert [k async for k in r.scan_iter("approval_token:*")] == []
    await r.aclose()


@pytest.mark.anyio
async def test_instant_auto_approval_is_not_lost(monkeypatch):
    """A headless backend may approve inside the webhook call itself, before Slack is even tried."""
    import fakeredis

    r = fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer(), decode_responses=True)
    monkeypatch.setattr(redis_pubsub, "_client", r)

    async def auto_approve(approval_token, request_details, settings=None):
        assert await redis_pubsub.publish_decision_by_token(approval_token, "approved", request_details["tenant_id"]) is True
        return True

    async def no_slack(*args, **kwargs):
        return False

    monkeypatch.setattr(proxy.notification, "send_generic_webhook", auto_approve)
    monkeypatch.setattr(proxy.slack_service, "send_approval_message", no_slack)
    downstream = Downstream()
    app, _ = make_app(downstream, hitl_timeout_seconds=2, **WEBHOOK)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        resp = await client.post("/api/v1/proxy/v1/refunds", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"})
    assert resp.status_code == 200
    assert len(downstream.requests) == 1
    await r.aclose()


# Approval message details

def test_approval_details_are_human_readable(decision):
    downstream = Downstream()
    policies = [rule(r"/v1/refunds", "requires_approval")]
    policies[0]["name"] = "Refunds need human approval"
    client, _ = make_client(downstream, policies=policies, hitl_timeout_seconds=120)
    resp = client.post(
        "/api/v1/proxy/v1/refunds",
        headers={**AUTH, "X-Target-Url": "https://api.stripe.com", "Content-Type": "application/x-www-form-urlencoded"},
        content=b"charge=ch_3UZE&amount=4999",
    )
    assert resp.status_code == 200
    d = decision["slack_details"]
    assert (d.agent_name, d.tenant_name, d.policy_name, d.service) == ("billing-bot", "Demo Co", "Refunds need human approval", "stripe")
    assert (d.method, d.endpoint, d.expires_in_seconds) == ("POST", "api.stripe.com/v1/refunds", 120)
    assert not hasattr(d, "params")
    assert downstream.requests[0].content == b"charge=ch_3UZE&amount=4999"


@pytest.mark.parametrize("policies, path", [
    ([rule("refunds", "requires_approval")], "/v1/refunds"),
    ([], "/v1/charges"),
], ids=["approval", "pass-through"])
def test_large_bodies_stream_through_unbuffered(decision, policies, path):
    # A 2 MB body exceeds the 1 MB cap any body-reading code path would apply, so this must stream.
    downstream = Downstream()
    client, _ = make_client(downstream, policies=policies)
    resp = client.post(f"/api/v1/proxy{path}", headers={**AUTH, "X-Target-Url": "https://api.stripe.com"},
                       content=b"x" * 2_000_000)
    assert resp.status_code == 200
    assert len(downstream.requests[0].content) == 2_000_000
