from __future__ import annotations

import hashlib
import logging
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import proxy
from app.api.callbacks import router as callbacks_router
from app.core.config import Settings, get_settings
from app.services import redis_pubsub
from app.services.supabase_client import get_supabase
from app.services.vault_service import VaultError, get_vault_service

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


class FakeSupabase:
    """Mimics supabase.table(...).select(...).eq(...).limit(...).execute()."""

    def __init__(self, rows_by_hash) -> None:
        self.rows_by_hash = rows_by_hash
        self.lookups = []

    def table(self, name):
        fake, filters = self, {}

        class Query:
            def select(self, cols):
                return self

            def eq(self, col, value):
                filters[col] = value
                return self

            def limit(self, n):
                return self

            async def execute(self):
                fake.lookups.append((name, dict(filters)))
                rows = fake.rows_by_hash.get(filters.get("agent_token"), [])
                return type("Resp", (), {"data": rows})()

        return Query()


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
    proxy._audit_logger.cache_clear()
    monkeypatch.setattr(proxy, "_http_client", None)
    # Test-only allowlisted hosts; real ones (api.stripe.com, ...) stay in place.
    for host, service in (("a.example", "acme"), ("api.example.com", "acme"), ("b.example", "beta")):
        monkeypatch.setitem(proxy.SERVICE_HOSTS, host, service)
    yield
    proxy._audit_logger.cache_clear()


def make_app(downstream=None, vault=None, **settings_overrides):
    supabase = FakeSupabase({hashlib.sha256(TOKEN.encode()).hexdigest(): [{"tenant_id": TENANT}]})
    settings = Settings(_env_file=None, **settings_overrides)
    app = FastAPI()
    app.include_router(proxy.router)
    app.include_router(callbacks_router)
    app.dependency_overrides[get_supabase] = lambda: supabase
    app.dependency_overrides[get_settings] = lambda: settings
    vault = FakeVault() if vault is None else vault
    app.dependency_overrides[get_vault_service] = lambda: vault
    if downstream is not None:
        app.dependency_overrides[proxy.get_http_client] = lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(downstream)
        )
    return app, supabase


def make_client(downstream=None, vault=None, **settings_overrides):
    app, supabase = make_app(downstream, vault, **settings_overrides)
    return TestClient(app), supabase


# Authentication

def test_missing_token_is_401():
    client, supabase = make_client(Downstream())
    resp = client.get("/api/v1/proxy/", headers={"X-Target-Url": "https://api.example.com"})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"
    assert supabase.lookups == []


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
    client, supabase = make_client(Downstream())
    client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://api.example.com"})
    assert supabase.lookups == [("agent_identities", {"agent_token": hashlib.sha256(TOKEN.encode()).hexdigest()})]


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

def test_community_edition_skips_audit(caplog):
    client, _ = make_client(Downstream())
    with caplog.at_level(logging.DEBUG, logger="app.api.proxy"):
        client.get("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example"})
    assert "Community Edition: Audit log skipped." in caplog.text


@pytest.fixture
def ee_audit(tmp_path, monkeypatch):
    pkg = tmp_path / "ee" / "api"
    pkg.mkdir(parents=True)
    (tmp_path / "ee" / "__init__.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "audit.py").write_text(
        "calls = []\n"
        "async def log_action(tenant_id, target_url, method, status_code):\n"
        "    calls.append((tenant_id, target_url, method, status_code))\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    # The repo's own ee/ may already be imported; drop it so the fake package is found.
    for mod in ("ee", "ee.api", "ee.api.audit"):
        sys.modules.pop(mod, None)
    yield
    for mod in ("ee", "ee.api", "ee.api.audit"):
        sys.modules.pop(mod, None)


def test_enterprise_audit_logs_success_and_failure(ee_audit):
    import ee.api.audit as audit

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


def test_unauthenticated_requests_are_not_audited(ee_audit):
    import ee.api.audit as audit

    client, _ = make_client(Downstream())
    client.get("/api/v1/proxy/", headers={"X-Target-Url": "https://a.example"})
    assert audit.calls == []


# Human-in-the-loop

@pytest.fixture
def decision(monkeypatch):
    state = {"value": "approved", "waited": [], "events": [], "slack_error": None}

    async def fake_send(request_id, target_url, tenant_id, settings=None):
        state["events"].append(("slack", request_id, target_url, tenant_id))
        if state["slack_error"] is not None:
            raise state["slack_error"]
        return True

    async def fake_wait(request_id, timeout=300):
        state["events"].append(("wait", request_id))
        state["waited"].append((request_id, timeout))
        if isinstance(state["value"], Exception):
            raise state["value"]
        return state["value"]

    monkeypatch.setattr(proxy.slack_service, "send_approval_message", fake_send)
    monkeypatch.setattr(redis_pubsub, "wait_for_approval", fake_wait)
    return state


@pytest.mark.parametrize("target", [
    "https://api.stripe.com/v1/refunds",
    "https://a.example/users/7/delete",
    "https://a.example/x?action=DELETE",
])
def test_high_risk_asks_slack_then_waits_then_forwards(decision, target):
    downstream = Downstream()
    client, _ = make_client(downstream, hitl_timeout_seconds=42)
    resp = client.post("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": target}, content=b"{}")
    assert resp.status_code == 200
    assert len(downstream.requests) == 1
    request_id, timeout = decision["waited"][0]
    assert timeout == 42
    assert decision["events"] == [("slack", request_id, target, TENANT), ("wait", request_id)]


def test_slack_failure_fails_closed(decision):
    from app.services.slack_service import SlackError

    decision["slack_error"] = SlackError("HTTP 404: no_service")
    downstream = Downstream()
    client, _ = make_client(downstream)
    resp = client.post("/api/v1/proxy/", headers={**AUTH, "X-Target-Url": "https://a.example/refund"})
    assert resp.status_code == 503
    assert decision["waited"] == []
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


def test_denied_request_is_audited(decision, ee_audit):
    import ee.api.audit as audit

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


def test_unknown_host_is_egress_denied(ee_audit):
    import ee.api.audit as audit

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


def test_decrypted_key_never_logged_or_audited(ee_audit, caplog, capsys):
    import ee.api.audit as audit

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
