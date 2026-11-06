from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from langchain_agentic_iam import SecureAPIWrapper

TOKEN = "agent-token-123"


@pytest.fixture
def proxy():
    """Fake proxy that records each request and echoes it back."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode()
            seen.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
            status = 403 if "deny" in self.path else 302 if "redirect" in self.path else 200
            payload = json.dumps({"detail": "Action denied by human overseer"} if status == 403 else {"ok": True}).encode()
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "https://elsewhere.example/steal")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/api/v1/proxy", seen
    server.shutdown()


def make(base):
    return SecureAPIWrapper(proxy_base_url=base, agent_token=TOKEN)


def test_get_routes_through_proxy(proxy):
    base, seen = proxy
    assert make(base).get("https://api.stripe.com/v1/charges?limit=3") == '{"ok": true}'
    req = seen[0]
    assert req["method"] == "GET"
    assert req["path"] == "/api/v1/proxy/v1/charges?limit=3"
    assert req["headers"]["X-Target-Url"] == "https://api.stripe.com"
    assert req["headers"]["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("method", ["post", "put", "patch"])
def test_body_methods_send_form_or_json(proxy, method):
    base, seen = proxy
    wrapper = make(base)
    getattr(wrapper, method)("https://api.stripe.com/v1/refunds", data={"charge": "ch_1"})
    getattr(wrapper, method)("https://api.example.com/items", json={"a": 1})
    assert seen[0]["method"] == method.upper()
    assert seen[0]["body"] == "charge=ch_1"
    assert seen[0]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert json.loads(seen[1]["body"]) == {"a": 1}


def test_delete(proxy):
    base, seen = proxy
    make(base).delete("https://api.github.com/repos/o/r/hooks/1")
    assert (seen[0]["method"], seen[0]["path"]) == ("DELETE", "/api/v1/proxy/repos/o/r/hooks/1")
    assert seen[0]["headers"]["X-Target-Url"] == "https://api.github.com"


def test_error_bodies_returned_as_text(proxy):
    base, _ = proxy
    assert "Action denied by human overseer" in make(base).post("https://api.stripe.com/v1/deny")


def test_redirects_not_followed(proxy):
    base, seen = proxy
    make(base).get("https://api.stripe.com/redirect")
    assert len(seen) == 1


def test_caller_cannot_override_auth_or_target(proxy):
    base, seen = proxy
    make(base).get("https://api.stripe.com/v1/x", headers={
        "authorization": "Bearer sk_live_raw", "x-target-url": "https://evil.example", "X-Trace": "1",
    })
    headers = seen[0]["headers"]
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert headers["X-Target-Url"] == "https://api.stripe.com"
    assert headers["X-Trace"] == "1"


@pytest.mark.parametrize("url, proxy_url, target", [
    ("https://api.stripe.com", "http://p/api/v1/proxy/", "https://api.stripe.com"),
    ("https://api.stripe.com:8443/v1/a%2Fb?x=1&y=2#frag", "http://p/api/v1/proxy/v1/a%2Fb?x=1&y=2", "https://api.stripe.com:8443"),
])
def test_route(url, proxy_url, target):
    assert SecureAPIWrapper(proxy_base_url="http://p/api/v1/proxy/", agent_token="t").route(url) == (proxy_url, target)


@pytest.mark.parametrize("url", ["/v1/charges", "ftp://api.stripe.com/x", "https://user:pw@api.stripe.com/x", "api.stripe.com/v1"])
def test_invalid_urls_rejected(url):
    with pytest.raises(ValueError):
        SecureAPIWrapper(agent_token="t").route(url)


def test_token_hidden_from_repr_and_serialization():
    wrapper = SecureAPIWrapper(agent_token=TOKEN)
    assert TOKEN not in repr(wrapper)
    assert TOKEN not in str(wrapper.model_dump())
    assert TOKEN not in wrapper.model_dump_json()
