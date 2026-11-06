from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

from crewai_agentic_iam import SecureAPIWrapper, SecureCrewAITool

TOKEN = "agent-token-123"


@pytest.fixture
def proxy():
    """Fake proxy that records each request."""
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def _handle(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
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
    yield SecureAPIWrapper(proxy_base_url=f"http://127.0.0.1:{server.server_port}/api/v1/proxy", agent_token=TOKEN), seen
    server.shutdown()


# SecureAPIWrapper

def test_get_routes_through_proxy(proxy):
    wrapper, seen = proxy
    assert wrapper.get("https://api.stripe.com/v1/charges?limit=3") == '{"ok": true}'
    req = seen[0]
    assert (req["method"], req["path"]) == ("GET", "/api/v1/proxy/v1/charges?limit=3")
    assert req["headers"]["X-Target-Url"] == "https://api.stripe.com"
    assert req["headers"]["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("method", ["post", "put", "patch"])
def test_body_methods(proxy, method):
    wrapper, seen = proxy
    getattr(wrapper, method)("https://api.stripe.com/v1/refunds", data={"charge": "ch_1"})
    assert (seen[0]["method"], seen[0]["body"]) == (method.upper(), "charge=ch_1")


def test_delete(proxy):
    wrapper, seen = proxy
    wrapper.delete("https://api.github.com/repos/o/r/hooks/1")
    assert (seen[0]["method"], seen[0]["path"]) == ("DELETE", "/api/v1/proxy/repos/o/r/hooks/1")


def test_denials_returned_as_text_and_redirects_not_followed(proxy):
    wrapper, seen = proxy
    assert "Action denied by human overseer" in wrapper.post("https://api.stripe.com/v1/deny")
    wrapper.get("https://api.stripe.com/redirect")
    assert len(seen) == 2


def test_caller_cannot_override_auth_or_target(proxy):
    wrapper, seen = proxy
    wrapper.get("https://api.stripe.com/v1/x", headers={"Authorization": "Bearer raw", "X-Target-Url": "https://evil.example"})
    assert seen[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert seen[0]["headers"]["X-Target-Url"] == "https://api.stripe.com"


@pytest.mark.parametrize("url", ["/v1/charges", "ftp://api.stripe.com/x", "https://user:pw@api.stripe.com/x"])
def test_invalid_urls_rejected(url):
    with pytest.raises(ValueError):
        SecureAPIWrapper(agent_token="t").route(url)


def test_token_hidden():
    wrapper = SecureAPIWrapper(agent_token=TOKEN)
    assert TOKEN not in repr(wrapper) and TOKEN not in wrapper.model_dump_json()


# SecureCrewAITool

def make_tool(wrapper, **kwargs):
    defaults = {"name": "Stripe tool", "description": "Calls Stripe.", "wrapper": wrapper,
                "endpoint": "https://api.stripe.com/v1/refunds", "method": "POST"}
    return SecureCrewAITool(**{**defaults, **kwargs})


def test_post_tool_sends_form_body(proxy):
    wrapper, seen = proxy
    out = make_tool(wrapper).run(params={"charge": "ch_9", "amount": 500})
    assert out == '{"ok": true}'
    req = seen[0]
    assert (req["method"], req["path"], req["headers"]["X-Target-Url"]) == ("POST", "/api/v1/proxy/v1/refunds", "https://api.stripe.com")
    assert parse_qs(req["body"]) == {"charge": ["ch_9"], "amount": ["500"]}


def test_json_body_format(proxy):
    wrapper, seen = proxy
    make_tool(wrapper, endpoint="https://api.github.com/repos/o/r/issues", body_format="json").run(params={"title": "Bug"})
    assert json.loads(seen[0]["body"]) == {"title": "Bug"}


def test_get_tool_sends_query_params(proxy):
    wrapper, seen = proxy
    make_tool(wrapper, endpoint="https://api.stripe.com/v1/charges", method="GET").run(params={"customer": "cus_1", "limit": 1})
    assert seen[0]["path"] == "/api/v1/proxy/v1/charges?customer=cus_1&limit=1"


def test_path_params_filled_and_escaped(proxy):
    wrapper, seen = proxy
    tool = make_tool(wrapper, endpoint="https://api.stripe.com/v1/customers/{customer_id}", method="DELETE")
    tool.run(path_params={"customer_id": "cus_1"})
    tool.run(path_params={"customer_id": "../charges?x=@evil.example#"})
    assert seen[0]["path"] == "/api/v1/proxy/v1/customers/cus_1"
    assert seen[1]["path"] == "/api/v1/proxy/v1/customers/..%2Fcharges%3Fx%3D%40evil.example%23"
    assert all(r["headers"]["X-Target-Url"] == "https://api.stripe.com" for r in seen)


@pytest.mark.parametrize("path_params", [{}, {"customer_id": "c", "extra": "x"}, {"customer_id": ".."}, {"customer_id": ""}])
def test_bad_path_params_return_error_without_calling(proxy, path_params):
    wrapper, seen = proxy
    tool = make_tool(wrapper, endpoint="https://api.stripe.com/v1/customers/{customer_id}", method="GET")
    assert tool.run(path_params=path_params).startswith("Error:")
    assert seen == []


@pytest.mark.parametrize("endpoint", [
    "https://{host}.stripe.com/v1/x",
    "https://api.stripe.com/v1/x?limit=1",
    "/v1/refunds",
    "https://api.stripe.com/v1/{}",
    "https://api.stripe.com/v1/{0}",
])
def test_invalid_endpoints_rejected(endpoint):
    with pytest.raises(ValueError):
        make_tool(SecureAPIWrapper(agent_token="t"), endpoint=endpoint)


def test_tool_exposes_args_schema_to_crewai():
    tool = make_tool(SecureAPIWrapper(agent_token="t"))
    assert set(tool.args_schema.model_json_schema()["properties"]) == {"path_params", "params"}
