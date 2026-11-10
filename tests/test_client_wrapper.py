"""End-to-end: the client SDK wrappers against the real proxy app over HTTP."""
from __future__ import annotations

import hashlib
import socket
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi import FastAPI

from app.api import proxy
from app.core.config import Settings, get_settings
from app.services.database import get_database
from app.services.policy_service import PolicyService, get_policy_service
from app.services.vault_service import get_vault_service
from tests.test_policy_service import FakePolicyTable
from tests.test_proxy import FakeAgentDB, FakeVault, STRIPE_KEY, TENANT, TOKEN

_CLIENTS = Path(__file__).resolve().parents[1] / "clients" / "python"
sys.path.insert(0, str(_CLIENTS / "langchain-agentic-iam"))
sys.path.insert(0, str(_CLIENTS / "crewai-agentic-iam"))
from crewai_agentic_iam.wrapper import SecureAPIWrapper as CrewAIWrapper  # noqa: E402
from langchain_agentic_iam import SecureAPIWrapper as LangChainWrapper  # noqa: E402

WRAPPERS = pytest.mark.parametrize("SecureAPIWrapper", [LangChainWrapper, CrewAIWrapper], ids=["langchain", "crewai"])


@pytest.fixture
def live_proxy(monkeypatch):
    sent = []

    def downstream(request: httpx.Request) -> httpx.Response:
        request.read()
        sent.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(b'{"id": "re_1", "object": "refund"}'))

    async def approve(*args, **kwargs):
        return "approved"

    async def no_slack(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy.redis_pubsub, "wait_for_approval", approve)
    monkeypatch.setattr(proxy.slack_service, "send_approval_message", no_slack)
    db = FakeAgentDB({hashlib.sha256(TOKEN.encode()).hexdigest(): {"tenant_id": TENANT}})
    settings = Settings(_env_file=None)
    app = FastAPI()
    app.include_router(proxy.router)
    app.dependency_overrides[get_database] = lambda: db
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_vault_service] = lambda: FakeVault()
    app.dependency_overrides[get_policy_service] = lambda: PolicyService(FakePolicyTable([]))
    app.dependency_overrides[proxy.get_http_client] = lambda: httpx.AsyncClient(transport=httpx.MockTransport(downstream))

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.01)
    yield f"http://127.0.0.1:{port}/api/v1/proxy", sent
    server.should_exit = True
    thread.join(5)


@WRAPPERS
def test_wrapper_through_real_proxy(live_proxy, SecureAPIWrapper):
    base, sent = live_proxy
    wrapper = SecureAPIWrapper(proxy_base_url=base, agent_token=TOKEN)

    assert wrapper.post("https://api.stripe.com/v1/refunds?expand[]=charge", data={"charge": "ch_1"}) == \
        '{"id": "re_1", "object": "refund"}'
    req = sent[0]
    assert req.method == "POST"
    assert (req.url.scheme, req.url.host, req.url.path) == ("https", "api.stripe.com", "/v1/refunds")
    assert dict(req.url.params) == {"expand[]": "charge"}
    assert req.content == b"charge=ch_1"
    assert req.headers["authorization"] == f"Bearer {STRIPE_KEY}"
    assert "x-target-url" not in req.headers


@WRAPPERS
def test_wrapper_surfaces_proxy_denials(live_proxy, SecureAPIWrapper):
    base, sent = live_proxy
    wrapper = SecureAPIWrapper(proxy_base_url=base, agent_token=TOKEN)
    assert "Egress denied" in wrapper.get("https://unknown.example/v1/x")
    assert "invalid agent token" in SecureAPIWrapper(proxy_base_url=base, agent_token="wrong").get("https://api.stripe.com/v1/x")
    assert sent == []
