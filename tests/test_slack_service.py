from __future__ import annotations

import json
import uuid

import httpx
import pytest

from app.core.config import Settings
from app.services import slack_service

WEBHOOK = "https://hooks.slack.com/services/T000/B000/secret-token"
TENANT = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def slack(monkeypatch):
    """Routes slack_service's outgoing requests to `handler` (default: Slack's 200 "ok")."""
    state = {"requests": [], "handler": lambda request: httpx.Response(200, text="ok")}
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        return state["handler"](request)

    monkeypatch.setattr(
        slack_service.httpx, "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    return state


def settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_message_has_warning_details_and_buttons():
    rid = str(uuid.uuid4())
    blocks = slack_service.approval_message(rid, "https://api.stripe.com/v1/refunds", TENANT)["blocks"]

    assert [b["type"] for b in blocks] == ["section", "section", "actions"]
    assert blocks[0]["text"]["text"] == "🚨 AI Agent requesting high-risk action."
    details = " ".join(f["text"] for f in blocks[1]["fields"])
    assert "https://api.stripe.com/v1/refunds" in details and TENANT in details

    approve, deny = blocks[2]["elements"]
    assert approve == {
        "type": "button", "text": {"type": "plain_text", "text": "Approve"},
        "style": "primary", "action_id": "approve_action", "value": f"{rid}:approved",
    }
    assert deny == {
        "type": "button", "text": {"type": "plain_text", "text": "Deny"},
        "style": "danger", "action_id": "deny_action", "value": f"{rid}:denied",
    }


def test_agent_controlled_text_cannot_ping_or_link():
    target = "https://evil.example/refund?<!channel>&x=<https://phish.example|Stripe>"
    fields = slack_service.approval_message("r", target, "<!here>")["blocks"][1]["fields"]
    text = " ".join(f["text"] for f in fields)
    assert "<" not in text and ">" not in text
    assert "&lt;!channel&gt;" in text and "&amp;x=" in text
    assert all(f["verbatim"] for f in fields)


def test_long_target_is_truncated_within_slack_limits():
    target = "https://a.example/" + "&" * 5000
    fields = slack_service.approval_message("r", target, TENANT)["blocks"][1]["fields"]
    assert all(len(f["text"]) <= 2000 for f in fields)
    assert fields[0]["text"].endswith("…")


@pytest.mark.anyio
async def test_send_posts_block_kit_json_to_webhook(slack):
    rid = str(uuid.uuid4())
    sent = await slack_service.send_approval_message(rid, "https://a.example/refund", TENANT,
                                                     settings=settings(slack_webhook_url=WEBHOOK))
    assert sent is True
    (request,) = slack["requests"]
    assert request.method == "POST" and str(request.url) == WEBHOOK
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == slack_service.approval_message(rid, "https://a.example/refund", TENANT)


@pytest.mark.anyio
async def test_without_webhook_nothing_is_sent(slack, caplog):
    rid = str(uuid.uuid4())
    assert await slack_service.send_approval_message(rid, "https://a.example/refund", TENANT, settings=settings()) is False
    assert slack["requests"] == []
    assert rid in caplog.text


@pytest.mark.anyio
@pytest.mark.parametrize("handler", [
    lambda request: httpx.Response(404, text="no_service"),
    lambda request: httpx.Response(400, text="invalid_payload"),
    lambda request: (_ for _ in ()).throw(httpx.ConnectError(f"cannot reach {request.url}")),
])
async def test_send_failure_raises_without_leaking_webhook(slack, handler):
    slack["handler"] = handler
    with pytest.raises(slack_service.SlackError) as error:
        await slack_service.send_approval_message("r", "https://a.example/refund", TENANT,
                                                  settings=settings(slack_webhook_url=WEBHOOK))
    assert "secret-token" not in str(error.value)
    # No chained httpx exception (whose message would contain the URL) reaches tracebacks.
    assert error.value.__cause__ is None
    assert error.value.__context__ is None or error.value.__suppress_context__


@pytest.mark.anyio
async def test_resolve_replaces_original_message(slack):
    url = "https://hooks.slack.com/actions/T1/123/abc"
    await slack_service.resolve_message(url, "Action Approved by <@U1>")
    (request,) = slack["requests"]
    assert str(request.url) == url
    body = json.loads(request.content)
    assert body["replace_original"] is True
    assert body["text"] == "Action Approved by <@U1>"
    assert all(block["type"] != "actions" for block in body["blocks"])


@pytest.mark.anyio
async def test_resolve_failure_is_only_logged(slack, caplog):
    slack["handler"] = lambda request: httpx.Response(500, text="oops")
    await slack_service.resolve_message("https://hooks.slack.com/actions/T1/1/a", "text")
    assert "Could not update the Slack approval message" in caplog.text
