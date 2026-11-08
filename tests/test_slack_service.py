from __future__ import annotations

import json
import uuid

import httpx
import pytest

from app.core.config import Settings
from app.services import slack_service
from app.services.approval_details import ApprovalDetails

WEBHOOK = "https://hooks.slack.com/services/T000/B000/secret-token"
TENANT = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"


def details(**overrides) -> ApprovalDetails:
    base = dict(
        method="POST", target_url="https://api.stripe.com/v1/refunds", tenant_id=TENANT, service="stripe",
        tenant_name="Demo Co", agent_name="billing-bot", policy_name="Refunds need human approval",
        expires_in_seconds=120,
    )
    return ApprovalDetails(**{**base, **overrides})


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


def _text(blocks) -> str:
    out = []
    for b in blocks:
        if "text" in b:
            out.append(b["text"]["text"])
        out += [f["text"] for f in b.get("fields", [])]
        out += [e["text"] for e in b.get("elements", []) if isinstance(e.get("text"), str)]
    return "\n".join(out)


def test_message_is_human_readable():
    rid = str(uuid.uuid4())
    msg = slack_service.approval_message(rid, details())
    blocks = msg["blocks"]
    assert [b["type"] for b in blocks] == ["header", "section", "context", "actions"]
    assert blocks[0]["text"] == {"type": "plain_text", "text": "🚨 Approval needed: billing-bot wants to create refund on Stripe"}
    assert msg["text"] == "🚨 Approval needed: billing-bot wants to create refund on Stripe"
    text = _text(blocks)
    for expected in ("*Agent:*\nbilling-bot", "*Workspace:*\nDemo Co", "`POST api.stripe.com/v1/refunds`",
                     "*Paused by policy:*\nRefunds need human approval",
                     "Automatically denied in 2 min", f"request `{rid[:8]}`"):
        assert expected in text
    assert TENANT not in text


def test_query_string_is_not_shown():
    text = _text(slack_service.approval_message("r", details(target_url="https://api.stripe.com/v1/refunds?api_key=sk_live_x"))["blocks"])
    assert "sk_live_x" not in text and "`POST api.stripe.com/v1/refunds`" in text


def test_message_falls_back_when_names_are_missing():
    text = _text(slack_service.approval_message("r", details(agent_name=None, tenant_name=None, policy_name=None))["blocks"])
    assert "An AI agent wants to create refund" in text
    assert f"*Workspace:*\n{TENANT}" in text


def test_buttons_unchanged():
    rid = str(uuid.uuid4())
    approve, deny = slack_service.approval_message(rid, details())["blocks"][-1]["elements"]
    assert approve == {
        "type": "button", "text": {"type": "plain_text", "text": "Approve"},
        "style": "primary", "action_id": "approve_action", "value": f"{rid}:approved",
    }
    assert deny == {
        "type": "button", "text": {"type": "plain_text", "text": "Deny"},
        "style": "danger", "action_id": "deny_action", "value": f"{rid}:denied",
    }


@pytest.mark.parametrize("method, url, summary", [
    ("POST", "https://api.stripe.com/v1/refunds", "create refund"),
    ("DELETE", "https://api.stripe.com/v1/customers/cus_123", "delete customer cus_123"),
    ("POST", "https://api.stripe.com/v1/payment_intents/pi_1/cancel", "create cancel"),
    ("PATCH", "https://api.github.com/repos/o/r/issues/42", "update issue 42"),
    ("GET", "https://api.stripe.com/", "read resource"),
    ("PUT", "https://api.github.com/user/emails", "update email"),
])
def test_action_summary(method, url, summary):
    assert slack_service.action_summary(method, url) == summary


def test_agent_controlled_text_cannot_ping_or_link():
    evil = "<!channel> <https://phish.example|Stripe>"
    msg = slack_service.approval_message("r", details(
        target_url="https://api.stripe.com/v1/<!here>", agent_name=evil, tenant_name=evil, policy_name=evil,
    ))
    mrkdwn = "\n".join(t for b in msg["blocks"][1:3] for t in
                       ([b["text"]["text"]] if "text" in b else []) + [f["text"] for f in b.get("fields", []) + b.get("elements", [])])
    assert "<" not in mrkdwn and ">" not in mrkdwn
    assert "&lt;!channel&gt;" in mrkdwn
    assert all(f.get("verbatim") for b in msg["blocks"][1:3] for f in b.get("fields", []) + b.get("elements", []))
    # Header is plain_text, which Slack never parses for mentions or links.
    assert msg["blocks"][0]["text"]["type"] == "plain_text"


def test_long_values_stay_within_slack_limits():
    long = "&" * 5000
    msg = slack_service.approval_message("r", details(agent_name=long, tenant_name=long, policy_name=long,
                                                      target_url="https://a.example/" + long))
    assert len(msg["blocks"][0]["text"]["text"]) <= 150
    assert all(len(f["text"]) <= 2000 for f in msg["blocks"][1]["fields"])


@pytest.mark.anyio
async def test_send_posts_block_kit_json_to_webhook(slack):
    rid = str(uuid.uuid4())
    sent = await slack_service.send_approval_message(rid, details(), settings=settings(slack_webhook_url=WEBHOOK))
    assert sent is True
    (request,) = slack["requests"]
    assert request.method == "POST" and str(request.url) == WEBHOOK
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == slack_service.approval_message(rid, details())


@pytest.mark.anyio
async def test_without_webhook_nothing_is_sent(slack, caplog):
    rid = str(uuid.uuid4())
    assert await slack_service.send_approval_message(rid, details(), settings=settings()) is False
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
        await slack_service.send_approval_message("r", details(), settings=settings(slack_webhook_url=WEBHOOK))
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
