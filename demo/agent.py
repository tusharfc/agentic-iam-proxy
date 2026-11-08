"""The on-camera agent: a real LangChain + OpenAI agent that handles a refund request.

It only holds an Agentic IAM agent token. Every Stripe call goes through the local proxy,
which injects the real key and pauses the refund until someone clicks Approve in Slack.

    GEMINI_API_KEY=... .venv-demo/bin/python demo/agent.py    # or OPENAI_API_KEY=...
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from urllib.parse import parse_qsl

DEMO_ENV = Path(__file__).with_name(".demo.env")
if not DEMO_ENV.exists():
    sys.exit("Run demo/setup_demo.py first.")
for line in DEMO_ENV.read_text().splitlines():
    key, _, value = line.partition("=")
    os.environ.setdefault(key, value)
if os.environ.get("AGENT_MODEL"):
    MODEL = os.environ["AGENT_MODEL"]
elif os.environ.get("OPENAI_API_KEY"):
    MODEL = "openai:gpt-4o-mini"
elif os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
    MODEL = "google_genai:gemini-3.5-flash"
else:
    sys.exit("Set GEMINI_API_KEY (or OPENAI_API_KEY) for the agent's LLM.")

from langchain.agents import create_agent  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from langchain_agentic_iam import SecureAPIWrapper  # noqa: E402

DIM, BOLD, CYAN, YELLOW, GREEN, RED, RESET = "\033[2m", "\033[1m", "\033[36m", "\033[33m", "\033[32m", "\033[31m", "\033[0m"
STRIPE_API = "https://api.stripe.com"

stripe = SecureAPIWrapper(agent_token=os.environ["AGENTIC_IAM_AGENT_TOKEN"])


def _call(method: str, path: str, data: dict | None = None) -> str:
    if not path.startswith("/"):
        return "Error: path must start with '/'"
    print(f"{CYAN}🤖 agent → {method} api.stripe.com{path}{RESET}", flush=True)
    if method == "POST" and path.startswith("/v1/refunds"):
        print(f"{YELLOW}⏸  paused by Agentic IAM Proxy: waiting for human approval in Slack…{RESET}", flush=True)
    started = time.monotonic()
    body = stripe.post(STRIPE_API + path, data=data) if method == "POST" else stripe.get(STRIPE_API + path)
    denied = "denied" in body.lower() or "timed out" in body.lower()
    colour = RED if denied else GREEN
    print(f"{colour}   ← {body[:110]}{'…' if len(body) > 110 else ''}{RESET} {DIM}({time.monotonic() - started:.1f}s){RESET}", flush=True)
    return body


@tool
def stripe_get(path: str) -> str:
    """Read from the Stripe API. `path` includes the query string, e.g. /v1/charges?customer=cus_123&limit=3."""
    return _call("GET", path)


@tool
def stripe_post(path: str, params: str) -> str:
    """Create a Stripe object. `params` is form-encoded, e.g. path=/v1/refunds, params="charge=ch_123"."""
    return _call("POST", path, dict(parse_qsl(params)))


agent = create_agent(
    model=MODEL,
    tools=[stripe_get, stripe_post],
    system_prompt=(
        "You are a billing support agent with Stripe API access. Look up charges before acting. "
        "If an action is denied or not approved, say so plainly and do not retry."
    ),
)

if __name__ == "__main__":
    customer = os.environ["DEMO_CUSTOMER_ID"]
    task = f"Customer {customer} says they were double-charged for their $49.99 Pro plan. Refund their most recent charge."
    print(f"{BOLD}📨 Support ticket:{RESET} {task}")
    print(f"{DIM}   agent credentials: Agentic IAM token only (no Stripe key){RESET}\n")
    result = agent.invoke({"messages": [{"role": "user", "content": task}]})
    print(f"\n{BOLD}✅ Agent:{RESET} {result['messages'][-1].content}")
