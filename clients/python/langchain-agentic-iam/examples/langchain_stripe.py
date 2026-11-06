"""LangChain agent that manages Stripe refunds without ever holding a Stripe key.

The agent calls the real Stripe API URLs. SecureAPIWrapper routes them through
Agentic IAM Proxy, which authenticates the agent token, asks a human in Slack
before refunds, and injects the real Stripe key from its vault.

Setup:
    pip install langchain-agentic-iam langchain langchain-openai
    export AGENTIC_IAM_AGENT_TOKEN=...   # from POST /api/v1/manage/agents
    export OPENAI_API_KEY=...            # the LLM's key; Stripe's lives only in the proxy vault
    python examples/langchain_stripe.py "Refund the most recent charge for customer cus_123"
"""
from __future__ import annotations

import os
import sys

from langchain.agents import create_agent
from langchain_core.tools import tool

from langchain_agentic_iam import SecureAPIWrapper

STRIPE_API = "https://api.stripe.com"
BAD_PATH = "Error: path must start with '/', e.g. /v1/charges"

stripe = SecureAPIWrapper(
    proxy_base_url=os.environ.get("AGENTIC_IAM_PROXY_URL", "http://localhost:8000/api/v1/proxy"),
    agent_token=os.environ["AGENTIC_IAM_AGENT_TOKEN"],
)


def _valid(path: str) -> bool:
    # Keep the model on api.stripe.com: "@evil.example" or ".evil.example" would change the host.
    return path.startswith("/")


@tool
def stripe_get(path: str) -> str:
    """Read from the Stripe API. `path` includes the query string, e.g. /v1/charges?customer=cus_123&limit=3."""
    return stripe.get(STRIPE_API + path) if _valid(path) else BAD_PATH


@tool
def stripe_post(path: str, params: dict[str, str]) -> str:
    """Create or update a Stripe object, e.g. path=/v1/refunds, params={"charge": "ch_123"}.
    Params are sent form-encoded, as Stripe expects."""
    return stripe.post(STRIPE_API + path, data=params) if _valid(path) else BAD_PATH


agent = create_agent(
    model=os.environ.get("AGENT_MODEL", "openai:gpt-4o-mini"),
    tools=[stripe_get, stripe_post],
    system_prompt=(
        "You are a billing assistant with access to the Stripe API. "
        "Look up the relevant objects before changing anything, then report what you did."
    ),
)


def main() -> None:
    task = " ".join(sys.argv[1:]) or "Refund the most recent charge for customer cus_123"
    result = agent.invoke({"messages": [{"role": "user", "content": task}]})
    print(result["messages"][-1].content)


if __name__ == "__main__":
    main()
