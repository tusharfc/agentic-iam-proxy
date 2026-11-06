"""CrewAI billing crew that refunds Stripe charges without ever holding a Stripe key.

The agent's tools call the real Stripe API endpoints. SecureCrewAITool routes them through
Agentic IAM Proxy, which authenticates the agent token, applies your tenant policies
(e.g. "refunds require approval"), asks a human in Slack, and injects the real Stripe key.

Setup:
    pip install crewai-agentic-iam
    export AGENTIC_IAM_AGENT_TOKEN=...   # from POST /api/v1/manage/agents
    export OPENAI_API_KEY=...            # the LLM's key; Stripe's lives only in the proxy vault
    python examples/crewai_stripe.py cus_123
"""
from __future__ import annotations

import os
import sys

from crewai import LLM, Agent, Crew, Task

from crewai_agentic_iam import SecureAPIWrapper, SecureCrewAITool

proxy = SecureAPIWrapper(
    proxy_base_url=os.environ.get("AGENTIC_IAM_PROXY_URL", "http://localhost:8000/api/v1/proxy"),
    agent_token=os.environ["AGENTIC_IAM_AGENT_TOKEN"],
)

list_charges = SecureCrewAITool(
    name="List Stripe charges",
    description="Lists a customer's charges, newest first. params: customer (required), limit (optional).",
    wrapper=proxy,
    endpoint="https://api.stripe.com/v1/charges",
    method="GET",
)

refund_charge = SecureCrewAITool(
    name="Refund a Stripe charge",
    description="Refunds a charge. params: charge (required, e.g. ch_123), amount in cents (optional, default full).",
    wrapper=proxy,
    endpoint="https://api.stripe.com/v1/refunds",
    method="POST",
)

billing_specialist = Agent(
    role="Billing Specialist",
    goal="Resolve customer billing requests accurately using the Stripe API.",
    backstory="You handle refunds for a SaaS company. You always look up a charge before refunding it.",
    tools=[list_charges, refund_charge],
    llm=LLM(model=os.environ.get("AGENT_MODEL", "gpt-4o-mini")),
    verbose=True,
)

refund_task = Task(
    description=(
        "Customer {customer_id} was double-charged. Find their most recent charge and refund it in full. "
        "If the refund is denied or not approved, report that instead of retrying."
    ),
    expected_output="The refunded charge ID and refund ID, or the reason the refund did not happen.",
    agent=billing_specialist,
)

# Traces can contain prompts and API responses (customer data); keep them off unless you opt in.
crew = Crew(agents=[billing_specialist], tasks=[refund_task], tracing=False)


if __name__ == "__main__":
    customer_id = sys.argv[1] if len(sys.argv) > 1 else "cus_123"
    print(crew.kickoff(inputs={"customer_id": customer_id}))
