# crewai-agentic-iam

Route your CrewAI agents' HTTP calls through [Agentic IAM Proxy](https://github.com/tusharfc/agentic-iam-proxy). Your agents never hold a real API key, and risky calls wait for a human to approve them in Slack.

```bash
pip install crewai-agentic-iam
```

```python
from crewai_agentic_iam import SecureAPIWrapper, SecureCrewAITool

proxy = SecureAPIWrapper(agent_token="...")  # proxy_base_url defaults to http://localhost:8000/api/v1/proxy

refund_charge = SecureCrewAITool(
    name="Refund a Stripe charge",
    description="Refunds a charge. params: charge (required), amount in cents (optional).",
    wrapper=proxy,
    endpoint="https://api.stripe.com/v1/refunds",
    method="POST",
)

get_customer = SecureCrewAITool(
    name="Get a Stripe customer",
    description="Fetches one customer. path_params: customer_id.",
    wrapper=proxy,
    endpoint="https://api.stripe.com/v1/customers/{customer_id}",
)
```

Give the tools to a CrewAI `Agent` as usual. Each tool is pinned to one method and endpoint. The agent only fills in `path_params` (the `{placeholders}`, URL-escaped so they can't change the path or host) and `params` (query string for GET/DELETE, a form body for POST/PUT/PATCH, or JSON with `body_format="json"`).

`SecureAPIWrapper` can also be used directly: `get`, `post`, `put`, `patch` and `delete` take the usual `requests` arguments and return the response text, including denials such as "Action denied by human overseer".

See [`examples/crewai_stripe.py`](examples/crewai_stripe.py) for a complete crew.

Licensed under Apache-2.0.
