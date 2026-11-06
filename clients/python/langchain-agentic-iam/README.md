# langchain-agentic-iam

Route your LangChain agent's HTTP calls through [Agentic IAM Proxy](https://github.com/tusharfc/agentic-iam-proxy). Your agent never holds a real API key, and risky calls wait for a human to approve them in Slack.

```bash
pip install langchain-agentic-iam
```

```python
from langchain_agentic_iam import SecureAPIWrapper

stripe = SecureAPIWrapper(agent_token="...")  # proxy_base_url defaults to http://localhost:8000/api/v1/proxy
stripe.post("https://api.stripe.com/v1/refunds", data={"charge": "ch_123"})
```

The wrapper sends the URL's origin in `X-Target-Url`, appends its path and query to the proxy URL, and authenticates with the agent token. It returns the response text, including denials such as "Action denied by human overseer". `get`, `post`, `put`, `patch` and `delete` take the usual `requests` arguments (`data=` sends form data, `json=` sends JSON).

See [`examples/langchain_stripe.py`](examples/langchain_stripe.py) for a complete LangChain agent.

Licensed under Apache-2.0.
