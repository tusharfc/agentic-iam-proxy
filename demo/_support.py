"""Off-camera helpers for demo/langchain_agent.py: config loading and classic AgentExecutor-style output."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler

DEMO_ENV = Path(__file__).with_name(".demo.env")
if not DEMO_ENV.exists():
    sys.exit("Run demo/setup_demo.py first.")
for _env_file in (DEMO_ENV, Path(__file__).with_name(".keys.env")):
    if _env_file.exists():
        for _line in _env_file.read_text().splitlines():
            _key, _, _value = _line.strip().partition("=")
            if _key and _value and not _key.startswith("#"):
                os.environ.setdefault(_key, _value)

AGENTIC_TOKEN = os.environ["AGENTIC_IAM_AGENT_TOKEN"]
CUSTOMER_ID = os.environ["DEMO_CUSTOMER_ID"]

BOLD, GREEN, CYAN, YELLOW, RED, RESET = "\033[1m", "\033[32m", "\033[36m", "\033[33m", "\033[31m", "\033[0m"


def summarize(body: str) -> str:
    """One readable line per API response, so observations fit on screen."""
    try:
        data = json.loads(body)
    except ValueError:
        return body[:200]
    if isinstance(data, dict) and data.get("object") == "refund":
        return f"200 OK · refund {data['id']} {data['status']} (${data['amount'] / 100:.2f})"
    if isinstance(data, dict) and data.get("object") == "list":
        rows = [f"{c['id']} ${c['amount'] / 100:.2f} {c.get('description') or ''} refunded={c['refunded']}"
                for c in data.get("data", [])]
        return "200 OK · " + ("; ".join(rows) or "no charges")
    if isinstance(data, dict) and "detail" in data:
        return f"Blocked by Agentic IAM Proxy: {data['detail']}"
    if isinstance(data, dict) and "error" in data:
        return f"Stripe error: {data['error'].get('message')}"
    return body[:200]


class ChainPrinter(BaseCallbackHandler):
    """Prints the real AgentExecutor's events in the classic verbose format."""

    def on_chain_start(self, serialized: Any, inputs: Any, *, parent_run_id=None, **kwargs: Any) -> None:
        if parent_run_id is None:
            print(f"\n{BOLD}{GREEN}> Entering new AgentExecutor chain...{RESET}", flush=True)

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        tool_input = json.dumps(action.tool_input) if isinstance(action.tool_input, dict) else action.tool_input
        print(f"{CYAN}Action: {action.tool}{RESET}\n{CYAN}Action Input: {tool_input}{RESET}", flush=True)

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        text = getattr(output, "content", output)
        colour = RED if str(text).startswith(("Blocked", "Stripe error")) else YELLOW
        print(f"{colour}Observation: {text}{RESET}", flush=True)

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        print(f"{GREEN}Final Answer: {finish.return_values.get('output')}{RESET}", flush=True)

    def on_chain_end(self, outputs: Any, *, parent_run_id=None, **kwargs: Any) -> None:
        if parent_run_id is None:
            print(f"\n{BOLD}{GREEN}> Finished chain.{RESET}", flush=True)
