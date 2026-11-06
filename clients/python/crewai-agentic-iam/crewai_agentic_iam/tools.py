from __future__ import annotations

from string import Formatter
from typing import Any, Dict, Literal, Type
from urllib.parse import quote, urlsplit

from crewai.tools import BaseTool
from pydantic import BaseModel, Field, model_validator

from crewai_agentic_iam.wrapper import SecureAPIWrapper

_BODY_METHODS = ("POST", "PUT", "PATCH")


class SecureRequestArgs(BaseModel):
    path_params: Dict[str, str] = Field(
        default_factory=dict,
        description="Values for the {placeholders} in the endpoint path, e.g. {\"customer_id\": \"cus_123\"}.",
    )
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Query parameters for GET/DELETE, or request body fields for POST/PUT/PATCH.",
    )


class SecureCrewAITool(BaseTool):
    """A CrewAI tool for one API endpoint, routed through Agentic IAM Proxy.

    The developer fixes the method and endpoint (scheme, host and path template); the agent
    only supplies placeholder values and parameters, so it cannot redirect the call elsewhere.

        SecureCrewAITool(
            name="Refund a Stripe charge",
            description="Refunds a charge. params: charge (required), amount in cents (optional).",
            wrapper=SecureAPIWrapper(agent_token="..."),
            endpoint="https://api.stripe.com/v1/refunds",
            method="POST",
        )
    """

    wrapper: SecureAPIWrapper
    endpoint: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    body_format: Literal["form", "json"] = "form"
    args_schema: Type[BaseModel] = SecureRequestArgs

    @model_validator(mode="after")
    def _check_endpoint(self) -> "SecureCrewAITool":
        fields = self._placeholders()
        if any(not f.isidentifier() for f in fields) or "{}" in self.endpoint:
            raise ValueError("endpoint placeholders must be named, e.g. {customer_id}")
        # Placeholders may only appear in the path: the host must stay fixed.
        parts = urlsplit(self.endpoint.format(**{f: "x" for f in fields}))
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("endpoint must be an absolute http(s) URL")
        if any("{" + f + "}" in urlsplit(self.endpoint).netloc for f in fields):
            raise ValueError("placeholders are only allowed in the endpoint path")
        if parts.query or parts.fragment:
            raise ValueError("endpoint must not contain a query string; pass query values via params")
        return self

    def _placeholders(self) -> list:
        return [field for _, field, _, _ in Formatter().parse(self.endpoint) if field]

    def build_url(self, path_params: Dict[str, Any]) -> str:
        fields = self._placeholders()
        missing = [f for f in fields if f not in path_params]
        unknown = [k for k in path_params if k not in fields]
        if missing or unknown:
            raise ValueError(f"path_params must be exactly {fields}; missing {missing}, unexpected {unknown}")
        values = {}
        for field in fields:
            value = str(path_params[field])
            if value in ("", ".", ".."):
                raise ValueError(f"invalid value for {field}: {value!r}")
            # Escape everything, so '/', '?', '#' or '@' can't change the path or host.
            values[field] = quote(value, safe="")
        return self.endpoint.format(**values)

    def _run(self, path_params: Dict[str, Any] | None = None, params: Dict[str, Any] | None = None, **_: Any) -> str:
        try:
            url = self.build_url(path_params or {})
        except ValueError as exc:
            return f"Error: {exc}"
        params = params or {}
        if self.method not in _BODY_METHODS:
            return self.wrapper.request(self.method, url, params=params)
        if self.body_format == "json":
            return self.wrapper.request(self.method, url, json=params)
        return self.wrapper.request(self.method, url, data=params)
