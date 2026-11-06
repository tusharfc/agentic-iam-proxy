from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

import requests
from pydantic import BaseModel, ConfigDict, PrivateAttr, SecretStr

TARGET_HEADER = "X-Target-Url"


class SecureAPIWrapper(BaseModel):
    """HTTP client that sends every call through Agentic IAM Proxy.

    Call real API URLs (``https://api.stripe.com/v1/refunds``); the proxy authenticates the
    agent token, applies tenant policies, may pause for human approval, and swaps in the real
    API key. Methods follow ``requests`` semantics and return the response text, including
    error bodies such as "Action denied by human overseer".
    """

    model_config = ConfigDict(frozen=True)

    proxy_base_url: str = "http://localhost:8000/api/v1/proxy"
    agent_token: SecretStr
    # Must exceed the proxy's HITL_TIMEOUT_SECONDS (300 by default) or approvals get cut off.
    timeout: float = 330.0

    _session: Optional[requests.Session] = PrivateAttr(default=None)

    def get(self, url: str, **kwargs: Any) -> str:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> str:
        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> str:
        return self.request("PUT", url, data=data, json=json, **kwargs)

    def patch(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> str:
        return self.request("PATCH", url, data=data, json=json, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> str:
        return self.request("DELETE", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> str:
        proxy_url, target = self.route(url)
        headers: Dict[str, str] = {
            k: v for k, v in (kwargs.pop("headers", None) or {}).items()
            if k.lower() not in ("authorization", TARGET_HEADER.lower())
        }
        headers[TARGET_HEADER] = target
        headers["Authorization"] = f"Bearer {self.agent_token.get_secret_value()}"
        kwargs.setdefault("timeout", self.timeout)
        # A followed redirect would leave the proxy and hit the target directly.
        kwargs["allow_redirects"] = False
        response = self._client().request(method, proxy_url, headers=headers, **kwargs)
        return response.text

    def route(self, url: str) -> Tuple[str, str]:
        """Splits a downstream URL into (proxy URL with path and query, X-Target-Url origin)."""
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"expected an absolute http(s) URL, got {url!r}")
        if parts.username is not None or parts.password is not None:
            raise ValueError("URLs with embedded credentials are not allowed")
        # The proxy appends the path to X-Target-Url, so the header carries only the origin.
        target = f"{parts.scheme}://{parts.netloc}"
        proxy_url = self.proxy_base_url.rstrip("/") + (parts.path or "/")
        if parts.query:
            proxy_url += "?" + parts.query
        return proxy_url, target

    def _client(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            # Agent traffic must go to the proxy directly, never via HTTP(S)_PROXY env settings.
            self._session.trust_env = False
        return self._session
