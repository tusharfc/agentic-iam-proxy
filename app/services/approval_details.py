from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ApprovalDetails:
    """What an approver needs to judge a paused request. All text is agent- or tenant-controlled."""

    method: str
    target_url: str
    tenant_id: str
    service: Optional[str] = None
    tenant_name: Optional[str] = None
    agent_name: Optional[str] = None
    policy_name: Optional[str] = None
    expires_in_seconds: int = 300

    @property
    def endpoint(self) -> str:
        parts = urlsplit(self.target_url)
        return f"{parts.netloc}{parts.path or '/'}"
