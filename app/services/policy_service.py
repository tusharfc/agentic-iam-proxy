from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import regex
from fastapi import Depends

from app.services.database import Database, get_database

log = logging.getLogger(__name__)

ALLOW, DENY, REQUIRES_APPROVAL = "allow", "deny", "requires_approval"
ACTIONS = frozenset({ALLOW, DENY, REQUIRES_APPROVAL})
DEFAULT_ACTION = ALLOW
MATCH_TIMEOUT_SECONDS = 0.05
MAX_SUBJECT_CHARS = 4096
# At equal priority the stricter rule wins.
_STRICTNESS = {DENY: 0, REQUIRES_APPROVAL: 1, ALLOW: 2}
_UNRESERVED_ESCAPE = re.compile(r"%(2[DdEe]|3[0-9]|[46][1-9A-Fa-f]|[57][0-9Aa]|5[Ff]|7[Ee])")


def _remove_dot_segments(path: str) -> str:
    out: List[str] = []
    for segment in path.split("/"):
        if segment == "..":
            if len(out) > 1:
                out.pop()
        elif segment != ".":
            out.append(segment)
    result = "/".join(out) + ("/" if path.endswith(("/.", "/..")) else "")
    return result if result.startswith("/") else "/" + result


def policy_subject(target_url: str) -> str:
    """scheme://host/path the downstream API will act on, with escapes like %66 ('f') decoded.

    The query string is excluded so an agent can't append text to dodge or trigger a rule.
    """
    parts = urlsplit(target_url)
    path = _UNRESERVED_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), parts.path or "/")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{_remove_dot_segments(path)}"


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    rule_name: Optional[str] = None


class PolicyService:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def evaluate_request(self, tenant_id: str, method: str, target_url: str) -> str:
        """Returns 'allow', 'deny' or 'requires_approval' for the first matching rule; 'allow' if none match."""
        return (await self.match_request(tenant_id, method, target_url)).action

    async def match_request(self, tenant_id: str, method: str, target_url: str) -> PolicyDecision:
        """Like evaluate_request, plus the name of the deciding rule (shown to approvers).

        Fails closed: a broken or runaway pattern on the evaluation path yields 'deny'.
        """
        rules = await self._rules(tenant_id)
        if not rules:
            return PolicyDecision(DEFAULT_ACTION)
        subject = policy_subject(target_url)
        if len(subject) > MAX_SUBJECT_CHARS:
            return PolicyDecision(DENY, "URL too long to evaluate")
        method = method.upper()
        for rule in rules:
            if rule["method"] not in ("*", method):
                continue
            try:
                matched = regex.search(rule["url_pattern"], subject, timeout=MATCH_TIMEOUT_SECONDS) is not None
            except (regex.error, TimeoutError) as exc:
                log.error("Policy %s (%r) for tenant %s failed to evaluate: %s; denying",
                          rule.get("id"), rule.get("name"), tenant_id, exc)
                return PolicyDecision(DENY, rule.get("name"))
            if matched:
                action = rule["action"]
                if action not in ACTIONS:
                    log.error("Policy %s for tenant %s has unknown action %r; denying", rule.get("id"), tenant_id, action)
                    return PolicyDecision(DENY, rule.get("name"))
                return PolicyDecision(action, rule.get("name"))
        return PolicyDecision(DEFAULT_ACTION)

    async def _rules(self, tenant_id: str) -> List[Dict[str, Any]]:
        rules = [dict(r, method=str(r["method"]).upper()) for r in await self._db.policies(tenant_id)]
        rules.sort(key=lambda r: (r["priority"], _STRICTNESS.get(r["action"], -1), str(r.get("id"))))
        return rules


def get_policy_service(db: Database = Depends(get_database)) -> PolicyService:
    return PolicyService(db)
