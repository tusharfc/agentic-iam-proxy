from __future__ import annotations

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit

import regex
from fastapi import Depends
from supabase import AsyncClient

from app.services.supabase_client import get_supabase

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


class PolicyService:
    def __init__(self, supabase: AsyncClient) -> None:
        self._supabase = supabase

    async def evaluate_request(self, tenant_id: str, method: str, target_url: str) -> str:
        """Returns 'allow', 'deny' or 'requires_approval' for the first matching rule; 'allow' if none match.

        Fails closed: a broken or runaway pattern on the evaluation path yields 'deny'.
        """
        rules = await self._rules(tenant_id)
        if not rules:
            return DEFAULT_ACTION
        subject = policy_subject(target_url)
        if len(subject) > MAX_SUBJECT_CHARS:
            return DENY
        method = method.upper()
        for rule in rules:
            if rule["method"] not in ("*", method):
                continue
            try:
                matched = regex.search(rule["url_pattern"], subject, timeout=MATCH_TIMEOUT_SECONDS) is not None
            except (regex.error, TimeoutError) as exc:
                log.error("Policy %s (%r) for tenant %s failed to evaluate: %s; denying",
                          rule.get("id"), rule.get("name"), tenant_id, exc)
                return DENY
            if matched:
                action = rule["action"]
                if action not in ACTIONS:
                    log.error("Policy %s for tenant %s has unknown action %r; denying", rule.get("id"), tenant_id, action)
                    return DENY
                return action
        return DEFAULT_ACTION

    async def _rules(self, tenant_id: str) -> List[Dict[str, Any]]:
        result = await (
            self._supabase.table("tenant_policies")
            .select("id, name, priority, method, url_pattern, action")
            .eq("tenant_id", tenant_id)
            .order("priority")
            .execute()
        )
        rules = [dict(r, method=str(r["method"]).upper()) for r in result.data or []]
        rules.sort(key=lambda r: (r["priority"], _STRICTNESS.get(r["action"], -1), str(r.get("id"))))
        return rules


def get_policy_service(supabase: AsyncClient = Depends(get_supabase)) -> PolicyService:
    return PolicyService(supabase)
