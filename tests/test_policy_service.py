from __future__ import annotations

import pytest

from app.services import policy_service
from app.services.policy_service import PolicyService, policy_subject

TENANT = "5f0c7c1e-2b55-4c2a-9a59-6d3f4b0f1a11"
OTHER = "9d1b2c3e-4f50-4a61-8b72-c3d4e5f60718"


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakePolicyTable:
    """Stand-in for Database.policies(): the tenant's rows, ordered by priority."""

    def __init__(self, rows) -> None:
        self.rows = rows
        self.queries = []

    async def policies(self, tenant_id):
        self.queries.append(tenant_id)
        return sorted((r for r in self.rows if r["tenant_id"] == tenant_id), key=lambda r: r["priority"])


def rule(pattern, action, priority=100, method="*", tenant=TENANT, rid=None):
    return {"id": rid or f"{priority}-{action}", "tenant_id": tenant, "name": f"{action} {pattern}",
            "priority": priority, "method": method, "url_pattern": pattern, "action": action}


async def evaluate(rules, method="POST", url="https://api.stripe.com/v1/refunds"):
    return await PolicyService(FakePolicyTable(rules)).evaluate_request(TENANT, method, url)


@pytest.mark.anyio
async def test_no_rules_allows():
    assert await evaluate([]) == "allow"


@pytest.mark.anyio
async def test_no_matching_rule_allows():
    assert await evaluate([rule(r"github\.com", "deny")]) == "allow"


@pytest.mark.anyio
async def test_queries_own_tenant_ordered_by_priority():
    table = FakePolicyTable([])
    await PolicyService(table).evaluate_request(TENANT, "GET", "https://api.stripe.com/")
    assert table.queries == [TENANT]


@pytest.mark.anyio
async def test_other_tenants_rules_ignored():
    assert await evaluate([rule("refunds", "deny", tenant=OTHER)]) == "allow"


@pytest.mark.anyio
async def test_lowest_priority_number_wins():
    rules = [rule("refunds", "deny", priority=20), rule(r".*stripe\.com/v1/refunds.*", "requires_approval", priority=10)]
    assert await evaluate(rules) == "requires_approval"


@pytest.mark.anyio
async def test_allow_rule_can_exempt_before_broader_rule():
    rules = [rule(r"/v1/refunds/re_safe$", "allow", priority=1), rule("refunds", "deny", priority=2)]
    assert await evaluate(rules, url="https://api.stripe.com/v1/refunds/re_safe") == "allow"
    assert await evaluate(rules, url="https://api.stripe.com/v1/refunds/re_other") == "deny"


@pytest.mark.anyio
async def test_equal_priority_stricter_action_wins():
    rules = [rule("refunds", "allow", priority=5), rule("refunds", "requires_approval", priority=5), rule("refunds", "deny", priority=5)]
    assert await evaluate(rules) == "deny"


@pytest.mark.anyio
@pytest.mark.parametrize("rule_method, request_method, expected", [
    ("*", "DELETE", "deny"),
    ("DELETE", "DELETE", "deny"),
    ("DELETE", "delete", "deny"),
    ("delete", "DELETE", "deny"),
    ("POST", "DELETE", "allow"),
])
async def test_method_matching(rule_method, request_method, expected):
    assert await evaluate([rule(".", "deny", method=rule_method)], method=request_method) == expected


@pytest.mark.anyio
@pytest.mark.parametrize("url", [
    "https://api.stripe.com/v1/re%66unds",
    "https://api.stripe.com/v1/%72%65%66%75%6E%64%73",
    "https://api.stripe.com/v1/charges/%2e%2e/refunds",
    "https://api.stripe.com/v1/charges/%2E%2E/./refunds",
    "https://API.STRIPE.COM/v1/refunds",
])
async def test_encoding_tricks_cannot_dodge_rules(url):
    assert await evaluate([rule(r"^https://api\.stripe\.com/v1/refunds$", "deny")], url=url) == "deny"


@pytest.mark.anyio
async def test_query_string_cannot_trigger_or_dodge_rules():
    # An allow rule for charges must not be satisfiable by appending it to a refund URL's query.
    rules = [rule(r"/v1/charges", "allow", priority=1), rule(r"/v1/refunds", "deny", priority=2)]
    assert await evaluate(rules, url="https://api.stripe.com/v1/refunds?x=/v1/charges") == "deny"
    assert await evaluate([rule("refunds", "deny")], url="https://api.stripe.com/v1/charges?note=refunds") == "allow"


@pytest.mark.anyio
async def test_invalid_pattern_fails_closed():
    rules = [rule("(unclosed", "allow", priority=1), rule("refunds", "allow", priority=2)]
    assert await evaluate(rules) == "deny"


@pytest.mark.anyio
async def test_pattern_after_a_match_is_not_evaluated():
    assert await evaluate([rule("refunds", "allow", priority=1), rule("(unclosed", "deny", priority=2)]) == "allow"


@pytest.mark.anyio
async def test_regex_timeout_fails_closed(monkeypatch):
    def slow(*args, **kwargs):
        assert kwargs["timeout"] == policy_service.MATCH_TIMEOUT_SECONDS
        raise TimeoutError("regex timed out")

    monkeypatch.setattr(policy_service.regex, "search", slow)
    assert await evaluate([rule("refunds", "allow")]) == "deny"


@pytest.mark.anyio
async def test_unknown_action_fails_closed():
    assert await evaluate([rule("refunds", "maybe")]) == "deny"


@pytest.mark.anyio
async def test_oversized_url_denied_only_when_rules_exist():
    url = "https://api.stripe.com/" + "a" * 5000
    assert await evaluate([rule("zzz", "deny")], url=url) == "deny"
    assert await evaluate([], url=url) == "allow"


@pytest.mark.parametrize("url, subject", [
    ("https://api.stripe.com/v1/refunds?limit=3#frag", "https://api.stripe.com/v1/refunds"),
    ("https://api.stripe.com", "https://api.stripe.com/"),
    ("https://api.stripe.com/a/b/../../..", "https://api.stripe.com/"),
    ("https://api.stripe.com/files/a%2Fb", "https://api.stripe.com/files/a%2Fb"),
])
def test_policy_subject(url, subject):
    assert policy_subject(url) == subject
