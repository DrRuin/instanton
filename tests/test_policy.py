"""Tests for the traffic policy engine."""

from __future__ import annotations

import pytest

from instanton.policy.actions import (
    ActionType,
    AllowAction,
    CircuitBreakerAction,
    DelayAction,
    DenyAction,
    HeaderAction,
    LogAction,
    RateLimitAction,
    RedirectAction,
    RewriteAction,
    TagAction,
)
from instanton.policy.engine import (
    PolicyEngine,
    create_ip_restriction_policy,
    create_rate_limit_policy,
)
from instanton.policy.rules import (
    ConditionOperator,
    MatchField,
    PolicyRule,
    RuleCondition,
    RuleSet,
    ip_allowlist_rule,
    ip_denylist_rule,
    method_restrict_rule,
)


class TestRuleCondition:
    """Tests for RuleCondition."""

    def test_equals_operator(self):
        """Test equals operator."""
        condition = RuleCondition(
            field=MatchField.METHOD,
            operator=ConditionOperator.EQUALS,
            value="GET",
        )
        context = {"req": {"method": "GET"}}
        assert condition.matches(context)

        context = {"req": {"method": "POST"}}
        assert not condition.matches(context)

    def test_not_equals_operator(self):
        """Test not equals operator."""
        condition = RuleCondition(
            field=MatchField.METHOD,
            operator=ConditionOperator.NOT_EQUALS,
            value="GET",
        )
        context = {"req": {"method": "POST"}}
        assert condition.matches(context)

    def test_contains_operator(self):
        """Test contains operator."""
        condition = RuleCondition(
            field=MatchField.PATH,
            operator=ConditionOperator.CONTAINS,
            value="api",
        )
        context = {"req": {"path": "/api/users"}}
        assert condition.matches(context)

        context = {"req": {"path": "/web/page"}}
        assert not condition.matches(context)

    def test_starts_with_operator(self):
        """Test starts_with operator."""
        condition = RuleCondition(
            field=MatchField.PATH,
            operator=ConditionOperator.STARTS_WITH,
            value="/api",
        )
        context = {"req": {"path": "/api/users"}}
        assert condition.matches(context)

        context = {"req": {"path": "/web/api"}}
        assert not condition.matches(context)

    def test_matches_operator(self):
        """Test regex matches operator."""
        condition = RuleCondition(
            field=MatchField.PATH,
            operator=ConditionOperator.MATCHES,
            value=r"/api/v\d+/.*",
        )
        context = {"req": {"path": "/api/v2/users"}}
        assert condition.matches(context)

        context = {"req": {"path": "/api/users"}}
        assert not condition.matches(context)

    def test_in_operator(self):
        """Test in operator."""
        condition = RuleCondition(
            field=MatchField.METHOD,
            operator=ConditionOperator.IN,
            value=["GET", "POST"],
        )
        context = {"req": {"method": "GET"}}
        assert condition.matches(context)

        context = {"req": {"method": "DELETE"}}
        assert not condition.matches(context)

    def test_exists_operator(self):
        """Test exists operator."""
        condition = RuleCondition(
            field=MatchField.HEADER,
            param="Authorization",
            operator=ConditionOperator.EXISTS,
        )
        context = {"req": {"headers": {"Authorization": "Bearer token"}}}
        assert condition.matches(context)

        context = {"req": {"headers": {}}}
        assert not condition.matches(context)

    def test_ip_in_cidr_operator(self):
        """Test IP CIDR matching."""
        condition = RuleCondition(
            field=MatchField.CLIENT_IP,
            operator=ConditionOperator.IP_IN_CIDR,
            value="192.168.1.0/24",
        )
        context = {"client": {"ip": "192.168.1.100"}}
        assert condition.matches(context)

        context = {"client": {"ip": "10.0.0.1"}}
        assert not condition.matches(context)

    def test_ip_in_cidr_list(self):
        """Test IP CIDR matching with list."""
        condition = RuleCondition(
            field=MatchField.CLIENT_IP,
            operator=ConditionOperator.IP_IN_CIDR,
            value=["192.168.1.0/24", "10.0.0.0/8"],
        )
        context = {"client": {"ip": "192.168.1.100"}}
        assert condition.matches(context)

        context = {"client": {"ip": "10.0.0.1"}}
        assert condition.matches(context)

        context = {"client": {"ip": "172.16.0.1"}}
        assert not condition.matches(context)

    def test_numeric_comparisons(self):
        """Test numeric comparison operators."""
        condition = RuleCondition(
            field=MatchField.CONTENT_LENGTH,
            operator=ConditionOperator.GREATER_THAN,
            value=1000,
        )
        context = {"req": {"content_length": 2000}}
        assert condition.matches(context)

        context = {"req": {"content_length": 500}}
        assert not condition.matches(context)

    def test_header_with_param(self):
        """Test header matching with param."""
        condition = RuleCondition(
            field=MatchField.HEADER,
            param="Content-Type",
            operator=ConditionOperator.CONTAINS,
            value="json",
        )
        context = {"req": {"headers": {"Content-Type": "application/json"}}}
        assert condition.matches(context)

        context = {"req": {"headers": {"Content-Type": "text/html"}}}
        assert not condition.matches(context)


class TestPolicyRule:
    """Tests for PolicyRule."""

    def test_empty_conditions_matches_all(self):
        """Test rule with no conditions matches everything."""
        rule = PolicyRule(
            id="test",
            name="Test Rule",
            conditions=[],
            actions=["allow"],
        )
        context = {"req": {"method": "GET", "path": "/"}}
        assert rule.matches(context)

    def test_disabled_rule_never_matches(self):
        """Test disabled rule never matches."""
        rule = PolicyRule(
            id="test",
            name="Test Rule",
            enabled=False,
            conditions=[],
            actions=["allow"],
        )
        context = {"req": {"method": "GET"}}
        assert not rule.matches(context)

    def test_match_all_conditions(self):
        """Test rule with match_all=True (AND)."""
        rule = PolicyRule(
            id="test",
            name="Test Rule",
            match_all=True,
            conditions=[
                RuleCondition(
                    field=MatchField.METHOD, operator=ConditionOperator.EQUALS, value="GET"
                ),
                RuleCondition(
                    field=MatchField.PATH, operator=ConditionOperator.STARTS_WITH, value="/api"
                ),
            ],
            actions=["allow"],
        )

        # Both match
        context = {"req": {"method": "GET", "path": "/api/users"}}
        assert rule.matches(context)

        # Only one matches
        context = {"req": {"method": "POST", "path": "/api/users"}}
        assert not rule.matches(context)

    def test_match_any_condition(self):
        """Test rule with match_all=False (OR)."""
        rule = PolicyRule(
            id="test",
            name="Test Rule",
            match_all=False,
            conditions=[
                RuleCondition(
                    field=MatchField.METHOD, operator=ConditionOperator.EQUALS, value="GET"
                ),
                RuleCondition(
                    field=MatchField.METHOD, operator=ConditionOperator.EQUALS, value="POST"
                ),
            ],
            actions=["allow"],
        )

        context = {"req": {"method": "GET"}}
        assert rule.matches(context)

        context = {"req": {"method": "POST"}}
        assert rule.matches(context)

        context = {"req": {"method": "DELETE"}}
        assert not rule.matches(context)


class TestRuleSet:
    """Tests for RuleSet."""

    def test_get_matching_rules(self):
        """Test getting matching rules sorted by priority."""
        rule_set = RuleSet(
            id="test",
            name="Test Set",
            rules=[
                PolicyRule(
                    id="low", name="Low Priority", priority=10, conditions=[], actions=["a"]
                ),
                PolicyRule(
                    id="high", name="High Priority", priority=0, conditions=[], actions=["b"]
                ),
                PolicyRule(
                    id="mid", name="Mid Priority", priority=5, conditions=[], actions=["c"]
                ),
            ],
        )

        context = {"req": {"method": "GET"}}
        matching = rule_set.get_matching_rules(context)

        assert len(matching) == 3
        assert matching[0].id == "high"
        assert matching[1].id == "mid"
        assert matching[2].id == "low"

    def test_disabled_rule_set(self):
        """Test disabled rule set returns no matches."""
        rule_set = RuleSet(
            id="test",
            name="Test Set",
            enabled=False,
            rules=[PolicyRule(id="test", name="Test", conditions=[], actions=[])],
        )

        context = {"req": {"method": "GET"}}
        assert rule_set.get_matching_rules(context) == []


class TestConvenienceFunctions:
    """Tests for convenience rule creation functions."""

    def test_ip_allowlist_rule(self):
        """Test IP allowlist rule creation."""
        rule = ip_allowlist_rule("test", ["192.168.1.0/24"])
        context = {"client": {"ip": "192.168.1.100"}}
        assert rule.matches(context)

        context = {"client": {"ip": "10.0.0.1"}}
        assert not rule.matches(context)

    def test_ip_denylist_rule(self):
        """Test IP denylist rule creation."""
        rule = ip_denylist_rule("test", ["192.168.1.0/24"])
        context = {"client": {"ip": "192.168.1.100"}}
        assert rule.matches(context)  # Matches the deny condition

    def test_method_restrict_rule(self):
        """Test method restriction rule creation."""
        rule = method_restrict_rule("test", ["GET", "POST"])
        context = {"req": {"method": "DELETE"}}
        assert rule.matches(context)  # Matches because DELETE is NOT in allowed

        context = {"req": {"method": "GET"}}
        assert not rule.matches(context)  # Does NOT match because GET is allowed


class TestAllowAction:
    """Tests for AllowAction."""

    @pytest.mark.asyncio
    async def test_execute(self):
        """Test allow action execution."""
        action = AllowAction(id="test")
        result = await action.execute({})

        assert result.success
        assert result.action_type == ActionType.ALLOW
        assert not result.stop_request


class TestDenyAction:
    """Tests for DenyAction."""

    @pytest.mark.asyncio
    async def test_execute_default(self):
        """Test deny action with defaults."""
        action = DenyAction(id="test")
        result = await action.execute({})

        assert result.success
        assert result.action_type == ActionType.DENY
        assert result.stop_request
        assert result.response_status == 403
        assert b"Access denied" in result.response_body

    @pytest.mark.asyncio
    async def test_execute_custom(self):
        """Test deny action with custom message."""
        action = DenyAction(id="test", status_code=401, message="Unauthorized")
        result = await action.execute({})

        assert result.response_status == 401
        assert b"Unauthorized" in result.response_body


class TestRateLimitAction:
    """Tests for RateLimitAction."""

    @pytest.mark.asyncio
    async def test_under_limit(self):
        """Test rate limit when under limit."""
        action = RateLimitAction(
            id="test",
            requests_per_window=10,
            window_seconds=60,
        )
        context = {"client": {"ip": "192.168.1.1"}}

        result = await action.execute(context)
        assert result.success
        assert not result.stop_request
        assert "X-RateLimit-Limit" in result.response_headers

    @pytest.mark.asyncio
    async def test_over_limit(self):
        """Test rate limit when over limit."""
        action = RateLimitAction(
            id="test",
            requests_per_window=2,
            window_seconds=60,
        )
        context = {"client": {"ip": "192.168.1.2"}}

        # First two requests should succeed
        await action.execute(context)
        await action.execute(context)

        # Third should be rate limited
        result = await action.execute(context)
        assert result.stop_request
        assert result.response_status == 429
        assert "Retry-After" in result.response_headers

    @pytest.mark.asyncio
    async def test_different_keys(self):
        """Test rate limiting with different keys."""
        action = RateLimitAction(
            id="test",
            requests_per_window=1,
            window_seconds=60,
        )

        # Different IPs have separate limits
        await action.execute({"client": {"ip": "192.168.1.3"}})
        result = await action.execute({"client": {"ip": "192.168.1.4"}})

        assert not result.stop_request  # Different key, not limited


class TestHeaderAction:
    """Tests for HeaderAction."""

    @pytest.mark.asyncio
    async def test_add_header(self):
        """Test adding a header."""
        action = HeaderAction(
            id="test",
            target="request",
            header_name="X-Custom",
            header_value="value",
        )
        context = {"req": {"headers": {}}}

        result = await action.execute(context)
        assert result.modified_request["headers"]["X-Custom"] == "value"

    @pytest.mark.asyncio
    async def test_remove_header(self):
        """Test removing a header."""
        action = HeaderAction(
            id="test",
            target="request",
            header_name="X-Remove",
            header_value=None,
        )
        context = {"req": {"headers": {"X-Remove": "value", "X-Keep": "keep"}}}

        result = await action.execute(context)
        assert "X-Remove" not in result.modified_request["headers"]
        assert result.modified_request["headers"]["X-Keep"] == "keep"


class TestRewriteAction:
    """Tests for RewriteAction."""

    @pytest.mark.asyncio
    async def test_rewrite_path(self):
        """Test path rewriting."""
        action = RewriteAction(
            id="test",
            pattern=r"/api/v1/(.*)",
            replacement=r"/api/v2/\1",
            target="path",
        )
        context = {"req": {"path": "/api/v1/users"}}

        result = await action.execute(context)
        assert result.modified_request["path"] == "/api/v2/users"

    @pytest.mark.asyncio
    async def test_rewrite_host(self):
        """Test host rewriting."""
        action = RewriteAction(
            id="test",
            type=ActionType.REWRITE_HOST,
            pattern=r"(.*)\.example\.com",
            replacement=r"\1.internal.com",
            target="host",
        )
        context = {"req": {"host": "api.example.com"}}

        result = await action.execute(context)
        assert result.modified_request["host"] == "api.internal.com"


class TestRedirectAction:
    """Tests for RedirectAction."""

    @pytest.mark.asyncio
    async def test_redirect(self):
        """Test basic redirect."""
        action = RedirectAction(
            id="test",
            target_url="https://example.com",
            status_code=301,
        )
        context = {"req": {"path": "/old-path", "query": ""}}

        result = await action.execute(context)
        assert result.stop_request
        assert result.response_status == 301
        assert result.response_headers["Location"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_redirect_preserve_path(self):
        """Test redirect with path preservation."""
        action = RedirectAction(
            id="test",
            target_url="https://example.com",
            preserve_path=True,
        )
        context = {"req": {"path": "/some/path", "query": ""}}

        result = await action.execute(context)
        assert result.response_headers["Location"] == "https://example.com/some/path"

    @pytest.mark.asyncio
    async def test_redirect_preserve_query(self):
        """Test redirect with query preservation."""
        action = RedirectAction(
            id="test",
            target_url="https://example.com",
            preserve_query=True,
        )
        context = {"req": {"path": "/path", "query": "foo=bar"}}

        result = await action.execute(context)
        assert "foo=bar" in result.response_headers["Location"]


class TestCircuitBreakerAction:
    """Tests for CircuitBreakerAction."""

    @pytest.mark.asyncio
    async def test_closed_circuit(self):
        """Test circuit breaker in closed state."""
        action = CircuitBreakerAction(
            id="test",
            failure_threshold=3,
            timeout_seconds=30,
        )
        context = {"conn": {"subdomain": "test"}}

        result = await action.execute(context)
        assert not result.stop_request

    @pytest.mark.asyncio
    async def test_open_circuit(self):
        """Test circuit breaker opens after failures."""
        action = CircuitBreakerAction(
            id="test",
            failure_threshold=2,
            timeout_seconds=30,
        )
        context = {"conn": {"subdomain": "test2"}}

        # Record failures
        await action.record_failure("test2")
        await action.record_failure("test2")

        # Circuit should be open
        result = await action.execute(context)
        assert result.stop_request
        assert result.response_status == 503


class TestDelayAction:
    """Tests for DelayAction."""

    @pytest.mark.asyncio
    async def test_delay(self):
        """Test delay action."""
        import time

        action = DelayAction(id="test", delay_ms=50, jitter_ms=0)

        start = time.time()
        await action.execute({})
        elapsed = (time.time() - start) * 1000

        assert elapsed >= 45  # Allow some variance


class TestLogAction:
    """Tests for LogAction."""

    @pytest.mark.asyncio
    async def test_log(self):
        """Test log action."""
        action = LogAction(
            id="test",
            message="Test log message",
            include_headers=True,
        )
        context = {
            "req": {"method": "GET", "path": "/api", "headers": {"X-Test": "value"}},
            "client": {"ip": "1.2.3.4"},
        }

        result = await action.execute(context)
        assert result.log_message is not None
        assert "Test log message" in result.log_message
        assert "GET" in result.log_message


class TestTagAction:
    """Tests for TagAction."""

    @pytest.mark.asyncio
    async def test_tag(self):
        """Test tag action."""
        action = TagAction(id="test", tags=["api", "authenticated"])

        result = await action.execute({})
        assert "api" in result.tags
        assert "authenticated" in result.tags


class TestPolicyEngine:
    """Tests for PolicyEngine."""

    @pytest.fixture
    def engine(self):
        engine = PolicyEngine()
        engine.add_action(AllowAction(id="allow"))
        engine.add_action(DenyAction(id="deny"))
        return engine

    @pytest.mark.asyncio
    async def test_no_rules_allows(self, engine):
        """Test that no rules defaults to allow."""
        context = {"req": {"method": "GET", "path": "/"}}
        result = await engine.evaluate(context)

        assert result.allowed

    @pytest.mark.asyncio
    async def test_rule_match_and_action(self, engine):
        """Test rule matching and action execution."""
        rule_set = RuleSet(
            id="test",
            name="Test",
            rules=[
                PolicyRule(
                    id="block_delete",
                    name="Block DELETE",
                    conditions=[
                        RuleCondition(
                            field=MatchField.METHOD,
                            operator=ConditionOperator.EQUALS,
                            value="DELETE",
                        )
                    ],
                    actions=["deny"],
                )
            ],
        )
        engine.add_rule_set(rule_set)

        # GET should be allowed
        context = {"req": {"method": "GET", "path": "/"}}
        result = await engine.evaluate(context)
        assert result.allowed

        # DELETE should be denied
        context = {"req": {"method": "DELETE", "path": "/"}}
        result = await engine.evaluate(context)
        assert not result.allowed
        assert result.response_status == 403

    @pytest.mark.asyncio
    async def test_rule_priority(self, engine):
        """Test that rules are evaluated by priority."""
        rule_set = RuleSet(
            id="test",
            name="Test",
            rules=[
                PolicyRule(
                    id="allow_all", name="Allow All", priority=10, conditions=[], actions=["allow"]
                ),
                PolicyRule(
                    id="deny_all", name="Deny All", priority=0, conditions=[], actions=["deny"]
                ),
            ],
        )
        engine.add_rule_set(rule_set)

        context = {"req": {"method": "GET", "path": "/"}}
        result = await engine.evaluate(context)

        # Higher priority deny should win
        assert not result.allowed
        assert "deny_all" in result.matched_rules[0]

    @pytest.mark.asyncio
    async def test_disabled_engine(self, engine):
        """Test that disabled engine allows all."""
        engine.enabled = False
        engine.add_rule_set(
            RuleSet(
                id="test",
                name="Test",
                rules=[PolicyRule(id="deny", name="Deny", conditions=[], actions=["deny"])],
            )
        )

        context = {"req": {"method": "GET", "path": "/"}}
        result = await engine.evaluate(context)

        assert result.allowed

    @pytest.mark.asyncio
    async def test_stats(self, engine):
        """Test statistics tracking."""
        engine.add_rule_set(
            RuleSet(
                id="test",
                name="Test",
                rules=[PolicyRule(id="allow", name="Allow", conditions=[], actions=["allow"])],
            )
        )

        for _ in range(5):
            await engine.evaluate({"req": {"method": "GET", "path": "/"}})

        stats = engine.get_stats()
        assert stats["total_evaluations"] == 5
        assert stats["requests_allowed"] == 5


class TestConveniencePolicyFunctions:
    """Tests for convenience policy creation functions."""

    @pytest.mark.asyncio
    async def test_ip_restriction_policy(self):
        """Test IP restriction policy creation."""
        engine = PolicyEngine()
        engine.add_action(AllowAction(id="allow"))
        engine.add_action(DenyAction(id="deny"))

        policy = create_ip_restriction_policy(
            denied_ips=["192.168.1.0/24"],
        )
        engine.add_rule_set(policy)

        # Denied IP
        context = {"req": {"method": "GET", "path": "/"}, "client": {"ip": "192.168.1.100"}}
        result = await engine.evaluate(context)
        assert not result.allowed

        # Allowed IP
        context = {"req": {"method": "GET", "path": "/"}, "client": {"ip": "10.0.0.1"}}
        result = await engine.evaluate(context)
        assert result.allowed

    @pytest.mark.asyncio
    async def test_rate_limit_policy(self):
        """Test rate limit policy creation."""
        # create_rate_limit_policy uses get_policy_engine() internally
        # to register the action, so we need to use the same engine
        from instanton.policy.engine import get_policy_engine

        engine = get_policy_engine()
        engine.reset_stats()

        policy = create_rate_limit_policy(
            requests_per_minute=2,
            by_ip=True,
        )
        engine.add_rule_set(policy)

        # Use a unique IP to avoid pollution from other tests
        context = {"req": {"method": "GET", "path": "/"}, "client": {"ip": "99.99.99.99"}}

        # First two should succeed
        result = await engine.evaluate(context)
        assert result.allowed
        result = await engine.evaluate(context)
        assert result.allowed

        # Third should be rate limited
        result = await engine.evaluate(context)
        assert not result.allowed
        assert result.response_status == 429

        # Cleanup
        engine.remove_rule_set(policy.id)
