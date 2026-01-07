"""Policy engine that evaluates rules and executes actions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from instanton.policy.actions import (
    ActionResult,
    ActionType,
    AllowAction,
    CircuitBreakerAction,
    DenyAction,
    HeaderAction,
    PolicyAction,
    RateLimitAction,
)
from instanton.policy.rules import PolicyRule, RuleSet

logger = structlog.get_logger()


@dataclass
class PolicyResult:
    """Result of policy evaluation."""

    allowed: bool = True
    matched_rules: list[str] = field(default_factory=list)
    executed_actions: list[ActionType] = field(default_factory=list)
    response_status: int | None = None
    response_body: bytes | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    modified_request: dict[str, Any] = field(default_factory=dict)
    modified_response: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    evaluation_time_ms: float = 0.0


class PolicyEngine:
    """Engine that evaluates traffic policies and executes actions."""

    def __init__(self):
        self._rule_sets: dict[str, RuleSet] = {}
        self._actions: dict[str, PolicyAction] = {}
        self._default_action: PolicyAction = AllowAction(id="default_allow")
        self._enabled: bool = True
        self._stats: dict[str, int] = {
            "total_evaluations": 0,
            "rules_matched": 0,
            "actions_executed": 0,
            "requests_denied": 0,
            "requests_allowed": 0,
        }
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def add_rule_set(self, rule_set: RuleSet) -> None:
        """Add a rule set to the engine."""
        self._rule_sets[rule_set.id] = rule_set

    def remove_rule_set(self, rule_set_id: str) -> bool:
        """Remove a rule set."""
        if rule_set_id in self._rule_sets:
            del self._rule_sets[rule_set_id]
            return True
        return False

    def get_rule_set(self, rule_set_id: str) -> RuleSet | None:
        """Get a rule set by ID."""
        return self._rule_sets.get(rule_set_id)

    def add_action(self, action: PolicyAction) -> None:
        """Register an action."""
        self._actions[action.id] = action

    def remove_action(self, action_id: str) -> bool:
        """Remove an action."""
        if action_id in self._actions:
            del self._actions[action_id]
            return True
        return False

    def get_action(self, action_id: str) -> PolicyAction | None:
        """Get an action by ID."""
        return self._actions.get(action_id)

    def set_default_action(self, action: PolicyAction) -> None:
        """Set the default action when no rules match."""
        self._default_action = action

    async def evaluate(
        self,
        context: dict[str, Any],
        phase: str = "request",
    ) -> PolicyResult:
        """Evaluate policies for the given context.

        Args:
            context: Request/response context with fields like:
                - req.method, req.path, req.headers, req.body
                - client.ip, client.port
                - conn.subdomain, conn.tunnel_id
                - time.hour, time.day_of_week
            phase: "request" or "response"

        Returns:
            PolicyResult with evaluation outcome
        """
        import time

        start_time = time.time()
        result = PolicyResult()

        if not self._enabled:
            result.allowed = True
            return result

        self._stats["total_evaluations"] += 1

        # Add time context
        now = datetime.now(UTC)
        context.setdefault("time", {})
        context["time"]["hour"] = now.hour
        context["time"]["minute"] = now.minute
        context["time"]["day_of_week"] = now.weekday()

        try:
            # Collect all matching rules from all rule sets
            all_matching_rules: list[tuple[PolicyRule, RuleSet]] = []

            for rule_set in self._rule_sets.values():
                matching = rule_set.get_matching_rules(context)
                for rule in matching:
                    all_matching_rules.append((rule, rule_set))

            # Sort by priority
            all_matching_rules.sort(key=lambda x: x[0].priority)

            # Execute actions for matching rules
            for rule, rule_set in all_matching_rules:
                result.matched_rules.append(f"{rule_set.id}:{rule.id}")
                self._stats["rules_matched"] += 1

                for action_id in rule.actions:
                    action = self._actions.get(action_id)
                    if not action or not action.enabled:
                        continue

                    action_result = await self._execute_action(action, context)
                    result.executed_actions.append(action_result.action_type)
                    self._stats["actions_executed"] += 1

                    # Merge action result
                    self._merge_action_result(result, action_result)

                    # Check if we should stop processing
                    if action_result.stop_request:
                        result.allowed = False
                        self._stats["requests_denied"] += 1
                        break

                    # Log messages
                    if action_result.log_message:
                        result.logs.append(action_result.log_message)

                    # Errors
                    if action_result.error:
                        result.errors.append(action_result.error)

                # Check if rule says to stop processing more rules
                if rule.stop_processing and result.matched_rules:
                    break

            # If no rules matched or all rules allowed, use default action
            if result.allowed and not result.matched_rules:
                action_result = await self._execute_action(self._default_action, context)
                if action_result.stop_request:
                    result.allowed = False
                    self._stats["requests_denied"] += 1
                else:
                    self._stats["requests_allowed"] += 1
            elif result.allowed:
                self._stats["requests_allowed"] += 1

        except Exception as e:
            logger.error("Policy evaluation error", error=str(e))
            result.errors.append(str(e))
            # On error, default to allow (fail-open)
            result.allowed = True

        result.evaluation_time_ms = (time.time() - start_time) * 1000
        return result

    async def _execute_action(
        self,
        action: PolicyAction,
        context: dict[str, Any],
    ) -> ActionResult:
        """Execute a single action."""
        try:
            return await action.execute(context)
        except Exception as e:
            logger.error(
                "Action execution error",
                action_id=action.id,
                action_type=action.type,
                error=str(e),
            )
            return ActionResult(
                success=False,
                action_type=action.type,
                error=str(e),
            )

    def _merge_action_result(
        self,
        policy_result: PolicyResult,
        action_result: ActionResult,
    ) -> None:
        """Merge an action result into the policy result."""
        if action_result.response_status:
            policy_result.response_status = action_result.response_status

        if action_result.response_body:
            policy_result.response_body = action_result.response_body

        if action_result.response_headers:
            policy_result.response_headers.update(action_result.response_headers)

        if action_result.modified_request:
            policy_result.modified_request.update(action_result.modified_request)

        if action_result.modified_response:
            policy_result.modified_response.update(action_result.modified_response)

        if action_result.tags:
            policy_result.tags.extend(action_result.tags)

    def get_stats(self) -> dict[str, Any]:
        """Get policy engine statistics."""
        return {
            **self._stats,
            "rule_sets": len(self._rule_sets),
            "actions": len(self._actions),
            "enabled": self._enabled,
        }

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._stats = {
            "total_evaluations": 0,
            "rules_matched": 0,
            "actions_executed": 0,
            "requests_denied": 0,
            "requests_allowed": 0,
        }

    async def record_circuit_breaker_result(
        self,
        key: str,
        success: bool,
    ) -> None:
        """Record a result for circuit breaker actions."""
        for action in self._actions.values():
            if isinstance(action, CircuitBreakerAction):
                if success:
                    await action.record_success(key)
                else:
                    await action.record_failure(key)


# Global engine instance
_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    """Get or create the global policy engine instance."""
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
        _setup_default_actions(_engine)
    return _engine


def set_policy_engine(engine: PolicyEngine) -> None:
    """Set the global policy engine instance."""
    global _engine
    _engine = engine


def _setup_default_actions(engine: PolicyEngine) -> None:
    """Setup default actions in the engine."""
    # Default allow/deny actions
    engine.add_action(AllowAction(id="allow"))
    engine.add_action(DenyAction(id="deny"))
    engine.add_action(DenyAction(id="deny_401", status_code=401, message="Unauthorized"))
    engine.add_action(DenyAction(id="deny_403", status_code=403, message="Forbidden"))
    engine.add_action(DenyAction(id="deny_404", status_code=404, message="Not Found"))

    # Default rate limit actions
    engine.add_action(
        RateLimitAction(
            id="rate_limit_default",
            requests_per_window=100,
            window_seconds=60,
        )
    )
    engine.add_action(
        RateLimitAction(
            id="rate_limit_strict",
            requests_per_window=10,
            window_seconds=60,
        )
    )
    engine.add_action(
        RateLimitAction(
            id="rate_limit_api",
            requests_per_window=1000,
            window_seconds=60,
            key_field="auth.identity",
        )
    )


# Convenience functions for creating common policy configurations


def create_ip_restriction_policy(
    allowed_ips: list[str] | None = None,
    denied_ips: list[str] | None = None,
) -> RuleSet:
    """Create a policy for IP-based access control."""
    from instanton.policy.rules import (
        ConditionOperator,
        MatchField,
        PolicyRule,
        RuleCondition,
    )

    rules = []

    if denied_ips:
        rules.append(
            PolicyRule(
                id="deny_ips",
                name="Deny Listed IPs",
                priority=0,  # Check deny list first
                conditions=[
                    RuleCondition(
                        field=MatchField.CLIENT_IP,
                        operator=ConditionOperator.IP_IN_CIDR,
                        value=denied_ips,
                    )
                ],
                actions=["deny"],
            )
        )

    if allowed_ips:
        rules.append(
            PolicyRule(
                id="allow_ips",
                name="Allow Listed IPs",
                priority=1,
                conditions=[
                    RuleCondition(
                        field=MatchField.CLIENT_IP,
                        operator=ConditionOperator.IP_IN_CIDR,
                        value=allowed_ips,
                    )
                ],
                actions=["allow"],
            )
        )
        # If we have an allow list, deny everything else
        rules.append(
            PolicyRule(
                id="deny_others",
                name="Deny All Others",
                priority=2,
                conditions=[],  # Matches everything
                actions=["deny"],
            )
        )

    return RuleSet(
        id="ip_restrictions",
        name="IP Restrictions",
        rules=rules,
    )


def create_rate_limit_policy(
    requests_per_minute: int = 100,
    by_ip: bool = True,
    paths: list[str] | None = None,
) -> RuleSet:
    """Create a rate limiting policy."""
    from instanton.policy.rules import (
        ConditionOperator,
        MatchField,
        PolicyRule,
        RuleCondition,
    )

    engine = get_policy_engine()

    # Create custom rate limit action
    action_id = f"rate_limit_{requests_per_minute}pm"
    engine.add_action(
        RateLimitAction(
            id=action_id,
            requests_per_window=requests_per_minute,
            window_seconds=60,
            key_field="client.ip" if by_ip else "conn.subdomain",
        )
    )

    rules = []

    if paths:
        for i, path in enumerate(paths):
            rules.append(
                PolicyRule(
                    id=f"rate_limit_path_{i}",
                    name=f"Rate Limit {path}",
                    conditions=[
                        RuleCondition(
                            field=MatchField.PATH,
                            operator=ConditionOperator.MATCHES,
                            value=path,
                        )
                    ],
                    actions=[action_id],
                    stop_processing=False,  # Continue to allow request
                )
            )
    else:
        rules.append(
            PolicyRule(
                id="rate_limit_all",
                name="Rate Limit All",
                conditions=[],
                actions=[action_id],
                stop_processing=False,
            )
        )

    return RuleSet(
        id="rate_limits",
        name="Rate Limits",
        rules=rules,
    )


def create_header_policy(
    add_headers: dict[str, str] | None = None,
    remove_headers: list[str] | None = None,
) -> RuleSet:
    """Create a policy for header manipulation."""
    from instanton.policy.rules import PolicyRule

    engine = get_policy_engine()
    rules = []

    if add_headers:
        for name, value in add_headers.items():
            action_id = f"add_header_{name.lower().replace('-', '_')}"
            engine.add_action(
                HeaderAction(
                    id=action_id,
                    header_name=name,
                    header_value=value,
                )
            )
            rules.append(
                PolicyRule(
                    id=f"rule_{action_id}",
                    name=f"Add {name} header",
                    conditions=[],
                    actions=[action_id],
                    stop_processing=False,
                )
            )

    if remove_headers:
        for name in remove_headers:
            action_id = f"remove_header_{name.lower().replace('-', '_')}"
            engine.add_action(
                HeaderAction(
                    id=action_id,
                    header_name=name,
                    header_value=None,  # None = remove
                )
            )
            rules.append(
                PolicyRule(
                    id=f"rule_{action_id}",
                    name=f"Remove {name} header",
                    conditions=[],
                    actions=[action_id],
                    stop_processing=False,
                )
            )

    return RuleSet(
        id="header_manipulation",
        name="Header Manipulation",
        rules=rules,
    )
