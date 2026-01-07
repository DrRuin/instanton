"""Traffic Policy Engine for Instanton tunnel application.

Features:
- Rule-based traffic matching
- IP restrictions (allow/deny lists)
- Rate limiting per-rule
- Header manipulation (add/remove/modify)
- URL rewriting and redirects
- Request/response transformation
- Circuit breaker patterns
- Webhook verification
"""

from instanton.policy.actions import (
    ActionType,
    AllowAction,
    CircuitBreakerAction,
    DenyAction,
    HeaderAction,
    RateLimitAction,
    RedirectAction,
    RewriteAction,
    TransformAction,
)
from instanton.policy.engine import (
    PolicyAction,
    PolicyEngine,
    PolicyResult,
    get_policy_engine,
)
from instanton.policy.rules import (
    ConditionOperator,
    MatchField,
    PolicyRule,
    RuleCondition,
)

__all__ = [
    # Engine
    "PolicyEngine",
    "PolicyResult",
    "PolicyAction",
    "get_policy_engine",
    # Rules
    "PolicyRule",
    "RuleCondition",
    "ConditionOperator",
    "MatchField",
    # Actions
    "ActionType",
    "AllowAction",
    "DenyAction",
    "RateLimitAction",
    "HeaderAction",
    "RewriteAction",
    "RedirectAction",
    "TransformAction",
    "CircuitBreakerAction",
]
