"""Instanton Ingress Routing Module.

Provides flexible routing rules for directing incoming requests to specific
tunnels based on path, host, HTTP method, headers, and other criteria.

Features:
- Path-based routing (prefix, exact, regex)
- Host-based routing with wildcard support
- HTTP method filtering
- Header matching and regex patterns
- Query parameter matching
- Composite rules with AND/OR logic
- Priority-based route evaluation
- Path rewriting and header manipulation

Usage:
    from instanton.ingress import IngressEngine, PathPrefixRule, RouteTarget

    # Create engine
    engine = IngressEngine()

    # Add route for API requests
    from instanton.ingress import IngressRoute
    engine.add_route(IngressRoute(
        name="api-route",
        rules=[PathPrefixRule(prefix="/api/")],
        target=RouteTarget(tunnel_id="api-tunnel"),
        priority=100,
    ))

    # Match incoming request
    context = {"path": "/api/users", "method": "GET", "host": "example.com"}
    target = engine.match(context)

    if target:
        print(f"Route to tunnel: {target.tunnel_id}")

Configuration:
    Ingress routes can also be configured via YAML:

    ingress:
      enabled: true
      routes:
        - name: api-route
          priority: 100
          rules:
            - type: path_prefix
              prefix: /api/
          target:
            tunnel_id: api-tunnel
"""

from instanton.ingress.config import (
    IngressConfig,
    IngressRouteConfig,
    IngressRuleConfig,
    IngressTargetConfig,
)
from instanton.ingress.engine import (
    IngressEngine,
    IngressRoute,
    RouteTarget,
    create_request_context,
)
from instanton.ingress.rules import (
    CompositeRule,
    HeaderRegexRule,
    HeaderRule,
    HostRule,
    IngressRule,
    MethodRule,
    PathExactRule,
    PathPrefixRule,
    PathRegexRule,
    QueryParamRule,
    RuleType,
    rule_from_dict,
)

__all__ = [
    # Engine
    "IngressEngine",
    "IngressRoute",
    "RouteTarget",
    "create_request_context",
    # Rules
    "IngressRule",
    "RuleType",
    "PathPrefixRule",
    "PathExactRule",
    "PathRegexRule",
    "HostRule",
    "MethodRule",
    "HeaderRule",
    "HeaderRegexRule",
    "QueryParamRule",
    "CompositeRule",
    "rule_from_dict",
    # Configuration
    "IngressConfig",
    "IngressRouteConfig",
    "IngressRuleConfig",
    "IngressTargetConfig",
]
