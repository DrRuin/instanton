"""Instanton Ingress Configuration Models.

Provides configuration models for defining ingress routes in YAML/JSON
configuration files.

Example YAML configuration:
    ingress:
      enabled: true
      routes:
        - name: api-route
          priority: 100
          rules:
            - type: path_prefix
              prefix: /api/
            - type: method
              methods: [GET, POST, PUT, DELETE]
          target:
            tunnel_id: api-tunnel
            strip_prefix: /api

        - name: web-route
          priority: 50
          rules:
            - type: host
              host_pattern: "*.myapp.com"
          target:
            tunnel_id: web-tunnel
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from instanton.ingress.engine import IngressEngine, IngressRoute, RouteTarget
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
)


@dataclass
class IngressRuleConfig:
    """Configuration for a single ingress rule.

    This is the user-facing configuration format that gets
    converted to IngressRule instances.
    """

    type: str
    """Rule type: path_prefix, path_exact, path_regex, host, method, header, etc."""

    # Path rules
    prefix: str | None = None
    path: str | None = None
    pattern: str | None = None

    # Host rules
    host_pattern: str | None = None

    # Method rules
    methods: list[str] | None = None

    # Header rules
    header_name: str | None = None
    header_value: str | None = None
    case_sensitive: bool = False

    # Query param rules
    param_name: str | None = None
    param_value: str | None = None

    # Composite rules
    rules: list[IngressRuleConfig] | None = None
    require_all: bool = True

    def to_rule(self, name: str = "", priority: int = 0) -> IngressRule:
        """Convert configuration to an IngressRule instance.

        Args:
            name: Optional rule name.
            priority: Optional rule priority.

        Returns:
            The appropriate IngressRule subclass instance.

        Raises:
            ValueError: If rule type is invalid or required fields are missing.
        """
        rule_type = RuleType(self.type)

        if rule_type == RuleType.PATH_PREFIX:
            if not self.prefix:
                raise ValueError("path_prefix rule requires 'prefix' field")
            return PathPrefixRule(
                name=name,
                priority=priority,
                prefix=self.prefix,
                case_sensitive=self.case_sensitive,
            )

        elif rule_type == RuleType.PATH_EXACT:
            if not self.path:
                raise ValueError("path_exact rule requires 'path' field")
            return PathExactRule(
                name=name,
                priority=priority,
                path=self.path,
                case_sensitive=self.case_sensitive,
            )

        elif rule_type == RuleType.PATH_REGEX:
            if not self.pattern:
                raise ValueError("path_regex rule requires 'pattern' field")
            return PathRegexRule(
                name=name,
                priority=priority,
                pattern=self.pattern,
            )

        elif rule_type == RuleType.HOST:
            return HostRule(
                name=name,
                priority=priority,
                host_pattern=self.host_pattern or "*",
            )

        elif rule_type == RuleType.METHOD:
            return MethodRule(
                name=name,
                priority=priority,
                methods=self.methods or ["GET"],
            )

        elif rule_type == RuleType.HEADER:
            if not self.header_name:
                raise ValueError("header rule requires 'header_name' field")
            return HeaderRule(
                name=name,
                priority=priority,
                header_name=self.header_name,
                header_value=self.header_value,
                case_sensitive=self.case_sensitive,
            )

        elif rule_type == RuleType.HEADER_REGEX:
            if not self.header_name or not self.pattern:
                raise ValueError(
                    "header_regex rule requires 'header_name' and 'pattern' fields"
                )
            return HeaderRegexRule(
                name=name,
                priority=priority,
                header_name=self.header_name,
                pattern=self.pattern,
            )

        elif rule_type == RuleType.QUERY_PARAM:
            if not self.param_name:
                raise ValueError("query_param rule requires 'param_name' field")
            return QueryParamRule(
                name=name,
                priority=priority,
                param_name=self.param_name,
                param_value=self.param_value,
            )

        elif rule_type == RuleType.COMPOSITE:
            if not self.rules:
                raise ValueError("composite rule requires 'rules' list")
            return CompositeRule(
                name=name,
                priority=priority,
                rules=[r.to_rule() for r in self.rules],
                require_all=self.require_all,
            )

        else:
            raise ValueError(f"Unknown rule type: {self.type}")


@dataclass
class IngressTargetConfig:
    """Configuration for a route target."""

    tunnel_id: str
    """The tunnel to route to."""

    backend_path: str | None = None
    """Optional path prefix for the backend."""

    strip_prefix: str | None = None
    """Optional prefix to strip from incoming path."""

    headers_add: dict[str, str] = field(default_factory=dict)
    """Headers to add to forwarded requests."""

    headers_remove: list[str] = field(default_factory=list)
    """Headers to remove from forwarded requests."""

    timeout_seconds: int | None = None
    """Custom timeout for this target."""

    def to_target(self) -> RouteTarget:
        """Convert to RouteTarget instance."""
        return RouteTarget(
            tunnel_id=self.tunnel_id,
            backend_path=self.backend_path,
            strip_prefix=self.strip_prefix,
            headers_add=self.headers_add,
            headers_remove=self.headers_remove,
            timeout_seconds=self.timeout_seconds,
        )


@dataclass
class IngressRouteConfig:
    """Configuration for an ingress route."""

    name: str
    """Unique route name."""

    target: IngressTargetConfig
    """Target configuration."""

    rules: list[IngressRuleConfig] = field(default_factory=list)
    """Rules that must match for this route."""

    priority: int = 0
    """Route priority (higher evaluated first)."""

    enabled: bool = True
    """Whether this route is active."""

    description: str = ""
    """Optional description."""

    def to_route(self) -> IngressRoute:
        """Convert to IngressRoute instance."""
        return IngressRoute(
            name=self.name,
            rules=[r.to_rule() for r in self.rules],
            target=self.target.to_target(),
            priority=self.priority,
            enabled=self.enabled,
            description=self.description,
        )


@dataclass
class IngressConfig:
    """Top-level ingress configuration."""

    enabled: bool = False
    """Whether ingress routing is enabled."""

    routes: list[IngressRouteConfig] = field(default_factory=list)
    """List of route configurations."""

    default_tunnel: str | None = None
    """Optional default tunnel when no routes match."""

    def to_engine(self) -> IngressEngine:
        """Create and configure an IngressEngine from this config.

        Returns:
            Configured IngressEngine instance.
        """
        engine = IngressEngine()
        for route_config in self.routes:
            engine.add_route(route_config.to_route())
        return engine

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IngressConfig:
        """Create configuration from dictionary.

        Args:
            data: Configuration dictionary (from YAML/JSON).

        Returns:
            IngressConfig instance.
        """
        routes = []
        for route_data in data.get("routes", []):
            # Parse rules
            rule_configs = []
            for rule_data in route_data.get("rules", []):
                # Handle nested composite rules
                nested_rules = None
                if "rules" in rule_data:
                    nested_rules = [
                        IngressRuleConfig(**nested) for nested in rule_data["rules"]
                    ]

                rule_config = IngressRuleConfig(
                    type=rule_data.get("type", "path_prefix"),
                    prefix=rule_data.get("prefix"),
                    path=rule_data.get("path"),
                    pattern=rule_data.get("pattern"),
                    host_pattern=rule_data.get("host_pattern"),
                    methods=rule_data.get("methods"),
                    header_name=rule_data.get("header_name"),
                    header_value=rule_data.get("header_value"),
                    case_sensitive=rule_data.get("case_sensitive", False),
                    param_name=rule_data.get("param_name"),
                    param_value=rule_data.get("param_value"),
                    rules=nested_rules,
                    require_all=rule_data.get("require_all", True),
                )
                rule_configs.append(rule_config)

            # Parse target
            target_data = route_data.get("target", {})
            target_config = IngressTargetConfig(
                tunnel_id=target_data.get("tunnel_id", ""),
                backend_path=target_data.get("backend_path"),
                strip_prefix=target_data.get("strip_prefix"),
                headers_add=target_data.get("headers_add", {}),
                headers_remove=target_data.get("headers_remove", []),
                timeout_seconds=target_data.get("timeout_seconds"),
            )

            route_config = IngressRouteConfig(
                name=route_data.get("name", ""),
                target=target_config,
                rules=rule_configs,
                priority=route_data.get("priority", 0),
                enabled=route_data.get("enabled", True),
                description=route_data.get("description", ""),
            )
            routes.append(route_config)

        return cls(
            enabled=data.get("enabled", False),
            routes=routes,
            default_tunnel=data.get("default_tunnel"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary.

        Returns:
            Configuration as dictionary.
        """
        return {
            "enabled": self.enabled,
            "default_tunnel": self.default_tunnel,
            "routes": [
                {
                    "name": r.name,
                    "priority": r.priority,
                    "enabled": r.enabled,
                    "description": r.description,
                    "rules": [
                        {
                            "type": rule.type,
                            "prefix": rule.prefix,
                            "path": rule.path,
                            "pattern": rule.pattern,
                            "host_pattern": rule.host_pattern,
                            "methods": rule.methods,
                            "header_name": rule.header_name,
                            "header_value": rule.header_value,
                            "case_sensitive": rule.case_sensitive,
                            "param_name": rule.param_name,
                            "param_value": rule.param_value,
                        }
                        for rule in r.rules
                    ],
                    "target": {
                        "tunnel_id": r.target.tunnel_id,
                        "backend_path": r.target.backend_path,
                        "strip_prefix": r.target.strip_prefix,
                        "headers_add": r.target.headers_add,
                        "headers_remove": r.target.headers_remove,
                        "timeout_seconds": r.target.timeout_seconds,
                    },
                }
                for r in self.routes
            ],
        }
