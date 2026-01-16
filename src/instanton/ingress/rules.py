"""Instanton Ingress Routing Rules.

Provides flexible routing rules for directing incoming requests to specific
tunnels based on path, host, HTTP method, headers, and other criteria.

Rule Types:
- PathPrefixRule: Match by path prefix (e.g., /api/)
- PathExactRule: Match exact path
- PathRegexRule: Match by regex pattern
- HostRule: Match by host header
- MethodRule: Match by HTTP method (GET, POST, etc.)
- HeaderRule: Match by header presence or value
- CompositeRule: Combine multiple rules with AND/OR logic

Example:
    # Route /api/* requests to api-tunnel
    rule = PathPrefixRule(prefix="/api/")
    if rule.matches({"path": "/api/users"}):
        # Route to api-tunnel
        pass
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleType(Enum):
    """Types of ingress routing rules."""

    PATH_PREFIX = "path_prefix"
    PATH_EXACT = "path_exact"
    PATH_REGEX = "path_regex"
    HOST = "host"
    HOST_REGEX = "host_regex"
    METHOD = "method"
    HEADER = "header"
    HEADER_REGEX = "header_regex"
    QUERY_PARAM = "query_param"
    COMPOSITE = "composite"


@dataclass
class IngressRule(ABC):
    """Base class for all ingress routing rules.

    Subclasses must implement the matches() method to check if a
    request context matches the rule criteria.
    """

    name: str = ""
    priority: int = 0
    enabled: bool = True

    @property
    @abstractmethod
    def rule_type(self) -> RuleType:
        """Return the type of this rule."""
        ...

    @abstractmethod
    def matches(self, context: dict[str, Any]) -> bool:
        """Check if the request context matches this rule.

        Args:
            context: Request context with keys like 'path', 'method',
                    'host', 'headers', 'query_params'.

        Returns:
            True if the request matches this rule.
        """
        ...

    def to_dict(self) -> dict[str, Any]:
        """Convert rule to dictionary for serialization."""
        return {
            "type": self.rule_type.value,
            "name": self.name,
            "priority": self.priority,
            "enabled": self.enabled,
        }


@dataclass
class PathPrefixRule(IngressRule):
    """Match requests by path prefix.

    Example:
        >>> rule = PathPrefixRule(prefix="/api/")
        >>> rule.matches({"path": "/api/users"})
        True
        >>> rule.matches({"path": "/web/page"})
        False
    """

    prefix: str = "/"
    case_sensitive: bool = False

    @property
    def rule_type(self) -> RuleType:
        return RuleType.PATH_PREFIX

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        path = context.get("path", "")
        if not self.case_sensitive:
            return path.lower().startswith(self.prefix.lower())
        return path.startswith(self.prefix)

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["prefix"] = self.prefix
        data["case_sensitive"] = self.case_sensitive
        return data


@dataclass
class PathExactRule(IngressRule):
    """Match requests by exact path.

    Example:
        >>> rule = PathExactRule(path="/health")
        >>> rule.matches({"path": "/health"})
        True
        >>> rule.matches({"path": "/health/"})
        False
    """

    path: str = "/"
    case_sensitive: bool = False

    @property
    def rule_type(self) -> RuleType:
        return RuleType.PATH_EXACT

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        request_path = context.get("path", "")
        if not self.case_sensitive:
            return request_path.lower() == self.path.lower()
        return request_path == self.path

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["path"] = self.path
        data["case_sensitive"] = self.case_sensitive
        return data


@dataclass
class PathRegexRule(IngressRule):
    """Match requests by path regex pattern.

    Example:
        >>> rule = PathRegexRule(pattern=r"/api/v[0-9]+/.*")
        >>> rule.matches({"path": "/api/v2/users"})
        True
        >>> rule.matches({"path": "/web/page"})
        False
    """

    pattern: str = ".*"
    _compiled: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern, re.IGNORECASE)

    @property
    def rule_type(self) -> RuleType:
        return RuleType.PATH_REGEX

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        path = context.get("path", "")
        return bool(self._compiled.match(path))

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["pattern"] = self.pattern
        return data


@dataclass
class HostRule(IngressRule):
    """Match requests by host header.

    Supports exact match or wildcard patterns (*.example.com).

    Example:
        >>> rule = HostRule(host_pattern="api.example.com")
        >>> rule.matches({"host": "api.example.com"})
        True
        >>> rule.matches({"host": "www.example.com"})
        False
    """

    host_pattern: str = "*"

    @property
    def rule_type(self) -> RuleType:
        return RuleType.HOST

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        host = context.get("host", "").lower()
        pattern = self.host_pattern.lower()

        if pattern == "*":
            return True

        # Handle wildcard patterns like *.example.com
        if pattern.startswith("*."):
            suffix = pattern[1:]  # Keep the dot: .example.com
            return host.endswith(suffix) and "." in host[: -len(suffix)]

        return host == pattern

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["host_pattern"] = self.host_pattern
        return data


@dataclass
class MethodRule(IngressRule):
    """Match requests by HTTP method.

    Example:
        >>> rule = MethodRule(methods=["POST", "PUT"])
        >>> rule.matches({"method": "POST"})
        True
        >>> rule.matches({"method": "GET"})
        False
    """

    methods: list[str] = field(default_factory=lambda: ["GET"])

    @property
    def rule_type(self) -> RuleType:
        return RuleType.METHOD

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        method = context.get("method", "GET").upper()
        return method in [m.upper() for m in self.methods]

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["methods"] = self.methods
        return data


@dataclass
class HeaderRule(IngressRule):
    """Match requests by header presence or value.

    If header_value is None, only checks for header presence.
    If header_value is set, checks for exact match.

    Example:
        >>> rule = HeaderRule(header_name="Authorization")
        >>> rule.matches({"headers": {"Authorization": "Bearer token"}})
        True
        >>> rule.matches({"headers": {}})
        False

        >>> rule = HeaderRule(header_name="X-Custom", header_value="expected")
        >>> rule.matches({"headers": {"X-Custom": "expected"}})
        True
        >>> rule.matches({"headers": {"X-Custom": "different"}})
        False
    """

    header_name: str = ""
    header_value: str | None = None
    case_sensitive: bool = False

    @property
    def rule_type(self) -> RuleType:
        return RuleType.HEADER

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        headers = context.get("headers", {})

        # Case-insensitive header name lookup
        header_key = None
        for key in headers:
            if key.lower() == self.header_name.lower():
                header_key = key
                break

        if header_key is None:
            return False

        # If no value specified, just check presence
        if self.header_value is None:
            return True

        # Check value match
        actual_value = headers[header_key]
        if self.case_sensitive:
            return actual_value == self.header_value
        return actual_value.lower() == self.header_value.lower()

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["header_name"] = self.header_name
        data["header_value"] = self.header_value
        data["case_sensitive"] = self.case_sensitive
        return data


@dataclass
class HeaderRegexRule(IngressRule):
    """Match requests by header value regex pattern.

    Example:
        >>> rule = HeaderRegexRule(header_name="User-Agent", pattern=r".*Chrome.*")
        >>> rule.matches({"headers": {"User-Agent": "Mozilla/5.0 Chrome/100"}})
        True
    """

    header_name: str = ""
    pattern: str = ".*"
    _compiled: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern, re.IGNORECASE)

    @property
    def rule_type(self) -> RuleType:
        return RuleType.HEADER_REGEX

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        headers = context.get("headers", {})

        # Case-insensitive header name lookup
        header_value = None
        for key, value in headers.items():
            if key.lower() == self.header_name.lower():
                header_value = value
                break

        if header_value is None:
            return False

        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)

        return bool(self._compiled.match(header_value))

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["header_name"] = self.header_name
        data["pattern"] = self.pattern
        return data


@dataclass
class QueryParamRule(IngressRule):
    """Match requests by query parameter presence or value.

    Example:
        >>> rule = QueryParamRule(param_name="debug", param_value="true")
        >>> rule.matches({"query_params": {"debug": "true"}})
        True
    """

    param_name: str = ""
    param_value: str | None = None

    @property
    def rule_type(self) -> RuleType:
        return RuleType.QUERY_PARAM

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        params = context.get("query_params", {})

        if self.param_name not in params:
            return False

        if self.param_value is None:
            return True

        return params[self.param_name] == self.param_value

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["param_name"] = self.param_name
        data["param_value"] = self.param_value
        return data


@dataclass
class CompositeRule(IngressRule):
    """Combine multiple rules with AND/OR logic.

    When require_all=True (AND): All rules must match.
    When require_all=False (OR): Any rule must match.

    Example:
        >>> composite = CompositeRule(
        ...     rules=[
        ...         PathPrefixRule(prefix="/api/"),
        ...         MethodRule(methods=["POST", "PUT"]),
        ...         HeaderRule(header_name="Authorization"),
        ...     ],
        ...     require_all=True,
        ... )
        >>> # Only matches if all three rules match
    """

    rules: list[IngressRule] = field(default_factory=list)
    require_all: bool = True  # True=AND, False=OR

    @property
    def rule_type(self) -> RuleType:
        return RuleType.COMPOSITE

    def matches(self, context: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        if not self.rules:
            return True

        if self.require_all:
            return all(rule.matches(context) for rule in self.rules)
        return any(rule.matches(context) for rule in self.rules)

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data["rules"] = [rule.to_dict() for rule in self.rules]
        data["require_all"] = self.require_all
        return data


def rule_from_dict(data: dict[str, Any]) -> IngressRule:
    """Create a rule from dictionary representation.

    Args:
        data: Dictionary with rule configuration.

    Returns:
        The appropriate IngressRule subclass instance.

    Raises:
        ValueError: If rule type is unknown.
    """
    rule_type = RuleType(data.get("type", "path_prefix"))
    name = data.get("name", "")
    priority = data.get("priority", 0)
    enabled = data.get("enabled", True)

    if rule_type == RuleType.PATH_PREFIX:
        return PathPrefixRule(
            name=name,
            priority=priority,
            enabled=enabled,
            prefix=data.get("prefix", "/"),
            case_sensitive=data.get("case_sensitive", False),
        )
    elif rule_type == RuleType.PATH_EXACT:
        return PathExactRule(
            name=name,
            priority=priority,
            enabled=enabled,
            path=data.get("path", "/"),
            case_sensitive=data.get("case_sensitive", False),
        )
    elif rule_type == RuleType.PATH_REGEX:
        return PathRegexRule(
            name=name,
            priority=priority,
            enabled=enabled,
            pattern=data.get("pattern", ".*"),
        )
    elif rule_type == RuleType.HOST:
        return HostRule(
            name=name,
            priority=priority,
            enabled=enabled,
            host_pattern=data.get("host_pattern", "*"),
        )
    elif rule_type == RuleType.METHOD:
        return MethodRule(
            name=name,
            priority=priority,
            enabled=enabled,
            methods=data.get("methods", ["GET"]),
        )
    elif rule_type == RuleType.HEADER:
        return HeaderRule(
            name=name,
            priority=priority,
            enabled=enabled,
            header_name=data.get("header_name", ""),
            header_value=data.get("header_value"),
            case_sensitive=data.get("case_sensitive", False),
        )
    elif rule_type == RuleType.HEADER_REGEX:
        return HeaderRegexRule(
            name=name,
            priority=priority,
            enabled=enabled,
            header_name=data.get("header_name", ""),
            pattern=data.get("pattern", ".*"),
        )
    elif rule_type == RuleType.QUERY_PARAM:
        return QueryParamRule(
            name=name,
            priority=priority,
            enabled=enabled,
            param_name=data.get("param_name", ""),
            param_value=data.get("param_value"),
        )
    elif rule_type == RuleType.COMPOSITE:
        return CompositeRule(
            name=name,
            priority=priority,
            enabled=enabled,
            rules=[rule_from_dict(r) for r in data.get("rules", [])],
            require_all=data.get("require_all", True),
        )
    else:
        raise ValueError(f"Unknown rule type: {rule_type}")
