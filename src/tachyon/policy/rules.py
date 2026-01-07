"""Policy rules and conditions for traffic matching."""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ConditionOperator(str, Enum):
    """Operators for condition matching."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    MATCHES = "matches"  # Regex match
    NOT_MATCHES = "not_matches"
    IN = "in"  # Value in list
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    GREATER_EQUAL = "gte"
    LESS_EQUAL = "lte"
    IP_IN_CIDR = "ip_in_cidr"
    IP_NOT_IN_CIDR = "ip_not_in_cidr"


class MatchField(str, Enum):
    """Fields that can be matched in conditions."""

    # Request fields
    METHOD = "req.method"
    PATH = "req.path"
    HOST = "req.host"
    SCHEME = "req.scheme"
    QUERY = "req.query"
    QUERY_PARAM = "req.query_param"  # Specific param
    HEADER = "req.header"  # Specific header
    BODY = "req.body"
    CONTENT_TYPE = "req.content_type"
    CONTENT_LENGTH = "req.content_length"
    USER_AGENT = "req.user_agent"

    # Client fields
    CLIENT_IP = "client.ip"
    CLIENT_PORT = "client.port"
    CLIENT_COUNTRY = "client.country"  # GeoIP
    CLIENT_CITY = "client.city"

    # Connection fields
    SUBDOMAIN = "conn.subdomain"
    TUNNEL_ID = "conn.tunnel_id"
    CONNECTION_COUNT = "conn.count"

    # Time fields
    HOUR = "time.hour"
    DAY_OF_WEEK = "time.day_of_week"
    MINUTE = "time.minute"

    # Auth fields
    AUTH_IDENTITY = "auth.identity"
    AUTH_SCOPE = "auth.scope"


class RuleCondition(BaseModel):
    """A single condition for rule matching."""

    field: MatchField | str
    operator: ConditionOperator = ConditionOperator.EQUALS
    value: Any = None
    param: str | None = None  # For parameterized fields like headers

    def matches(self, context: dict[str, Any]) -> bool:
        """Check if this condition matches the given context."""
        # Get the field value from context
        field_value = self._get_field_value(context)

        # Handle existence checks
        if self.operator == ConditionOperator.EXISTS:
            return field_value is not None
        if self.operator == ConditionOperator.NOT_EXISTS:
            return field_value is None

        # If field doesn't exist and we're not checking existence, no match
        if field_value is None:
            return False

        # Convert to string for string operations
        str_value = str(field_value)
        compare_value = self.value

        # String operations
        if self.operator == ConditionOperator.EQUALS:
            return str_value == str(compare_value)
        elif self.operator == ConditionOperator.NOT_EQUALS:
            return str_value != str(compare_value)
        elif self.operator == ConditionOperator.CONTAINS:
            return str(compare_value).lower() in str_value.lower()
        elif self.operator == ConditionOperator.NOT_CONTAINS:
            return str(compare_value).lower() not in str_value.lower()
        elif self.operator == ConditionOperator.STARTS_WITH:
            return str_value.startswith(str(compare_value))
        elif self.operator == ConditionOperator.ENDS_WITH:
            return str_value.endswith(str(compare_value))
        elif self.operator == ConditionOperator.MATCHES:
            try:
                return bool(re.search(str(compare_value), str_value))
            except re.error:
                return False
        elif self.operator == ConditionOperator.NOT_MATCHES:
            try:
                return not bool(re.search(str(compare_value), str_value))
            except re.error:
                return True
        elif self.operator == ConditionOperator.IN:
            if isinstance(compare_value, (list, tuple, set)):
                return str_value in [str(v) for v in compare_value]
            return str_value in str(compare_value).split(",")
        elif self.operator == ConditionOperator.NOT_IN:
            if isinstance(compare_value, (list, tuple, set)):
                return str_value not in [str(v) for v in compare_value]
            return str_value not in str(compare_value).split(",")

        # Numeric operations
        elif self.operator in (
            ConditionOperator.GREATER_THAN,
            ConditionOperator.LESS_THAN,
            ConditionOperator.GREATER_EQUAL,
            ConditionOperator.LESS_EQUAL,
        ):
            try:
                num_value = float(field_value)
                num_compare = float(compare_value)
                if self.operator == ConditionOperator.GREATER_THAN:
                    return num_value > num_compare
                elif self.operator == ConditionOperator.LESS_THAN:
                    return num_value < num_compare
                elif self.operator == ConditionOperator.GREATER_EQUAL:
                    return num_value >= num_compare
                elif self.operator == ConditionOperator.LESS_EQUAL:
                    return num_value <= num_compare
            except (ValueError, TypeError):
                return False

        # IP operations
        elif self.operator == ConditionOperator.IP_IN_CIDR:
            return self._check_ip_in_cidr(str_value, compare_value)
        elif self.operator == ConditionOperator.IP_NOT_IN_CIDR:
            return not self._check_ip_in_cidr(str_value, compare_value)

        return False

    def _get_field_value(self, context: dict[str, Any]) -> Any:
        """Extract the field value from the context."""
        field_str = self.field if isinstance(self.field, str) else self.field.value

        # Handle parameterized fields
        if field_str == "req.header" and self.param:
            headers = context.get("req", {}).get("headers", {})
            # Case-insensitive header lookup
            for k, v in headers.items():
                if k.lower() == self.param.lower():
                    return v
            return None

        if field_str == "req.query_param" and self.param:
            query_params = context.get("req", {}).get("query_params", {})
            return query_params.get(self.param)

        # Handle dotted path
        parts = field_str.split(".")
        value: Any = context
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
            if value is None:
                return None
        return value

    def _check_ip_in_cidr(self, ip: str, cidr: Any) -> bool:
        """Check if IP address is in CIDR range(s)."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            if isinstance(cidr, (list, tuple)):
                for c in cidr:
                    network = ipaddress.ip_network(c, strict=False)
                    if ip_addr in network:
                        return True
                return False
            else:
                network = ipaddress.ip_network(str(cidr), strict=False)
                return ip_addr in network
        except ValueError:
            return False


class PolicyRule(BaseModel):
    """A traffic policy rule with conditions and actions."""

    id: str
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 0  # Lower = higher priority
    conditions: list[RuleCondition] = Field(default_factory=list)
    match_all: bool = True  # True = AND, False = OR
    actions: list[str] = Field(default_factory=list)  # Action IDs
    stop_processing: bool = True  # Stop after this rule matches

    def matches(self, context: dict[str, Any]) -> bool:
        """Check if this rule matches the given context."""
        if not self.enabled:
            return False

        if not self.conditions:
            # No conditions = always matches
            return True

        if self.match_all:
            # All conditions must match (AND)
            return all(c.matches(context) for c in self.conditions)
        else:
            # Any condition must match (OR)
            return any(c.matches(context) for c in self.conditions)


class RuleSet(BaseModel):
    """A collection of policy rules."""

    id: str
    name: str
    description: str = ""
    enabled: bool = True
    rules: list[PolicyRule] = Field(default_factory=list)

    def get_matching_rules(self, context: dict[str, Any]) -> list[PolicyRule]:
        """Get all rules that match the context, sorted by priority."""
        if not self.enabled:
            return []

        matching = [r for r in self.rules if r.matches(context)]
        return sorted(matching, key=lambda r: r.priority)

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule to the set."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        for i, r in enumerate(self.rules):
            if r.id == rule_id:
                del self.rules[i]
                return True
        return False

    def get_rule(self, rule_id: str) -> PolicyRule | None:
        """Get a rule by ID."""
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None


# Convenience functions for creating common rules


def ip_allowlist_rule(
    rule_id: str,
    allowed_ips: list[str],
    name: str = "IP Allowlist",
) -> PolicyRule:
    """Create a rule that allows only specific IP addresses/ranges."""
    return PolicyRule(
        id=rule_id,
        name=name,
        conditions=[
            RuleCondition(
                field=MatchField.CLIENT_IP,
                operator=ConditionOperator.IP_IN_CIDR,
                value=allowed_ips,
            )
        ],
        actions=["allow"],
    )


def ip_denylist_rule(
    rule_id: str,
    denied_ips: list[str],
    name: str = "IP Denylist",
) -> PolicyRule:
    """Create a rule that denies specific IP addresses/ranges."""
    return PolicyRule(
        id=rule_id,
        name=name,
        conditions=[
            RuleCondition(
                field=MatchField.CLIENT_IP,
                operator=ConditionOperator.IP_IN_CIDR,
                value=denied_ips,
            )
        ],
        actions=["deny"],
    )


def path_rate_limit_rule(
    rule_id: str,
    path_pattern: str,
    rate_limit_action: str,
    name: str = "Path Rate Limit",
) -> PolicyRule:
    """Create a rule that rate limits requests to specific paths."""
    return PolicyRule(
        id=rule_id,
        name=name,
        conditions=[
            RuleCondition(
                field=MatchField.PATH,
                operator=ConditionOperator.MATCHES,
                value=path_pattern,
            )
        ],
        actions=[rate_limit_action],
    )


def method_restrict_rule(
    rule_id: str,
    allowed_methods: list[str],
    name: str = "Method Restriction",
) -> PolicyRule:
    """Create a rule that restricts allowed HTTP methods."""
    return PolicyRule(
        id=rule_id,
        name=name,
        conditions=[
            RuleCondition(
                field=MatchField.METHOD,
                operator=ConditionOperator.NOT_IN,
                value=allowed_methods,
            )
        ],
        actions=["deny"],
    )


def header_required_rule(
    rule_id: str,
    header_name: str,
    header_value: str | None = None,
    name: str = "Required Header",
) -> PolicyRule:
    """Create a rule that requires a specific header."""
    if header_value:
        condition = RuleCondition(
            field=MatchField.HEADER,
            param=header_name,
            operator=ConditionOperator.EQUALS,
            value=header_value,
        )
    else:
        condition = RuleCondition(
            field=MatchField.HEADER,
            param=header_name,
            operator=ConditionOperator.EXISTS,
        )

    return PolicyRule(
        id=rule_id,
        name=name,
        conditions=[condition],
        match_all=False,  # Invert - this matches when header is missing
        actions=["deny"],
    )
