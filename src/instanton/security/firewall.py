"""Application firewall for Instanton.

This module provides comprehensive firewall capabilities:
- IP allowlist/blocklist
- CIDR range support
- Country blocking (via GeoIP)
- User-agent filtering
- Path-based rules
- Header-based rules
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from re import Pattern
from typing import Any

from cachetools import TTLCache

logger = logging.getLogger(__name__)

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


class RuleAction(Enum):
    """Action to take when a rule matches."""

    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"
    CHALLENGE = "challenge"
    RATE_LIMIT = "rate_limit"


class RuleTarget(Enum):
    """Target of a firewall rule."""

    IP = "ip"
    CIDR = "cidr"
    COUNTRY = "country"
    USER_AGENT = "user_agent"
    PATH = "path"
    HEADER = "header"
    METHOD = "method"
    HOST = "host"


@dataclass
class FirewallRule:
    """A single firewall rule."""

    id: str
    name: str
    target: RuleTarget
    pattern: str
    action: RuleAction
    enabled: bool = True
    priority: int = 100  # Lower = higher priority
    description: str = ""
    created_at: float = field(default_factory=time.time)
    hit_count: int = 0
    last_hit: float | None = None

    # Optional fields for specific rule types
    header_name: str | None = None  # For HEADER rules
    case_sensitive: bool = False
    invert: bool = False  # Invert the match result

    # Compiled pattern (cached)
    _compiled_pattern: Pattern | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Compile the pattern after initialization."""
        self._compile_pattern()

    def _compile_pattern(self) -> None:
        """Compile the pattern for faster matching."""
        if self.target in (RuleTarget.PATH, RuleTarget.USER_AGENT, RuleTarget.HOST):
            # Use fnmatch patterns converted to regex
            try:
                regex_pattern = fnmatch.translate(self.pattern)
                flags = 0 if self.case_sensitive else re.IGNORECASE
                self._compiled_pattern = re.compile(regex_pattern, flags)
            except re.error as e:
                logger.error("Invalid pattern '%s' for rule %s: %s", self.pattern, self.id, e)
                self._compiled_pattern = None
        elif self.target == RuleTarget.HEADER:
            # Header values use regex
            try:
                flags = 0 if self.case_sensitive else re.IGNORECASE
                self._compiled_pattern = re.compile(self.pattern, flags)
            except re.error as e:
                logger.error("Invalid regex '%s' for rule %s: %s", self.pattern, self.id, e)
                self._compiled_pattern = None

    def matches(
        self,
        ip: str | None = None,
        country: str | None = None,
        user_agent: str | None = None,
        path: str | None = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
        host: str | None = None,
    ) -> bool:
        """Check if this rule matches the given request.

        Args:
            ip: Client IP address
            country: Country code from GeoIP
            user_agent: User-Agent header
            path: Request path
            headers: All request headers
            method: HTTP method
            host: Host header

        Returns:
            True if the rule matches
        """
        if not self.enabled:
            return False

        result = self._matches_target(
            ip=ip,
            country=country,
            user_agent=user_agent,
            path=path,
            headers=headers,
            method=method,
            host=host,
        )

        if self.invert:
            result = not result

        if result:
            self.hit_count += 1
            self.last_hit = time.time()

        return result

    def _matches_target(
        self,
        ip: str | None,
        country: str | None,
        user_agent: str | None,
        path: str | None,
        headers: dict[str, str] | None,
        method: str | None,
        host: str | None,
    ) -> bool:
        """Internal matching logic for each target type."""
        if self.target == RuleTarget.IP:
            if not ip:
                return False
            return ip == self.pattern

        elif self.target == RuleTarget.CIDR:
            if not ip:
                return False
            try:
                network = ip_network(self.pattern, strict=False)
                client_ip = ip_address(ip)
                return client_ip in network
            except ValueError:
                return False

        elif self.target == RuleTarget.COUNTRY:
            if not country:
                return False
            pattern_upper = self.pattern.upper()
            country_upper = country.upper()
            if "," in pattern_upper:
                return country_upper in pattern_upper.split(",")
            return country_upper == pattern_upper

        elif self.target == RuleTarget.USER_AGENT:
            if not user_agent:
                return False
            if self._compiled_pattern:
                return bool(self._compiled_pattern.match(user_agent))
            return self.pattern.lower() in user_agent.lower()

        elif self.target == RuleTarget.PATH:
            if not path:
                return False
            if self._compiled_pattern:
                return bool(self._compiled_pattern.match(path))
            return fnmatch.fnmatch(path, self.pattern)

        elif self.target == RuleTarget.HEADER:
            if not headers or not self.header_name:
                return False
            header_value = headers.get(self.header_name)
            if not header_value:
                # Try case-insensitive header lookup
                for name, value in headers.items():
                    if name.lower() == self.header_name.lower():
                        header_value = value
                        break
            if not header_value:
                return False
            if self._compiled_pattern:
                return bool(self._compiled_pattern.search(header_value))
            return self.pattern in header_value

        elif self.target == RuleTarget.METHOD:
            if not method:
                return False
            pattern_upper = self.pattern.upper()
            method_upper = method.upper()
            if "," in pattern_upper:
                return method_upper in pattern_upper.split(",")
            return method_upper == pattern_upper

        elif self.target == RuleTarget.HOST:
            if not host:
                return False
            if self._compiled_pattern:
                return bool(self._compiled_pattern.match(host))
            return fnmatch.fnmatch(host, self.pattern)

        return False

    def to_dict(self) -> dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target.value,
            "pattern": self.pattern,
            "action": self.action.value,
            "enabled": self.enabled,
            "priority": self.priority,
            "description": self.description,
            "created_at": self.created_at,
            "hit_count": self.hit_count,
            "last_hit": self.last_hit,
            "header_name": self.header_name,
            "case_sensitive": self.case_sensitive,
            "invert": self.invert,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FirewallRule:
        """Create rule from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            target=RuleTarget(data["target"]),
            pattern=data["pattern"],
            action=RuleAction(data["action"]),
            enabled=data.get("enabled", True),
            priority=data.get("priority", 100),
            description=data.get("description", ""),
            created_at=data.get("created_at", time.time()),
            hit_count=data.get("hit_count", 0),
            last_hit=data.get("last_hit"),
            header_name=data.get("header_name"),
            case_sensitive=data.get("case_sensitive", False),
            invert=data.get("invert", False),
        )


@dataclass
class FirewallResult:
    """Result of a firewall check."""

    allowed: bool
    action: RuleAction
    matched_rule: FirewallRule | None = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "allowed": self.allowed,
            "action": self.action.value,
            "matched_rule_id": self.matched_rule.id if self.matched_rule else None,
            "message": self.message,
        }


class Firewall:
    """Application firewall with comprehensive filtering capabilities."""

    def __init__(
        self,
        default_action: RuleAction = RuleAction.ALLOW,
        enable_logging: bool = True,
        cache_size: int = 10000,
        cache_ttl: float = 60.0,
    ) -> None:
        """Initialize the firewall.

        Args:
            default_action: Action when no rules match
            enable_logging: Enable logging of matches
            cache_size: Size of the decision cache
            cache_ttl: TTL for cached decisions
        """
        self._default_action = default_action
        self._enable_logging = enable_logging
        self._rules: list[FirewallRule] = []
        self._rules_by_id: dict[str, FirewallRule] = {}
        self._lock = asyncio.Lock()

        # IP allowlist and blocklist for fast lookup
        self._ip_allowlist: set[str] = set()
        self._ip_blocklist: set[str] = set()
        self._cidr_allowlist: list[IPNetwork] = []
        self._cidr_blocklist: list[IPNetwork] = []

        # Decision cache
        self._cache: TTLCache = TTLCache(maxsize=cache_size, ttl=cache_ttl)

        # Statistics
        self._stats = {
            "total_checks": 0,
            "allowed": 0,
            "denied": 0,
            "cache_hits": 0,
        }

    @property
    def rules(self) -> list[FirewallRule]:
        """Get all rules (sorted by priority)."""
        return sorted(self._rules, key=lambda r: r.priority)

    def add_rule(self, rule: FirewallRule) -> None:
        """Add a firewall rule.

        Args:
            rule: Rule to add
        """
        if rule.id in self._rules_by_id:
            raise ValueError(f"Rule with ID '{rule.id}' already exists")

        self._rules.append(rule)
        self._rules_by_id[rule.id] = rule

        # Update fast lookup sets
        if rule.target == RuleTarget.IP and rule.enabled:
            if rule.action == RuleAction.ALLOW:
                self._ip_allowlist.add(rule.pattern)
            elif rule.action == RuleAction.DENY:
                self._ip_blocklist.add(rule.pattern)
        elif rule.target == RuleTarget.CIDR and rule.enabled:
            try:
                network = ip_network(rule.pattern, strict=False)
                if rule.action == RuleAction.ALLOW:
                    self._cidr_allowlist.append(network)
                elif rule.action == RuleAction.DENY:
                    self._cidr_blocklist.append(network)
            except ValueError:
                pass

        # Clear cache when rules change
        self._cache.clear()

        logger.info("Added firewall rule: %s (%s)", rule.name, rule.id)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a firewall rule.

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if rule was removed
        """
        if rule_id not in self._rules_by_id:
            return False

        rule = self._rules_by_id[rule_id]
        self._rules.remove(rule)
        del self._rules_by_id[rule_id]

        # Update fast lookup sets
        if rule.target == RuleTarget.IP:
            self._ip_allowlist.discard(rule.pattern)
            self._ip_blocklist.discard(rule.pattern)
        elif rule.target == RuleTarget.CIDR:
            try:
                network = ip_network(rule.pattern, strict=False)
                if network in self._cidr_allowlist:
                    self._cidr_allowlist.remove(network)
                if network in self._cidr_blocklist:
                    self._cidr_blocklist.remove(network)
            except ValueError:
                pass

        # Clear cache when rules change
        self._cache.clear()

        logger.info("Removed firewall rule: %s", rule_id)
        return True

    def update_rule(self, rule_id: str, **updates: Any) -> bool:
        """Update a firewall rule.

        Args:
            rule_id: ID of the rule to update
            **updates: Fields to update

        Returns:
            True if rule was updated
        """
        if rule_id not in self._rules_by_id:
            return False

        rule = self._rules_by_id[rule_id]

        for key, value in updates.items():
            if hasattr(rule, key):
                setattr(rule, key, value)

        # Recompile pattern if changed
        if "pattern" in updates:
            rule._compile_pattern()

        # Clear cache when rules change
        self._cache.clear()

        logger.info("Updated firewall rule: %s", rule_id)
        return True

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a firewall rule."""
        return self.update_rule(rule_id, enabled=True)

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a firewall rule."""
        return self.update_rule(rule_id, enabled=False)

    def get_rule(self, rule_id: str) -> FirewallRule | None:
        """Get a rule by ID."""
        return self._rules_by_id.get(rule_id)

    def add_ip_to_allowlist(self, ip: str, name: str = "") -> FirewallRule:
        """Convenience method to add an IP to the allowlist.

        Args:
            ip: IP address to allow
            name: Optional name for the rule

        Returns:
            The created rule
        """
        rule_id = f"allowlist_ip_{ip.replace('.', '_').replace(':', '_')}"
        rule = FirewallRule(
            id=rule_id,
            name=name or f"Allowlist IP {ip}",
            target=RuleTarget.IP,
            pattern=ip,
            action=RuleAction.ALLOW,
            priority=10,  # High priority for allowlist
        )
        self.add_rule(rule)
        return rule

    def add_ip_to_blocklist(self, ip: str, name: str = "") -> FirewallRule:
        """Convenience method to add an IP to the blocklist.

        Args:
            ip: IP address to block
            name: Optional name for the rule

        Returns:
            The created rule
        """
        rule_id = f"blocklist_ip_{ip.replace('.', '_').replace(':', '_')}"
        rule = FirewallRule(
            id=rule_id,
            name=name or f"Blocklist IP {ip}",
            target=RuleTarget.IP,
            pattern=ip,
            action=RuleAction.DENY,
            priority=20,
        )
        self.add_rule(rule)
        return rule

    def add_cidr_to_allowlist(self, cidr: str, name: str = "") -> FirewallRule:
        """Add a CIDR range to the allowlist.

        Args:
            cidr: CIDR range to allow (e.g., "192.168.1.0/24")
            name: Optional name for the rule

        Returns:
            The created rule
        """
        rule_id = f"allowlist_cidr_{cidr.replace('.', '_').replace('/', '_').replace(':', '_')}"
        rule = FirewallRule(
            id=rule_id,
            name=name or f"Allowlist CIDR {cidr}",
            target=RuleTarget.CIDR,
            pattern=cidr,
            action=RuleAction.ALLOW,
            priority=15,
        )
        self.add_rule(rule)
        return rule

    def add_cidr_to_blocklist(self, cidr: str, name: str = "") -> FirewallRule:
        """Add a CIDR range to the blocklist.

        Args:
            cidr: CIDR range to block (e.g., "192.168.1.0/24")
            name: Optional name for the rule

        Returns:
            The created rule
        """
        rule_id = f"blocklist_cidr_{cidr.replace('.', '_').replace('/', '_').replace(':', '_')}"
        rule = FirewallRule(
            id=rule_id,
            name=name or f"Blocklist CIDR {cidr}",
            target=RuleTarget.CIDR,
            pattern=cidr,
            action=RuleAction.DENY,
            priority=25,
        )
        self.add_rule(rule)
        return rule

    def block_country(self, country_code: str, name: str = "") -> FirewallRule:
        """Block a country by country code.

        Args:
            country_code: ISO country code (e.g., "CN", "RU")
            name: Optional name for the rule

        Returns:
            The created rule
        """
        rule_id = f"block_country_{country_code.upper()}"
        rule = FirewallRule(
            id=rule_id,
            name=name or f"Block country {country_code.upper()}",
            target=RuleTarget.COUNTRY,
            pattern=country_code.upper(),
            action=RuleAction.DENY,
            priority=50,
        )
        self.add_rule(rule)
        return rule

    def block_user_agent_pattern(self, pattern: str, name: str = "") -> FirewallRule:
        """Block user agents matching a pattern.

        Args:
            pattern: Glob pattern to match (e.g., "*bot*", "*curl*")
            name: Optional name for the rule

        Returns:
            The created rule
        """
        import hashlib

        pattern_hash = hashlib.md5(pattern.encode()).hexdigest()[:8]
        rule_id = f"block_ua_{pattern_hash}"
        rule = FirewallRule(
            id=rule_id,
            name=name or f"Block User-Agent {pattern}",
            target=RuleTarget.USER_AGENT,
            pattern=pattern,
            action=RuleAction.DENY,
            priority=60,
        )
        self.add_rule(rule)
        return rule

    def block_path_pattern(self, pattern: str, name: str = "") -> FirewallRule:
        """Block paths matching a pattern.

        Args:
            pattern: Glob pattern to match (e.g., "/admin/*", "*.php")
            name: Optional name for the rule

        Returns:
            The created rule
        """
        import hashlib

        pattern_hash = hashlib.md5(pattern.encode()).hexdigest()[:8]
        rule_id = f"block_path_{pattern_hash}"
        rule = FirewallRule(
            id=rule_id,
            name=name or f"Block path {pattern}",
            target=RuleTarget.PATH,
            pattern=pattern,
            action=RuleAction.DENY,
            priority=70,
        )
        self.add_rule(rule)
        return rule

    def _generate_cache_key(
        self,
        ip: str | None,
        country: str | None,
        user_agent: str | None,
        path: str | None,
        method: str | None,
        host: str | None,
    ) -> str:
        """Generate a cache key for a request."""
        return f"{ip}|{country}|{user_agent}|{path}|{method}|{host}"

    async def check(
        self,
        ip: str | None = None,
        country: str | None = None,
        user_agent: str | None = None,
        path: str | None = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
        host: str | None = None,
    ) -> FirewallResult:
        """Check a request against the firewall rules.

        Rules are evaluated in priority order. First matching rule determines the action.

        Args:
            ip: Client IP address
            country: Country code from GeoIP
            user_agent: User-Agent header
            path: Request path
            headers: All request headers
            method: HTTP method
            host: Host header

        Returns:
            FirewallResult with the decision
        """
        self._stats["total_checks"] += 1

        # Check cache first
        cache_key = self._generate_cache_key(ip, country, user_agent, path, method, host)
        if cache_key in self._cache:
            self._stats["cache_hits"] += 1
            return self._cache[cache_key]

        # Fast path: check IP allowlist/blocklist
        if ip:
            if ip in self._ip_allowlist:
                result = FirewallResult(
                    allowed=True,
                    action=RuleAction.ALLOW,
                    message="IP in allowlist",
                )
                self._stats["allowed"] += 1
                self._cache[cache_key] = result
                return result

            if ip in self._ip_blocklist:
                result = FirewallResult(
                    allowed=False,
                    action=RuleAction.DENY,
                    message="IP in blocklist",
                )
                self._stats["denied"] += 1
                self._cache[cache_key] = result
                return result

            # Check CIDR allowlist/blocklist
            try:
                client_ip = ip_address(ip)
                for network in self._cidr_allowlist:
                    if client_ip in network:
                        result = FirewallResult(
                            allowed=True,
                            action=RuleAction.ALLOW,
                            message=f"IP in allowlisted CIDR {network}",
                        )
                        self._stats["allowed"] += 1
                        self._cache[cache_key] = result
                        return result

                for network in self._cidr_blocklist:
                    if client_ip in network:
                        result = FirewallResult(
                            allowed=False,
                            action=RuleAction.DENY,
                            message=f"IP in blocklisted CIDR {network}",
                        )
                        self._stats["denied"] += 1
                        self._cache[cache_key] = result
                        return result
            except ValueError:
                pass

        # Evaluate rules in priority order
        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.matches(
                ip=ip,
                country=country,
                user_agent=user_agent,
                path=path,
                headers=headers,
                method=method,
                host=host,
            ):
                allowed = rule.action in (RuleAction.ALLOW, RuleAction.LOG, RuleAction.RATE_LIMIT)

                if self._enable_logging:
                    log_level = logging.DEBUG if allowed else logging.WARNING
                    logger.log(
                        log_level,
                        "Firewall rule matched: %s (%s) -> %s for IP=%s path=%s",
                        rule.name,
                        rule.id,
                        rule.action.value,
                        ip,
                        path,
                    )

                result = FirewallResult(
                    allowed=allowed,
                    action=rule.action,
                    matched_rule=rule,
                    message=f"Matched rule: {rule.name}",
                )

                if allowed:
                    self._stats["allowed"] += 1
                else:
                    self._stats["denied"] += 1

                self._cache[cache_key] = result
                return result

        # No rules matched, use default action
        allowed = self._default_action in (RuleAction.ALLOW, RuleAction.LOG)
        result = FirewallResult(
            allowed=allowed,
            action=self._default_action,
            message="No rules matched, using default action",
        )

        if allowed:
            self._stats["allowed"] += 1
        else:
            self._stats["denied"] += 1

        self._cache[cache_key] = result
        return result

    def clear_cache(self) -> None:
        """Clear the decision cache."""
        self._cache.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get firewall statistics."""
        return {
            **self._stats,
            "rule_count": len(self._rules),
            "ip_allowlist_size": len(self._ip_allowlist),
            "ip_blocklist_size": len(self._ip_blocklist),
            "cidr_allowlist_size": len(self._cidr_allowlist),
            "cidr_blocklist_size": len(self._cidr_blocklist),
            "cache_size": len(self._cache),
        }

    def export_rules(self) -> list[dict[str, Any]]:
        """Export all rules as a list of dictionaries."""
        return [rule.to_dict() for rule in self._rules]

    def import_rules(self, rules_data: list[dict[str, Any]]) -> int:
        """Import rules from a list of dictionaries.

        Args:
            rules_data: List of rule dictionaries

        Returns:
            Number of rules imported
        """
        imported = 0
        for rule_data in rules_data:
            try:
                rule = FirewallRule.from_dict(rule_data)
                if rule.id not in self._rules_by_id:
                    self.add_rule(rule)
                    imported += 1
            except Exception as e:
                logger.error("Failed to import rule: %s", e)
        return imported


@dataclass
class FirewallConfig:
    """Configuration for the firewall."""

    enabled: bool = True
    default_action: str = "allow"  # "allow" or "deny"
    enable_logging: bool = True
    cache_size: int = 10000
    cache_ttl: float = 60.0
    ip_allowlist: list[str] = field(default_factory=list)
    ip_blocklist: list[str] = field(default_factory=list)
    cidr_allowlist: list[str] = field(default_factory=list)
    cidr_blocklist: list[str] = field(default_factory=list)
    blocked_countries: list[str] = field(default_factory=list)
    blocked_user_agents: list[str] = field(default_factory=list)
    blocked_paths: list[str] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)

    def create_firewall(self) -> Firewall:
        """Create a Firewall from this configuration."""
        default = RuleAction.ALLOW if self.default_action == "allow" else RuleAction.DENY

        firewall = Firewall(
            default_action=default,
            enable_logging=self.enable_logging,
            cache_size=self.cache_size,
            cache_ttl=self.cache_ttl,
        )

        # Add allowlist IPs
        for ip in self.ip_allowlist:
            firewall.add_ip_to_allowlist(ip)

        # Add blocklist IPs
        for ip in self.ip_blocklist:
            firewall.add_ip_to_blocklist(ip)

        # Add CIDR allowlist
        for cidr in self.cidr_allowlist:
            firewall.add_cidr_to_allowlist(cidr)

        # Add CIDR blocklist
        for cidr in self.cidr_blocklist:
            firewall.add_cidr_to_blocklist(cidr)

        # Add blocked countries
        for country in self.blocked_countries:
            firewall.block_country(country)

        # Add blocked user agents
        for ua_pattern in self.blocked_user_agents:
            firewall.block_user_agent_pattern(ua_pattern)

        # Add blocked paths
        for path_pattern in self.blocked_paths:
            firewall.block_path_pattern(path_pattern)

        # Import additional rules
        if self.rules:
            firewall.import_rules(self.rules)

        return firewall
