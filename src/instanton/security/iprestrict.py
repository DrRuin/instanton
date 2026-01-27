"""IP restriction with CIDR allow/deny lists.

Uses Python's built-in ipaddress module for fast network matching.
Supports both IPv4 and IPv6 addresses and CIDR notation.

Example:
    restrictor = IPRestrictor(
        allow=["10.0.0.0/8", "192.168.1.0/24"],
        deny=["192.168.1.100"],
    )

    if restrictor.is_allowed("192.168.1.50"):
        handle_request()
    else:
        return 403  # Forbidden
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network


class IPPolicy(Enum):
    """Default policy when no rules match."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass
class IPCheckResult:
    """Result of an IP restriction check."""

    allowed: bool
    matched_rule: str | None
    reason: str


@dataclass
class IPRestrictor:
    """Fast IP restriction checker with CIDR support.

    Rules are evaluated in order:
    1. Check deny list (if match, deny)
    2. Check allow list (if match, allow)
    3. Apply default policy

    Both IPv4 and IPv6 are supported.
    """

    allow: Sequence[str] = field(default_factory=list)
    deny: Sequence[str] = field(default_factory=list)
    default_policy: IPPolicy = IPPolicy.ALLOW

    _allow_networks: list[IPv4Network | IPv6Network] = field(default_factory=list, init=False)
    _deny_networks: list[IPv4Network | IPv6Network] = field(default_factory=list, init=False)
    _allow_exact: set[IPv4Address | IPv6Address] = field(default_factory=set, init=False)
    _deny_exact: set[IPv4Address | IPv6Address] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        """Parse and optimize rule lists."""
        for rule in self.allow:
            self._add_rule(rule, allow=True)
        for rule in self.deny:
            self._add_rule(rule, allow=False)

    def _add_rule(self, rule: str, allow: bool) -> None:
        """Parse and add a rule to the appropriate list."""
        rule = rule.strip()
        if not rule:
            return

        try:
            if "/" in rule:
                network = ip_network(rule, strict=False)
                if allow:
                    self._allow_networks.append(network)
                else:
                    self._deny_networks.append(network)
            else:
                addr = ip_address(rule)
                if allow:
                    self._allow_exact.add(addr)
                else:
                    self._deny_exact.add(addr)
        except ValueError:
            pass

    def is_allowed(self, ip: str) -> bool:
        """Quick check if IP is allowed. O(n) where n is number of rules."""
        return self.check(ip).allowed

    def check(self, ip: str) -> IPCheckResult:
        """Check if IP is allowed with detailed result."""
        try:
            addr = ip_address(ip.strip())
        except ValueError:
            return IPCheckResult(
                allowed=False,
                matched_rule=None,
                reason=f"Invalid IP address: {ip}",
            )

        if addr in self._deny_exact:
            return IPCheckResult(
                allowed=False,
                matched_rule=str(addr),
                reason="IP in deny list",
            )

        for network in self._deny_networks:
            if addr in network:
                return IPCheckResult(
                    allowed=False,
                    matched_rule=str(network),
                    reason="IP in denied network",
                )

        if addr in self._allow_exact:
            return IPCheckResult(
                allowed=True,
                matched_rule=str(addr),
                reason="IP in allow list",
            )

        for network in self._allow_networks:
            if addr in network:
                return IPCheckResult(
                    allowed=True,
                    matched_rule=str(network),
                    reason="IP in allowed network",
                )

        if self.default_policy == IPPolicy.ALLOW:
            return IPCheckResult(
                allowed=True,
                matched_rule=None,
                reason="Default policy: allow",
            )
        else:
            return IPCheckResult(
                allowed=False,
                matched_rule=None,
                reason="Default policy: deny",
            )

    def add_allow(self, rule: str) -> None:
        """Add a rule to the allow list."""
        self._add_rule(rule, allow=True)

    def add_deny(self, rule: str) -> None:
        """Add a rule to the deny list."""
        self._add_rule(rule, allow=False)

    def remove_allow(self, rule: str) -> bool:
        """Remove a rule from the allow list. Returns True if found."""
        rule = rule.strip()
        try:
            if "/" in rule:
                network = ip_network(rule, strict=False)
                if network in self._allow_networks:
                    self._allow_networks.remove(network)
                    return True
            else:
                addr = ip_address(rule)
                if addr in self._allow_exact:
                    self._allow_exact.discard(addr)
                    return True
        except ValueError:
            pass
        return False

    def remove_deny(self, rule: str) -> bool:
        """Remove a rule from the deny list. Returns True if found."""
        rule = rule.strip()
        try:
            if "/" in rule:
                network = ip_network(rule, strict=False)
                if network in self._deny_networks:
                    self._deny_networks.remove(network)
                    return True
            else:
                addr = ip_address(rule)
                if addr in self._deny_exact:
                    self._deny_exact.discard(addr)
                    return True
        except ValueError:
            pass
        return False

    def clear(self) -> None:
        """Clear all rules."""
        self._allow_networks.clear()
        self._deny_networks.clear()
        self._allow_exact.clear()
        self._deny_exact.clear()

    @property
    def rule_count(self) -> int:
        """Total number of rules."""
        return (
            len(self._allow_networks)
            + len(self._deny_networks)
            + len(self._allow_exact)
            + len(self._deny_exact)
        )


def create_ip_restrictor(
    allow: Sequence[str] | None = None,
    deny: Sequence[str] | None = None,
    default_policy: str = "allow",
) -> IPRestrictor:
    """Create an IP restrictor with the given rules.

    Args:
        allow: List of allowed IPs/CIDRs (e.g., ["10.0.0.0/8", "192.168.1.1"])
        deny: List of denied IPs/CIDRs
        default_policy: "allow" or "deny" when no rules match

    Returns:
        Configured IPRestrictor instance
    """
    policy = IPPolicy.ALLOW if default_policy == "allow" else IPPolicy.DENY
    return IPRestrictor(
        allow=allow or [],
        deny=deny or [],
        default_policy=policy,
    )
