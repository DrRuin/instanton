"""Tests for IP restrictions module."""

from __future__ import annotations

import pytest

from instanton.security.iprestrict import (
    IPCheckResult,
    IPPolicy,
    IPRestrictor,
    create_ip_restrictor,
)


class TestIPRestrictor:
    """Tests for IPRestrictor."""

    def test_default_allow_policy(self):
        """Test default allow policy."""
        restrictor = IPRestrictor()
        assert restrictor.is_allowed("192.168.1.1") is True
        assert restrictor.is_allowed("10.0.0.1") is True

    def test_default_deny_policy(self):
        """Test deny default policy."""
        restrictor = IPRestrictor(default_policy=IPPolicy.DENY)
        assert restrictor.is_allowed("192.168.1.1") is False
        assert restrictor.is_allowed("10.0.0.1") is False

    def test_allow_list_exact_ip(self):
        """Test allow list with exact IP."""
        restrictor = IPRestrictor(
            allow=["192.168.1.100"],
            default_policy=IPPolicy.DENY,
        )
        assert restrictor.is_allowed("192.168.1.100") is True
        assert restrictor.is_allowed("192.168.1.101") is False

    def test_deny_list_exact_ip(self):
        """Test deny list with exact IP."""
        restrictor = IPRestrictor(deny=["192.168.1.100"])
        assert restrictor.is_allowed("192.168.1.100") is False
        assert restrictor.is_allowed("192.168.1.101") is True

    def test_allow_list_cidr(self):
        """Test allow list with CIDR notation."""
        restrictor = IPRestrictor(
            allow=["10.0.0.0/8"],
            default_policy=IPPolicy.DENY,
        )
        assert restrictor.is_allowed("10.0.0.1") is True
        assert restrictor.is_allowed("10.255.255.255") is True
        assert restrictor.is_allowed("11.0.0.1") is False

    def test_deny_list_cidr(self):
        """Test deny list with CIDR notation."""
        restrictor = IPRestrictor(deny=["10.0.0.0/8"])
        assert restrictor.is_allowed("10.0.0.1") is False
        assert restrictor.is_allowed("10.255.255.255") is False
        assert restrictor.is_allowed("192.168.1.1") is True

    def test_deny_takes_precedence(self):
        """Test that deny rules take precedence over allow."""
        restrictor = IPRestrictor(
            allow=["10.0.0.0/8"],
            deny=["10.0.0.100"],  # Deny specific IP in allowed range
            default_policy=IPPolicy.DENY,
        )
        assert restrictor.is_allowed("10.0.0.1") is True
        assert restrictor.is_allowed("10.0.0.100") is False  # Deny takes precedence
        assert restrictor.is_allowed("10.0.0.101") is True

    def test_ipv6_support(self):
        """Test IPv6 address support."""
        restrictor = IPRestrictor(
            allow=["2001:db8::/32"],
            default_policy=IPPolicy.DENY,
        )
        assert restrictor.is_allowed("2001:db8::1") is True
        assert restrictor.is_allowed("2001:db9::1") is False

    def test_check_returns_result_object(self):
        """Test check returns IPCheckResult."""
        restrictor = IPRestrictor()
        result = restrictor.check("192.168.1.1")
        assert isinstance(result, IPCheckResult)
        assert result.allowed is True
        assert isinstance(result.reason, str)

    def test_check_result_denied(self):
        """Test check result when denied."""
        restrictor = IPRestrictor(deny=["192.168.1.100"])
        result = restrictor.check("192.168.1.100")
        assert result.allowed is False
        assert result.matched_rule == "192.168.1.100"
        assert "deny" in result.reason.lower()

    def test_check_result_allowed_by_rule(self):
        """Test check result when allowed by rule."""
        restrictor = IPRestrictor(
            allow=["192.168.1.0/24"],
            default_policy=IPPolicy.DENY,
        )
        result = restrictor.check("192.168.1.50")
        assert result.allowed is True
        assert result.matched_rule == "192.168.1.0/24"

    def test_invalid_ip_denied(self):
        """Test invalid IP address is denied."""
        restrictor = IPRestrictor()
        result = restrictor.check("not-an-ip")
        assert result.allowed is False
        assert "Invalid" in result.reason

    def test_add_allow_rule(self):
        """Test adding allow rule dynamically."""
        restrictor = IPRestrictor(default_policy=IPPolicy.DENY)
        assert restrictor.is_allowed("10.0.0.1") is False

        restrictor.add_allow("10.0.0.0/8")
        assert restrictor.is_allowed("10.0.0.1") is True

    def test_add_deny_rule(self):
        """Test adding deny rule dynamically."""
        restrictor = IPRestrictor()
        assert restrictor.is_allowed("192.168.1.1") is True

        restrictor.add_deny("192.168.1.1")
        assert restrictor.is_allowed("192.168.1.1") is False

    def test_remove_allow_rule(self):
        """Test removing allow rule."""
        restrictor = IPRestrictor(
            allow=["10.0.0.0/8"],
            default_policy=IPPolicy.DENY,
        )
        assert restrictor.is_allowed("10.0.0.1") is True

        result = restrictor.remove_allow("10.0.0.0/8")
        assert result is True
        assert restrictor.is_allowed("10.0.0.1") is False

    def test_remove_deny_rule(self):
        """Test removing deny rule."""
        restrictor = IPRestrictor(deny=["192.168.1.1"])
        assert restrictor.is_allowed("192.168.1.1") is False

        result = restrictor.remove_deny("192.168.1.1")
        assert result is True
        assert restrictor.is_allowed("192.168.1.1") is True

    def test_remove_nonexistent_rule(self):
        """Test removing rule that doesn't exist."""
        restrictor = IPRestrictor()
        result = restrictor.remove_allow("10.0.0.0/8")
        assert result is False

    def test_clear_all_rules(self):
        """Test clearing all rules."""
        restrictor = IPRestrictor(
            allow=["10.0.0.0/8", "192.168.1.1"],
            deny=["172.16.0.0/12"],
        )
        assert restrictor.rule_count > 0

        restrictor.clear()
        assert restrictor.rule_count == 0

    def test_rule_count(self):
        """Test rule count property."""
        restrictor = IPRestrictor(
            allow=["10.0.0.0/8", "192.168.1.1"],  # 1 network + 1 exact
            deny=["172.16.0.0/12"],  # 1 network
        )
        assert restrictor.rule_count == 3

    def test_whitespace_handling(self):
        """Test that whitespace is handled correctly."""
        restrictor = IPRestrictor(
            allow=["  10.0.0.1  ", "192.168.1.0/24 "],
            default_policy=IPPolicy.DENY,
        )
        assert restrictor.is_allowed("10.0.0.1") is True
        assert restrictor.is_allowed("192.168.1.50") is True

    def test_empty_rule_ignored(self):
        """Test that empty rules are ignored."""
        restrictor = IPRestrictor(
            allow=["", "   ", "10.0.0.1"],
            default_policy=IPPolicy.DENY,
        )
        # Should not raise and should work with valid rule
        assert restrictor.is_allowed("10.0.0.1") is True
        assert restrictor.rule_count == 1

    def test_invalid_cidr_ignored(self):
        """Test that invalid CIDR notation is ignored."""
        restrictor = IPRestrictor(
            allow=["invalid-cidr", "10.0.0.1"],
            default_policy=IPPolicy.DENY,
        )
        # Should work with valid rule
        assert restrictor.is_allowed("10.0.0.1") is True


class TestCreateIPRestrictor:
    """Tests for create_ip_restrictor factory."""

    def test_creates_with_defaults(self):
        """Test create with default values."""
        restrictor = create_ip_restrictor()
        assert restrictor.default_policy == IPPolicy.ALLOW
        assert restrictor.rule_count == 0

    def test_creates_with_allow_list(self):
        """Test create with allow list."""
        restrictor = create_ip_restrictor(
            allow=["10.0.0.0/8", "192.168.1.1"],
            default_policy="deny",
        )
        assert restrictor.default_policy == IPPolicy.DENY
        assert restrictor.is_allowed("10.0.0.1") is True
        assert restrictor.is_allowed("8.8.8.8") is False

    def test_creates_with_deny_list(self):
        """Test create with deny list."""
        restrictor = create_ip_restrictor(
            deny=["192.168.1.100", "10.0.0.0/8"],
        )
        assert restrictor.is_allowed("192.168.1.100") is False
        assert restrictor.is_allowed("10.0.0.1") is False
        assert restrictor.is_allowed("8.8.8.8") is True

    def test_none_values_handled(self):
        """Test None values for allow/deny."""
        restrictor = create_ip_restrictor(allow=None, deny=None)
        assert restrictor.rule_count == 0


class TestIPPolicy:
    """Tests for IPPolicy enum."""

    def test_policy_values(self):
        """Test IPPolicy enum values."""
        assert IPPolicy.ALLOW.value == "allow"
        assert IPPolicy.DENY.value == "deny"


class TestIPCheckResult:
    """Tests for IPCheckResult dataclass."""

    def test_result_fields(self):
        """Test IPCheckResult has correct fields."""
        result = IPCheckResult(
            allowed=True,
            matched_rule="10.0.0.0/8",
            reason="IP in allowed network",
        )
        assert result.allowed is True
        assert result.matched_rule == "10.0.0.0/8"
        assert result.reason == "IP in allowed network"

    def test_result_none_matched_rule(self):
        """Test IPCheckResult with no matched rule."""
        result = IPCheckResult(
            allowed=True,
            matched_rule=None,
            reason="Default policy: allow",
        )
        assert result.matched_rule is None
