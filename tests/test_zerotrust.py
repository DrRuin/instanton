"""Tests for Zero Trust Network Access (ZTNA) module."""

from datetime import UTC, datetime, timedelta

import pytest

from instanton.security.zerotrust import (
    AccessDecision,
    AccessRequest,
    AccessResult,
    DeviceComplianceStatus,
    DeviceInfo,
    DevicePosturePolicy,
    IdentityContext,
    RiskLevel,
    RiskScore,
    TrustLevel,
    ZeroTrustEngine,
    ZeroTrustPolicy,
    create_device_from_request,
    create_moderate_policy,
    create_permissive_policy,
    create_service_identity,
    create_strict_policy,
    create_user_identity,
    evaluate_access,
    get_zero_trust_engine,
)

# ==============================================================================
# Trust Level and Risk Score Tests
# ==============================================================================


class TestTrustLevel:
    """Tests for TrustLevel enumeration."""

    def test_trust_levels_order(self):
        """Test that trust levels are ordered correctly."""
        assert TrustLevel.UNTRUSTED.value < TrustLevel.LOW.value
        assert TrustLevel.LOW.value < TrustLevel.MEDIUM.value
        assert TrustLevel.MEDIUM.value < TrustLevel.HIGH.value
        assert TrustLevel.HIGH.value < TrustLevel.VERIFIED.value

    def test_trust_level_comparison(self):
        """Test trust level value comparisons."""
        assert TrustLevel.HIGH.value > TrustLevel.LOW.value
        assert TrustLevel.MEDIUM.value >= TrustLevel.MEDIUM.value


class TestRiskScore:
    """Tests for RiskScore dataclass."""

    def test_default_risk_score(self):
        """Test default risk score initialization."""
        risk = RiskScore()
        assert risk.overall == 0.0
        assert risk.identity_risk == 0.0
        assert risk.device_risk == 0.0
        assert risk.network_risk == 0.0
        assert risk.behavior_risk == 0.0
        assert risk.resource_risk == 0.0
        assert risk.factors == []

    def test_calculate_overall(self):
        """Test overall risk calculation with weights."""
        risk = RiskScore(
            identity_risk=0.5,
            device_risk=0.5,
            network_risk=0.5,
            behavior_risk=0.5,
            resource_risk=0.5,
        )
        overall = risk.calculate_overall()
        assert overall == 0.5
        assert risk.overall == 0.5

    def test_calculate_overall_weighted(self):
        """Test weighted risk calculation."""
        risk = RiskScore(
            identity_risk=1.0,  # 0.25 weight
            device_risk=0.0,  # 0.20 weight
            network_risk=0.0,  # 0.20 weight
            behavior_risk=0.0,  # 0.20 weight
            resource_risk=0.0,  # 0.15 weight
        )
        overall = risk.calculate_overall()
        assert overall == 0.25

    def test_risk_level_minimal(self):
        """Test minimal risk level classification."""
        risk = RiskScore(overall=0.1)
        assert risk.risk_level == RiskLevel.MINIMAL

    def test_risk_level_low(self):
        """Test low risk level classification."""
        risk = RiskScore(overall=0.3)
        assert risk.risk_level == RiskLevel.LOW

    def test_risk_level_medium(self):
        """Test medium risk level classification."""
        risk = RiskScore(overall=0.5)
        assert risk.risk_level == RiskLevel.MEDIUM

    def test_risk_level_high(self):
        """Test high risk level classification."""
        risk = RiskScore(overall=0.7)
        assert risk.risk_level == RiskLevel.HIGH

    def test_risk_level_critical(self):
        """Test critical risk level classification."""
        risk = RiskScore(overall=0.9)
        assert risk.risk_level == RiskLevel.CRITICAL


# ==============================================================================
# Device Info and Posture Tests
# ==============================================================================


class TestDeviceInfo:
    """Tests for DeviceInfo dataclass."""

    def test_default_device_info(self):
        """Test default device info initialization."""
        device = DeviceInfo(device_id="test-device")
        assert device.device_id == "test-device"
        assert device.device_type == "unknown"
        assert device.is_managed is False
        assert device.disk_encrypted is False

    def test_compliance_status_compliant(self):
        """Test compliant device status."""
        device = DeviceInfo(
            device_id="test",
            disk_encrypted=True,
            firewall_enabled=True,
            os_up_to_date=True,
        )
        assert device.compliance_status() == DeviceComplianceStatus.COMPLIANT

    def test_compliance_status_jailbroken(self):
        """Test non-compliant status for jailbroken device."""
        device = DeviceInfo(
            device_id="test",
            jailbroken=True,
            disk_encrypted=True,
            firewall_enabled=True,
        )
        assert device.compliance_status() == DeviceComplianceStatus.NON_COMPLIANT

    def test_compliance_status_rooted(self):
        """Test non-compliant status for rooted device."""
        device = DeviceInfo(
            device_id="test",
            rooted=True,
            disk_encrypted=True,
            firewall_enabled=True,
        )
        assert device.compliance_status() == DeviceComplianceStatus.NON_COMPLIANT

    def test_compliance_status_needs_update(self):
        """Test requires update status."""
        device = DeviceInfo(
            device_id="test",
            disk_encrypted=True,
            firewall_enabled=True,
            os_up_to_date=False,
        )
        assert device.compliance_status() == DeviceComplianceStatus.REQUIRES_UPDATE

    def test_calculate_risk_low(self):
        """Test low risk calculation for compliant device."""
        device = DeviceInfo(
            device_id="test",
            disk_encrypted=True,
            firewall_enabled=True,
            antivirus_active=True,
            os_up_to_date=True,
            is_managed=True,
        )
        risk = device.calculate_risk()
        assert risk == 0.0

    def test_calculate_risk_high(self):
        """Test high risk calculation for problematic device."""
        device = DeviceInfo(
            device_id="test",
            jailbroken=True,
            is_tor=True,
            disk_encrypted=False,
            firewall_enabled=False,
        )
        risk = device.calculate_risk()
        assert risk > 0.7


class TestDevicePosturePolicy:
    """Tests for DevicePosturePolicy."""

    def test_default_policy(self):
        """Test default policy initialization."""
        policy = DevicePosturePolicy()
        assert policy.require_disk_encryption is True
        assert policy.require_firewall is True
        assert policy.block_jailbroken is True
        assert policy.block_rooted is True
        assert policy.block_tor is True

    def test_evaluate_compliant_device(self):
        """Test evaluation of compliant device."""
        policy = DevicePosturePolicy()
        device = DeviceInfo(
            device_id="test",
            disk_encrypted=True,
            firewall_enabled=True,
            os_up_to_date=True,  # Default policy requires OS to be updated
        )
        is_compliant, violations = policy.evaluate(device)
        assert is_compliant is True
        assert violations == []

    def test_evaluate_non_compliant_jailbroken(self):
        """Test evaluation of jailbroken device."""
        policy = DevicePosturePolicy()
        device = DeviceInfo(
            device_id="test",
            jailbroken=True,
            disk_encrypted=True,
            firewall_enabled=True,
        )
        is_compliant, violations = policy.evaluate(device)
        assert is_compliant is False
        assert "Device is jailbroken" in violations

    def test_evaluate_non_compliant_encryption(self):
        """Test evaluation when encryption is missing."""
        policy = DevicePosturePolicy(require_disk_encryption=True)
        device = DeviceInfo(
            device_id="test",
            disk_encrypted=False,
            firewall_enabled=True,
        )
        is_compliant, violations = policy.evaluate(device)
        assert is_compliant is False
        assert "Disk encryption is not enabled" in violations

    def test_evaluate_blocked_country(self):
        """Test evaluation with blocked country."""
        policy = DevicePosturePolicy(blocked_countries=["XX"])
        device = DeviceInfo(
            device_id="test",
            geo_country="XX",
            disk_encrypted=True,
            firewall_enabled=True,
        )
        is_compliant, violations = policy.evaluate(device)
        assert is_compliant is False
        assert "Country 'XX' is blocked" in violations

    def test_evaluate_allowed_country(self):
        """Test evaluation with allowed country."""
        policy = DevicePosturePolicy(allowed_countries=["US", "CA"])
        device = DeviceInfo(
            device_id="test",
            geo_country="JP",
            disk_encrypted=True,
            firewall_enabled=True,
        )
        is_compliant, violations = policy.evaluate(device)
        assert is_compliant is False
        assert "Country 'JP' is not allowed" in violations

    def test_evaluate_tor_blocked(self):
        """Test evaluation with Tor blocked."""
        policy = DevicePosturePolicy(block_tor=True)
        device = DeviceInfo(
            device_id="test",
            is_tor=True,
            disk_encrypted=True,
            firewall_enabled=True,
        )
        is_compliant, violations = policy.evaluate(device)
        assert is_compliant is False
        assert "Tor network is blocked" in violations


# ==============================================================================
# Identity Context Tests
# ==============================================================================


class TestIdentityContext:
    """Tests for IdentityContext dataclass."""

    def test_default_identity(self):
        """Test default identity initialization."""
        identity = IdentityContext(identity_id="user:123")
        assert identity.identity_id == "user:123"
        assert identity.identity_type == "user"
        assert identity.trust_level == TrustLevel.LOW

    def test_is_session_expired(self):
        """Test session expiration check."""
        identity = IdentityContext(
            identity_id="user:123",
            session_start=datetime.now(UTC) - timedelta(hours=2),
        )
        assert identity.is_session_expired(timedelta(hours=1)) is True
        assert identity.is_session_expired(timedelta(hours=3)) is False

    def test_is_idle_timeout(self):
        """Test idle timeout check."""
        identity = IdentityContext(
            identity_id="user:123",
            last_activity=datetime.now(UTC) - timedelta(minutes=30),
        )
        assert identity.is_idle_timeout(timedelta(minutes=15)) is True
        assert identity.is_idle_timeout(timedelta(minutes=45)) is False

    def test_has_permission(self):
        """Test permission check."""
        identity = IdentityContext(
            identity_id="user:123",
            permissions=["read", "write"],
        )
        assert identity.has_permission("read") is True
        assert identity.has_permission("delete") is False

    def test_has_role(self):
        """Test role check."""
        identity = IdentityContext(
            identity_id="user:123",
            roles=["admin", "user"],
        )
        assert identity.has_role("admin") is True
        assert identity.has_role("superadmin") is False

    def test_is_member_of(self):
        """Test group membership check."""
        identity = IdentityContext(
            identity_id="user:123",
            groups=["developers", "qa"],
        )
        assert identity.is_member_of("developers") is True
        assert identity.is_member_of("managers") is False

    def test_calculate_risk_mfa_verified(self):
        """Test risk calculation with MFA verified."""
        identity = IdentityContext(
            identity_id="user:123",
            mfa_verified=True,
            auth_strength=2,
            is_verified=True,
        )
        risk = identity.calculate_risk()
        assert risk < 0.2

    def test_calculate_risk_no_mfa(self):
        """Test risk calculation without MFA."""
        identity = IdentityContext(
            identity_id="user:123",
            mfa_verified=False,
            auth_strength=1,
            is_verified=False,
        )
        risk = identity.calculate_risk()
        assert risk >= 0.5


# ==============================================================================
# Zero Trust Policy Tests
# ==============================================================================


class TestZeroTrustPolicy:
    """Tests for ZeroTrustPolicy."""

    def test_default_policy(self):
        """Test default policy initialization."""
        policy = ZeroTrustPolicy(policy_id="test", name="Test Policy")
        assert policy.policy_id == "test"
        assert policy.enabled is True
        assert policy.min_trust_level == TrustLevel.LOW

    def test_matches_resource_wildcard(self):
        """Test resource matching with wildcards."""
        policy = ZeroTrustPolicy(
            policy_id="test",
            name="Test",
            resource_patterns=["/api/*"],
        )
        assert policy.matches_resource("/api/users") is True
        assert policy.matches_resource("/web/index") is False

    def test_matches_resource_all(self):
        """Test resource matching when no patterns defined."""
        policy = ZeroTrustPolicy(policy_id="test", name="Test")
        assert policy.matches_resource("/any/path") is True

    def test_is_ip_allowed_blocklist(self):
        """Test IP blocking."""
        policy = ZeroTrustPolicy(
            policy_id="test",
            name="Test",
            blocked_ips=["1.2.3.4", "10.0.0.0/8"],
        )
        assert policy.is_ip_allowed("1.2.3.4") is False
        assert policy.is_ip_allowed("10.1.2.3") is False
        assert policy.is_ip_allowed("192.168.1.1") is True

    def test_is_ip_allowed_allowlist(self):
        """Test IP allowlist."""
        policy = ZeroTrustPolicy(
            policy_id="test",
            name="Test",
            allowed_ips=["192.168.0.0/16"],
        )
        assert policy.is_ip_allowed("192.168.1.1") is True
        assert policy.is_ip_allowed("10.0.0.1") is False

    def test_is_time_allowed_default(self):
        """Test time check with no restrictions."""
        policy = ZeroTrustPolicy(policy_id="test", name="Test")
        assert policy.is_time_allowed() is True


# ==============================================================================
# Zero Trust Engine Tests
# ==============================================================================


class TestZeroTrustEngine:
    """Tests for ZeroTrustEngine."""

    @pytest.fixture
    def engine(self):
        """Create a fresh engine instance."""
        return ZeroTrustEngine()

    def test_default_engine(self, engine):
        """Test default engine initialization."""
        assert engine.enabled is True
        stats = engine.get_stats()
        assert stats["total_requests"] == 0

    def test_add_policy(self, engine):
        """Test adding a policy."""
        policy = ZeroTrustPolicy(policy_id="test", name="Test")
        engine.add_policy(policy)
        assert engine.get_policy("test") is not None

    def test_remove_policy(self, engine):
        """Test removing a policy."""
        policy = ZeroTrustPolicy(policy_id="test", name="Test")
        engine.add_policy(policy)
        assert engine.remove_policy("test") is True
        assert engine.get_policy("test") is None

    def test_register_session(self, engine):
        """Test session registration."""
        identity = IdentityContext(identity_id="user:123", session_id="sess-123")
        engine.register_session(identity)
        assert engine.get_session("sess-123") is not None

    def test_invalidate_session(self, engine):
        """Test session invalidation."""
        identity = IdentityContext(identity_id="user:123", session_id="sess-123")
        engine.register_session(identity)
        assert engine.invalidate_session("sess-123") is True
        assert engine.get_session("sess-123") is None

    @pytest.mark.asyncio
    async def test_evaluate_disabled(self, engine):
        """Test evaluation when engine is disabled."""
        engine.enabled = False
        request = AccessRequest(resource_path="/api/test")
        result = await engine.evaluate(request)
        assert result.allowed is True
        assert result.reason == "Zero Trust is disabled"

    @pytest.mark.asyncio
    async def test_evaluate_allowed_request(self, engine):
        """Test evaluation of allowed request."""
        identity = create_user_identity(
            user_id="123",
            username="testuser",
            mfa_verified=True,
        )
        request = AccessRequest(
            identity=identity,
            resource_path="/api/test",
            source_ip="192.168.1.1",
        )
        result = await engine.evaluate(request)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_evaluate_blocked_ip(self, engine):
        """Test evaluation with blocked IP."""
        policy = ZeroTrustPolicy(
            policy_id="block-ip",
            name="Block IP",
            blocked_ips=["10.0.0.0/8"],
        )
        engine.add_policy(policy)

        request = AccessRequest(
            resource_path="/api/test",
            source_ip="10.1.2.3",
        )
        result = await engine.evaluate(request)
        assert result.allowed is False
        assert "ip_not_allowed" in result.factors

    @pytest.mark.asyncio
    async def test_evaluate_mfa_required(self, engine):
        """Test evaluation when MFA is required."""
        policy = ZeroTrustPolicy(
            policy_id="require-mfa",
            name="Require MFA",
            require_mfa=True,
        )
        engine.add_policy(policy)

        identity = IdentityContext(
            identity_id="user:123",
            mfa_verified=False,
            trust_level=TrustLevel.MEDIUM,
        )
        request = AccessRequest(
            identity=identity,
            resource_path="/api/test",
        )
        result = await engine.evaluate(request)
        assert result.allowed is False
        assert result.decision == AccessDecision.CHALLENGE
        assert result.requires_mfa is True

    @pytest.mark.asyncio
    async def test_evaluate_device_compliance(self, engine):
        """Test evaluation with device compliance requirement."""
        policy = ZeroTrustPolicy(
            policy_id="device-check",
            name="Device Check",
            require_device_compliance=True,
            device_policy=DevicePosturePolicy(
                require_disk_encryption=True,
            ),
        )
        engine.add_policy(policy)

        device = DeviceInfo(
            device_id="test-device",
            disk_encrypted=False,
        )
        identity = create_user_identity(user_id="123", username="test")
        request = AccessRequest(
            identity=identity,
            device=device,
            resource_path="/api/test",
        )
        result = await engine.evaluate(request)
        assert result.allowed is False
        assert "device_not_compliant" in result.factors

    @pytest.mark.asyncio
    async def test_evaluate_trust_level_insufficient(self, engine):
        """Test evaluation with insufficient trust level."""
        policy = ZeroTrustPolicy(
            policy_id="high-trust",
            name="High Trust Required",
            min_trust_level=TrustLevel.HIGH,
        )
        engine.add_policy(policy)

        identity = IdentityContext(
            identity_id="user:123",
            trust_level=TrustLevel.LOW,
        )
        request = AccessRequest(
            identity=identity,
            resource_path="/api/test",
        )
        result = await engine.evaluate(request)
        assert result.allowed is False
        assert result.decision == AccessDecision.STEP_UP

    @pytest.mark.asyncio
    async def test_evaluate_anonymous_access(self, engine):
        """Test evaluation of anonymous access."""
        policy = ZeroTrustPolicy(
            policy_id="require-auth",
            name="Require Auth",
            min_trust_level=TrustLevel.LOW,
        )
        engine.add_policy(policy)

        request = AccessRequest(
            identity=None,
            resource_path="/api/test",
        )
        result = await engine.evaluate(request)
        assert result.allowed is False
        assert result.decision == AccessDecision.CHALLENGE
        assert result.challenge_type == "authenticate"

    @pytest.mark.asyncio
    async def test_stats_tracking(self, engine):
        """Test statistics tracking."""
        identity = create_user_identity(user_id="123", username="test")
        request = AccessRequest(identity=identity, resource_path="/test")

        await engine.evaluate(request)
        await engine.evaluate(request)

        stats = engine.get_stats()
        assert stats["total_requests"] == 2


# ==============================================================================
# Convenience Function Tests
# ==============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_service_identity(self):
        """Test creating a service identity."""
        identity = create_service_identity(
            service_name="my-service",
            permissions=["read", "write"],
        )
        assert identity.identity_id == "service:my-service"
        assert identity.identity_type == "service"
        assert "read" in identity.permissions
        assert identity.trust_level == TrustLevel.MEDIUM

    def test_create_user_identity(self):
        """Test creating a user identity."""
        identity = create_user_identity(
            user_id="123",
            username="testuser",
            email="test@example.com",
            groups=["developers"],
            mfa_verified=True,
        )
        assert identity.identity_id == "user:123"
        assert identity.identity_type == "user"
        assert identity.username == "testuser"
        assert identity.mfa_verified is True
        assert identity.trust_level == TrustLevel.HIGH

    def test_create_user_identity_no_mfa(self):
        """Test creating user identity without MFA."""
        identity = create_user_identity(
            user_id="123",
            username="testuser",
            mfa_verified=False,
        )
        assert identity.trust_level == TrustLevel.MEDIUM
        assert identity.auth_strength == 1

    def test_create_device_from_request_windows(self):
        """Test device creation from Windows user agent."""
        device = create_device_from_request(
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        )
        assert device.os_name == "windows"
        assert device.browser_name == "chrome"
        assert device.device_type == "desktop"

    def test_create_device_from_request_ios(self):
        """Test device creation from iOS user agent."""
        device = create_device_from_request(
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/605.1",
        )
        assert device.os_name == "ios"
        assert device.browser_name == "safari"
        assert device.device_type == "mobile"

    def test_create_device_from_request_android(self):
        """Test device creation from Android user agent."""
        device = create_device_from_request(
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Linux; Android 14) Chrome/120.0",
        )
        assert device.os_name == "android"
        assert device.device_type == "mobile"


# ==============================================================================
# Pre-configured Policy Tests
# ==============================================================================


class TestPreconfiguredPolicies:
    """Tests for pre-configured policies."""

    def test_strict_policy(self):
        """Test strict policy configuration."""
        policy = create_strict_policy()
        assert policy.min_trust_level == TrustLevel.HIGH
        assert policy.require_mfa is True
        assert policy.require_device_compliance is True
        assert policy.max_risk_score == 0.4
        assert policy.session_timeout_minutes == 60

    def test_moderate_policy(self):
        """Test moderate policy configuration."""
        policy = create_moderate_policy()
        assert policy.min_trust_level == TrustLevel.MEDIUM
        assert policy.require_mfa is False
        assert policy.max_risk_score == 0.6
        assert policy.session_timeout_minutes == 480

    def test_permissive_policy(self):
        """Test permissive policy configuration."""
        policy = create_permissive_policy()
        assert policy.min_trust_level == TrustLevel.LOW
        assert policy.require_mfa is False
        assert policy.max_risk_score == 0.8
        assert policy.session_timeout_minutes == 1440


# ==============================================================================
# Global Engine Tests
# ==============================================================================


class TestGlobalEngine:
    """Tests for global engine instance."""

    def test_get_zero_trust_engine(self):
        """Test getting the global engine."""
        engine = get_zero_trust_engine()
        assert engine is not None
        assert isinstance(engine, ZeroTrustEngine)

    def test_get_same_engine(self):
        """Test that we get the same engine instance."""
        engine1 = get_zero_trust_engine()
        engine2 = get_zero_trust_engine()
        assert engine1 is engine2

    @pytest.mark.asyncio
    async def test_evaluate_access_function(self):
        """Test the evaluate_access convenience function."""
        identity = create_user_identity(user_id="123", username="test")
        result = await evaluate_access(
            identity=identity,
            resource_path="/api/test",
            action="read",
        )
        assert isinstance(result, AccessResult)


# ==============================================================================
# Session Management Tests
# ==============================================================================


class TestSessionManagement:
    """Tests for session timeout and idle timeout."""

    @pytest.fixture
    def engine(self):
        """Create engine with session policy."""
        engine = ZeroTrustEngine()
        policy = ZeroTrustPolicy(
            policy_id="session-test",
            name="Session Test",
            session_timeout_minutes=60,
            idle_timeout_minutes=15,
        )
        engine.add_policy(policy)
        return engine

    @pytest.mark.asyncio
    async def test_session_not_expired(self, engine):
        """Test with valid session."""
        identity = IdentityContext(
            identity_id="user:123",
            session_start=datetime.now(UTC) - timedelta(minutes=30),
            last_activity=datetime.now(UTC) - timedelta(minutes=5),
            trust_level=TrustLevel.MEDIUM,
        )
        request = AccessRequest(identity=identity, resource_path="/test")
        result = await engine.evaluate(request)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_session_expired(self, engine):
        """Test with expired session."""
        identity = IdentityContext(
            identity_id="user:123",
            session_start=datetime.now(UTC) - timedelta(hours=2),
            last_activity=datetime.now(UTC) - timedelta(minutes=5),
            trust_level=TrustLevel.MEDIUM,
        )
        request = AccessRequest(identity=identity, resource_path="/test")
        result = await engine.evaluate(request)
        assert result.allowed is False
        assert "session_expired" in result.factors

    @pytest.mark.asyncio
    async def test_idle_timeout(self, engine):
        """Test with idle timeout exceeded."""
        identity = IdentityContext(
            identity_id="user:123",
            session_start=datetime.now(UTC) - timedelta(minutes=30),
            last_activity=datetime.now(UTC) - timedelta(minutes=20),
            trust_level=TrustLevel.MEDIUM,
        )
        request = AccessRequest(identity=identity, resource_path="/test")
        result = await engine.evaluate(request)
        assert result.allowed is False
        assert "idle_timeout" in result.factors


# ==============================================================================
# Risk Score Calculation Tests
# ==============================================================================


class TestRiskCalculation:
    """Tests for risk score calculation."""

    @pytest.fixture
    def engine(self):
        """Create engine for risk tests."""
        return ZeroTrustEngine()

    @pytest.mark.asyncio
    async def test_low_risk_request(self, engine):
        """Test risk calculation for low-risk request."""
        identity = create_user_identity(
            user_id="123",
            username="test",
            mfa_verified=True,
        )
        device = DeviceInfo(
            device_id="test",
            disk_encrypted=True,
            firewall_enabled=True,
            os_up_to_date=True,
            is_managed=True,
        )
        request = AccessRequest(
            identity=identity,
            device=device,
            resource_path="/api/public",
            action="read",
        )
        result = await engine.evaluate(request)
        assert result.risk_score is not None
        assert result.risk_score.overall < 0.3

    @pytest.mark.asyncio
    async def test_high_risk_device(self, engine):
        """Test risk calculation for high-risk device."""
        identity = create_user_identity(user_id="123", username="test")
        device = DeviceInfo(
            device_id="test",
            is_tor=True,
            jailbroken=True,
            disk_encrypted=False,
        )
        request = AccessRequest(
            identity=identity,
            device=device,
            resource_path="/api/test",
        )
        result = await engine.evaluate(request)
        assert result.risk_score is not None
        assert result.risk_score.device_risk > 0.5

    @pytest.mark.asyncio
    async def test_sensitive_resource_risk(self, engine):
        """Test risk calculation for sensitive resource."""
        identity = create_user_identity(user_id="123", username="test")
        request = AccessRequest(
            identity=identity,
            resource_path="/admin/settings",
            action="write",
            method="PUT",
        )
        result = await engine.evaluate(request)
        assert result.risk_score is not None
        assert result.risk_score.resource_risk > 0.3
