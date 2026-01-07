"""Zero Trust Network Access (ZTNA) module for Instanton.

Implements Zero Trust security model with:
- Identity-based access control (never trust, always verify)
- Device posture assessment
- Continuous authentication and authorization
- Micro-segmentation and least-privilege access
- Session management with re-verification
- Risk-based adaptive policies
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum, auto
from typing import Any
from uuid import UUID, uuid4

import structlog

logger = structlog.get_logger()


# ==============================================================================
# Trust Level and Risk Scoring
# ==============================================================================


class TrustLevel(Enum):
    """Trust levels for Zero Trust evaluation."""

    UNTRUSTED = 0  # No access
    LOW = 1  # Basic access with restrictions
    MEDIUM = 2  # Standard access
    HIGH = 3  # Extended access
    VERIFIED = 4  # Full access (requires strong auth)


class RiskLevel(Enum):
    """Risk levels for access decisions."""

    MINIMAL = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass
class RiskScore:
    """Comprehensive risk score for access decision."""

    overall: float = 0.0  # 0.0 = no risk, 1.0 = maximum risk
    identity_risk: float = 0.0
    device_risk: float = 0.0
    network_risk: float = 0.0
    behavior_risk: float = 0.0
    resource_risk: float = 0.0
    factors: list[str] = field(default_factory=list)

    def calculate_overall(self) -> float:
        """Calculate weighted overall risk score."""
        weights = {
            "identity": 0.25,
            "device": 0.20,
            "network": 0.20,
            "behavior": 0.20,
            "resource": 0.15,
        }
        self.overall = (
            self.identity_risk * weights["identity"]
            + self.device_risk * weights["device"]
            + self.network_risk * weights["network"]
            + self.behavior_risk * weights["behavior"]
            + self.resource_risk * weights["resource"]
        )
        return self.overall

    @property
    def risk_level(self) -> RiskLevel:
        """Get categorical risk level."""
        if self.overall < 0.2:
            return RiskLevel.MINIMAL
        elif self.overall < 0.4:
            return RiskLevel.LOW
        elif self.overall < 0.6:
            return RiskLevel.MEDIUM
        elif self.overall < 0.8:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


# ==============================================================================
# Device Posture Assessment
# ==============================================================================


class DeviceComplianceStatus(Enum):
    """Device compliance status."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    REQUIRES_UPDATE = "requires_update"


@dataclass
class DeviceInfo:
    """Information about the connecting device."""

    device_id: str
    device_type: str = "unknown"  # desktop, mobile, server, iot
    os_name: str = ""
    os_version: str = ""
    browser_name: str = ""
    browser_version: str = ""
    user_agent: str = ""
    fingerprint: str = ""
    # Security posture
    is_managed: bool = False
    has_mdm: bool = False
    disk_encrypted: bool = False
    firewall_enabled: bool = False
    antivirus_active: bool = False
    os_up_to_date: bool = False
    # Network
    ip_address: str = ""
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    geo_country: str = ""
    geo_city: str = ""
    # Risk factors
    jailbroken: bool = False
    rooted: bool = False

    def compliance_status(self) -> DeviceComplianceStatus:
        """Evaluate device compliance."""
        if self.jailbroken or self.rooted:
            return DeviceComplianceStatus.NON_COMPLIANT

        if not self.os_up_to_date:
            return DeviceComplianceStatus.REQUIRES_UPDATE

        required_checks = [
            self.disk_encrypted,
            self.firewall_enabled,
        ]

        if all(required_checks):
            return DeviceComplianceStatus.COMPLIANT

        return DeviceComplianceStatus.NON_COMPLIANT

    def calculate_risk(self) -> float:
        """Calculate device risk score (0.0 to 1.0)."""
        risk = 0.0

        # High risk factors
        if self.jailbroken or self.rooted:
            risk += 0.4
        if self.is_tor:
            risk += 0.3
        if self.is_proxy:
            risk += 0.1

        # Medium risk factors
        if not self.disk_encrypted:
            risk += 0.15
        if not self.firewall_enabled:
            risk += 0.1
        if not self.antivirus_active:
            risk += 0.1
        if not self.os_up_to_date:
            risk += 0.15
        if not self.is_managed:
            risk += 0.1

        return min(risk, 1.0)


@dataclass
class DevicePosturePolicy:
    """Policy for device posture requirements."""

    require_managed: bool = False
    require_mdm: bool = False
    require_disk_encryption: bool = True
    require_firewall: bool = True
    require_antivirus: bool = False
    require_os_updated: bool = True
    block_jailbroken: bool = True
    block_rooted: bool = True
    block_tor: bool = True
    block_vpn: bool = False
    allowed_os: list[str] = field(default_factory=list)  # Empty = all allowed
    allowed_device_types: list[str] = field(default_factory=list)
    allowed_countries: list[str] = field(default_factory=list)
    blocked_countries: list[str] = field(default_factory=list)

    def evaluate(self, device: DeviceInfo) -> tuple[bool, list[str]]:
        """Evaluate device against policy.

        Returns:
            Tuple of (is_compliant, list of violation reasons)
        """
        violations = []

        if self.require_managed and not device.is_managed:
            violations.append("Device is not managed")

        if self.require_mdm and not device.has_mdm:
            violations.append("MDM is not installed")

        if self.require_disk_encryption and not device.disk_encrypted:
            violations.append("Disk encryption is not enabled")

        if self.require_firewall and not device.firewall_enabled:
            violations.append("Firewall is not enabled")

        if self.require_antivirus and not device.antivirus_active:
            violations.append("Antivirus is not active")

        if self.require_os_updated and not device.os_up_to_date:
            violations.append("OS is not up to date")

        if self.block_jailbroken and device.jailbroken:
            violations.append("Device is jailbroken")

        if self.block_rooted and device.rooted:
            violations.append("Device is rooted")

        if self.block_tor and device.is_tor:
            violations.append("Tor network is blocked")

        if self.block_vpn and device.is_vpn:
            violations.append("VPN is blocked")

        if self.allowed_os and device.os_name.lower() not in [os.lower() for os in self.allowed_os]:
            violations.append(f"OS '{device.os_name}' is not allowed")

        if self.allowed_device_types and device.device_type.lower() not in [
            dt.lower() for dt in self.allowed_device_types
        ]:
            violations.append(f"Device type '{device.device_type}' is not allowed")

        if self.blocked_countries and device.geo_country in self.blocked_countries:
            violations.append(f"Country '{device.geo_country}' is blocked")

        if self.allowed_countries and device.geo_country not in self.allowed_countries:
            violations.append(f"Country '{device.geo_country}' is not allowed")

        return len(violations) == 0, violations


# ==============================================================================
# Identity Context
# ==============================================================================


@dataclass
class IdentityContext:
    """Context about the authenticated identity."""

    identity_id: str
    identity_type: str = "user"  # user, service, device
    username: str = ""
    email: str = ""
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    # Authentication details
    auth_method: str = ""  # jwt, mtls, api_key, oauth
    auth_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    auth_strength: int = 1  # 1=single factor, 2=MFA, 3=strong MFA
    mfa_verified: bool = False
    # Session info
    session_id: str = ""
    session_start: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_activity: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Trust info
    is_verified: bool = False
    trust_level: TrustLevel = TrustLevel.LOW

    def is_session_expired(self, max_age: timedelta) -> bool:
        """Check if session has expired."""
        return datetime.now(UTC) - self.session_start > max_age

    def is_idle_timeout(self, idle_timeout: timedelta) -> bool:
        """Check if session is idle for too long."""
        return datetime.now(UTC) - self.last_activity > idle_timeout

    def has_permission(self, permission: str) -> bool:
        """Check if identity has a specific permission."""
        return permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Check if identity has a specific role."""
        return role in self.roles

    def is_member_of(self, group: str) -> bool:
        """Check if identity is member of a group."""
        return group in self.groups

    def calculate_risk(self) -> float:
        """Calculate identity risk score."""
        risk = 0.0

        # Lower auth strength = higher risk
        if self.auth_strength == 1:
            risk += 0.3
        elif self.auth_strength == 2:
            risk += 0.1

        # No MFA = higher risk
        if not self.mfa_verified:
            risk += 0.2

        # Service accounts can be higher risk
        if self.identity_type == "service":
            risk += 0.1

        # Not verified = higher risk
        if not self.is_verified:
            risk += 0.2

        return min(risk, 1.0)


# ==============================================================================
# Access Request and Decision
# ==============================================================================


@dataclass
class AccessRequest:
    """Request for access to a resource."""

    request_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Identity
    identity: IdentityContext | None = None
    # Device
    device: DeviceInfo | None = None
    # Resource being accessed
    resource_type: str = ""  # api, application, network, data
    resource_id: str = ""
    resource_path: str = ""
    # Request details
    action: str = ""  # read, write, delete, execute
    method: str = ""  # GET, POST, PUT, DELETE
    source_ip: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    # Context
    subdomain: str = ""
    tunnel_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class AccessDecision(Enum):
    """Access decision types."""

    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # Require additional auth
    STEP_UP = "step_up"  # Require stronger auth
    CONDITIONAL = "conditional"  # Allow with restrictions


@dataclass
class AccessResult:
    """Result of access decision."""

    decision: AccessDecision
    allowed: bool
    reason: str = ""
    risk_score: RiskScore | None = None
    required_trust_level: TrustLevel = TrustLevel.LOW
    actual_trust_level: TrustLevel = TrustLevel.UNTRUSTED
    # Additional requirements
    requires_mfa: bool = False
    requires_device_compliance: bool = False
    requires_step_up: bool = False
    challenge_type: str = ""  # mfa, captcha, device_verify
    # Restrictions if conditional allow
    restrictions: list[str] = field(default_factory=list)
    allowed_operations: list[str] = field(default_factory=list)
    denied_operations: list[str] = field(default_factory=list)
    # Metadata
    policy_id: str = ""
    evaluation_time_ms: float = 0.0
    factors: list[str] = field(default_factory=list)


# ==============================================================================
# Zero Trust Policy
# ==============================================================================


@dataclass
class ZeroTrustPolicy:
    """Zero Trust access policy."""

    policy_id: str
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 100  # Lower = higher priority
    # Scope
    resource_patterns: list[str] = field(default_factory=list)  # Glob patterns
    identity_patterns: list[str] = field(default_factory=list)
    # Requirements
    min_trust_level: TrustLevel = TrustLevel.LOW
    require_mfa: bool = False
    require_device_compliance: bool = False
    allowed_auth_methods: list[str] = field(default_factory=list)
    # Device posture
    device_policy: DevicePosturePolicy | None = None
    # Network restrictions
    allowed_ips: list[str] = field(default_factory=list)  # CIDR ranges
    blocked_ips: list[str] = field(default_factory=list)
    # Time-based access
    allowed_hours: tuple[int, int] | None = None  # (start_hour, end_hour)
    allowed_days: list[int] | None = None  # 0=Monday, 6=Sunday
    # Risk thresholds
    max_risk_score: float = 0.7
    # Session
    session_timeout_minutes: int = 480  # 8 hours
    idle_timeout_minutes: int = 30
    reauthenticate_on_risk: bool = True
    # Actions
    on_deny_action: str = "block"  # block, challenge, log
    on_high_risk_action: str = "challenge"  # block, challenge, allow_restricted

    def matches_resource(self, resource_path: str) -> bool:
        """Check if policy matches the resource."""
        import fnmatch

        if not self.resource_patterns:
            return True  # Match all if no patterns

        return any(fnmatch.fnmatch(resource_path, pattern) for pattern in self.resource_patterns)

    def matches_identity(self, identity_id: str) -> bool:
        """Check if policy matches the identity."""
        import fnmatch

        if not self.identity_patterns:
            return True  # Match all if no patterns

        return any(fnmatch.fnmatch(identity_id, pattern) for pattern in self.identity_patterns)

    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is allowed by policy."""
        try:
            ip_addr = ipaddress.ip_address(ip)

            # Check blocked IPs first
            for blocked in self.blocked_ips:
                if "/" in blocked:
                    if ip_addr in ipaddress.ip_network(blocked, strict=False):
                        return False
                elif ip == blocked:
                    return False

            # Check allowed IPs
            if not self.allowed_ips:
                return True  # Allow all if no allowlist

            for allowed in self.allowed_ips:
                if "/" in allowed:
                    if ip_addr in ipaddress.ip_network(allowed, strict=False):
                        return True
                elif ip == allowed:
                    return True

            return False

        except ValueError:
            return False

    def is_time_allowed(self) -> bool:
        """Check if current time is within allowed window."""
        now = datetime.now(UTC)

        # Check day of week
        if self.allowed_days is not None and now.weekday() not in self.allowed_days:
            return False

        # Check hour
        if self.allowed_hours is not None:
            start, end = self.allowed_hours
            if start <= end:
                if not (start <= now.hour < end):
                    return False
            else:  # Overnight range
                if not (now.hour >= start or now.hour < end):
                    return False

        return True


# ==============================================================================
# Zero Trust Engine
# ==============================================================================


class ZeroTrustEngine:
    """Core Zero Trust evaluation engine.

    Implements "never trust, always verify" principle with:
    - Continuous verification
    - Least privilege access
    - Micro-segmentation
    - Risk-based adaptive policies
    """

    def __init__(self) -> None:
        self._policies: dict[str, ZeroTrustPolicy] = {}
        self._sessions: dict[str, IdentityContext] = {}
        self._device_cache: dict[str, DeviceInfo] = {}
        self._risk_cache: dict[str, tuple[float, RiskScore]] = {}
        self._access_log: list[dict[str, Any]] = []
        self._stats = {
            "total_requests": 0,
            "allowed": 0,
            "denied": 0,
            "challenged": 0,
            "step_up_required": 0,
        }
        self._lock = asyncio.Lock()
        # Default policy
        self._default_policy = ZeroTrustPolicy(
            policy_id="default",
            name="Default Zero Trust Policy",
            min_trust_level=TrustLevel.LOW,
            require_mfa=False,
            require_device_compliance=False,
        )
        self._enabled = True

    @property
    def enabled(self) -> bool:
        """Check if Zero Trust is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable Zero Trust."""
        self._enabled = value

    def add_policy(self, policy: ZeroTrustPolicy) -> None:
        """Add or update a policy."""
        self._policies[policy.policy_id] = policy
        logger.info("Zero Trust policy added", policy_id=policy.policy_id, name=policy.name)

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False

    def get_policy(self, policy_id: str) -> ZeroTrustPolicy | None:
        """Get a policy by ID."""
        return self._policies.get(policy_id)

    def set_default_policy(self, policy: ZeroTrustPolicy) -> None:
        """Set the default policy."""
        self._default_policy = policy

    def register_session(self, identity: IdentityContext) -> None:
        """Register an authenticated session."""
        self._sessions[identity.session_id] = identity

    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def get_session(self, session_id: str) -> IdentityContext | None:
        """Get session by ID."""
        return self._sessions.get(session_id)

    def update_device_info(self, device_id: str, device: DeviceInfo) -> None:
        """Update cached device information."""
        self._device_cache[device_id] = device

    async def evaluate(self, request: AccessRequest) -> AccessResult:
        """Evaluate an access request using Zero Trust principles.

        This is the main entry point for Zero Trust evaluation.
        """
        start_time = time.time()
        self._stats["total_requests"] += 1

        if not self._enabled:
            return AccessResult(
                decision=AccessDecision.ALLOW,
                allowed=True,
                reason="Zero Trust is disabled",
                evaluation_time_ms=(time.time() - start_time) * 1000,
            )

        # Calculate risk score
        risk_score = await self._calculate_risk_score(request)

        # Find matching policies
        matching_policies = self._get_matching_policies(request)

        # Evaluate against policies (sorted by priority)
        result = await self._evaluate_policies(request, matching_policies, risk_score)
        result.risk_score = risk_score
        result.evaluation_time_ms = (time.time() - start_time) * 1000

        # Update stats
        if result.allowed:
            self._stats["allowed"] += 1
        elif result.decision == AccessDecision.DENY:
            self._stats["denied"] += 1
        elif result.decision == AccessDecision.CHALLENGE:
            self._stats["challenged"] += 1
        elif result.decision == AccessDecision.STEP_UP:
            self._stats["step_up_required"] += 1

        # Log access attempt
        await self._log_access(request, result)

        return result

    async def _calculate_risk_score(self, request: AccessRequest) -> RiskScore:
        """Calculate comprehensive risk score for the request."""
        risk = RiskScore()

        # Identity risk
        if request.identity:
            risk.identity_risk = request.identity.calculate_risk()
            if request.identity.auth_strength == 1:
                risk.factors.append("single_factor_auth")
            if not request.identity.mfa_verified:
                risk.factors.append("no_mfa")

        # Device risk
        if request.device:
            risk.device_risk = request.device.calculate_risk()
            if request.device.is_tor:
                risk.factors.append("tor_network")
            if request.device.jailbroken or request.device.rooted:
                risk.factors.append("compromised_device")
            if not request.device.disk_encrypted:
                risk.factors.append("unencrypted_device")

        # Network risk
        risk.network_risk = await self._calculate_network_risk(request)
        if risk.network_risk > 0.5:
            risk.factors.append("suspicious_network")

        # Behavior risk
        risk.behavior_risk = await self._calculate_behavior_risk(request)
        if risk.behavior_risk > 0.5:
            risk.factors.append("anomalous_behavior")

        # Resource risk (sensitive resources = higher risk)
        risk.resource_risk = self._calculate_resource_risk(request)
        if risk.resource_risk > 0.5:
            risk.factors.append("sensitive_resource")

        risk.calculate_overall()
        return risk

    async def _calculate_network_risk(self, request: AccessRequest) -> float:
        """Calculate network-based risk."""
        risk = 0.0

        if request.device:
            if request.device.is_tor:
                risk += 0.5
            if request.device.is_proxy:
                risk += 0.2
            if request.device.is_vpn:
                risk += 0.1  # VPN might be legitimate

        # Check if IP is from unusual location
        if request.source_ip:
            # Could integrate with GeoIP/threat intelligence here
            pass

        return min(risk, 1.0)

    async def _calculate_behavior_risk(self, request: AccessRequest) -> float:
        """Calculate behavior-based risk (anomaly detection)."""
        risk = 0.0

        if request.identity:
            # Check for unusual access patterns
            # This would typically integrate with a behavior analytics system
            session_age = datetime.now(UTC) - request.identity.session_start
            if session_age < timedelta(seconds=5):
                # Very new session
                risk += 0.1

            # Check time of access
            hour = datetime.now(UTC).hour
            if hour < 6 or hour > 22:
                risk += 0.1  # Off-hours access

        return min(risk, 1.0)

    def _calculate_resource_risk(self, request: AccessRequest) -> float:
        """Calculate resource sensitivity risk."""
        risk = 0.0

        # Sensitive paths
        sensitive_patterns = [
            "/admin",
            "/api/internal",
            "/settings",
            "/users",
            "/billing",
            "/secrets",
        ]

        path_lower = request.resource_path.lower()
        for pattern in sensitive_patterns:
            if pattern in path_lower:
                risk += 0.3
                break

        # Sensitive actions
        if request.action in ["delete", "write", "execute"]:
            risk += 0.2

        # Sensitive methods
        if request.method in ["DELETE", "PUT", "PATCH"]:
            risk += 0.1

        return min(risk, 1.0)

    def _get_matching_policies(self, request: AccessRequest) -> list[ZeroTrustPolicy]:
        """Get policies that match the request."""
        matching = []

        for policy in self._policies.values():
            if not policy.enabled:
                continue

            # Check resource match
            if not policy.matches_resource(request.resource_path):
                continue

            # Check identity match
            identity_id = request.identity.identity_id if request.identity else ""
            if not policy.matches_identity(identity_id):
                continue

            matching.append(policy)

        # Sort by priority (lower = higher priority)
        matching.sort(key=lambda p: p.priority)

        return matching

    async def _evaluate_policies(
        self,
        request: AccessRequest,
        policies: list[ZeroTrustPolicy],
        risk_score: RiskScore,
    ) -> AccessResult:
        """Evaluate request against matching policies."""
        # Use default policy if no matching policies
        if not policies:
            policies = [self._default_policy]

        factors = []

        for policy in policies:
            result = await self._evaluate_single_policy(request, policy, risk_score)
            factors.extend(result.factors)

            # If denied, return immediately
            if result.decision == AccessDecision.DENY:
                result.factors = factors
                return result

            # If challenge or step-up required, return
            if result.decision in (AccessDecision.CHALLENGE, AccessDecision.STEP_UP):
                result.factors = factors
                return result

        # All policies passed
        return AccessResult(
            decision=AccessDecision.ALLOW,
            allowed=True,
            reason="All Zero Trust policies passed",
            actual_trust_level=(
                request.identity.trust_level if request.identity else TrustLevel.UNTRUSTED
            ),
            factors=factors,
        )

    async def _evaluate_single_policy(
        self,
        request: AccessRequest,
        policy: ZeroTrustPolicy,
        risk_score: RiskScore,
    ) -> AccessResult:
        """Evaluate request against a single policy."""
        factors = []

        # Check IP restrictions
        if request.source_ip and not policy.is_ip_allowed(request.source_ip):
            factors.append("ip_not_allowed")
            return AccessResult(
                decision=AccessDecision.DENY,
                allowed=False,
                reason="IP address not allowed",
                policy_id=policy.policy_id,
                factors=factors,
            )

        # Check time restrictions
        if not policy.is_time_allowed():
            factors.append("outside_allowed_time")
            return AccessResult(
                decision=AccessDecision.DENY,
                allowed=False,
                reason="Access not allowed at this time",
                policy_id=policy.policy_id,
                factors=factors,
            )

        # Check identity requirements
        if request.identity:
            # Check trust level
            if request.identity.trust_level.value < policy.min_trust_level.value:
                factors.append("insufficient_trust_level")
                return AccessResult(
                    decision=AccessDecision.STEP_UP,
                    allowed=False,
                    reason="Insufficient trust level",
                    required_trust_level=policy.min_trust_level,
                    actual_trust_level=request.identity.trust_level,
                    requires_step_up=True,
                    policy_id=policy.policy_id,
                    factors=factors,
                )

            # Check MFA requirement
            if policy.require_mfa and not request.identity.mfa_verified:
                factors.append("mfa_required")
                return AccessResult(
                    decision=AccessDecision.CHALLENGE,
                    allowed=False,
                    reason="MFA verification required",
                    requires_mfa=True,
                    challenge_type="mfa",
                    policy_id=policy.policy_id,
                    factors=factors,
                )

            # Check auth method
            auth_allowed = request.identity.auth_method in policy.allowed_auth_methods
            if policy.allowed_auth_methods and not auth_allowed:
                factors.append("auth_method_not_allowed")
                return AccessResult(
                    decision=AccessDecision.DENY,
                    allowed=False,
                    reason=f"Auth method '{request.identity.auth_method}' not allowed",
                    policy_id=policy.policy_id,
                    factors=factors,
                )

            # Check session timeout
            session_max_age = timedelta(minutes=policy.session_timeout_minutes)
            if request.identity.is_session_expired(session_max_age):
                factors.append("session_expired")
                return AccessResult(
                    decision=AccessDecision.CHALLENGE,
                    allowed=False,
                    reason="Session has expired",
                    requires_step_up=True,
                    challenge_type="reauthenticate",
                    policy_id=policy.policy_id,
                    factors=factors,
                )

            # Check idle timeout
            if request.identity.is_idle_timeout(timedelta(minutes=policy.idle_timeout_minutes)):
                factors.append("idle_timeout")
                return AccessResult(
                    decision=AccessDecision.CHALLENGE,
                    allowed=False,
                    reason="Session idle timeout",
                    requires_step_up=True,
                    challenge_type="reauthenticate",
                    policy_id=policy.policy_id,
                    factors=factors,
                )
        else:
            # No identity context - might be anonymous access
            if policy.min_trust_level.value > TrustLevel.UNTRUSTED.value:
                factors.append("authentication_required")
                return AccessResult(
                    decision=AccessDecision.CHALLENGE,
                    allowed=False,
                    reason="Authentication required",
                    challenge_type="authenticate",
                    policy_id=policy.policy_id,
                    factors=factors,
                )

        # Check device compliance
        if policy.require_device_compliance or policy.device_policy:
            if request.device:
                device_policy = policy.device_policy or DevicePosturePolicy()
                is_compliant, violations = device_policy.evaluate(request.device)
                if not is_compliant:
                    factors.append("device_not_compliant")
                    factors.extend([f"device:{v}" for v in violations])
                    return AccessResult(
                        decision=AccessDecision.DENY,
                        allowed=False,
                        reason=f"Device compliance failed: {', '.join(violations)}",
                        requires_device_compliance=True,
                        policy_id=policy.policy_id,
                        factors=factors,
                    )
            elif policy.require_device_compliance:
                factors.append("device_info_required")
                return AccessResult(
                    decision=AccessDecision.CHALLENGE,
                    allowed=False,
                    reason="Device information required",
                    requires_device_compliance=True,
                    challenge_type="device_verify",
                    policy_id=policy.policy_id,
                    factors=factors,
                )

        # Check risk score
        if risk_score.overall > policy.max_risk_score:
            factors.append("high_risk_score")
            if policy.reauthenticate_on_risk:
                return AccessResult(
                    decision=AccessDecision.CHALLENGE,
                    allowed=False,
                    reason=f"Risk score too high ({risk_score.overall:.2f})",
                    requires_step_up=True,
                    challenge_type="step_up_auth",
                    policy_id=policy.policy_id,
                    factors=factors,
                )
            elif policy.on_high_risk_action == "block":
                return AccessResult(
                    decision=AccessDecision.DENY,
                    allowed=False,
                    reason=f"Risk score exceeds threshold ({risk_score.overall:.2f})",
                    policy_id=policy.policy_id,
                    factors=factors,
                )
            elif policy.on_high_risk_action == "allow_restricted":
                return AccessResult(
                    decision=AccessDecision.CONDITIONAL,
                    allowed=True,
                    reason="Allowed with restrictions due to high risk",
                    restrictions=["read_only", "rate_limited"],
                    policy_id=policy.policy_id,
                    factors=factors,
                )

        # All checks passed
        return AccessResult(
            decision=AccessDecision.ALLOW,
            allowed=True,
            reason="Policy evaluation passed",
            actual_trust_level=(
                request.identity.trust_level if request.identity else TrustLevel.UNTRUSTED
            ),
            policy_id=policy.policy_id,
            factors=factors,
        )

    async def _log_access(self, request: AccessRequest, result: AccessResult) -> None:
        """Log access attempt for audit."""
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "request_id": str(request.request_id),
            "identity_id": request.identity.identity_id if request.identity else None,
            "source_ip": request.source_ip,
            "resource_path": request.resource_path,
            "action": request.action,
            "decision": result.decision.value,
            "allowed": result.allowed,
            "reason": result.reason,
            "risk_score": result.risk_score.overall if result.risk_score else None,
            "policy_id": result.policy_id,
            "factors": result.factors,
        }

        async with self._lock:
            self._access_log.append(log_entry)
            # Keep last 10000 entries
            if len(self._access_log) > 10000:
                self._access_log = self._access_log[-10000:]

        logger.info(
            "Zero Trust access decision",
            decision=result.decision.value,
            allowed=result.allowed,
            identity=request.identity.identity_id if request.identity else "anonymous",
            resource=request.resource_path,
            risk=result.risk_score.overall if result.risk_score else 0,
        )

    def get_stats(self) -> dict[str, Any]:
        """Get Zero Trust engine statistics."""
        return {
            **self._stats,
            "policies": len(self._policies),
            "active_sessions": len(self._sessions),
            "enabled": self._enabled,
        }

    def get_access_log(
        self,
        limit: int = 100,
        identity_id: str | None = None,
        decision: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get access log entries with optional filtering."""
        log = self._access_log

        if identity_id:
            log = [e for e in log if e.get("identity_id") == identity_id]

        if decision:
            log = [e for e in log if e.get("decision") == decision]

        return log[-limit:]


# ==============================================================================
# Global Engine Instance
# ==============================================================================


_engine: ZeroTrustEngine | None = None


def get_zero_trust_engine() -> ZeroTrustEngine:
    """Get or create the global Zero Trust engine."""
    global _engine
    if _engine is None:
        _engine = ZeroTrustEngine()
    return _engine


def set_zero_trust_engine(engine: ZeroTrustEngine) -> None:
    """Set the global Zero Trust engine."""
    global _engine
    _engine = engine


# ==============================================================================
# Convenience Functions
# ==============================================================================


async def evaluate_access(
    identity: IdentityContext | None = None,
    device: DeviceInfo | None = None,
    resource_path: str = "",
    action: str = "read",
    source_ip: str = "",
    **kwargs: Any,
) -> AccessResult:
    """Convenience function to evaluate access."""
    engine = get_zero_trust_engine()
    request = AccessRequest(
        identity=identity,
        device=device,
        resource_path=resource_path,
        action=action,
        source_ip=source_ip,
        **kwargs,
    )
    return await engine.evaluate(request)


def create_service_identity(
    service_name: str,
    permissions: list[str] | None = None,
    **kwargs: Any,
) -> IdentityContext:
    """Create an identity context for a service account."""
    return IdentityContext(
        identity_id=f"service:{service_name}",
        identity_type="service",
        username=service_name,
        auth_method="api_key",
        auth_strength=1,
        permissions=permissions or [],
        trust_level=TrustLevel.MEDIUM,
        session_id=hashlib.sha256(f"{service_name}:{time.time()}".encode()).hexdigest()[:32],
        **kwargs,
    )


def create_user_identity(
    user_id: str,
    username: str,
    email: str = "",
    groups: list[str] | None = None,
    roles: list[str] | None = None,
    mfa_verified: bool = False,
    auth_method: str = "jwt",
    **kwargs: Any,
) -> IdentityContext:
    """Create an identity context for a user."""
    auth_strength = 2 if mfa_verified else 1
    trust_level = TrustLevel.HIGH if mfa_verified else TrustLevel.MEDIUM

    return IdentityContext(
        identity_id=f"user:{user_id}",
        identity_type="user",
        username=username,
        email=email,
        groups=groups or [],
        roles=roles or [],
        auth_method=auth_method,
        auth_strength=auth_strength,
        mfa_verified=mfa_verified,
        trust_level=trust_level,
        session_id=hashlib.sha256(f"{user_id}:{time.time()}".encode()).hexdigest()[:32],
        **kwargs,
    )


def create_device_from_request(
    ip_address: str,
    user_agent: str,
    headers: dict[str, str] | None = None,
) -> DeviceInfo:
    """Create device info from HTTP request data."""
    import hashlib

    headers = headers or {}

    # Parse user agent for device info
    os_name = "unknown"
    browser_name = "unknown"
    device_type = "desktop"

    ua_lower = user_agent.lower()
    if "windows" in ua_lower:
        os_name = "windows"
    elif "android" in ua_lower:
        # Check android before linux since android UAs contain "linux"
        os_name = "android"
        device_type = "mobile"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "ios"
        device_type = "mobile"
    elif "mac" in ua_lower:
        os_name = "macos"
    elif "linux" in ua_lower:
        os_name = "linux"

    if "chrome" in ua_lower:
        browser_name = "chrome"
    elif "firefox" in ua_lower:
        browser_name = "firefox"
    elif "safari" in ua_lower:
        browser_name = "safari"
    elif "edge" in ua_lower:
        browser_name = "edge"

    # Create device fingerprint
    fingerprint = hashlib.sha256(f"{user_agent}:{ip_address}".encode()).hexdigest()[:16]

    return DeviceInfo(
        device_id=fingerprint,
        device_type=device_type,
        os_name=os_name,
        browser_name=browser_name,
        user_agent=user_agent,
        fingerprint=fingerprint,
        ip_address=ip_address,
        # These would need to be determined by external services
        is_tor="tor" in ua_lower,
        is_vpn=False,
        is_proxy=False,
    )


# ==============================================================================
# Pre-configured Policies
# ==============================================================================


def create_strict_policy(policy_id: str = "strict") -> ZeroTrustPolicy:
    """Create a strict Zero Trust policy."""
    return ZeroTrustPolicy(
        policy_id=policy_id,
        name="Strict Zero Trust",
        description="High security policy requiring MFA and device compliance",
        min_trust_level=TrustLevel.HIGH,
        require_mfa=True,
        require_device_compliance=True,
        device_policy=DevicePosturePolicy(
            require_disk_encryption=True,
            require_firewall=True,
            require_os_updated=True,
            block_jailbroken=True,
            block_rooted=True,
            block_tor=True,
        ),
        max_risk_score=0.4,
        session_timeout_minutes=60,
        idle_timeout_minutes=15,
        reauthenticate_on_risk=True,
    )


def create_moderate_policy(policy_id: str = "moderate") -> ZeroTrustPolicy:
    """Create a moderate Zero Trust policy."""
    return ZeroTrustPolicy(
        policy_id=policy_id,
        name="Moderate Zero Trust",
        description="Balanced security policy with standard requirements",
        min_trust_level=TrustLevel.MEDIUM,
        require_mfa=False,
        require_device_compliance=False,
        device_policy=DevicePosturePolicy(
            require_disk_encryption=False,
            require_firewall=False,
            block_tor=True,
        ),
        max_risk_score=0.6,
        session_timeout_minutes=480,
        idle_timeout_minutes=30,
        reauthenticate_on_risk=True,
    )


def create_permissive_policy(policy_id: str = "permissive") -> ZeroTrustPolicy:
    """Create a permissive Zero Trust policy."""
    return ZeroTrustPolicy(
        policy_id=policy_id,
        name="Permissive Zero Trust",
        description="Low friction policy with basic verification",
        min_trust_level=TrustLevel.LOW,
        require_mfa=False,
        require_device_compliance=False,
        max_risk_score=0.8,
        session_timeout_minutes=1440,  # 24 hours
        idle_timeout_minutes=120,
        reauthenticate_on_risk=False,
    )
