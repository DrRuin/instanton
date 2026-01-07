"""Security module for Instanton tunnel application.

This module provides comprehensive security features including:
- Rate limiting and DDoS protection
- Firewall capabilities
- Certificate management and mTLS
- OWASP security hardening
- TLS hardening
- Request/Response sanitization
- Zero Trust Network Access (ZTNA)
"""

# Rate limiting (existing)
# Certificate management (existing)
from instanton.security.certificates import (
    ACMEClient,
    CertificateManager,
    CertificateStore,
    generate_self_signed_cert,
    parse_certificate_info,
)
from instanton.security.certificates import (
    CertificateInfo as CertInfo,
)

# DDoS protection (existing)
from instanton.security.ddos import (
    ConnectionTracker,
    DDoSProtector,
    IPReputationTracker,
    RequestFingerprint,
)

# Firewall (existing)
from instanton.security.firewall import (
    Firewall,
    FirewallRule,
    RuleAction,
)

# OWASP Security Hardening (new)
from instanton.security.hardening import (
    ConnectionLimiter,
    InputValidator,
    RequestSmugglingDetector,
    RequestValidator,
    SecureHeaders,
    SecurityConfig,
    SecurityHardeningManager,
    SecurityLevel,
    ValidationError,
    ValidationResult,
)

# mTLS (existing)
from instanton.security.mtls import (
    ClientCertInfo,
    ClientCertValidator,
    ClientCertVerifyMode,
    MTLSConfig,
    MTLSContext,
    extract_client_cert_from_ssl,
)
from instanton.security.ratelimit import (
    AdaptiveRateLimiter,
    RateLimitManager,
    RateLimitResult,
    SlidingWindowLimiter,
    TokenBucketLimiter,
)

# Request/Response Sanitization (new)
from instanton.security.sanitizer import (
    BodySanitizer,
    CookieSanitizer,
    HeaderSanitizer,
    ParsedCookie,
    RequestResponseSanitizer,
    SanitizationConfig,
    SanitizationMode,
    SanitizationResult,
)

# TLS Hardening (new)
from instanton.security.tls import (
    CertificateInfo,
    CertificatePinner,
    CertificateValidator,
    CipherStrength,
    CipherSuites,
    ECCurves,
    OCSPStapler,
    TLSConfig,
    TLSContextFactory,
    TLSManager,
    TLSVersion,
)

# Zero Trust Network Access (ZTNA)
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
    set_zero_trust_engine,
)

__all__ = [
    # Rate limiting
    "TokenBucketLimiter",
    "SlidingWindowLimiter",
    "AdaptiveRateLimiter",
    "RateLimitManager",
    "RateLimitResult",
    # DDoS protection
    "DDoSProtector",
    "ConnectionTracker",
    "RequestFingerprint",
    "IPReputationTracker",
    # Firewall
    "Firewall",
    "FirewallRule",
    "RuleAction",
    # Certificate management
    "ACMEClient",
    "CertInfo",
    "CertificateManager",
    "CertificateStore",
    "generate_self_signed_cert",
    "parse_certificate_info",
    # mTLS
    "ClientCertInfo",
    "ClientCertValidator",
    "ClientCertVerifyMode",
    "MTLSConfig",
    "MTLSContext",
    "extract_client_cert_from_ssl",
    # OWASP Security Hardening
    "SecurityLevel",
    "SecurityConfig",
    "SecureHeaders",
    "ValidationError",
    "ValidationResult",
    "InputValidator",
    "RequestSmugglingDetector",
    "ConnectionLimiter",
    "RequestValidator",
    "SecurityHardeningManager",
    # TLS Hardening
    "TLSVersion",
    "CipherStrength",
    "TLSConfig",
    "CipherSuites",
    "ECCurves",
    "CertificateInfo",
    "CertificateValidator",
    "CertificatePinner",
    "TLSContextFactory",
    "OCSPStapler",
    "TLSManager",
    # Request/Response Sanitization
    "SanitizationMode",
    "SanitizationConfig",
    "HeaderSanitizer",
    "ParsedCookie",
    "CookieSanitizer",
    "BodySanitizer",
    "SanitizationResult",
    "RequestResponseSanitizer",
    # Zero Trust Network Access
    "TrustLevel",
    "RiskLevel",
    "RiskScore",
    "DeviceComplianceStatus",
    "DeviceInfo",
    "DevicePosturePolicy",
    "IdentityContext",
    "AccessRequest",
    "AccessDecision",
    "AccessResult",
    "ZeroTrustPolicy",
    "ZeroTrustEngine",
    "get_zero_trust_engine",
    "set_zero_trust_engine",
    "evaluate_access",
    "create_service_identity",
    "create_user_identity",
    "create_device_from_request",
    "create_strict_policy",
    "create_moderate_policy",
    "create_permissive_policy",
]
