"""Security module for Instanton tunnel application.

This module provides comprehensive security features including:
- Rate limiting and DDoS protection
- Firewall capabilities
- Certificate management and mTLS
- OWASP security hardening
- TLS hardening
- Request/Response sanitization
- Zero Trust Network Access (ZTNA)
- Full ACME/LetsEncrypt support (from scratch)
- Caddy-style automatic TLS (from scratch)
- sslip.io-style wildcard DNS (from scratch)
- instanton.tech domain management
- Self-hosted relay server support
"""

# Full ACME/LetsEncrypt support (from scratch)
from instanton.security.acme import (
    ACMEAccount,
    ACMEAuthorization,
    ACMEChallenge,
    ACMEDirectory,
    ACMEOrder,
    AuthorizationStatus,
    CaddyConfig,
    CaddyManager,
    CertificateAutoRenewal,
    CertificateResult,
    ChallengeType,
    CloudflareDNSProvider,
    DNSProvider,
    FullACMEClient,
    HostingerDNSProvider,
    HTTP01ChallengeServer,
    ManualDNSProvider,
    OrderStatus,
    WildcardDNSConfig,
    get_nip_domain,
    get_public_ip,
    get_sslip_domain,
)
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

# Certificate Manager (from scratch) - instanton.tech and self-hosted support
from instanton.security.certmanager import (
    INSTANTON_DOMAIN,
    INSTANTON_RELAY_DOMAIN,
    INSTANTON_WILDCARD,
    AutoTLSManager,
    CertificateBundle,
    CertificateGenerator,
    CertificateSource,
    InstantonDomainConfig,
    InstantonDomainManager,
    KeyType,
    SelfHostedConfig,
    WildcardDNSService,
)
from instanton.security.certmanager import (
    CertificateStore as CertStore,
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
    # Full ACME/LetsEncrypt support
    "ACMEDirectory",
    "ACMEAccount",
    "ACMEAuthorization",
    "ACMEChallenge",
    "ACMEOrder",
    "AuthorizationStatus",
    "ChallengeType",
    "OrderStatus",
    "CertificateResult",
    "FullACMEClient",
    "HTTP01ChallengeServer",
    "CertificateAutoRenewal",
    # DNS Providers
    "DNSProvider",
    "CloudflareDNSProvider",
    "HostingerDNSProvider",
    "ManualDNSProvider",
    # Caddy integration
    "CaddyConfig",
    "CaddyManager",
    # sslip.io/nip.io support
    "WildcardDNSConfig",
    "get_sslip_domain",
    "get_nip_domain",
    "get_public_ip",
    # Certificate Manager (from scratch)
    "INSTANTON_DOMAIN",
    "INSTANTON_RELAY_DOMAIN",
    "INSTANTON_WILDCARD",
    "CertificateBundle",
    "CertificateGenerator",
    "CertificateSource",
    "KeyType",
    "CertStore",
    "AutoTLSManager",
    "InstantonDomainConfig",
    "InstantonDomainManager",
    "SelfHostedConfig",
    "WildcardDNSService",
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
