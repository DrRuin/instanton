"""Security module for Instanton tunnel application.

This module provides security features including:
- Certificate management and mTLS
- TLS hardening
- Full ACME/LetsEncrypt support
- Caddy-style automatic TLS
- sslip.io-style wildcard DNS
- instanton.tech domain management
- Self-hosted relay server support
- Rate limiting (sliding window)
- IP restrictions (CIDR allow/deny)
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

# High-Performance Hashing (BLAKE3)
from instanton.security.hashing import (
    BLAKE3_AVAILABLE,
    HashAlgorithm,
    Hasher,
    HashResult,
    compute_checksum,
    fast_hash,
    fingerprint_request,
    get_available_algorithm,
    hash_api_key,
    hash_file,
    hash_password,
    hash_stream,
    verify_checksum,
)

# IP Restrictions
from instanton.security.iprestrict import (
    IPCheckResult,
    IPPolicy,
    IPRestrictor,
    create_ip_restrictor,
)

# mTLS
from instanton.security.mtls import (
    ClientCertInfo,
    ClientCertValidator,
    ClientCertVerifyMode,
    MTLSConfig,
    MTLSContext,
    extract_client_cert_from_ssl,
)

# Rate Limiting
from instanton.security.ratelimit import (
    RateLimitConfig,
    RateLimiter,
    RateLimitResult,
    SlidingWindowCounter,
    create_rate_limiter,
)

# Request Signing (HMAC/Ed25519)
from instanton.security.signing import (
    KeyPair,
    RequestSigner,
    RequestVerifier,
    SignatureAlgorithm,
    SignatureVerificationResult,
    SignedRequest,
    create_signed_headers,
)

# TLS Hardening
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

__all__ = [
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
    # Rate Limiting
    "RateLimitConfig",
    "RateLimiter",
    "RateLimitResult",
    "SlidingWindowCounter",
    "create_rate_limiter",
    # IP Restrictions
    "IPCheckResult",
    "IPPolicy",
    "IPRestrictor",
    "create_ip_restrictor",
    # High-Performance Hashing (BLAKE3)
    "BLAKE3_AVAILABLE",
    "HashAlgorithm",
    "HashResult",
    "Hasher",
    "compute_checksum",
    "fast_hash",
    "fingerprint_request",
    "get_available_algorithm",
    "hash_api_key",
    "hash_file",
    "hash_password",
    "hash_stream",
    "verify_checksum",
    # Request Signing (HMAC/Ed25519)
    "KeyPair",
    "RequestSigner",
    "RequestVerifier",
    "SignatureAlgorithm",
    "SignatureVerificationResult",
    "SignedRequest",
    "create_signed_headers",
]
