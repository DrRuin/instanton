"""OWASP Security Hardening for Instanton Tunnel Application.

This module provides comprehensive security implementations including:
- Input validation and sanitization
- Header injection prevention
- Request smuggling detection
- Path traversal prevention
- Host header validation
- Content-Length validation
- Chunked encoding validation
- HTTP desync attack protection
- Secure header injection
- Request size limits
- Connection limits per IP
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import unquote, urlparse

import structlog

logger = structlog.get_logger()


# ==============================================================================
# Security Configuration
# ==============================================================================


class SecurityLevel(Enum):
    """Security enforcement level."""

    STRICT = "strict"  # Block all suspicious requests
    MODERATE = "moderate"  # Block obvious attacks, log suspicious
    PERMISSIVE = "permissive"  # Log only, don't block


@dataclass
class SecurityConfig:
    """Security hardening configuration."""

    # Request size limits
    max_request_size: int = 10 * 1024 * 1024  # 10 MB
    max_header_size: int = 8 * 1024  # 8 KB
    max_header_count: int = 100
    max_uri_length: int = 8192
    max_body_size: int = 10 * 1024 * 1024  # 10 MB

    # Connection limits
    max_connections_per_ip: int = 100
    connection_rate_limit: int = 50  # per second
    connection_rate_window: float = 1.0  # seconds

    # Timeouts
    header_timeout: float = 30.0
    body_timeout: float = 60.0
    keepalive_timeout: float = 5.0

    # Security level
    security_level: SecurityLevel = SecurityLevel.STRICT

    # Allowed hosts (empty = allow all)
    allowed_hosts: list[str] = field(default_factory=list)

    # Trusted proxies for X-Forwarded-For
    trusted_proxies: list[str] = field(default_factory=list)


# ==============================================================================
# Security Headers
# ==============================================================================


@dataclass
class SecureHeaders:
    """Secure HTTP headers to inject into responses."""

    # X-Frame-Options - prevent clickjacking
    x_frame_options: str = "DENY"

    # Content-Security-Policy
    content_security_policy: str = "default-src 'self'; frame-ancestors 'none'"

    # Strict-Transport-Security (HSTS)
    strict_transport_security: str = "max-age=31536000; includeSubDomains; preload"

    # X-Content-Type-Options - prevent MIME sniffing
    x_content_type_options: str = "nosniff"

    # X-XSS-Protection - deprecated but still useful for older browsers
    x_xss_protection: str = "1; mode=block"

    # Referrer-Policy
    referrer_policy: str = "strict-origin-when-cross-origin"

    # Permissions-Policy (formerly Feature-Policy)
    permissions_policy: str = "geolocation=(), microphone=(), camera=()"

    # Cross-Origin policies
    cross_origin_opener_policy: str = "same-origin"
    cross_origin_embedder_policy: str = "require-corp"
    cross_origin_resource_policy: str = "same-origin"

    # Cache control for sensitive resources
    cache_control: str = "no-store, no-cache, must-revalidate, private"

    # Pragma (for HTTP/1.0 compatibility)
    pragma: str = "no-cache"

    def to_dict(self) -> dict[str, str]:
        """Convert to header dictionary."""
        return {
            "X-Frame-Options": self.x_frame_options,
            "Content-Security-Policy": self.content_security_policy,
            "Strict-Transport-Security": self.strict_transport_security,
            "X-Content-Type-Options": self.x_content_type_options,
            "X-XSS-Protection": self.x_xss_protection,
            "Referrer-Policy": self.referrer_policy,
            "Permissions-Policy": self.permissions_policy,
            "Cross-Origin-Opener-Policy": self.cross_origin_opener_policy,
            "Cross-Origin-Embedder-Policy": self.cross_origin_embedder_policy,
            "Cross-Origin-Resource-Policy": self.cross_origin_resource_policy,
            "Cache-Control": self.cache_control,
            "Pragma": self.pragma,
        }


# ==============================================================================
# Validation Results
# ==============================================================================


class ValidationError(Exception):
    """Security validation error."""

    def __init__(self, message: str, code: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


@dataclass
class ValidationResult:
    """Result of security validation."""

    valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, message: str, code: str, **details: Any) -> None:
        """Add a validation error."""
        self.valid = False
        self.errors.append(ValidationError(message, code, details))

    def add_warning(self, message: str) -> None:
        """Add a validation warning."""
        self.warnings.append(message)


# ==============================================================================
# Input Validation
# ==============================================================================


class InputValidator:
    """Validates and sanitizes all user inputs."""

    # Dangerous patterns for header injection
    HEADER_INJECTION_PATTERNS = [
        re.compile(r"[\r\n]"),  # CRLF injection
        re.compile(r"%0[da]", re.IGNORECASE),  # URL-encoded CRLF
        re.compile(r"\\[rn]"),  # Escaped CRLF
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        re.compile(r"\.\."),  # Direct traversal
        re.compile(r"%2e%2e", re.IGNORECASE),  # URL-encoded
        re.compile(r"%252e%252e", re.IGNORECASE),  # Double URL-encoded
        re.compile(r"\.%2e", re.IGNORECASE),  # Mixed encoding
        re.compile(r"%2e\.", re.IGNORECASE),  # Mixed encoding
        re.compile(r"%c0%ae", re.IGNORECASE),  # Overlong UTF-8
        re.compile(r"%c1%9c", re.IGNORECASE),  # Overlong UTF-8
    ]

    # Null byte patterns
    NULL_BYTE_PATTERNS = [
        re.compile(r"\x00"),  # Literal null
        re.compile(r"%00"),  # URL-encoded null
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        re.compile(r"[;&|`$]"),  # Shell metacharacters
        re.compile(r"\$\("),  # Command substitution
        re.compile(r"`"),  # Backtick execution
    ]

    def __init__(self, config: SecurityConfig | None = None):
        self.config = config or SecurityConfig()

    def validate_header_name(self, name: str) -> ValidationResult:
        """Validate HTTP header name."""
        result = ValidationResult(valid=True)

        if not name:
            result.add_error("Header name cannot be empty", "EMPTY_HEADER_NAME")
            return result

        # Check for invalid characters (RFC 7230)
        if not re.match(r"^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$", name):
            result.add_error(
                "Header name contains invalid characters", "INVALID_HEADER_NAME", name=name
            )

        # Check for injection attempts
        for pattern in self.HEADER_INJECTION_PATTERNS:
            if pattern.search(name):
                result.add_error("Header injection attempt detected", "HEADER_INJECTION", name=name)
                break

        return result

    def validate_header_value(self, value: str, name: str = "") -> ValidationResult:
        """Validate HTTP header value."""
        result = ValidationResult(valid=True)

        # Check length
        if len(value) > self.config.max_header_size:
            result.add_error(
                f"Header value exceeds maximum size ({self.config.max_header_size})",
                "HEADER_TOO_LARGE",
                name=name,
                size=len(value),
            )

        # Check for CRLF injection
        for pattern in self.HEADER_INJECTION_PATTERNS:
            if pattern.search(value):
                result.add_error(
                    "Header injection attempt detected in value", "HEADER_INJECTION", name=name
                )
                break

        # Check for null bytes
        for pattern in self.NULL_BYTE_PATTERNS:
            if pattern.search(value):
                result.add_error("Null byte detected in header value", "NULL_BYTE", name=name)
                break

        return result

    def validate_path(self, path: str) -> ValidationResult:
        """Validate URL path for traversal attacks."""
        result = ValidationResult(valid=True)

        if not path:
            return result

        # Check length
        if len(path) > self.config.max_uri_length:
            result.add_error(
                f"Path exceeds maximum length ({self.config.max_uri_length})",
                "PATH_TOO_LONG",
                length=len(path),
            )

        # Decode and check for traversal attempts
        decoded_path = path
        for _ in range(3):  # Handle multiple levels of encoding
            try:
                decoded_path = unquote(decoded_path)
            except Exception:
                break

        # Check for path traversal
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if pattern.search(path) or pattern.search(decoded_path):
                result.add_error("Path traversal attempt detected", "PATH_TRAVERSAL", path=path)
                break

        # Check for null bytes
        for pattern in self.NULL_BYTE_PATTERNS:
            if pattern.search(path) or pattern.search(decoded_path):
                result.add_error("Null byte detected in path", "NULL_BYTE", path=path)
                break

        # Normalize and check for escaping document root
        try:
            parsed = urlparse(path)
            normalized = parsed.path
            if normalized.startswith("//"):
                result.add_warning("Double slash in path may indicate attack")
        except Exception:
            result.add_error("Invalid path format", "INVALID_PATH", path=path)

        return result

    def validate_host(self, host: str) -> ValidationResult:
        """Validate Host header value."""
        result = ValidationResult(valid=True)

        if not host:
            result.add_error("Host header is required", "MISSING_HOST")
            return result

        # Remove port if present
        host_without_port = host.rsplit(":", 1)[0].lower()

        # Strip brackets for IPv6
        if host_without_port.startswith("[") and host_without_port.endswith("]"):
            host_without_port = host_without_port[1:-1]

        # Check for CRLF injection
        for pattern in self.HEADER_INJECTION_PATTERNS:
            if pattern.search(host):
                result.add_error("Header injection in Host header", "HOST_INJECTION", host=host)
                return result

        # Validate against allowed hosts if configured
        if self.config.allowed_hosts and not self._is_host_allowed(host_without_port):
            result.add_error("Host not in allowed hosts list", "HOST_NOT_ALLOWED", host=host)

        # Validate format
        if not self._is_valid_host_format(host_without_port):
            result.add_error("Invalid host format", "INVALID_HOST_FORMAT", host=host)

        return result

    def _is_host_allowed(self, host: str) -> bool:
        """Check if host is in allowed list."""
        for allowed in self.config.allowed_hosts:
            if allowed.startswith("."):
                # Wildcard subdomain match
                if host.endswith(allowed) or host == allowed[1:]:
                    return True
            elif allowed == "*" or host == allowed.lower():
                return True
        return False

    def _is_valid_host_format(self, host: str) -> bool:
        """Check if host has valid format."""
        # Try as IP address
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass

        # Validate as hostname (RFC 1123)
        if len(host) > 253:
            return False

        hostname_regex = re.compile(
            r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)*(?!-)[a-z0-9-]{1,63}(?<!-)$",
            re.IGNORECASE,
        )
        return bool(hostname_regex.match(host))

    def sanitize_input(self, value: str) -> str:
        """Sanitize a string by removing dangerous characters."""
        # Remove null bytes
        value = value.replace("\x00", "")
        value = re.sub(r"%00", "", value, flags=re.IGNORECASE)

        # Remove CRLF
        value = value.replace("\r", "").replace("\n", "")
        value = re.sub(r"%0[da]", "", value, flags=re.IGNORECASE)

        return value


# ==============================================================================
# Request Smuggling Detection
# ==============================================================================


class RequestSmugglingDetector:
    """Detects HTTP request smuggling attempts.

    Protects against:
    - CL.TE (Content-Length, Transfer-Encoding conflict)
    - TE.CL (Transfer-Encoding, Content-Length conflict)
    - TE.TE (Transfer-Encoding obfuscation)
    - HTTP desync attacks
    """

    # Transfer-Encoding obfuscation patterns
    TE_OBFUSCATION_PATTERNS = [
        re.compile(r"transfer-encoding\s*:\s*chunked\s*,", re.IGNORECASE),
        re.compile(r"transfer-encoding\s*:\s*x", re.IGNORECASE),
        re.compile(r"transfer-encoding\s*:\s*\n", re.IGNORECASE),
        re.compile(r"transfer[\s-]*encoding", re.IGNORECASE),
    ]

    def __init__(self, config: SecurityConfig | None = None):
        self.config = config or SecurityConfig()

    def detect_smuggling(
        self, headers: dict[str, str | list[str]], raw_headers: str | None = None
    ) -> ValidationResult:
        """Detect request smuggling attempts."""
        result = ValidationResult(valid=True)

        # Normalize headers to lowercase
        normalized: dict[str, list[str]] = {}
        for key, value in headers.items():
            lower_key = key.lower()
            if isinstance(value, list):
                normalized[lower_key] = value
            else:
                normalized.setdefault(lower_key, []).append(value)

        content_lengths = normalized.get("content-length", [])
        transfer_encodings = normalized.get("transfer-encoding", [])

        # Check for CL.TE or TE.CL conflict
        if content_lengths and transfer_encodings:
            result.add_error(
                "Both Content-Length and Transfer-Encoding present",
                "SMUGGLING_CL_TE_CONFLICT",
                content_length=content_lengths,
                transfer_encoding=transfer_encodings,
            )

        # Check for multiple Content-Length headers
        if len(content_lengths) > 1:
            result.add_error(
                "Multiple Content-Length headers", "SMUGGLING_MULTIPLE_CL", values=content_lengths
            )

        # Check for multiple Transfer-Encoding headers
        if len(transfer_encodings) > 1:
            result.add_error(
                "Multiple Transfer-Encoding headers",
                "SMUGGLING_MULTIPLE_TE",
                values=transfer_encodings,
            )

        # Validate Content-Length format
        for cl in content_lengths:
            if not self._is_valid_content_length(cl):
                result.add_error("Invalid Content-Length value", "INVALID_CONTENT_LENGTH", value=cl)

        # Check for Transfer-Encoding obfuscation
        for te in transfer_encodings:
            te_lower = te.lower().strip()
            if te_lower not in ("chunked", "identity", "gzip", "deflate", "compress"):
                result.add_error(
                    "Unknown or obfuscated Transfer-Encoding", "SMUGGLING_TE_OBFUSCATION", value=te
                )

        # Check raw headers for obfuscation if available
        if raw_headers:
            for pattern in self.TE_OBFUSCATION_PATTERNS:
                if pattern.search(raw_headers):
                    result.add_error(
                        "Transfer-Encoding obfuscation detected",
                        "SMUGGLING_TE_OBFUSCATION",
                        pattern=pattern.pattern,
                    )
                    break

        return result

    def _is_valid_content_length(self, value: str) -> bool:
        """Check if Content-Length value is valid."""
        try:
            cl = int(value.strip())
            return cl >= 0
        except (ValueError, AttributeError):
            return False

    def validate_chunked_encoding(self, body: bytes) -> ValidationResult:
        """Validate chunked transfer encoding format."""
        result = ValidationResult(valid=True)

        pos = 0
        while pos < len(body):
            # Find chunk size line
            line_end = body.find(b"\r\n", pos)
            if line_end == -1:
                result.add_error("Malformed chunked encoding: missing CRLF", "CHUNKED_MALFORMED")
                break

            size_line = body[pos:line_end]

            # Extract chunk size (may include extension)
            size_str = size_line.split(b";")[0]

            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                result.add_error(
                    "Invalid chunk size",
                    "CHUNKED_INVALID_SIZE",
                    size_line=size_line.decode("latin-1", errors="replace"),
                )
                break

            if chunk_size < 0:
                result.add_error("Negative chunk size", "CHUNKED_NEGATIVE_SIZE")
                break

            # Last chunk
            if chunk_size == 0:
                break

            # Skip chunk data and trailing CRLF
            data_start = line_end + 2
            data_end = data_start + chunk_size

            if data_end + 2 > len(body):
                result.add_error("Chunked encoding: incomplete chunk", "CHUNKED_INCOMPLETE")
                break

            if body[data_end : data_end + 2] != b"\r\n":
                result.add_error("Chunked encoding: missing trailing CRLF", "CHUNKED_MISSING_CRLF")
                break

            pos = data_end + 2

        return result


# ==============================================================================
# Connection Limiter
# ==============================================================================


class ConnectionLimiter:
    """Limits connections per IP to prevent resource exhaustion."""

    def __init__(self, config: SecurityConfig | None = None):
        self.config = config or SecurityConfig()

        # Active connections per IP
        self._connections: dict[str, int] = defaultdict(int)

        # Connection rate tracking per IP
        self._rate_tracking: dict[str, list[float]] = defaultdict(list)

        # Lock for thread safety
        self._lock = asyncio.Lock()

    async def check_connection(self, ip: str) -> ValidationResult:
        """Check if a new connection from IP is allowed."""
        result = ValidationResult(valid=True)

        # Parse and normalize IP
        try:
            ip_addr = ipaddress.ip_address(ip)
            normalized_ip = str(ip_addr)
        except ValueError:
            result.add_error("Invalid IP address", "INVALID_IP", ip=ip)
            return result

        async with self._lock:
            # Check connection count
            current_count = self._connections[normalized_ip]
            if current_count >= self.config.max_connections_per_ip:
                result.add_error(
                    f"Too many connections from IP ({current_count})",
                    "TOO_MANY_CONNECTIONS",
                    ip=normalized_ip,
                    count=current_count,
                    limit=self.config.max_connections_per_ip,
                )
                return result

            # Check connection rate
            now = time.time()
            window_start = now - self.config.connection_rate_window

            # Clean old entries
            self._rate_tracking[normalized_ip] = [
                t for t in self._rate_tracking[normalized_ip] if t > window_start
            ]

            recent_count = len(self._rate_tracking[normalized_ip])
            if recent_count >= self.config.connection_rate_limit:
                result.add_error(
                    f"Connection rate limit exceeded ({recent_count}/s)",
                    "CONNECTION_RATE_EXCEEDED",
                    ip=normalized_ip,
                    rate=recent_count,
                    limit=self.config.connection_rate_limit,
                )
                return result

            # Record this connection
            self._connections[normalized_ip] += 1
            self._rate_tracking[normalized_ip].append(now)

        return result

    async def release_connection(self, ip: str) -> None:
        """Release a connection from IP."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            normalized_ip = str(ip_addr)
        except ValueError:
            return

        async with self._lock:
            if self._connections[normalized_ip] > 0:
                self._connections[normalized_ip] -= 1

    async def get_connection_count(self, ip: str) -> int:
        """Get current connection count for IP."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            normalized_ip = str(ip_addr)
        except ValueError:
            return 0

        async with self._lock:
            return self._connections[normalized_ip]


# ==============================================================================
# Request Validator
# ==============================================================================


class RequestValidator:
    """Comprehensive HTTP request validator."""

    def __init__(self, config: SecurityConfig | None = None):
        self.config = config or SecurityConfig()
        self.input_validator = InputValidator(config)
        self.smuggling_detector = RequestSmugglingDetector(config)

    def validate_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str | list[str]],
        body: bytes | None = None,
        raw_headers: str | None = None,
    ) -> ValidationResult:
        """Validate an HTTP request comprehensively."""
        result = ValidationResult(valid=True)

        # Validate method
        method_result = self._validate_method(method)
        if not method_result.valid:
            result.errors.extend(method_result.errors)
            result.valid = False

        # Validate path
        path_result = self.input_validator.validate_path(path)
        if not path_result.valid:
            result.errors.extend(path_result.errors)
            result.valid = False
        result.warnings.extend(path_result.warnings)

        # Validate headers
        headers_result = self._validate_headers(headers)
        if not headers_result.valid:
            result.errors.extend(headers_result.errors)
            result.valid = False
        result.warnings.extend(headers_result.warnings)

        # Check for request smuggling
        smuggling_result = self.smuggling_detector.detect_smuggling(headers, raw_headers)
        if not smuggling_result.valid:
            result.errors.extend(smuggling_result.errors)
            result.valid = False

        # Validate Host header
        host = self._get_header(headers, "host")
        if host:
            host_result = self.input_validator.validate_host(host)
            if not host_result.valid:
                result.errors.extend(host_result.errors)
                result.valid = False
        else:
            result.add_error("Missing Host header", "MISSING_HOST")

        # Validate body size
        if body is not None:
            body_result = self._validate_body(body, headers)
            if not body_result.valid:
                result.errors.extend(body_result.errors)
                result.valid = False

        return result

    def _validate_method(self, method: str) -> ValidationResult:
        """Validate HTTP method."""
        result = ValidationResult(valid=True)

        valid_methods = {
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
            "CONNECT",
            "TRACE",
        }

        if not method:
            result.add_error("Missing HTTP method", "MISSING_METHOD")
        elif method.upper() not in valid_methods:
            result.add_warning(f"Unusual HTTP method: {method}")

        # Check for method tampering
        if method != method.strip():
            result.add_error("HTTP method contains whitespace", "METHOD_WHITESPACE")

        return result

    def _validate_headers(self, headers: dict[str, str | list[str]]) -> ValidationResult:
        """Validate all headers."""
        result = ValidationResult(valid=True)

        # Check header count
        if len(headers) > self.config.max_header_count:
            result.add_error(
                f"Too many headers ({len(headers)})",
                "TOO_MANY_HEADERS",
                count=len(headers),
                limit=self.config.max_header_count,
            )

        for name, value in headers.items():
            # Validate name
            name_result = self.input_validator.validate_header_name(name)
            if not name_result.valid:
                result.errors.extend(name_result.errors)
                result.valid = False

            # Validate value(s)
            values = value if isinstance(value, list) else [value]
            for v in values:
                value_result = self.input_validator.validate_header_value(str(v), name)
                if not value_result.valid:
                    result.errors.extend(value_result.errors)
                    result.valid = False

        return result

    def _validate_body(self, body: bytes, headers: dict[str, str | list[str]]) -> ValidationResult:
        """Validate request body."""
        result = ValidationResult(valid=True)

        # Check size
        if len(body) > self.config.max_body_size:
            result.add_error(
                f"Body exceeds maximum size ({len(body)} > {self.config.max_body_size})",
                "BODY_TOO_LARGE",
                size=len(body),
                limit=self.config.max_body_size,
            )

        # Validate Content-Length if present
        content_length = self._get_header(headers, "content-length")
        if content_length:
            try:
                declared_length = int(content_length)
                if declared_length != len(body):
                    result.add_error(
                        f"Content-Length mismatch ({declared_length} != {len(body)})",
                        "CONTENT_LENGTH_MISMATCH",
                        declared=declared_length,
                        actual=len(body),
                    )
            except ValueError:
                result.add_error(
                    "Invalid Content-Length value", "INVALID_CONTENT_LENGTH", value=content_length
                )

        # Validate chunked encoding if applicable
        transfer_encoding = self._get_header(headers, "transfer-encoding")
        if transfer_encoding and "chunked" in transfer_encoding.lower():
            chunked_result = self.smuggling_detector.validate_chunked_encoding(body)
            if not chunked_result.valid:
                result.errors.extend(chunked_result.errors)
                result.valid = False

        return result

    def _get_header(self, headers: dict[str, str | list[str]], name: str) -> str | None:
        """Get header value case-insensitively."""
        name_lower = name.lower()
        for key, value in headers.items():
            if key.lower() == name_lower:
                if isinstance(value, list):
                    return value[0] if value else None
                return value
        return None


# ==============================================================================
# Security Hardening Manager
# ==============================================================================


class SecurityHardeningManager:
    """Main manager for all security hardening features."""

    def __init__(self, config: SecurityConfig | None = None):
        self.config = config or SecurityConfig()
        self.input_validator = InputValidator(config)
        self.smuggling_detector = RequestSmugglingDetector(config)
        self.connection_limiter = ConnectionLimiter(config)
        self.request_validator = RequestValidator(config)
        self.secure_headers = SecureHeaders()

    async def validate_connection(self, client_ip: str) -> ValidationResult:
        """Validate a new connection."""
        return await self.connection_limiter.check_connection(client_ip)

    async def release_connection(self, client_ip: str) -> None:
        """Release a connection."""
        await self.connection_limiter.release_connection(client_ip)

    def validate_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str | list[str]],
        body: bytes | None = None,
        raw_headers: str | None = None,
    ) -> ValidationResult:
        """Validate an incoming HTTP request."""
        return self.request_validator.validate_request(method, path, headers, body, raw_headers)

    def get_secure_headers(self) -> dict[str, str]:
        """Get security headers to inject into responses."""
        return self.secure_headers.to_dict()

    def inject_secure_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Inject security headers into response headers."""
        secure = self.secure_headers.to_dict()
        result = dict(headers)

        for name, value in secure.items():
            # Don't override if already present
            if name.lower() not in {k.lower() for k in result}:
                result[name] = value

        return result

    def should_block(self, result: ValidationResult) -> bool:
        """Determine if request should be blocked based on validation result."""
        if self.config.security_level == SecurityLevel.PERMISSIVE:
            return False

        if result.valid:
            return False

        if self.config.security_level == SecurityLevel.STRICT:
            return True

        # Moderate: block critical errors only
        critical_codes = {
            "SMUGGLING_CL_TE_CONFLICT",
            "SMUGGLING_MULTIPLE_CL",
            "SMUGGLING_MULTIPLE_TE",
            "SMUGGLING_TE_OBFUSCATION",
            "PATH_TRAVERSAL",
            "HEADER_INJECTION",
            "HOST_INJECTION",
            "TOO_MANY_CONNECTIONS",
        }

        return any(error.code in critical_codes for error in result.errors)


__all__ = [
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
]
