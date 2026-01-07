"""Request/Response Sanitization for Instanton Tunnel Application.

This module provides comprehensive sanitization including:
- Header sanitization (remove internal headers before forwarding)
- Cookie sanitization (secure, httponly, samesite)
- Body size validation
- Content-type validation
- Response sanitization
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from urllib.parse import parse_qs, urlencode

import structlog

logger = structlog.get_logger()


# ==============================================================================
# Sanitization Configuration
# ==============================================================================


class SanitizationMode(Enum):
    """Sanitization enforcement mode."""

    STRICT = "strict"  # Remove all non-whitelisted
    MODERATE = "moderate"  # Remove known dangerous only
    PERMISSIVE = "permissive"  # Log but don't remove


@dataclass
class SanitizationConfig:
    """Sanitization configuration."""

    # Mode
    mode: SanitizationMode = SanitizationMode.STRICT

    # Body limits
    max_body_size: int = 10 * 1024 * 1024  # 10 MB
    max_json_depth: int = 20
    max_json_keys: int = 1000

    # Cookie settings
    force_secure_cookies: bool = True
    force_httponly_cookies: bool = True
    force_samesite_cookies: str | None = "Lax"  # None, Lax, Strict
    cookie_max_age: int | None = None  # Optional max age in seconds

    # Content type validation
    allowed_content_types: list[str] = field(
        default_factory=lambda: [
            "application/json",
            "application/xml",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
            "text/html",
            "text/xml",
            "application/octet-stream",
        ]
    )

    # Headers to always remove from requests (before forwarding)
    request_headers_blacklist: list[str] = field(
        default_factory=lambda: [
            # Proxy/gateway headers that could be spoofed
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-real-ip",
            "x-original-url",
            "x-rewrite-url",
            # Internal headers
            "x-internal-token",
            "x-internal-auth",
            "x-debug",
            "x-debug-token",
            # Potentially dangerous
            "proxy",
            "proxy-connection",
            "proxy-authorization",
            # TRACE/TRACK attack vectors
            "trace",
            "track",
        ]
    )

    # Headers to always remove from responses (before sending to client)
    response_headers_blacklist: list[str] = field(
        default_factory=lambda: [
            # Internal server information
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-runtime",
            "x-version",
            "x-debug-token",
            "x-debug-token-link",
            # Server details
            "server",  # Often reveals server software
            # Internal routing
            "x-internal-redirect",
            "x-internal-status",
            # Development headers
            "x-sourcefiles",
        ]
    )

    # Request headers whitelist (for strict mode)
    request_headers_whitelist: list[str] = field(
        default_factory=lambda: [
            "accept",
            "accept-charset",
            "accept-encoding",
            "accept-language",
            "authorization",
            "cache-control",
            "connection",
            "content-encoding",
            "content-language",
            "content-length",
            "content-type",
            "cookie",
            "date",
            "expect",
            "from",
            "host",
            "if-match",
            "if-modified-since",
            "if-none-match",
            "if-range",
            "if-unmodified-since",
            "max-forwards",
            "origin",
            "pragma",
            "range",
            "referer",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "user-agent",
            "via",
            "warning",
        ]
    )


# ==============================================================================
# Header Sanitizer
# ==============================================================================


class HeaderSanitizer:
    """Sanitizes HTTP headers for security."""

    # Headers that should never be duplicated
    SINGLE_VALUE_HEADERS = {
        "host",
        "content-length",
        "content-type",
        "authorization",
        "origin",
        "referer",
        "user-agent",
    }

    # Patterns for detecting potentially malicious header values
    MALICIOUS_PATTERNS = [
        re.compile(r"[\r\n]"),  # CRLF injection
        re.compile(r"%0[da]", re.IGNORECASE),  # URL-encoded CRLF
        re.compile(r"\x00"),  # Null bytes
        re.compile(r"%00"),  # URL-encoded null
    ]

    def __init__(self, config: SanitizationConfig | None = None):
        self.config = config or SanitizationConfig()
        self._request_blacklist = {h.lower() for h in self.config.request_headers_blacklist}
        self._response_blacklist = {h.lower() for h in self.config.response_headers_blacklist}
        self._whitelist = {h.lower() for h in self.config.request_headers_whitelist}

    def sanitize_request_headers(
        self,
        headers: dict[str, str | list[str]],
        client_ip: str | None = None,
        preserve_forwarded: bool = False,
    ) -> dict[str, str]:
        """Sanitize request headers before forwarding to backend.

        Args:
            headers: Original request headers
            client_ip: Client IP to add as X-Forwarded-For
            preserve_forwarded: Whether to preserve existing forwarded headers

        Returns:
            Sanitized headers dictionary
        """
        result: dict[str, str] = {}
        removed: list[str] = []

        for name, value in headers.items():
            name_lower = name.lower()

            # Handle list values
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)

            # Check blacklist
            if name_lower in self._request_blacklist and not (
                preserve_forwarded and name_lower.startswith("x-forwarded")
            ):
                removed.append(name)
                continue

            # In strict mode, check whitelist
            if (
                self.config.mode == SanitizationMode.STRICT
                and name_lower not in self._whitelist
                and not name_lower.startswith("x-")
            ):
                removed.append(name)
                continue

            # Check for malicious patterns
            if self._has_malicious_pattern(value):
                removed.append(name)
                continue

            # Sanitize the value
            sanitized_value = self._sanitize_header_value(value)
            result[name] = sanitized_value

        # Add forwarding headers
        if client_ip:
            result["X-Forwarded-For"] = client_ip
            result["X-Real-IP"] = client_ip

        if removed:
            logger.debug("Removed request headers", headers=removed)

        return result

    def sanitize_response_headers(
        self,
        headers: dict[str, str | list[str]],
        add_security_headers: bool = True,
    ) -> dict[str, str]:
        """Sanitize response headers before sending to client.

        Args:
            headers: Original response headers
            add_security_headers: Whether to add security headers

        Returns:
            Sanitized headers dictionary
        """
        result: dict[str, str] = {}
        removed: list[str] = []

        for name, value in headers.items():
            name_lower = name.lower()

            # Handle list values
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)

            # Check blacklist
            if name_lower in self._response_blacklist:
                removed.append(name)
                continue

            # Check for malicious patterns
            if self._has_malicious_pattern(value):
                removed.append(name)
                continue

            # Sanitize the value
            sanitized_value = self._sanitize_header_value(value)
            result[name] = sanitized_value

        if removed:
            logger.debug("Removed response headers", headers=removed)

        return result

    def _has_malicious_pattern(self, value: str) -> bool:
        """Check if value contains malicious patterns."""
        return any(pattern.search(value) for pattern in self.MALICIOUS_PATTERNS)

    def _sanitize_header_value(self, value: str) -> str:
        """Sanitize a header value by removing dangerous characters."""
        # Remove null bytes
        value = value.replace("\x00", "")
        # Remove CRLF
        value = value.replace("\r", "").replace("\n", "")
        # Strip whitespace
        value = value.strip()
        return value


# ==============================================================================
# Cookie Sanitizer
# ==============================================================================


@dataclass
class ParsedCookie:
    """Parsed cookie with all attributes."""

    name: str
    value: str
    domain: str | None = None
    path: str | None = None
    expires: datetime | None = None
    max_age: int | None = None
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None


class CookieSanitizer:
    """Sanitizes HTTP cookies for security."""

    # Cookie name validation (RFC 6265)
    VALID_COOKIE_NAME = re.compile(r"^[!#$%&\'*+\-.0-9A-Z^_`a-z|~]+$")

    # Dangerous characters in cookie values
    DANGEROUS_CHARS = re.compile(r"[\x00-\x1f\x7f\r\n;,]")

    def __init__(self, config: SanitizationConfig | None = None):
        self.config = config or SanitizationConfig()

    def parse_set_cookie(self, header_value: str) -> ParsedCookie | None:
        """Parse a Set-Cookie header value."""
        parts = header_value.split(";")
        if not parts:
            return None

        # First part is name=value
        name_value = parts[0].strip()
        if "=" not in name_value:
            return None

        name, value = name_value.split("=", 1)
        name = name.strip()
        value = value.strip()

        if not name:
            return None

        cookie = ParsedCookie(name=name, value=value)

        # Parse attributes
        for part in parts[1:]:
            part = part.strip().lower()
            if "=" in part:
                attr_name, attr_value = part.split("=", 1)
                attr_name = attr_name.strip()
                attr_value = attr_value.strip()

                if attr_name == "domain":
                    cookie.domain = attr_value
                elif attr_name == "path":
                    cookie.path = attr_value
                elif attr_name == "max-age":
                    with contextlib.suppress(ValueError):
                        cookie.max_age = int(attr_value)
                elif attr_name == "expires":
                    cookie.expires = self._parse_expires(attr_value)
                elif attr_name == "samesite":
                    cookie.samesite = attr_value.capitalize()
            else:
                if part == "secure":
                    cookie.secure = True
                elif part == "httponly":
                    cookie.httponly = True

        return cookie

    def _parse_expires(self, value: str) -> datetime | None:
        """Parse cookie expires attribute."""
        # Common formats
        formats = [
            "%a, %d %b %Y %H:%M:%S GMT",
            "%a, %d-%b-%Y %H:%M:%S GMT",
            "%A, %d-%b-%y %H:%M:%S GMT",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        return None

    def sanitize_set_cookie(self, header_value: str) -> str | None:
        """Sanitize a Set-Cookie header value.

        Returns sanitized header value or None if cookie should be rejected.
        """
        cookie = self.parse_set_cookie(header_value)
        if not cookie:
            return None

        # Validate cookie name
        if not self.VALID_COOKIE_NAME.match(cookie.name):
            logger.warning("Invalid cookie name rejected", name=cookie.name)
            return None

        # Sanitize cookie value
        if self.DANGEROUS_CHARS.search(cookie.value):
            cookie.value = self.DANGEROUS_CHARS.sub("", cookie.value)

        # Apply security attributes
        if self.config.force_secure_cookies:
            cookie.secure = True

        if self.config.force_httponly_cookies:
            cookie.httponly = True

        if self.config.force_samesite_cookies:
            cookie.samesite = self.config.force_samesite_cookies

        if self.config.cookie_max_age is not None:
            cookie.max_age = min(
                cookie.max_age or self.config.cookie_max_age, self.config.cookie_max_age
            )

        # Build sanitized Set-Cookie header
        return self._build_set_cookie(cookie)

    def _build_set_cookie(self, cookie: ParsedCookie) -> str:
        """Build a Set-Cookie header value from parsed cookie."""
        parts = [f"{cookie.name}={cookie.value}"]

        if cookie.domain:
            parts.append(f"Domain={cookie.domain}")
        if cookie.path:
            parts.append(f"Path={cookie.path}")
        if cookie.max_age is not None:
            parts.append(f"Max-Age={cookie.max_age}")
        if cookie.expires:
            expires_str = cookie.expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
            parts.append(f"Expires={expires_str}")
        if cookie.secure:
            parts.append("Secure")
        if cookie.httponly:
            parts.append("HttpOnly")
        if cookie.samesite:
            parts.append(f"SameSite={cookie.samesite}")

        return "; ".join(parts)

    def sanitize_cookies(self, headers: dict[str, str | list[str]]) -> dict[str, str | list[str]]:
        """Sanitize all Set-Cookie headers in a response."""
        result = dict(headers)

        # Find Set-Cookie headers (case-insensitive)
        set_cookie_key = None
        set_cookie_values: list[str] = []

        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookie_key = key
                set_cookie_values = list(value) if isinstance(value, list) else [value]
                break

        if not set_cookie_values:
            return result

        # Sanitize each cookie
        sanitized: list[str] = []
        for cookie_value in set_cookie_values:
            sanitized_value = self.sanitize_set_cookie(cookie_value)
            if sanitized_value:
                sanitized.append(sanitized_value)

        # Update result
        if set_cookie_key:
            if sanitized:
                result[set_cookie_key] = sanitized if len(sanitized) > 1 else sanitized[0]
            else:
                del result[set_cookie_key]

        return result


# ==============================================================================
# Body Sanitizer
# ==============================================================================


class BodySanitizer:
    """Sanitizes request and response bodies."""

    # Dangerous content type patterns
    DANGEROUS_CONTENT_TYPES = [
        re.compile(r"application/x-executable", re.IGNORECASE),
        re.compile(r"application/x-msdownload", re.IGNORECASE),
        re.compile(r"application/x-sh", re.IGNORECASE),
        re.compile(r"application/x-csh", re.IGNORECASE),
    ]

    def __init__(self, config: SanitizationConfig | None = None):
        self.config = config or SanitizationConfig()
        self._allowed_types = {ct.lower() for ct in self.config.allowed_content_types}

    def validate_content_type(self, content_type: str | None) -> tuple[bool, str | None]:
        """Validate content type is allowed.

        Returns (valid, error_message)
        """
        if not content_type:
            return True, None  # No content type is OK for some requests

        # Extract base content type (without parameters)
        base_type = content_type.split(";")[0].strip().lower()

        # Check against dangerous patterns
        for pattern in self.DANGEROUS_CONTENT_TYPES:
            if pattern.match(base_type):
                return False, f"Dangerous content type: {base_type}"

        # In strict mode, check whitelist
        if self.config.mode == SanitizationMode.STRICT and base_type not in self._allowed_types:
            # Check for wildcard match (e.g., text/*)
            type_category = base_type.split("/")[0]
            if f"{type_category}/*" not in self._allowed_types:
                return False, f"Content type not in whitelist: {base_type}"

        return True, None

    def validate_body_size(
        self, body: bytes, content_length: int | None = None
    ) -> tuple[bool, str | None]:
        """Validate body size.

        Returns (valid, error_message)
        """
        actual_size = len(body)

        # Check against max size
        if actual_size > self.config.max_body_size:
            return False, f"Body size {actual_size} exceeds limit {self.config.max_body_size}"

        # Check Content-Length match
        if content_length is not None and content_length != actual_size:
            return (
                False,
                f"Content-Length mismatch: declared {content_length}, actual {actual_size}",
            )

        return True, None

    def sanitize_json_body(self, body: bytes) -> tuple[bytes, list[str]]:
        """Sanitize JSON body by validating structure.

        Returns (sanitized_body, warnings)
        """
        import json

        warnings: list[str] = []

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            warnings.append(f"Invalid JSON: {e}")
            return body, warnings

        # Check depth and key count
        depth, key_count = self._analyze_json(data)

        if depth > self.config.max_json_depth:
            warnings.append(f"JSON depth {depth} exceeds limit {self.config.max_json_depth}")

        if key_count > self.config.max_json_keys:
            warnings.append(f"JSON key count {key_count} exceeds limit {self.config.max_json_keys}")

        return body, warnings

    def _analyze_json(self, data: Any, current_depth: int = 1) -> tuple[int, int]:
        """Analyze JSON structure for depth and key count."""
        max_depth = current_depth
        key_count = 0

        if isinstance(data, dict):
            key_count = len(data)
            for value in data.values():
                child_depth, child_keys = self._analyze_json(value, current_depth + 1)
                max_depth = max(max_depth, child_depth)
                key_count += child_keys
        elif isinstance(data, list):
            for item in data:
                child_depth, child_keys = self._analyze_json(item, current_depth + 1)
                max_depth = max(max_depth, child_depth)
                key_count += child_keys

        return max_depth, key_count

    def sanitize_form_body(self, body: bytes) -> tuple[bytes, list[str]]:
        """Sanitize URL-encoded form body.

        Returns (sanitized_body, warnings)
        """
        warnings: list[str] = []

        try:
            # Parse form data
            parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)

            # Sanitize each field
            sanitized: dict[str, list[str]] = {}
            for key, values in parsed.items():
                # Remove null bytes and control characters
                clean_key = re.sub(r"[\x00-\x1f]", "", key)
                clean_values = [re.sub(r"[\x00-\x1f]", "", v) for v in values]

                if clean_key != key:
                    warnings.append(f"Sanitized form field name: {repr(key)}")

                sanitized[clean_key] = clean_values

            # Re-encode
            result = urlencode(sanitized, doseq=True).encode("utf-8")
            return result, warnings

        except Exception as e:
            warnings.append(f"Form parsing error: {e}")
            return body, warnings


# ==============================================================================
# Request/Response Sanitizer
# ==============================================================================


@dataclass
class SanitizationResult:
    """Result of sanitization operation."""

    headers: dict[str, str]
    body: bytes | None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class RequestResponseSanitizer:
    """Complete request/response sanitizer."""

    def __init__(self, config: SanitizationConfig | None = None):
        self.config = config or SanitizationConfig()
        self.header_sanitizer = HeaderSanitizer(config)
        self.cookie_sanitizer = CookieSanitizer(config)
        self.body_sanitizer = BodySanitizer(config)

    def sanitize_request(
        self,
        headers: dict[str, str | list[str]],
        body: bytes | None = None,
        client_ip: str | None = None,
    ) -> SanitizationResult:
        """Sanitize an incoming request.

        Args:
            headers: Request headers
            body: Request body (optional)
            client_ip: Client IP address

        Returns:
            SanitizationResult with sanitized headers and body
        """
        result = SanitizationResult(headers={}, body=body, warnings=[], errors=[])

        # Sanitize headers
        result.headers = self.header_sanitizer.sanitize_request_headers(
            headers, client_ip=client_ip
        )

        # Validate and sanitize body
        if body is not None:
            # Get content type
            content_type = None
            for key, value in headers.items():
                if key.lower() == "content-type":
                    content_type = value if isinstance(value, str) else value[0]
                    break

            # Validate content type
            ct_valid, ct_error = self.body_sanitizer.validate_content_type(content_type)
            if not ct_valid and ct_error:
                result.errors.append(ct_error)

            # Validate body size
            content_length = None
            for key, value in headers.items():
                if key.lower() == "content-length":
                    with contextlib.suppress(ValueError, TypeError):
                        content_length = int(value if isinstance(value, str) else value[0])
                    break

            size_valid, size_error = self.body_sanitizer.validate_body_size(body, content_length)
            if not size_valid and size_error:
                result.errors.append(size_error)

            # Sanitize body based on content type
            if content_type:
                base_type = content_type.split(";")[0].strip().lower()
                if base_type == "application/json":
                    result.body, warnings = self.body_sanitizer.sanitize_json_body(body)
                    result.warnings.extend(warnings)
                elif base_type == "application/x-www-form-urlencoded":
                    result.body, warnings = self.body_sanitizer.sanitize_form_body(body)
                    result.warnings.extend(warnings)

        return result

    def sanitize_response(
        self,
        headers: dict[str, str | list[str]],
        body: bytes | None = None,
        status_code: int = 200,
    ) -> SanitizationResult:
        """Sanitize an outgoing response.

        Args:
            headers: Response headers
            body: Response body (optional)
            status_code: HTTP status code

        Returns:
            SanitizationResult with sanitized headers and body
        """
        result = SanitizationResult(headers={}, body=body, warnings=[], errors=[])

        # Sanitize headers
        result.headers = self.header_sanitizer.sanitize_response_headers(headers)

        # Sanitize cookies
        headers_for_cookies: dict[str, str | list[str]] = dict(result.headers)
        sanitized_with_cookies = self.cookie_sanitizer.sanitize_cookies(headers_for_cookies)
        result.headers = {
            k: v if isinstance(v, str) else v[0] for k, v in sanitized_with_cookies.items()
        }

        # For error responses, be extra careful about information disclosure
        if status_code >= 400:
            # Remove headers that might leak information
            info_disclosure_headers = ["x-error-message", "x-error-details", "x-exception"]
            for header in info_disclosure_headers:
                if header in result.headers:
                    del result.headers[header]

        return result


# ==============================================================================
# Exports
# ==============================================================================


__all__ = [
    "SanitizationMode",
    "SanitizationConfig",
    "HeaderSanitizer",
    "ParsedCookie",
    "CookieSanitizer",
    "BodySanitizer",
    "SanitizationResult",
    "RequestResponseSanitizer",
]
