"""Instanton exception classes for better error handling.

This module provides user-friendly exception classes that hide
implementation details and provide clear, actionable error messages.
"""

from __future__ import annotations


class InstantonError(Exception):
    """Base exception for all Instanton errors.

    All Instanton exceptions inherit from this class, making it easy
    to catch all Instanton-related errors.
    """

    def __init__(self, message: str, code: str | None = None, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.code = code or "INSTANTON_ERROR"
        self.details = details or {}

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class ConnectionError(InstantonError):
    """Base class for connection-related errors."""

    pass


class ConnectionTimeoutError(ConnectionError):
    """Raised when connection to the server times out."""

    def __init__(self, server: str, timeout: float):
        super().__init__(
            f"Connection to {server} timed out after {timeout}s. "
            "Please check your network connection and server address.",
            code="CONNECTION_TIMEOUT",
            details={"server": server, "timeout": timeout},
        )


class ConnectionRefusedError(ConnectionError):
    """Raised when server refuses the connection."""

    def __init__(self, server: str, reason: str | None = None):
        msg = f"Connection to {server} was refused."
        if reason:
            msg += f" Reason: {reason}"
        else:
            msg += " The server may be down or the address may be incorrect."
        super().__init__(msg, code="CONNECTION_REFUSED", details={"server": server})


class ServerUnavailableError(ConnectionError):
    """Raised when server is unavailable."""

    def __init__(self, server: str):
        super().__init__(
            f"Server {server} is currently unavailable. Please try again later.",
            code="SERVER_UNAVAILABLE",
            details={"server": server},
        )


class SSLError(ConnectionError):
    """Raised when there's an SSL/TLS certificate issue."""

    def __init__(self, message: str | None = None):
        super().__init__(
            message
            or "SSL certificate verification failed. "
            "If using a self-signed certificate, ensure it's properly configured.",
            code="SSL_ERROR",
        )


class TunnelError(InstantonError):
    """Base class for tunnel-related errors."""

    pass


class TunnelCreationError(TunnelError):
    """Raised when tunnel creation fails."""

    def __init__(self, reason: str):
        super().__init__(f"Failed to create tunnel: {reason}", code="TUNNEL_CREATION_FAILED")


class SubdomainTakenError(TunnelError):
    """Raised when requested subdomain is already in use."""

    def __init__(self, subdomain: str):
        super().__init__(
            f"Subdomain '{subdomain}' is already in use. "
            "Please choose a different subdomain or let Instanton generate one.",
            code="SUBDOMAIN_TAKEN",
            details={"subdomain": subdomain},
        )


class InvalidSubdomainError(TunnelError):
    """Raised when subdomain format is invalid."""

    def __init__(self, subdomain: str, reason: str | None = None):
        msg = f"Invalid subdomain '{subdomain}'."
        if reason:
            msg += f" {reason}"
        else:
            msg += " Subdomains must be 3-63 characters, alphanumeric with hyphens."
        super().__init__(msg, code="INVALID_SUBDOMAIN", details={"subdomain": subdomain})


class ServerFullError(TunnelError):
    """Raised when server has reached maximum tunnel capacity."""

    def __init__(self):
        super().__init__(
            "Server has reached maximum tunnel capacity. Please try again later.",
            code="SERVER_FULL",
        )


class TunnelDisconnectedError(TunnelError):
    """Raised when tunnel is unexpectedly disconnected."""

    def __init__(self, reason: str | None = None):
        msg = "Tunnel disconnected unexpectedly."
        if reason:
            msg += f" Reason: {reason}"
        super().__init__(msg, code="TUNNEL_DISCONNECTED")


class AuthenticationError(InstantonError):
    """Base class for authentication-related errors."""

    pass


class InvalidTokenError(AuthenticationError):
    """Raised when authentication token is invalid."""

    def __init__(self):
        super().__init__(
            "Invalid or expired authentication token. "
            "Please check your token or generate a new one.",
            code="INVALID_TOKEN",
        )


class AuthenticationRequiredError(AuthenticationError):
    """Raised when authentication is required but not provided."""

    def __init__(self):
        super().__init__(
            "Authentication required. Please provide an auth token "
            "using --auth-token or INSTANTON_AUTH_TOKEN environment variable.",
            code="AUTH_REQUIRED",
        )


class PermissionDeniedError(AuthenticationError):
    """Raised when user doesn't have permission for an action."""

    def __init__(self, action: str | None = None):
        msg = "Permission denied."
        if action:
            msg += f" You don't have permission to: {action}"
        super().__init__(msg, code="PERMISSION_DENIED")


class RateLimitError(InstantonError):
    """Raised when rate limit is exceeded."""

    def __init__(self, retry_after: float | None = None):
        msg = "Rate limit exceeded."
        if retry_after:
            msg += f" Please retry after {retry_after:.1f} seconds."
        else:
            msg += " Please wait before making more requests."
        super().__init__(msg, code="RATE_LIMITED", details={"retry_after": retry_after})


class ProtocolError(InstantonError):
    """Base class for protocol-related errors."""

    pass


class ProtocolVersionError(ProtocolError):
    """Raised when protocol versions are incompatible."""

    def __init__(self, client_version: int, server_version: int):
        super().__init__(
            f"Protocol version mismatch. Client version {client_version} "
            f"is not compatible with server version {server_version}. "
            "Please update your Instanton client.",
            code="PROTOCOL_MISMATCH",
            details={"client_version": client_version, "server_version": server_version},
        )


class MessageDecodingError(ProtocolError):
    """Raised when message cannot be decoded."""

    def __init__(self, reason: str | None = None):
        msg = "Failed to decode message from server."
        if reason:
            msg += f" Reason: {reason}"
        super().__init__(msg, code="MESSAGE_DECODE_ERROR")


class LocalServiceError(InstantonError):
    """Base class for errors related to the local service being tunneled."""

    pass


class LocalServiceUnavailableError(LocalServiceError):
    """Raised when local service is not reachable."""

    def __init__(self, port: int, host: str = "localhost"):
        super().__init__(
            f"Cannot reach local service at {host}:{port}. "
            "Please ensure your application is running.",
            code="LOCAL_SERVICE_UNAVAILABLE",
            details={"host": host, "port": port},
        )


class LocalServiceTimeoutError(LocalServiceError):
    """Raised when local service times out."""

    def __init__(self, port: int, timeout: float):
        super().__init__(
            f"Local service on port {port} did not respond within {timeout}s. "
            "The request may be taking too long or the service is overloaded.",
            code="LOCAL_SERVICE_TIMEOUT",
            details={"port": port, "timeout": timeout},
        )


class ConfigurationError(InstantonError):
    """Raised when there's a configuration issue."""

    def __init__(self, message: str):
        super().__init__(message, code="CONFIG_ERROR")


class InvalidPortError(ConfigurationError):
    """Raised when port number is invalid."""

    def __init__(self, port: int):
        super().__init__(f"Invalid port number: {port}. Port must be between 1 and 65535.")
        self.details = {"port": port}


def format_error_for_user(error: Exception) -> str:
    """Format any exception into a user-friendly message.

    This function converts any exception (including system exceptions)
    into a clean, user-friendly message without stack traces.
    """
    if isinstance(error, InstantonError):
        return str(error)

    error_type = type(error).__name__
    error_msg = str(error)

    if "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
        return "[CONNECTION_TIMEOUT] Connection timed out. Please check your network."

    if "refused" in error_msg.lower():
        return "[CONNECTION_REFUSED] Connection refused. Server may be unavailable."

    if "ssl" in error_type.lower() or "certificate" in error_msg.lower():
        return "[SSL_ERROR] SSL/TLS error. Please check certificate configuration."

    if "dns" in error_msg.lower() or "name resolution" in error_msg.lower():
        return "[DNS_ERROR] Cannot resolve server address. Please check your connection."

    return f"[ERROR] An error occurred: {error_type}. Please try again or check logs for details."
