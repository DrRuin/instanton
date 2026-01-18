"""Tests for Instanton exception classes and error handling."""


from instanton.core.exceptions import (
    AuthenticationRequiredError,
    ConfigurationError,
    ConnectionRefusedError,
    ConnectionTimeoutError,
    InstantonError,
    InvalidPortError,
    InvalidSubdomainError,
    InvalidTokenError,
    LocalServiceTimeoutError,
    LocalServiceUnavailableError,
    MessageDecodingError,
    PermissionDeniedError,
    ProtocolVersionError,
    RateLimitError,
    ServerFullError,
    ServerUnavailableError,
    SSLError,
    SubdomainTakenError,
    TunnelCreationError,
    TunnelDisconnectedError,
    format_error_for_user,
)


class TestInstantonError:
    """Tests for base InstantonError class."""

    def test_basic_error(self):
        """Test basic error creation."""
        error = InstantonError("Something went wrong")
        assert str(error) == "[INSTANTON_ERROR] Something went wrong"
        assert error.message == "Something went wrong"
        assert error.code == "INSTANTON_ERROR"
        assert error.details == {}

    def test_error_with_code(self):
        """Test error with custom code."""
        error = InstantonError("Custom error", code="CUSTOM_CODE")
        assert str(error) == "[CUSTOM_CODE] Custom error"
        assert error.code == "CUSTOM_CODE"

    def test_error_with_details(self):
        """Test error with details."""
        error = InstantonError("Error", details={"key": "value"})
        assert error.details == {"key": "value"}


class TestConnectionErrors:
    """Tests for connection-related errors."""

    def test_connection_timeout_error(self):
        """Test connection timeout error."""
        error = ConnectionTimeoutError("example.com:4443", 30.0)
        assert "example.com:4443" in str(error)
        assert "30.0s" in str(error)
        assert error.code == "CONNECTION_TIMEOUT"
        assert error.details["server"] == "example.com:4443"
        assert error.details["timeout"] == 30.0

    def test_connection_refused_error(self):
        """Test connection refused error."""
        error = ConnectionRefusedError("example.com:4443")
        assert "example.com:4443" in str(error)
        assert "refused" in str(error).lower()
        assert error.code == "CONNECTION_REFUSED"

    def test_connection_refused_error_with_reason(self):
        """Test connection refused error with reason."""
        error = ConnectionRefusedError("example.com", "server busy")
        assert "server busy" in str(error)

    def test_server_unavailable_error(self):
        """Test server unavailable error."""
        error = ServerUnavailableError("relay.instanton.tech")
        assert "relay.instanton.tech" in str(error)
        assert error.code == "SERVER_UNAVAILABLE"

    def test_ssl_error(self):
        """Test SSL error."""
        error = SSLError()
        assert "SSL" in str(error) or "certificate" in str(error).lower()
        assert error.code == "SSL_ERROR"

    def test_ssl_error_with_message(self):
        """Test SSL error with custom message."""
        error = SSLError("Certificate expired")
        assert "Certificate expired" in str(error)


class TestTunnelErrors:
    """Tests for tunnel-related errors."""

    def test_tunnel_creation_error(self):
        """Test tunnel creation error."""
        error = TunnelCreationError("Server rejected connection")
        assert "Server rejected connection" in str(error)
        assert error.code == "TUNNEL_CREATION_FAILED"

    def test_subdomain_taken_error(self):
        """Test subdomain taken error."""
        error = SubdomainTakenError("myapp")
        assert "myapp" in str(error)
        assert "already in use" in str(error).lower()
        assert error.code == "SUBDOMAIN_TAKEN"
        assert error.details["subdomain"] == "myapp"

    def test_invalid_subdomain_error(self):
        """Test invalid subdomain error."""
        error = InvalidSubdomainError("ab")
        assert "ab" in str(error)
        assert error.code == "INVALID_SUBDOMAIN"

    def test_invalid_subdomain_error_with_reason(self):
        """Test invalid subdomain error with reason."""
        error = InvalidSubdomainError("test", "Too short")
        assert "Too short" in str(error)

    def test_server_full_error(self):
        """Test server full error."""
        error = ServerFullError()
        assert "capacity" in str(error).lower() or "full" in str(error).lower()
        assert error.code == "SERVER_FULL"

    def test_tunnel_disconnected_error(self):
        """Test tunnel disconnected error."""
        error = TunnelDisconnectedError()
        assert "disconnected" in str(error).lower()
        assert error.code == "TUNNEL_DISCONNECTED"

    def test_tunnel_disconnected_error_with_reason(self):
        """Test tunnel disconnected error with reason."""
        error = TunnelDisconnectedError("Idle timeout")
        assert "Idle timeout" in str(error)


class TestAuthenticationErrors:
    """Tests for authentication-related errors."""

    def test_invalid_token_error(self):
        """Test invalid token error."""
        error = InvalidTokenError()
        assert "invalid" in str(error).lower() or "expired" in str(error).lower()
        assert error.code == "INVALID_TOKEN"

    def test_authentication_required_error(self):
        """Test authentication required error."""
        error = AuthenticationRequiredError()
        assert "authentication" in str(error).lower()
        assert error.code == "AUTH_REQUIRED"

    def test_permission_denied_error(self):
        """Test permission denied error."""
        error = PermissionDeniedError()
        assert "permission" in str(error).lower()
        assert error.code == "PERMISSION_DENIED"

    def test_permission_denied_error_with_action(self):
        """Test permission denied error with action."""
        error = PermissionDeniedError("create tunnel")
        assert "create tunnel" in str(error)


class TestRateLimitError:
    """Tests for rate limit error."""

    def test_rate_limit_error(self):
        """Test basic rate limit error."""
        error = RateLimitError()
        assert "rate limit" in str(error).lower()
        assert error.code == "RATE_LIMITED"

    def test_rate_limit_error_with_retry(self):
        """Test rate limit error with retry time."""
        error = RateLimitError(retry_after=60.0)
        assert "60" in str(error)
        assert error.details["retry_after"] == 60.0


class TestProtocolErrors:
    """Tests for protocol-related errors."""

    def test_protocol_version_error(self):
        """Test protocol version mismatch error."""
        error = ProtocolVersionError(1, 2)
        assert "1" in str(error)
        assert "2" in str(error)
        assert error.code == "PROTOCOL_MISMATCH"
        assert error.details["client_version"] == 1
        assert error.details["server_version"] == 2

    def test_message_decoding_error(self):
        """Test message decoding error."""
        error = MessageDecodingError()
        assert "decode" in str(error).lower()
        assert error.code == "MESSAGE_DECODE_ERROR"

    def test_message_decoding_error_with_reason(self):
        """Test message decoding error with reason."""
        error = MessageDecodingError("Invalid magic bytes")
        assert "Invalid magic bytes" in str(error)


class TestLocalServiceErrors:
    """Tests for local service errors."""

    def test_local_service_unavailable_error(self):
        """Test local service unavailable error."""
        error = LocalServiceUnavailableError(8000)
        assert "8000" in str(error)
        assert "localhost" in str(error)
        assert error.code == "LOCAL_SERVICE_UNAVAILABLE"

    def test_local_service_unavailable_error_custom_host(self):
        """Test local service unavailable with custom host."""
        error = LocalServiceUnavailableError(3000, "127.0.0.1")
        assert "127.0.0.1" in str(error)
        assert "3000" in str(error)

    def test_local_service_timeout_error(self):
        """Test local service timeout error."""
        error = LocalServiceTimeoutError(8000, 30.0)
        assert "8000" in str(error)
        assert "30" in str(error)
        assert error.code == "LOCAL_SERVICE_TIMEOUT"


class TestConfigurationErrors:
    """Tests for configuration errors."""

    def test_configuration_error(self):
        """Test basic configuration error."""
        error = ConfigurationError("Invalid config file")
        assert "Invalid config file" in str(error)
        assert error.code == "CONFIG_ERROR"

    def test_invalid_port_error(self):
        """Test invalid port error."""
        error = InvalidPortError(99999)
        assert "99999" in str(error)
        assert "65535" in str(error)


class TestErrorInheritance:
    """Tests for error class inheritance."""

    def test_connection_errors_inherit_from_instanton_error(self):
        """Test connection errors inherit correctly."""
        assert issubclass(ConnectionTimeoutError, InstantonError)
        assert issubclass(ConnectionRefusedError, InstantonError)
        assert issubclass(ServerUnavailableError, InstantonError)
        assert issubclass(SSLError, InstantonError)

    def test_tunnel_errors_inherit_from_instanton_error(self):
        """Test tunnel errors inherit correctly."""
        assert issubclass(TunnelCreationError, InstantonError)
        assert issubclass(SubdomainTakenError, InstantonError)
        assert issubclass(InvalidSubdomainError, InstantonError)
        assert issubclass(ServerFullError, InstantonError)

    def test_auth_errors_inherit_from_instanton_error(self):
        """Test auth errors inherit correctly."""
        assert issubclass(InvalidTokenError, InstantonError)
        assert issubclass(AuthenticationRequiredError, InstantonError)
        assert issubclass(PermissionDeniedError, InstantonError)

    def test_protocol_errors_inherit_from_instanton_error(self):
        """Test protocol errors inherit correctly."""
        assert issubclass(ProtocolVersionError, InstantonError)
        assert issubclass(MessageDecodingError, InstantonError)


class TestFormatErrorForUser:
    """Tests for format_error_for_user function."""

    def test_format_instanton_error(self):
        """Test formatting InstantonError."""
        error = ConnectionTimeoutError("server.com", 30.0)
        result = format_error_for_user(error)
        assert "[CONNECTION_TIMEOUT]" in result

    def test_format_timeout_error(self):
        """Test formatting timeout-related errors."""
        error = Exception("connection timed out")
        result = format_error_for_user(error)
        assert "CONNECTION_TIMEOUT" in result

    def test_format_refused_error(self):
        """Test formatting connection refused errors."""
        error = Exception("Connection refused")
        result = format_error_for_user(error)
        assert "CONNECTION_REFUSED" in result

    def test_format_ssl_error(self):
        """Test formatting SSL errors."""
        error = Exception("certificate verify failed")
        result = format_error_for_user(error)
        assert "SSL" in result

    def test_format_dns_error(self):
        """Test formatting DNS errors."""
        error = Exception("Name resolution failed")
        result = format_error_for_user(error)
        assert "DNS" in result

    def test_format_generic_error(self):
        """Test formatting generic errors."""
        error = ValueError("Unknown error")
        result = format_error_for_user(error)
        assert "ERROR" in result
        assert "ValueError" in result


class TestErrorUsability:
    """Tests for error usability and clarity."""

    def test_errors_have_helpful_messages(self):
        """Test that errors have helpful, actionable messages."""
        error = ConnectionTimeoutError("server.com", 30.0)
        msg = str(error).lower()
        assert "check" in msg or "network" in msg

        error = SubdomainTakenError("myapp")
        msg = str(error).lower()
        assert "choose" in msg or "different" in msg or "let" in msg

        error = AuthenticationRequiredError()
        msg = str(error).lower()
        assert "token" in msg or "auth" in msg

    def test_errors_can_be_caught_by_base_class(self):
        """Test that all errors can be caught by InstantonError."""
        errors = [
            ConnectionTimeoutError("server.com", 30.0),
            SubdomainTakenError("test"),
            InvalidTokenError(),
            RateLimitError(),
            LocalServiceUnavailableError(8000),
        ]

        for error in errors:
            try:
                raise error
            except InstantonError as e:
                assert e is error
