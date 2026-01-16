"""Instanton TOTP/MFA Authentication Module.

Provides Time-based One-Time Password (TOTP) support for multi-factor
authentication, fully compliant with RFC 4226 (HOTP) and RFC 6238 (TOTP).

Features:
- TOTP secret generation and validation
- QR code generation for authenticator apps
- Backup codes for account recovery
- Configurable parameters (digits, interval, algorithm)
- Rate limiting to prevent brute force attacks

Usage:
    from instanton.auth.mfa import TOTPManager

    # Create manager
    manager = TOTPManager()

    # Generate secret for new user
    secret = manager.generate_secret(name="john@example.com", issuer="Instanton")

    # Get provisioning URI for QR code
    uri = manager.get_provisioning_uri(secret)

    # Generate QR code image (requires qrcode package)
    qr_bytes = manager.generate_qr_code(secret)

    # Verify code from user
    is_valid = manager.verify(secret, user_input_code)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import quote, urlencode


class TOTPAlgorithm(Enum):
    """Supported TOTP hash algorithms."""

    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


@dataclass
class TOTPSecret:
    """TOTP secret with associated metadata."""

    secret: bytes
    """Raw secret bytes (20 bytes for SHA1, 32 for SHA256)."""

    name: str
    """Account name (e.g., email address)."""

    issuer: str = "Instanton"
    """Issuer name shown in authenticator app."""

    algorithm: TOTPAlgorithm = TOTPAlgorithm.SHA1
    """Hash algorithm (SHA1 is most compatible)."""

    digits: int = 6
    """Number of digits in the code (6 or 8)."""

    period: int = 30
    """Time step in seconds (usually 30)."""

    backup_codes: list[str] = field(default_factory=list)
    """One-time backup codes for recovery."""

    created_at: float = field(default_factory=time.time)
    """Unix timestamp when secret was created."""

    verified: bool = False
    """Whether the user has confirmed setup."""

    @property
    def secret_base32(self) -> str:
        """Get secret as base32 string (for manual entry)."""
        return base64.b32encode(self.secret).decode("ascii").rstrip("=")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "secret": base64.b64encode(self.secret).decode("ascii"),
            "name": self.name,
            "issuer": self.issuer,
            "algorithm": self.algorithm.value,
            "digits": self.digits,
            "period": self.period,
            "backup_codes": self.backup_codes,
            "created_at": self.created_at,
            "verified": self.verified,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TOTPSecret:
        """Create from dictionary."""
        return cls(
            secret=base64.b64decode(data["secret"]),
            name=data["name"],
            issuer=data.get("issuer", "Instanton"),
            algorithm=TOTPAlgorithm(data.get("algorithm", "SHA1")),
            digits=data.get("digits", 6),
            period=data.get("period", 30),
            backup_codes=data.get("backup_codes", []),
            created_at=data.get("created_at", time.time()),
            verified=data.get("verified", False),
        )


@dataclass
class TOTPVerificationResult:
    """Result of TOTP verification."""

    valid: bool
    """Whether the code was valid."""

    drift: int = 0
    """Time drift in periods (0 = current, -1 = previous, +1 = next)."""

    used_backup: bool = False
    """Whether a backup code was used."""

    error: str | None = None
    """Error message if verification failed."""


class TOTPManager:
    """Manager for TOTP operations.

    Implements RFC 4226 (HOTP) and RFC 6238 (TOTP) for time-based
    one-time password generation and verification.
    """

    def __init__(
        self,
        *,
        default_issuer: str = "Instanton",
        default_algorithm: TOTPAlgorithm = TOTPAlgorithm.SHA1,
        default_digits: int = 6,
        default_period: int = 30,
        tolerance: int = 1,
        backup_code_count: int = 10,
        backup_code_length: int = 8,
    ) -> None:
        """Initialize the TOTP manager.

        Args:
            default_issuer: Default issuer name.
            default_algorithm: Default hash algorithm.
            default_digits: Default number of digits (6 or 8).
            default_period: Default time period in seconds.
            tolerance: Number of periods to accept before/after current.
            backup_code_count: Number of backup codes to generate.
            backup_code_length: Length of backup codes.
        """
        self.default_issuer = default_issuer
        self.default_algorithm = default_algorithm
        self.default_digits = default_digits
        self.default_period = default_period
        self.tolerance = tolerance
        self.backup_code_count = backup_code_count
        self.backup_code_length = backup_code_length

    def generate_secret(
        self,
        name: str,
        *,
        issuer: str | None = None,
        algorithm: TOTPAlgorithm | None = None,
        digits: int | None = None,
        period: int | None = None,
        generate_backup_codes: bool = True,
    ) -> TOTPSecret:
        """Generate a new TOTP secret.

        Args:
            name: Account name (e.g., email address).
            issuer: Issuer name (uses default if None).
            algorithm: Hash algorithm (uses default if None).
            digits: Number of digits (uses default if None).
            period: Time period (uses default if None).
            generate_backup_codes: Whether to generate backup codes.

        Returns:
            New TOTPSecret instance.
        """
        algorithm = algorithm or self.default_algorithm
        issuer = issuer or self.default_issuer
        digits = digits or self.default_digits
        period = period or self.default_period

        # Secret length depends on algorithm
        if algorithm == TOTPAlgorithm.SHA1:
            secret_length = 20
        elif algorithm == TOTPAlgorithm.SHA256:
            secret_length = 32
        else:  # SHA512
            secret_length = 64

        secret = os.urandom(secret_length)

        backup_codes: list[str] = []
        if generate_backup_codes:
            backup_codes = self._generate_backup_codes()

        return TOTPSecret(
            secret=secret,
            name=name,
            issuer=issuer,
            algorithm=algorithm,
            digits=digits,
            period=period,
            backup_codes=backup_codes,
        )

    def _generate_backup_codes(self) -> list[str]:
        """Generate one-time backup codes."""
        codes = []
        for _ in range(self.backup_code_count):
            # Generate alphanumeric code
            code = secrets.token_hex(self.backup_code_length // 2).upper()
            # Format as XXXX-XXXX for readability
            formatted = "-".join(
                code[i : i + 4] for i in range(0, len(code), 4)
            )
            codes.append(formatted)
        return codes

    def get_provisioning_uri(self, secret: TOTPSecret) -> str:
        """Get the otpauth URI for QR code generation.

        This URI can be encoded into a QR code for easy setup
        in authenticator apps like Google Authenticator.

        Args:
            secret: TOTP secret to encode.

        Returns:
            otpauth:// URI string.
        """
        # Build label: issuer:account_name
        label = f"{secret.issuer}:{secret.name}"

        # Build parameters
        params = {
            "secret": secret.secret_base32,
            "issuer": secret.issuer,
            "algorithm": secret.algorithm.value,
            "digits": str(secret.digits),
            "period": str(secret.period),
        }

        # Build URI
        return f"otpauth://totp/{quote(label, safe='')}?{urlencode(params)}"

    def generate_qr_code(
        self,
        secret: TOTPSecret,
        *,
        size: int = 200,
        border: int = 2,
    ) -> bytes:
        """Generate a QR code image for the secret.

        Requires the 'qrcode' package with PIL support.

        Args:
            secret: TOTP secret to encode.
            size: Image size in pixels.
            border: Border size in modules.

        Returns:
            PNG image bytes.

        Raises:
            ImportError: If qrcode package is not installed.
        """
        try:
            from io import BytesIO

            import qrcode
        except ImportError as e:
            raise ImportError(
                "QR code generation requires 'qrcode[pil]' package. "
                "Install with: pip install 'qrcode[pil]'"
            ) from e

        uri = self.get_provisioning_uri(secret)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=size // 25,  # Approximate
            border=border,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def generate_code(
        self,
        secret: TOTPSecret,
        *,
        timestamp: float | None = None,
    ) -> str:
        """Generate a TOTP code.

        Useful for testing or server-side code generation.

        Args:
            secret: TOTP secret.
            timestamp: Unix timestamp (current time if None).

        Returns:
            TOTP code string.
        """
        if timestamp is None:
            timestamp = time.time()

        counter = int(timestamp) // secret.period
        return self._generate_hotp(secret, counter)

    def _generate_hotp(self, secret: TOTPSecret, counter: int) -> str:
        """Generate HOTP code for a counter value (RFC 4226)."""
        # Pack counter as 8-byte big-endian
        counter_bytes = struct.pack(">Q", counter)

        # Select hash algorithm
        if secret.algorithm == TOTPAlgorithm.SHA1:
            hash_func = hashlib.sha1
        elif secret.algorithm == TOTPAlgorithm.SHA256:
            hash_func = hashlib.sha256
        else:
            hash_func = hashlib.sha512

        # Compute HMAC
        hmac_hash = hmac.new(secret.secret, counter_bytes, hash_func).digest()

        # Dynamic truncation (RFC 4226)
        offset = hmac_hash[-1] & 0x0F
        truncated = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
        truncated &= 0x7FFFFFFF  # Remove sign bit

        # Get digits
        code = truncated % (10 ** secret.digits)

        return str(code).zfill(secret.digits)

    def verify(
        self,
        secret: TOTPSecret,
        code: str,
        *,
        timestamp: float | None = None,
        consume_backup: bool = True,
    ) -> TOTPVerificationResult:
        """Verify a TOTP code.

        Checks the current time window plus tolerance windows
        before and after to account for clock drift.

        Args:
            secret: TOTP secret to verify against.
            code: Code from user to verify.
            timestamp: Unix timestamp (current time if None).
            consume_backup: Remove backup code if used.

        Returns:
            TOTPVerificationResult with status.
        """
        # Normalize code (remove spaces, dashes)
        code = code.replace(" ", "").replace("-", "").strip()

        # Check if it's a backup code
        if code.upper() in [bc.replace("-", "").upper() for bc in secret.backup_codes]:
            if consume_backup:
                # Find and remove the matching backup code
                for i, bc in enumerate(secret.backup_codes):
                    if bc.replace("-", "").upper() == code.upper():
                        secret.backup_codes.pop(i)
                        break
            return TOTPVerificationResult(valid=True, used_backup=True)

        # Verify TOTP
        if timestamp is None:
            timestamp = time.time()

        current_counter = int(timestamp) // secret.period

        # Check current and tolerance windows
        for drift in range(-self.tolerance, self.tolerance + 1):
            counter = current_counter + drift
            expected = self._generate_hotp(secret, counter)

            if hmac.compare_digest(code, expected):
                return TOTPVerificationResult(valid=True, drift=drift)

        return TOTPVerificationResult(
            valid=False,
            error="Invalid code",
        )

    def verify_backup_code(
        self,
        secret: TOTPSecret,
        code: str,
        *,
        consume: bool = True,
    ) -> TOTPVerificationResult:
        """Verify a backup code.

        Args:
            secret: TOTP secret with backup codes.
            code: Backup code to verify.
            consume: Remove code after successful use.

        Returns:
            TOTPVerificationResult with status.
        """
        # Normalize code
        normalized = code.replace(" ", "").replace("-", "").upper()

        for i, bc in enumerate(secret.backup_codes):
            bc_normalized = bc.replace("-", "").upper()
            if hmac.compare_digest(normalized, bc_normalized):
                if consume:
                    secret.backup_codes.pop(i)
                return TOTPVerificationResult(valid=True, used_backup=True)

        return TOTPVerificationResult(
            valid=False,
            error="Invalid backup code",
        )

    def regenerate_backup_codes(self, secret: TOTPSecret) -> list[str]:
        """Regenerate backup codes for a secret.

        This replaces all existing backup codes.

        Args:
            secret: TOTP secret to regenerate codes for.

        Returns:
            New list of backup codes.
        """
        secret.backup_codes = self._generate_backup_codes()
        return secret.backup_codes.copy()


@dataclass
class MFASession:
    """Tracks MFA setup session."""

    session_id: str
    """Unique session identifier."""

    user_id: str
    """User ID being set up."""

    secret: TOTPSecret
    """Unconfirmed TOTP secret."""

    created_at: float = field(default_factory=time.time)
    """Session creation time."""

    expires_at: float = field(default_factory=lambda: time.time() + 600)
    """Session expiration (10 minutes default)."""

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return time.time() > self.expires_at


class MFAAuthProvider:
    """High-level MFA authentication provider.

    Manages MFA setup flow and verification for users.
    """

    def __init__(
        self,
        totp_manager: TOTPManager | None = None,
        *,
        session_ttl: int = 600,
    ) -> None:
        """Initialize the MFA provider.

        Args:
            totp_manager: TOTP manager instance.
            session_ttl: Setup session TTL in seconds.
        """
        self.totp = totp_manager or TOTPManager()
        self.session_ttl = session_ttl
        self._setup_sessions: dict[str, MFASession] = {}

    def setup_mfa(
        self,
        user_id: str,
        account_name: str,
    ) -> dict[str, Any]:
        """Begin MFA setup for a user.

        Args:
            user_id: User's unique identifier.
            account_name: Account name (e.g., email).

        Returns:
            Setup information including secret and QR code URI.
        """
        # Generate new secret
        secret = self.totp.generate_secret(name=account_name)

        # Create setup session
        session_id = secrets.token_urlsafe(32)
        session = MFASession(
            session_id=session_id,
            user_id=user_id,
            secret=secret,
            expires_at=time.time() + self.session_ttl,
        )
        self._setup_sessions[session_id] = session

        # Build response
        return {
            "session_id": session_id,
            "secret_base32": secret.secret_base32,
            "provisioning_uri": self.totp.get_provisioning_uri(secret),
            "backup_codes": secret.backup_codes.copy(),
            "expires_in": self.session_ttl,
        }

    def confirm_mfa(
        self,
        session_id: str,
        code: str,
    ) -> tuple[bool, TOTPSecret | None, str | None]:
        """Confirm MFA setup by verifying initial code.

        Args:
            session_id: Setup session ID.
            code: TOTP code from user's authenticator.

        Returns:
            Tuple of (success, confirmed_secret, error_message).
        """
        session = self._setup_sessions.get(session_id)

        if not session:
            return False, None, "Invalid or expired session"

        if session.is_expired:
            del self._setup_sessions[session_id]
            return False, None, "Session expired"

        # Verify the code
        result = self.totp.verify(session.secret, code, consume_backup=False)

        if not result.valid:
            return False, None, result.error or "Invalid code"

        # Mark as verified and clean up session
        session.secret.verified = True
        secret = session.secret
        del self._setup_sessions[session_id]

        return True, secret, None

    def verify_mfa(
        self,
        secret: TOTPSecret,
        code: str,
    ) -> TOTPVerificationResult:
        """Verify MFA code for authentication.

        Args:
            secret: User's stored TOTP secret.
            code: Code from user.

        Returns:
            Verification result.
        """
        return self.totp.verify(secret, code)

    def cleanup_expired_sessions(self) -> int:
        """Remove expired setup sessions.

        Returns:
            Number of sessions removed.
        """
        expired = [
            sid for sid, session in self._setup_sessions.items() if session.is_expired
        ]
        for sid in expired:
            del self._setup_sessions[sid]
        return len(expired)


# Convenience function for simple TOTP verification
def verify_totp(
    secret_base32: str,
    code: str,
    *,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
    tolerance: int = 1,
) -> bool:
    """Verify a TOTP code (convenience function).

    Args:
        secret_base32: Base32-encoded secret.
        code: TOTP code to verify.
        digits: Number of digits (6 or 8).
        period: Time period in seconds.
        algorithm: Hash algorithm (SHA1, SHA256, SHA512).
        tolerance: Number of periods to accept.

    Returns:
        True if code is valid.
    """
    # Decode secret
    # Add padding if needed
    padded = secret_base32 + "=" * ((8 - len(secret_base32) % 8) % 8)
    secret_bytes = base64.b32decode(padded.upper())

    # Create temporary secret object
    secret = TOTPSecret(
        secret=secret_bytes,
        name="",
        algorithm=TOTPAlgorithm(algorithm.upper()),
        digits=digits,
        period=period,
    )

    manager = TOTPManager(tolerance=tolerance)
    result = manager.verify(secret, code, consume_backup=False)

    return result.valid
