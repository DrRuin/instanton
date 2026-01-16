"""Instanton Request Signing Module.

Provides cryptographic request signing for authentication and integrity
verification using HMAC-SHA256 or Ed25519 signatures.

Features:
- HMAC-SHA256 signing (symmetric key)
- Ed25519 signing (asymmetric key)
- HTTP Signature header generation (draft-cavage-http-signatures)
- Request canonicalization
- Timestamp-based replay protection

Usage:
    from instanton.security.signing import RequestSigner, RequestVerifier

    # HMAC signing
    signer = RequestSigner(secret_key=b"shared-secret")
    signed = signer.sign("POST", "/api/users", headers, body)

    # Add signature to request
    headers["Authorization"] = f"Signature {signed.signature_header}"

    # Verify on receiver
    verifier = RequestVerifier(secret_key=b"shared-secret")
    result = verifier.verify("POST", "/api/users", headers, body)
    if result.valid:
        process_request()
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SignatureAlgorithm(Enum):
    """Supported signature algorithms."""

    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA512 = "hmac-sha512"
    ED25519 = "ed25519"


@dataclass
class SignedRequest:
    """Result of signing a request."""

    method: str
    """HTTP method."""

    path: str
    """Request path."""

    signature: bytes
    """Raw signature bytes."""

    signature_base64: str
    """Base64-encoded signature."""

    algorithm: SignatureAlgorithm
    """Algorithm used for signing."""

    signed_headers: list[str]
    """Headers included in signature."""

    timestamp: int
    """Unix timestamp when signed."""

    key_id: str | None = None
    """Key identifier for key lookup."""

    nonce: str | None = None
    """Random nonce for replay protection."""

    @property
    def signature_header(self) -> str:
        """Generate Signature header value (draft-cavage-http-signatures style)."""
        parts = [
            f'keyId="{self.key_id or "default"}"',
            f'algorithm="{self.algorithm.value}"',
            f'headers="{" ".join(self.signed_headers)}"',
            f'signature="{self.signature_base64}"',
        ]
        if self.nonce:
            parts.append(f'nonce="{self.nonce}"')
        return ", ".join(parts)


@dataclass
class SignatureVerificationResult:
    """Result of signature verification."""

    valid: bool
    """Whether signature is valid."""

    error: str | None = None
    """Error message if verification failed."""

    key_id: str | None = None
    """Key ID from signature."""

    algorithm: SignatureAlgorithm | None = None
    """Algorithm used for verification."""

    timestamp: int | None = None
    """Timestamp from signature."""

    age_seconds: int | None = None
    """Age of signature in seconds."""


@dataclass
class KeyPair:
    """Ed25519 key pair for asymmetric signing."""

    private_key: bytes
    """32-byte private key."""

    public_key: bytes
    """32-byte public key."""

    key_id: str = ""
    """Key identifier."""

    created_at: float = field(default_factory=time.time)
    """Creation timestamp."""

    @classmethod
    def generate(cls, key_id: str = "") -> KeyPair:
        """Generate a new Ed25519 key pair.

        Args:
            key_id: Optional key identifier.

        Returns:
            New KeyPair instance.

        Raises:
            ImportError: If cryptography package is not installed.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as e:
            raise ImportError(
                "Ed25519 signing requires 'cryptography' package. "
                "Install with: pip install cryptography"
            ) from e

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        return cls(
            private_key=private_key.private_bytes_raw(),
            public_key=public_key.public_bytes_raw(),
            key_id=key_id or base64.urlsafe_b64encode(os.urandom(8)).decode()[:11],
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "private_key": base64.b64encode(self.private_key).decode(),
            "public_key": base64.b64encode(self.public_key).decode(),
            "key_id": self.key_id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyPair:
        """Create from dictionary."""
        return cls(
            private_key=base64.b64decode(data["private_key"]),
            public_key=base64.b64decode(data["public_key"]),
            key_id=data.get("key_id", ""),
            created_at=data.get("created_at", time.time()),
        )


class RequestSigner:
    """Signs HTTP requests for authentication and integrity.

    Supports both HMAC (symmetric) and Ed25519 (asymmetric) signing.
    """

    # Default headers to sign
    DEFAULT_SIGNED_HEADERS = [
        "(request-target)",
        "host",
        "date",
        "content-type",
        "digest",
    ]

    def __init__(
        self,
        *,
        secret_key: bytes | None = None,
        key_pair: KeyPair | None = None,
        algorithm: SignatureAlgorithm | None = None,
        key_id: str | None = None,
        signed_headers: list[str] | None = None,
        include_nonce: bool = True,
        include_timestamp: bool = True,
    ) -> None:
        """Initialize the request signer.

        Args:
            secret_key: Shared secret for HMAC signing.
            key_pair: Key pair for Ed25519 signing.
            algorithm: Signature algorithm (auto-detected if not specified).
            key_id: Key identifier.
            signed_headers: Headers to include in signature.
            include_nonce: Include random nonce for replay protection.
            include_timestamp: Include timestamp in signature.
        """
        if secret_key:
            self.secret_key = secret_key
            self.key_pair = None
            self.algorithm = algorithm or SignatureAlgorithm.HMAC_SHA256
        elif key_pair:
            self.secret_key = None
            self.key_pair = key_pair
            self.algorithm = SignatureAlgorithm.ED25519
        else:
            raise ValueError("Either secret_key or key_pair must be provided")

        self.key_id = key_id or (key_pair.key_id if key_pair else "default")
        self.signed_headers = signed_headers or self.DEFAULT_SIGNED_HEADERS.copy()
        self.include_nonce = include_nonce
        self.include_timestamp = include_timestamp

    def sign(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> SignedRequest:
        """Sign an HTTP request.

        Args:
            method: HTTP method.
            path: Request path.
            headers: Request headers.
            body: Optional request body.

        Returns:
            SignedRequest with signature details.
        """
        timestamp = int(time.time())
        nonce = base64.urlsafe_b64encode(os.urandom(16)).decode() if self.include_nonce else None

        # Prepare headers for signing
        signing_headers = dict(headers)

        # Add timestamp header if not present
        if self.include_timestamp and "x-signature-timestamp" not in signing_headers:
            signing_headers["x-signature-timestamp"] = str(timestamp)

        # Add nonce header if included
        if nonce and "x-signature-nonce" not in signing_headers:
            signing_headers["x-signature-nonce"] = nonce

        # Add body digest if body present
        if body and "digest" not in signing_headers:
            digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
            signing_headers["digest"] = f"SHA-256={digest}"

        # Build signing string
        signing_string = self._build_signing_string(
            method, path, signing_headers, self.signed_headers
        )

        # Sign
        if self.algorithm == SignatureAlgorithm.ED25519:
            signature = self._sign_ed25519(signing_string.encode())
        else:
            signature = self._sign_hmac(signing_string.encode())

        return SignedRequest(
            method=method,
            path=path,
            signature=signature,
            signature_base64=base64.b64encode(signature).decode(),
            algorithm=self.algorithm,
            signed_headers=self.signed_headers,
            timestamp=timestamp,
            key_id=self.key_id,
            nonce=nonce,
        )

    def _build_signing_string(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        signed_headers: list[str],
    ) -> str:
        """Build the canonical signing string."""
        lines = []

        for header_name in signed_headers:
            if header_name == "(request-target)":
                lines.append(f"(request-target): {method.lower()} {path}")
            elif header_name == "(created)":
                lines.append(f"(created): {int(time.time())}")
            elif header_name == "(expires)":
                lines.append(f"(expires): {int(time.time()) + 300}")
            else:
                # Case-insensitive header lookup
                value = None
                for h, v in headers.items():
                    if h.lower() == header_name.lower():
                        value = v
                        break
                if value is not None:
                    lines.append(f"{header_name.lower()}: {value}")

        return "\n".join(lines)

    def _sign_hmac(self, data: bytes) -> bytes:
        """Sign with HMAC."""
        if self.algorithm == SignatureAlgorithm.HMAC_SHA512:
            return hmac.new(self.secret_key, data, hashlib.sha512).digest()
        else:
            return hmac.new(self.secret_key, data, hashlib.sha256).digest()

    def _sign_ed25519(self, data: bytes) -> bytes:
        """Sign with Ed25519."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as e:
            raise ImportError(
                "Ed25519 signing requires 'cryptography' package"
            ) from e

        private_key = Ed25519PrivateKey.from_private_bytes(self.key_pair.private_key)
        return private_key.sign(data)


class RequestVerifier:
    """Verifies signed HTTP requests.

    Supports both HMAC (symmetric) and Ed25519 (asymmetric) verification.
    """

    def __init__(
        self,
        *,
        secret_key: bytes | None = None,
        public_key: bytes | None = None,
        key_resolver: Any | None = None,
        max_age_seconds: int = 300,
        require_nonce: bool = False,
    ) -> None:
        """Initialize the request verifier.

        Args:
            secret_key: Shared secret for HMAC verification.
            public_key: Public key for Ed25519 verification.
            key_resolver: Callable that resolves key_id to key material.
            max_age_seconds: Maximum signature age to accept.
            require_nonce: Require nonce in signatures.
        """
        self.secret_key = secret_key
        self.public_key = public_key
        self.key_resolver = key_resolver
        self.max_age_seconds = max_age_seconds
        self.require_nonce = require_nonce
        self._used_nonces: set[str] = set()

    def verify(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None = None,
        signature_header: str | None = None,
    ) -> SignatureVerificationResult:
        """Verify a signed request.

        Args:
            method: HTTP method.
            path: Request path.
            headers: Request headers (including signature).
            body: Optional request body.
            signature_header: Signature header value (or extracted from headers).

        Returns:
            SignatureVerificationResult with status.
        """
        # Extract signature header
        if signature_header is None:
            signature_header = headers.get("Authorization", "")
            if signature_header.startswith("Signature "):
                signature_header = signature_header[10:]
            elif "Signature" in headers:
                signature_header = headers["Signature"]
            else:
                return SignatureVerificationResult(
                    valid=False,
                    error="No signature header found",
                )

        # Parse signature header
        try:
            parsed = self._parse_signature_header(signature_header)
        except ValueError as e:
            return SignatureVerificationResult(
                valid=False,
                error=f"Invalid signature header: {e}",
            )

        key_id = parsed.get("keyId", "default")
        algorithm = SignatureAlgorithm(parsed.get("algorithm", "hmac-sha256"))
        signed_headers = parsed.get("headers", "(request-target)").split()
        signature_b64 = parsed.get("signature", "")
        nonce = parsed.get("nonce")

        # Check nonce if required
        if self.require_nonce and not nonce:
            return SignatureVerificationResult(
                valid=False,
                error="Nonce required but not present",
                key_id=key_id,
                algorithm=algorithm,
            )

        # Check for nonce reuse
        if nonce:
            if nonce in self._used_nonces:
                return SignatureVerificationResult(
                    valid=False,
                    error="Nonce already used (replay attack)",
                    key_id=key_id,
                    algorithm=algorithm,
                )

        # Check timestamp
        timestamp_str = headers.get("x-signature-timestamp")
        timestamp = int(timestamp_str) if timestamp_str else None
        age_seconds = None

        if timestamp:
            age_seconds = int(time.time()) - timestamp
            if age_seconds > self.max_age_seconds:
                return SignatureVerificationResult(
                    valid=False,
                    error=f"Signature expired (age: {age_seconds}s)",
                    key_id=key_id,
                    algorithm=algorithm,
                    timestamp=timestamp,
                    age_seconds=age_seconds,
                )

        # Verify body digest if present
        if body and "digest" in [h.lower() for h in signed_headers]:
            expected_digest = f"SHA-256={base64.b64encode(hashlib.sha256(body).digest()).decode()}"
            actual_digest = headers.get("digest", "")
            if not hmac.compare_digest(expected_digest, actual_digest):
                return SignatureVerificationResult(
                    valid=False,
                    error="Body digest mismatch",
                    key_id=key_id,
                    algorithm=algorithm,
                )

        # Build signing string
        signing_string = self._build_signing_string(method, path, headers, signed_headers)

        # Decode signature
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            return SignatureVerificationResult(
                valid=False,
                error="Invalid signature encoding",
                key_id=key_id,
                algorithm=algorithm,
            )

        # Verify signature
        if algorithm == SignatureAlgorithm.ED25519:
            valid = self._verify_ed25519(signing_string.encode(), signature, key_id)
        else:
            valid = self._verify_hmac(signing_string.encode(), signature, algorithm, key_id)

        if valid and nonce:
            self._used_nonces.add(nonce)
            # Cleanup old nonces (simple approach)
            if len(self._used_nonces) > 10000:
                self._used_nonces.clear()

        return SignatureVerificationResult(
            valid=valid,
            error=None if valid else "Signature mismatch",
            key_id=key_id,
            algorithm=algorithm,
            timestamp=timestamp,
            age_seconds=age_seconds,
        )

    def _parse_signature_header(self, header: str) -> dict[str, str]:
        """Parse Signature header value."""
        result = {}
        # Simple parser for key="value" pairs
        import re
        pattern = r'(\w+)="([^"]*)"'
        for match in re.finditer(pattern, header):
            result[match.group(1)] = match.group(2)
        return result

    def _build_signing_string(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        signed_headers: list[str],
    ) -> str:
        """Build the canonical signing string."""
        lines = []

        for header_name in signed_headers:
            if header_name == "(request-target)":
                lines.append(f"(request-target): {method.lower()} {path}")
            else:
                # Case-insensitive header lookup
                value = None
                for h, v in headers.items():
                    if h.lower() == header_name.lower():
                        value = v
                        break
                if value is not None:
                    lines.append(f"{header_name.lower()}: {value}")

        return "\n".join(lines)

    def _verify_hmac(
        self,
        data: bytes,
        signature: bytes,
        algorithm: SignatureAlgorithm,
        key_id: str,
    ) -> bool:
        """Verify HMAC signature."""
        # Get key
        key = self.secret_key
        if key is None and self.key_resolver:
            key = self.key_resolver(key_id)
        if key is None:
            return False

        if algorithm == SignatureAlgorithm.HMAC_SHA512:
            expected = hmac.new(key, data, hashlib.sha512).digest()
        else:
            expected = hmac.new(key, data, hashlib.sha256).digest()

        return hmac.compare_digest(expected, signature)

    def _verify_ed25519(
        self,
        data: bytes,
        signature: bytes,
        key_id: str,
    ) -> bool:
        """Verify Ed25519 signature."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError:
            return False

        # Get public key
        public_key = self.public_key
        if public_key is None and self.key_resolver:
            public_key = self.key_resolver(key_id)
        if public_key is None:
            return False

        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, data)
            return True
        except Exception:
            return False


def create_signed_headers(
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes | None = None,
    *,
    secret_key: bytes | None = None,
    key_pair: KeyPair | None = None,
) -> dict[str, str]:
    """Create signed request headers (convenience function).

    Args:
        method: HTTP method.
        path: Request path.
        headers: Original headers.
        body: Optional request body.
        secret_key: HMAC secret key.
        key_pair: Ed25519 key pair.

    Returns:
        Headers with signature added.
    """
    signer = RequestSigner(secret_key=secret_key, key_pair=key_pair)
    signed = signer.sign(method, path, headers, body)

    result = dict(headers)
    result["Authorization"] = f"Signature {signed.signature_header}"

    if signed.nonce:
        result["X-Signature-Nonce"] = signed.nonce
    result["X-Signature-Timestamp"] = str(signed.timestamp)

    return result
