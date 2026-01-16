"""Instanton High-Performance Hashing Module.

Provides BLAKE3-based hashing utilities that are 14x faster than SHA256.
Falls back gracefully to SHA256 when BLAKE3 is unavailable.

Features:
- BLAKE3 hashing (when available, 14x faster than SHA256)
- SHA256 fallback for compatibility
- Key derivation functions
- Request fingerprinting
- API key hashing

Usage:
    from instanton.security.hashing import fast_hash, hash_api_key

    # Fast content hashing
    digest = fast_hash(b"some data")

    # Secure API key hashing
    hashed_key = hash_api_key("sk_live_abc123")

    # Request fingerprinting
    fingerprint = fingerprint_request("GET", "/api/users", {"Host": "example.com"})
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Any

# Try to import blake3, fall back to sha256
try:
    import blake3

    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False


class HashAlgorithm(Enum):
    """Supported hash algorithms."""

    SHA256 = "sha256"
    BLAKE3 = "blake3"


@dataclass(frozen=True)
class HashResult:
    """Result of a hash operation."""

    digest: str
    """Hexadecimal hash digest."""

    algorithm: HashAlgorithm
    """Algorithm used for hashing."""

    length: int
    """Length of the original data in bytes."""


class Hasher:
    """High-performance hasher with BLAKE3 support.

    Uses BLAKE3 when available (14x faster than SHA256),
    falls back to SHA256 for compatibility.
    """

    def __init__(
        self,
        algorithm: HashAlgorithm | None = None,
        *,
        force_sha256: bool = False,
    ) -> None:
        """Initialize the hasher.

        Args:
            algorithm: Preferred algorithm (auto-selects if None).
            force_sha256: Force SHA256 even if BLAKE3 is available.
        """
        if algorithm is not None:
            self.algorithm = algorithm
        elif force_sha256 or not BLAKE3_AVAILABLE:
            self.algorithm = HashAlgorithm.SHA256
        else:
            self.algorithm = HashAlgorithm.BLAKE3

    def hash(self, data: bytes) -> HashResult:
        """Compute hash of data.

        Args:
            data: Data to hash.

        Returns:
            HashResult with digest and metadata.
        """
        if self.algorithm == HashAlgorithm.BLAKE3 and BLAKE3_AVAILABLE:
            digest = blake3.blake3(data).hexdigest()
        else:
            digest = hashlib.sha256(data).hexdigest()

        return HashResult(
            digest=digest,
            algorithm=self.algorithm,
            length=len(data),
        )

    def hash_keyed(self, data: bytes, key: bytes) -> HashResult:
        """Compute keyed hash (MAC) of data.

        Uses BLAKE3's keyed mode or HMAC-SHA256.

        Args:
            data: Data to hash.
            key: Key for MAC computation.

        Returns:
            HashResult with keyed digest.
        """
        if self.algorithm == HashAlgorithm.BLAKE3 and BLAKE3_AVAILABLE:
            # BLAKE3 keyed mode requires exactly 32 bytes
            if len(key) != 32:
                # Derive a 32-byte key from the input
                key = blake3.blake3(key).digest()
            digest = blake3.blake3(data, key=key).hexdigest()
        else:
            # HMAC-SHA256 for compatibility
            digest = hmac.new(key, data, hashlib.sha256).hexdigest()

        return HashResult(
            digest=digest,
            algorithm=self.algorithm,
            length=len(data),
        )

    def derive_key(
        self,
        context: str,
        key_material: bytes,
        length: int = 32,
    ) -> bytes:
        """Derive a key from input material.

        Uses BLAKE3's key derivation mode or HKDF-like construction.

        Args:
            context: Context string for domain separation.
            key_material: Input key material.
            length: Desired output length in bytes.

        Returns:
            Derived key bytes.
        """
        if self.algorithm == HashAlgorithm.BLAKE3 and BLAKE3_AVAILABLE:
            return blake3.blake3(
                key_material,
                derive_key_context=context,
            ).digest(length=length)
        else:
            # Simple HKDF-like construction with SHA256
            # PRK = HMAC(salt, IKM)
            prk = hmac.new(context.encode(), key_material, hashlib.sha256).digest()
            # Expand: OKM = HMAC(PRK, info || 0x01)
            info = context.encode()
            okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
            return okm[:length]

    def verify(self, data: bytes, expected_digest: str) -> bool:
        """Verify data against expected digest.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            data: Data to verify.
            expected_digest: Expected hash digest (hex).

        Returns:
            True if data matches expected digest.
        """
        result = self.hash(data)
        return hmac.compare_digest(result.digest, expected_digest)

    def verify_keyed(
        self,
        data: bytes,
        key: bytes,
        expected_digest: str,
    ) -> bool:
        """Verify keyed hash against expected digest.

        Args:
            data: Data to verify.
            key: MAC key.
            expected_digest: Expected keyed hash digest (hex).

        Returns:
            True if keyed hash matches.
        """
        result = self.hash_keyed(data, key)
        return hmac.compare_digest(result.digest, expected_digest)


# Default hasher instance (uses BLAKE3 if available)
_default_hasher = Hasher()


def fast_hash(data: bytes) -> str:
    """Compute fast hash of data.

    Uses BLAKE3 when available (14x faster than SHA256).

    Args:
        data: Data to hash.

    Returns:
        Hexadecimal hash digest.
    """
    return _default_hasher.hash(data).digest


def hash_api_key(key: str) -> str:
    """Hash an API key for storage.

    Uses BLAKE3 with a domain-specific context for security.

    Args:
        key: API key to hash.

    Returns:
        Hashed API key (hex).
    """
    hasher = Hasher()
    # Use key derivation with domain separation
    derived = hasher.derive_key(
        context="instanton.api_key.hash.v1",
        key_material=key.encode("utf-8"),
    )
    return derived.hex()


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, bytes]:
    """Hash a password with salt.

    Note: For production password hashing, consider using argon2 or bcrypt.
    This is a fast hash suitable for tokens, not user passwords.

    Args:
        password: Password to hash.
        salt: Optional salt bytes (generated if not provided).

    Returns:
        Tuple of (hash digest, salt used).
    """
    import os

    if salt is None:
        salt = os.urandom(32)

    hasher = Hasher()
    salted = salt + password.encode("utf-8")
    digest = hasher.hash(salted).digest

    return digest, salt


def fingerprint_request(
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes | None = None,
    *,
    include_body: bool = False,
) -> str:
    """Generate a fingerprint for an HTTP request.

    Creates a unique hash based on request characteristics.
    Useful for caching, deduplication, and request signing.

    Args:
        method: HTTP method (GET, POST, etc.).
        path: Request path.
        headers: Request headers.
        body: Optional request body.
        include_body: Whether to include body in fingerprint.

    Returns:
        Request fingerprint (hex hash).
    """
    # Normalize headers (lowercase keys, sorted)
    normalized_headers = sorted(
        (k.lower(), v) for k, v in headers.items() if not _is_excluded_header(k)
    )

    # Build fingerprint data
    parts: list[str] = [
        method.upper(),
        path,
    ]
    for key, value in normalized_headers:
        parts.append(f"{key}:{value}")

    fingerprint_data = "\n".join(parts).encode("utf-8")

    if include_body and body:
        fingerprint_data += b"\n" + body

    return fast_hash(fingerprint_data)


@lru_cache(maxsize=100)
def _is_excluded_header(header: str) -> bool:
    """Check if header should be excluded from fingerprint."""
    excluded = {
        "date",
        "x-request-id",
        "x-trace-id",
        "x-correlation-id",
        "x-forwarded-for",
        "x-real-ip",
        "cookie",
        "set-cookie",
        "authorization",  # Usually handled separately
    }
    return header.lower() in excluded


def compute_checksum(data: bytes) -> str:
    """Compute a fast checksum for data integrity.

    Args:
        data: Data to checksum.

    Returns:
        Checksum string (hex).
    """
    return fast_hash(data)


def verify_checksum(data: bytes, checksum: str) -> bool:
    """Verify data integrity against checksum.

    Args:
        data: Data to verify.
        checksum: Expected checksum (hex).

    Returns:
        True if checksum matches.
    """
    return hmac.compare_digest(fast_hash(data), checksum)


def get_available_algorithm() -> HashAlgorithm:
    """Get the best available hash algorithm.

    Returns:
        BLAKE3 if available, otherwise SHA256.
    """
    return HashAlgorithm.BLAKE3 if BLAKE3_AVAILABLE else HashAlgorithm.SHA256


def hash_file(
    path: str,
    *,
    chunk_size: int = 64 * 1024,
) -> str:
    """Hash a file efficiently using streaming.

    Reads file in chunks to handle large files without
    loading entire file into memory.

    Args:
        path: Path to file.
        chunk_size: Size of chunks to read.

    Returns:
        File hash (hex).
    """
    if BLAKE3_AVAILABLE:
        hasher = blake3.blake3()
    else:
        hasher = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)

    return hasher.hexdigest()


def hash_stream(
    stream: Any,
    *,
    chunk_size: int = 64 * 1024,
) -> str:
    """Hash data from a stream.

    Args:
        stream: File-like object with read() method.
        chunk_size: Size of chunks to read.

    Returns:
        Stream hash (hex).
    """
    if BLAKE3_AVAILABLE:
        hasher = blake3.blake3()
    else:
        hasher = hashlib.sha256()

    while chunk := stream.read(chunk_size):
        hasher.update(chunk)

    return hasher.hexdigest()
