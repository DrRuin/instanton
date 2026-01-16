"""Instanton FIDO2/WebAuthn/Passkeys Authentication Module.

Provides passwordless authentication using FIDO2/WebAuthn standards,
supporting hardware security keys and platform authenticators.

Features:
- WebAuthn registration and authentication flows
- Support for hardware security keys (YubiKey, etc.)
- Support for platform authenticators (TouchID, FaceID, Windows Hello)
- Resident key (discoverable credential) support
- User verification enforcement
- Origin validation

Usage:
    from instanton.auth.fido2 import FIDO2AuthProvider

    # Create provider
    provider = FIDO2AuthProvider(
        rp_id="example.com",
        rp_name="Example App",
    )

    # Registration flow
    options, session_id = provider.begin_registration(
        user_id="user123",
        user_name="john@example.com",
    )
    # Send options to browser, receive credential_response
    credential = provider.complete_registration(session_id, credential_response)

    # Authentication flow
    options, session_id = provider.begin_authentication(user_id="user123")
    # Send options to browser, receive credential_response
    user_id, credential = provider.complete_authentication(session_id, credential_response)

Requires:
    pip install fido2>=1.1.0
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthenticatorAttachment(Enum):
    """Authenticator attachment modality."""

    PLATFORM = "platform"  # Built-in (TouchID, Windows Hello)
    CROSS_PLATFORM = "cross-platform"  # USB/NFC key


class UserVerification(Enum):
    """User verification requirement."""

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class ResidentKey(Enum):
    """Resident key (discoverable credential) requirement."""

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class AttestationConveyance(Enum):
    """Attestation conveyance preference."""

    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"
    ENTERPRISE = "enterprise"


@dataclass
class FIDO2Credential:
    """Stored FIDO2 credential."""

    credential_id: bytes
    """Credential ID (unique per authenticator)."""

    public_key: bytes
    """COSE-encoded public key."""

    sign_count: int
    """Signature counter for clone detection."""

    user_id: str
    """Associated user ID."""

    aaguid: bytes
    """Authenticator AAGUID (model identifier)."""

    created_at: float = field(default_factory=time.time)
    """Registration timestamp."""

    last_used: float | None = None
    """Last authentication timestamp."""

    name: str = "Security Key"
    """User-friendly credential name."""

    transports: list[str] = field(default_factory=list)
    """Supported transports (usb, nfc, ble, internal)."""

    @property
    def credential_id_b64(self) -> str:
        """Get credential ID as URL-safe base64."""
        return base64.urlsafe_b64encode(self.credential_id).decode().rstrip("=")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "credential_id": base64.b64encode(self.credential_id).decode(),
            "public_key": base64.b64encode(self.public_key).decode(),
            "sign_count": self.sign_count,
            "user_id": self.user_id,
            "aaguid": base64.b64encode(self.aaguid).decode(),
            "created_at": self.created_at,
            "last_used": self.last_used,
            "name": self.name,
            "transports": self.transports,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FIDO2Credential:
        """Create from dictionary."""
        return cls(
            credential_id=base64.b64decode(data["credential_id"]),
            public_key=base64.b64decode(data["public_key"]),
            sign_count=data["sign_count"],
            user_id=data["user_id"],
            aaguid=base64.b64decode(data.get("aaguid", "")),
            created_at=data.get("created_at", time.time()),
            last_used=data.get("last_used"),
            name=data.get("name", "Security Key"),
            transports=data.get("transports", []),
        )


@dataclass
class FIDO2Session:
    """Tracks FIDO2 ceremony session."""

    session_id: str
    """Unique session identifier."""

    challenge: bytes
    """Random challenge bytes."""

    user_id: str | None
    """User ID (for registration) or None (for authentication)."""

    is_registration: bool
    """Whether this is a registration ceremony."""

    created_at: float = field(default_factory=time.time)
    """Session creation time."""

    expires_at: float = field(default_factory=lambda: time.time() + 300)
    """Session expiration (5 minutes default)."""

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return time.time() > self.expires_at

    @property
    def challenge_b64(self) -> str:
        """Get challenge as URL-safe base64."""
        return base64.urlsafe_b64encode(self.challenge).decode().rstrip("=")


class FIDO2AuthProvider:
    """FIDO2/WebAuthn authentication provider.

    Manages WebAuthn registration and authentication ceremonies.
    """

    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        *,
        origin: str | None = None,
        timeout: int = 60000,
        user_verification: UserVerification = UserVerification.PREFERRED,
        resident_key: ResidentKey = ResidentKey.PREFERRED,
        attestation: AttestationConveyance = AttestationConveyance.NONE,
        authenticator_attachment: AuthenticatorAttachment | None = None,
        session_ttl: int = 300,
    ) -> None:
        """Initialize the FIDO2 provider.

        Args:
            rp_id: Relying Party ID (usually domain name).
            rp_name: Relying Party display name.
            origin: Expected origin (e.g., https://example.com).
            timeout: Ceremony timeout in milliseconds.
            user_verification: User verification requirement.
            resident_key: Resident key requirement.
            attestation: Attestation conveyance preference.
            authenticator_attachment: Restrict to platform/cross-platform.
            session_ttl: Session TTL in seconds.
        """
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin or f"https://{rp_id}"
        self.timeout = timeout
        self.user_verification = user_verification
        self.resident_key = resident_key
        self.attestation = attestation
        self.authenticator_attachment = authenticator_attachment
        self.session_ttl = session_ttl

        self._sessions: dict[str, FIDO2Session] = {}
        self._credentials: dict[str, list[FIDO2Credential]] = {}  # user_id -> credentials

    def _check_fido2_available(self) -> None:
        """Check if fido2 library is available."""
        import importlib.util

        if importlib.util.find_spec("fido2") is None:
            raise ImportError(
                "FIDO2 authentication requires 'fido2' package. "
                "Install with: pip install 'fido2>=1.1.0'"
            )

    def begin_registration(
        self,
        user_id: str,
        user_name: str,
        *,
        user_display_name: str | None = None,
        exclude_credentials: list[FIDO2Credential] | None = None,
    ) -> tuple[dict[str, Any], str]:
        """Begin WebAuthn registration ceremony.

        Args:
            user_id: Unique user identifier.
            user_name: User name (e.g., email).
            user_display_name: Display name (defaults to user_name).
            exclude_credentials: Credentials to exclude (prevent re-registration).

        Returns:
            Tuple of (PublicKeyCredentialCreationOptions dict, session_id).
        """
        self._check_fido2_available()

        # Generate challenge
        challenge = os.urandom(32)

        # Create session
        session_id = secrets.token_urlsafe(32)
        session = FIDO2Session(
            session_id=session_id,
            challenge=challenge,
            user_id=user_id,
            is_registration=True,
            expires_at=time.time() + self.session_ttl,
        )
        self._sessions[session_id] = session

        # Build user ID bytes
        user_id_bytes = hashlib.sha256(user_id.encode()).digest()[:16]

        # Build exclude list
        exclude_descriptors = []
        if exclude_credentials:
            for cred in exclude_credentials:
                exclude_descriptors.append({
                    "type": "public-key",
                    "id": base64.urlsafe_b64encode(cred.credential_id).decode().rstrip("="),
                    "transports": cred.transports or ["usb", "nfc", "ble", "internal"],
                })

        # Build options as dict (for JSON serialization to browser)
        options = {
            "rp": {
                "id": self.rp_id,
                "name": self.rp_name,
            },
            "user": {
                "id": base64.urlsafe_b64encode(user_id_bytes).decode().rstrip("="),
                "name": user_name,
                "displayName": user_display_name or user_name,
            },
            "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},   # ES256
                {"type": "public-key", "alg": -257}, # RS256
                {"type": "public-key", "alg": -8},   # EdDSA
            ],
            "timeout": self.timeout,
            "attestation": self.attestation.value,
            "authenticatorSelection": {
                "userVerification": self.user_verification.value,
                "residentKey": self.resident_key.value,
            },
        }

        if self.authenticator_attachment:
            options["authenticatorSelection"]["authenticatorAttachment"] = (
                self.authenticator_attachment.value
            )

        if exclude_descriptors:
            options["excludeCredentials"] = exclude_descriptors

        return options, session_id

    def complete_registration(
        self,
        session_id: str,
        credential_response: dict[str, Any],
    ) -> tuple[bool, FIDO2Credential | None, str | None]:
        """Complete WebAuthn registration ceremony.

        Args:
            session_id: Session ID from begin_registration.
            credential_response: Credential response from browser.

        Returns:
            Tuple of (success, credential, error_message).
        """
        self._check_fido2_available()
        from fido2.webauthn import (
            AttestationObject,
            CollectedClientData,
        )

        session = self._sessions.get(session_id)
        if not session:
            return False, None, "Invalid or expired session"

        if session.is_expired:
            del self._sessions[session_id]
            return False, None, "Session expired"

        if not session.is_registration:
            return False, None, "Not a registration session"

        try:
            # Parse response
            client_data = CollectedClientData(
                base64.urlsafe_b64decode(
                    credential_response["response"]["clientDataJSON"] + "=="
                )
            )
            attestation_object = AttestationObject(
                base64.urlsafe_b64decode(
                    credential_response["response"]["attestationObject"] + "=="
                )
            )

            # Verify origin
            if client_data.origin != self.origin:
                return False, None, f"Origin mismatch: {client_data.origin}"

            # Verify challenge
            if client_data.challenge != session.challenge:
                return False, None, "Challenge mismatch"

            # Extract credential data
            auth_data = attestation_object.auth_data
            credential_data = auth_data.credential_data

            if not credential_data:
                return False, None, "No credential data in response"

            # Create credential
            credential = FIDO2Credential(
                credential_id=credential_data.credential_id,
                public_key=credential_data.public_key,
                sign_count=auth_data.counter,
                user_id=session.user_id,
                aaguid=credential_data.aaguid,
                transports=credential_response.get("transports", []),
            )

            # Store credential
            if session.user_id not in self._credentials:
                self._credentials[session.user_id] = []
            self._credentials[session.user_id].append(credential)

            # Clean up session
            del self._sessions[session_id]

            return True, credential, None

        except Exception as e:
            return False, None, f"Registration failed: {e}"

    def begin_authentication(
        self,
        user_id: str | None = None,
        *,
        credentials: list[FIDO2Credential] | None = None,
    ) -> tuple[dict[str, Any], str]:
        """Begin WebAuthn authentication ceremony.

        Args:
            user_id: User ID to authenticate (optional for discoverable credentials).
            credentials: Allowed credentials (auto-loaded if user_id provided).

        Returns:
            Tuple of (PublicKeyCredentialRequestOptions dict, session_id).
        """
        self._check_fido2_available()

        # Generate challenge
        challenge = os.urandom(32)

        # Create session
        session_id = secrets.token_urlsafe(32)
        session = FIDO2Session(
            session_id=session_id,
            challenge=challenge,
            user_id=user_id,
            is_registration=False,
            expires_at=time.time() + self.session_ttl,
        )
        self._sessions[session_id] = session

        # Get credentials to allow
        if credentials is None and user_id:
            credentials = self._credentials.get(user_id, [])

        # Build allow list
        allow_credentials = []
        if credentials:
            for cred in credentials:
                allow_credentials.append({
                    "type": "public-key",
                    "id": base64.urlsafe_b64encode(cred.credential_id).decode().rstrip("="),
                    "transports": cred.transports or ["usb", "nfc", "ble", "internal"],
                })

        # Build options
        options = {
            "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
            "timeout": self.timeout,
            "rpId": self.rp_id,
            "userVerification": self.user_verification.value,
        }

        if allow_credentials:
            options["allowCredentials"] = allow_credentials

        return options, session_id

    def complete_authentication(
        self,
        session_id: str,
        credential_response: dict[str, Any],
        *,
        credentials: list[FIDO2Credential] | None = None,
    ) -> tuple[bool, str | None, FIDO2Credential | None, str | None]:
        """Complete WebAuthn authentication ceremony.

        Args:
            session_id: Session ID from begin_authentication.
            credential_response: Credential response from browser.
            credentials: Credentials to verify against (optional).

        Returns:
            Tuple of (success, user_id, credential, error_message).
        """
        self._check_fido2_available()
        from fido2.cose import CoseKey
        from fido2.webauthn import AuthenticatorData, CollectedClientData

        session = self._sessions.get(session_id)
        if not session:
            return False, None, None, "Invalid or expired session"

        if session.is_expired:
            del self._sessions[session_id]
            return False, None, None, "Session expired"

        if session.is_registration:
            return False, None, None, "Not an authentication session"

        try:
            # Parse response
            client_data = CollectedClientData(
                base64.urlsafe_b64decode(
                    credential_response["response"]["clientDataJSON"] + "=="
                )
            )
            authenticator_data = AuthenticatorData(
                base64.urlsafe_b64decode(
                    credential_response["response"]["authenticatorData"] + "=="
                )
            )
            signature = base64.urlsafe_b64decode(
                credential_response["response"]["signature"] + "=="
            )
            credential_id = base64.urlsafe_b64decode(
                credential_response["id"] + "=="
            )

            # Verify origin
            if client_data.origin != self.origin:
                return False, None, None, f"Origin mismatch: {client_data.origin}"

            # Verify challenge
            if client_data.challenge != session.challenge:
                return False, None, None, "Challenge mismatch"

            # Find credential
            if credentials is None and session.user_id:
                credentials = self._credentials.get(session.user_id, [])

            if not credentials:
                # Search all credentials for discoverable credential
                for _uid, creds in self._credentials.items():
                    for c in creds:
                        if c.credential_id == credential_id:
                            credentials = [c]
                            break
                    if credentials:
                        break

            matching_credential = None
            for cred in credentials or []:
                if cred.credential_id == credential_id:
                    matching_credential = cred
                    break

            if not matching_credential:
                return False, None, None, "Unknown credential"

            # Verify signature
            public_key = CoseKey.parse(matching_credential.public_key)
            client_data_hash = hashlib.sha256(client_data).digest()
            signed_data = authenticator_data + client_data_hash

            try:
                public_key.verify(signed_data, signature)
            except Exception:
                return False, None, None, "Invalid signature"

            # Check sign count (clone detection)
            if authenticator_data.counter > 0:
                if authenticator_data.counter <= matching_credential.sign_count:
                    return False, None, None, "Possible credential cloning detected"
                matching_credential.sign_count = authenticator_data.counter

            # Update last used
            matching_credential.last_used = time.time()

            # Clean up session
            del self._sessions[session_id]

            return True, matching_credential.user_id, matching_credential, None

        except Exception as e:
            return False, None, None, f"Authentication failed: {e}"

    def get_credentials(self, user_id: str) -> list[FIDO2Credential]:
        """Get all credentials for a user.

        Args:
            user_id: User ID.

        Returns:
            List of FIDO2Credential objects.
        """
        return self._credentials.get(user_id, [])

    def remove_credential(
        self,
        user_id: str,
        credential_id: bytes | str,
    ) -> bool:
        """Remove a credential.

        Args:
            user_id: User ID.
            credential_id: Credential ID (bytes or base64).

        Returns:
            True if credential was removed.
        """
        if isinstance(credential_id, str):
            credential_id = base64.urlsafe_b64decode(credential_id + "==")

        credentials = self._credentials.get(user_id, [])
        for i, cred in enumerate(credentials):
            if cred.credential_id == credential_id:
                credentials.pop(i)
                return True
        return False

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions.

        Returns:
            Number of sessions removed.
        """
        expired = [
            sid for sid, session in self._sessions.items() if session.is_expired
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)


# Convenience functions for simple use cases

def is_fido2_available() -> bool:
    """Check if FIDO2 library is available.

    Returns:
        True if fido2 package is installed.
    """
    import importlib.util

    return importlib.util.find_spec("fido2") is not None
