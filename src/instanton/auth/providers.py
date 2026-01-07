"""Authentication providers for Instanton.

Supports multiple authentication methods:
- API Key authentication
- JWT (JSON Web Token) authentication
- HTTP Basic authentication
- OAuth2/OIDC integration
- mTLS (Mutual TLS) client certificate authentication
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ssl
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

import httpx
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

if TYPE_CHECKING:
    from aiohttp import web


class AuthType(str, Enum):
    """Authentication type enumeration."""

    API_KEY = "api_key"
    JWT = "jwt"
    BASIC = "basic"
    OAUTH = "oauth"
    MTLS = "mtls"
    ANONYMOUS = "anonymous"


@dataclass
class AuthResult:
    """Result of an authentication attempt.

    Attributes:
        authenticated: Whether authentication was successful.
        auth_type: The type of authentication used.
        identity: The authenticated identity (user ID, client ID, etc.).
        scopes: List of granted scopes/permissions.
        metadata: Additional metadata from the auth provider.
        error: Error message if authentication failed.
        expires_at: When the authentication expires (for tokens).
    """

    authenticated: bool
    auth_type: AuthType = AuthType.ANONYMOUS
    identity: str | None = None
    scopes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    expires_at: datetime | None = None

    @staticmethod
    def success(
        auth_type: AuthType,
        identity: str,
        scopes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        expires_at: datetime | None = None,
    ) -> AuthResult:
        """Create a successful auth result."""
        return AuthResult(
            authenticated=True,
            auth_type=auth_type,
            identity=identity,
            scopes=scopes or [],
            metadata=metadata or {},
            expires_at=expires_at,
        )

    @staticmethod
    def failure(error: str, auth_type: AuthType = AuthType.ANONYMOUS) -> AuthResult:
        """Create a failed auth result."""
        return AuthResult(
            authenticated=False,
            auth_type=auth_type,
            error=error,
        )


class AuthProvider(ABC):
    """Abstract base class for authentication providers.

    All authentication providers must implement this interface.
    """

    @property
    @abstractmethod
    def auth_type(self) -> AuthType:
        """Return the type of authentication this provider handles."""
        ...

    @abstractmethod
    async def authenticate(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> AuthResult:
        """Authenticate a request or credentials.

        Args:
            request: The incoming HTTP request (optional).
            credentials: Dictionary of credentials (optional).

        Returns:
            AuthResult with authentication outcome.
        """
        ...

    @abstractmethod
    async def validate(self, token: str) -> AuthResult:
        """Validate a token or credential string.

        Args:
            token: The token/credential to validate.

        Returns:
            AuthResult with validation outcome.
        """
        ...


class APIKeyProvider(AuthProvider):
    """API Key authentication provider.

    Supports:
    - API key validation with scopes
    - Key prefix validation (e.g., 'tach_')
    - Hash-based lookup (keys stored hashed)
    - Key expiration
    """

    def __init__(
        self,
        key_prefix: str = "tach_",
        header_name: str = "X-API-Key",
        query_param: str = "api_key",
    ) -> None:
        """Initialize API key provider.

        Args:
            key_prefix: Expected prefix for API keys.
            header_name: HTTP header name for API key.
            query_param: Query parameter name for API key.
        """
        self.key_prefix = key_prefix
        self.header_name = header_name
        self.query_param = query_param
        self._storage: dict[str, dict[str, Any]] | None = None

    @property
    def auth_type(self) -> AuthType:
        return AuthType.API_KEY

    def set_storage(self, storage: dict[str, dict[str, Any]]) -> None:
        """Set the storage backend for API key lookups.

        Args:
            storage: Dictionary mapping key hashes to key metadata.
        """
        self._storage = storage

    def _hash_key(self, key: str) -> str:
        """Hash an API key for secure storage/lookup.

        Args:
            key: The raw API key.

        Returns:
            SHA-256 hash of the key.
        """
        return hashlib.sha256(key.encode()).hexdigest()

    def _extract_key(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> str | None:
        """Extract API key from request or credentials.

        Args:
            request: The HTTP request.
            credentials: Credential dictionary.

        Returns:
            The extracted API key or None.
        """
        # Try credentials dict first
        if credentials and (key := credentials.get("api_key")):
            return key

        # Try request headers and query params
        if request:
            # Check header
            if key := request.headers.get(self.header_name):
                return key
            # Check query param
            if key := request.query.get(self.query_param):
                return key

        return None

    async def authenticate(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> AuthResult:
        """Authenticate using API key."""
        key = self._extract_key(request, credentials)

        if not key:
            return AuthResult.failure("No API key provided", AuthType.API_KEY)

        return await self.validate(key)

    async def validate(self, token: str) -> AuthResult:
        """Validate an API key.

        Args:
            token: The API key to validate.

        Returns:
            AuthResult with validation outcome.
        """
        # Check prefix
        if self.key_prefix and not token.startswith(self.key_prefix):
            return AuthResult.failure(
                f"Invalid API key format (expected prefix: {self.key_prefix})",
                AuthType.API_KEY,
            )

        if self._storage is None:
            return AuthResult.failure("API key storage not configured", AuthType.API_KEY)

        # Look up hashed key
        key_hash = self._hash_key(token)
        key_data = self._storage.get(key_hash)

        if not key_data:
            return AuthResult.failure("Invalid API key", AuthType.API_KEY)

        # Check expiration
        if expires_at := key_data.get("expires_at"):
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            if expires_at < datetime.now(UTC):
                return AuthResult.failure("API key expired", AuthType.API_KEY)

        # Check if revoked
        if key_data.get("revoked", False):
            return AuthResult.failure("API key revoked", AuthType.API_KEY)

        return AuthResult.success(
            auth_type=AuthType.API_KEY,
            identity=key_data.get("client_id", key_hash[:16]),
            scopes=key_data.get("scopes", []),
            metadata={
                "key_id": key_data.get("key_id"),
                "name": key_data.get("name"),
            },
            expires_at=expires_at if isinstance(expires_at, datetime) else None,
        )


class JWTProvider(AuthProvider):
    """JWT (JSON Web Token) authentication provider.

    Supports:
    - HS256 (symmetric) and RS256 (asymmetric) algorithms
    - Standard JWT claims validation (exp, iat, nbf, iss, aud)
    - Custom claims extraction
    - Token refresh validation
    """

    def __init__(
        self,
        secret_key: str | None = None,
        public_key: str | None = None,
        algorithm: str = "HS256",
        issuer: str | None = None,
        audience: str | None = None,
        leeway: int = 10,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer",
    ) -> None:
        """Initialize JWT provider.

        Args:
            secret_key: Secret for HS256 algorithm.
            public_key: Public key for RS256 algorithm.
            algorithm: JWT algorithm (HS256 or RS256).
            issuer: Expected token issuer (iss claim).
            audience: Expected audience (aud claim).
            leeway: Seconds of leeway for time-based claims.
            header_name: HTTP header for the token.
            header_prefix: Token prefix (e.g., 'Bearer').
        """
        self.secret_key = secret_key
        self.public_key = public_key
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self.header_name = header_name
        self.header_prefix = header_prefix

        # Determine signing key based on algorithm
        if algorithm.startswith("HS"):
            if not secret_key:
                raise ValueError("Secret key required for HS* algorithms")
            self._verify_key = secret_key
        elif algorithm.startswith("RS") or algorithm.startswith("ES"):
            if not public_key:
                raise ValueError("Public key required for RS*/ES* algorithms")
            self._verify_key = public_key
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        # Revocation list
        self._revoked_tokens: set[str] = set()

    @property
    def auth_type(self) -> AuthType:
        return AuthType.JWT

    def add_to_revocation_list(self, token_id: str) -> None:
        """Add a token ID (jti) to the revocation list.

        Args:
            token_id: The JWT ID to revoke.
        """
        self._revoked_tokens.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        """Check if a token ID is revoked.

        Args:
            token_id: The JWT ID to check.

        Returns:
            True if revoked, False otherwise.
        """
        return token_id in self._revoked_tokens

    def _extract_token(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> str | None:
        """Extract JWT from request or credentials.

        Args:
            request: The HTTP request.
            credentials: Credential dictionary.

        Returns:
            The extracted token or None.
        """
        # Try credentials dict first
        if credentials:
            if token := credentials.get("token"):
                return token
            if token := credentials.get("jwt"):
                return token

        # Try request headers and query params
        if request:
            # Check Authorization header
            auth_header = request.headers.get(self.header_name, "")
            if auth_header.startswith(f"{self.header_prefix} "):
                return auth_header[len(self.header_prefix) + 1 :]

            # Check query param (for WebSocket)
            if token := request.query.get("token"):
                return token
            if token := request.query.get("access_token"):
                return token

        return None

    async def authenticate(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> AuthResult:
        """Authenticate using JWT."""
        token = self._extract_token(request, credentials)

        if not token:
            return AuthResult.failure("No JWT provided", AuthType.JWT)

        return await self.validate(token)

    async def validate(self, token: str) -> AuthResult:
        """Validate a JWT token.

        Args:
            token: The JWT to validate.

        Returns:
            AuthResult with validation outcome.
        """
        try:
            # Decode and validate the token
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "require_exp": True,
                "leeway": self.leeway,
            }

            # Add audience/issuer verification if configured
            kwargs: dict[str, Any] = {
                "algorithms": [self.algorithm],
                "options": options,
            }
            if self.audience:
                kwargs["audience"] = self.audience
            if self.issuer:
                kwargs["issuer"] = self.issuer

            claims = jwt.decode(token, self._verify_key, **kwargs)

            # Check revocation list
            if (jti := claims.get("jti")) and self.is_revoked(jti):
                return AuthResult.failure("Token has been revoked", AuthType.JWT)

            # Extract expiration
            expires_at = None
            if exp := claims.get("exp"):
                expires_at = datetime.fromtimestamp(exp, tz=UTC)

            # Extract scopes from 'scope' or 'scopes' claim
            scopes: list[str] = []
            if scope := claims.get("scope"):
                scopes = scope.split() if isinstance(scope, str) else scope
            elif scope_list := claims.get("scopes"):
                scopes = scope_list if isinstance(scope_list, list) else [scope_list]

            return AuthResult.success(
                auth_type=AuthType.JWT,
                identity=claims.get("sub", claims.get("client_id")),
                scopes=scopes,
                metadata={
                    "claims": claims,
                    "jti": claims.get("jti"),
                    "iss": claims.get("iss"),
                },
                expires_at=expires_at,
            )

        except ExpiredSignatureError:
            return AuthResult.failure("Token has expired", AuthType.JWT)
        except JWTClaimsError as e:
            return AuthResult.failure(f"Invalid claims: {e}", AuthType.JWT)
        except JWTError as e:
            return AuthResult.failure(f"Invalid token: {e}", AuthType.JWT)


class BasicAuthProvider(AuthProvider):
    """HTTP Basic authentication provider.

    Supports:
    - Username/password validation
    - Secure password comparison (timing-safe)
    - Integration with user storage backends
    """

    def __init__(
        self,
        realm: str = "Instanton",
        verify_func: Any = None,
    ) -> None:
        """Initialize Basic auth provider.

        Args:
            realm: Authentication realm for WWW-Authenticate header.
            verify_func: Async function to verify credentials.
                         Signature: async def verify(username, password) -> dict | None
        """
        self.realm = realm
        self._verify_func = verify_func
        self._users: dict[str, dict[str, Any]] = {}

    @property
    def auth_type(self) -> AuthType:
        return AuthType.BASIC

    def add_user(
        self,
        username: str,
        password_hash: str,
        scopes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a user for authentication.

        Args:
            username: The username.
            password_hash: Hashed password (use passlib for hashing).
            scopes: User's granted scopes.
            metadata: Additional user metadata.
        """
        self._users[username] = {
            "password_hash": password_hash,
            "scopes": scopes or [],
            "metadata": metadata or {},
        }

    def set_verify_function(self, func: Any) -> None:
        """Set a custom verification function.

        Args:
            func: Async function to verify credentials.
        """
        self._verify_func = func

    def _extract_credentials(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> tuple[str, str] | None:
        """Extract username/password from request or credentials.

        Args:
            request: The HTTP request.
            credentials: Credential dictionary.

        Returns:
            Tuple of (username, password) or None.
        """
        # Try credentials dict first
        if credentials:
            username = credentials.get("username")
            password = credentials.get("password")
            if username and password:
                return (username, password)

        # Try Authorization header
        if request:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                try:
                    encoded = auth_header[6:]
                    decoded = base64.b64decode(encoded).decode("utf-8")
                    if ":" in decoded:
                        username, password = decoded.split(":", 1)
                        return (username, password)
                except (ValueError, UnicodeDecodeError):
                    pass

        return None

    async def authenticate(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> AuthResult:
        """Authenticate using Basic auth."""
        creds = self._extract_credentials(request, credentials)

        if not creds:
            return AuthResult.failure("No credentials provided", AuthType.BASIC)

        username, password = creds

        # Use custom verify function if provided
        if self._verify_func:
            result = await self._verify_func(username, password)
            if result:
                return AuthResult.success(
                    auth_type=AuthType.BASIC,
                    identity=username,
                    scopes=result.get("scopes", []),
                    metadata=result.get("metadata", {}),
                )
            return AuthResult.failure("Invalid credentials", AuthType.BASIC)

        # Use internal user storage
        user = self._users.get(username)
        if not user:
            return AuthResult.failure("Invalid credentials", AuthType.BASIC)

        # Import passlib for password verification
        try:
            from passlib.hash import argon2

            if not argon2.verify(password, user["password_hash"]):
                return AuthResult.failure("Invalid credentials", AuthType.BASIC)
        except ImportError:
            # Fallback to timing-safe comparison for pre-hashed passwords
            if not hmac.compare_digest(
                hashlib.sha256(password.encode()).hexdigest(),
                user["password_hash"],
            ):
                return AuthResult.failure("Invalid credentials", AuthType.BASIC)

        return AuthResult.success(
            auth_type=AuthType.BASIC,
            identity=username,
            scopes=user.get("scopes", []),
            metadata=user.get("metadata", {}),
        )

    async def validate(self, token: str) -> AuthResult:
        """Validate Basic auth token (base64 encoded credentials).

        Args:
            token: Base64 encoded 'username:password'.

        Returns:
            AuthResult with validation outcome.
        """
        try:
            decoded = base64.b64decode(token).decode("utf-8")
            if ":" not in decoded:
                return AuthResult.failure("Invalid Basic auth format", AuthType.BASIC)

            username, password = decoded.split(":", 1)
            return await self.authenticate(credentials={"username": username, "password": password})
        except (ValueError, UnicodeDecodeError):
            return AuthResult.failure("Invalid Basic auth encoding", AuthType.BASIC)


class OAuthProvider(AuthProvider):
    """OAuth2/OIDC authentication provider.

    Supports:
    - Token introspection
    - OIDC userinfo endpoint
    - JWKS key fetching
    - Multiple OAuth providers (Google, GitHub, etc.)
    """

    def __init__(
        self,
        provider_name: str,
        client_id: str,
        client_secret: str | None = None,
        authorization_url: str | None = None,
        token_url: str | None = None,
        userinfo_url: str | None = None,
        introspection_url: str | None = None,
        jwks_url: str | None = None,
        issuer: str | None = None,
        scopes: list[str] | None = None,
    ) -> None:
        """Initialize OAuth provider.

        Args:
            provider_name: Name of the OAuth provider.
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            authorization_url: OAuth authorization endpoint.
            token_url: OAuth token endpoint.
            userinfo_url: OIDC userinfo endpoint.
            introspection_url: Token introspection endpoint (RFC 7662).
            jwks_url: JWKS endpoint for token verification.
            issuer: Expected token issuer.
            scopes: Default scopes to request.
        """
        self.provider_name = provider_name
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_url = authorization_url
        self.token_url = token_url
        self.userinfo_url = userinfo_url
        self.introspection_url = introspection_url
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.scopes = scopes or ["openid", "profile", "email"]

        # Cache for JWKS keys
        self._jwks_cache: dict[str, Any] = {}
        self._jwks_cache_time: float = 0
        self._jwks_cache_ttl: float = 3600  # 1 hour

    @property
    def auth_type(self) -> AuthType:
        return AuthType.OAUTH

    @classmethod
    def google(cls, client_id: str, client_secret: str) -> OAuthProvider:
        """Create a Google OAuth provider."""
        return cls(
            provider_name="google",
            client_id=client_id,
            client_secret=client_secret,
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
            jwks_url="https://www.googleapis.com/oauth2/v3/certs",
            issuer="https://accounts.google.com",
        )

    @classmethod
    def github(cls, client_id: str, client_secret: str) -> OAuthProvider:
        """Create a GitHub OAuth provider."""
        return cls(
            provider_name="github",
            client_id=client_id,
            client_secret=client_secret,
            authorization_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            userinfo_url="https://api.github.com/user",
            scopes=["read:user", "user:email"],
        )

    async def _fetch_jwks(self) -> dict[str, Any]:
        """Fetch and cache JWKS keys."""
        if not self.jwks_url:
            return {}

        now = time.time()
        if self._jwks_cache and now - self._jwks_cache_time < self._jwks_cache_ttl:
            return self._jwks_cache

        async with httpx.AsyncClient() as client:
            response = await client.get(self.jwks_url)
            response.raise_for_status()
            self._jwks_cache = response.json()
            self._jwks_cache_time = now

        return self._jwks_cache

    async def _introspect_token(self, token: str) -> dict[str, Any] | None:
        """Introspect a token using RFC 7662."""
        if not self.introspection_url:
            return None

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.introspection_url,
                data={"token": token},
                auth=(self.client_id, self.client_secret) if self.client_secret else None,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("active"):
                    return data

        return None

    async def _fetch_userinfo(self, token: str) -> dict[str, Any] | None:
        """Fetch user info using the access token."""
        if not self.userinfo_url:
            return None

        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.userinfo_url,
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code == 200:
                return response.json()

        return None

    def _extract_token(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> str | None:
        """Extract OAuth token from request or credentials."""
        # Try credentials dict first
        if credentials:
            if token := credentials.get("access_token"):
                return token
            if token := credentials.get("token"):
                return token

        # Try request headers
        if request:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                return auth_header[7:]

        return None

    async def authenticate(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> AuthResult:
        """Authenticate using OAuth token."""
        token = self._extract_token(request, credentials)

        if not token:
            return AuthResult.failure("No OAuth token provided", AuthType.OAUTH)

        return await self.validate(token)

    async def validate(self, token: str) -> AuthResult:
        """Validate an OAuth access token.

        Args:
            token: The OAuth access token.

        Returns:
            AuthResult with validation outcome.
        """
        try:
            # Try token introspection first
            if self.introspection_url:
                introspection = await self._introspect_token(token)
                if introspection:
                    return AuthResult.success(
                        auth_type=AuthType.OAUTH,
                        identity=introspection.get("sub") or introspection.get("username"),
                        scopes=introspection.get("scope", "").split(),
                        metadata={
                            "provider": self.provider_name,
                            "introspection": introspection,
                        },
                        expires_at=(
                            datetime.fromtimestamp(introspection["exp"], tz=UTC)
                            if "exp" in introspection
                            else None
                        ),
                    )

            # Try userinfo endpoint
            if self.userinfo_url:
                userinfo = await self._fetch_userinfo(token)
                if userinfo:
                    return AuthResult.success(
                        auth_type=AuthType.OAUTH,
                        identity=userinfo.get("sub") or userinfo.get("id") or userinfo.get("login"),
                        scopes=self.scopes,
                        metadata={
                            "provider": self.provider_name,
                            "userinfo": userinfo,
                        },
                    )

            # Try JWT validation with JWKS
            if self.jwks_url:
                jwks = await self._fetch_jwks()
                if jwks.get("keys"):
                    try:
                        # Get the header to find the right key
                        unverified_header = jwt.get_unverified_header(token)
                        kid = unverified_header.get("kid")

                        # Find the matching key
                        key = None
                        for k in jwks["keys"]:
                            if k.get("kid") == kid:
                                key = k
                                break

                        if key:
                            from jose import jwk

                            public_key = jwk.construct(key)
                            claims = jwt.decode(
                                token,
                                public_key,
                                algorithms=["RS256", "ES256"],
                                audience=self.client_id,
                                issuer=self.issuer,
                            )

                            return AuthResult.success(
                                auth_type=AuthType.OAUTH,
                                identity=claims.get("sub"),
                                scopes=claims.get("scope", "").split(),
                                metadata={
                                    "provider": self.provider_name,
                                    "claims": claims,
                                },
                                expires_at=(
                                    datetime.fromtimestamp(claims["exp"], tz=UTC)
                                    if "exp" in claims
                                    else None
                                ),
                            )
                    except JWTError:
                        pass

            return AuthResult.failure(
                "Unable to validate OAuth token",
                AuthType.OAUTH,
            )

        except httpx.HTTPError as e:
            return AuthResult.failure(f"OAuth validation error: {e}", AuthType.OAUTH)


class MTLSProvider(AuthProvider):
    """Mutual TLS (mTLS) client certificate authentication provider.

    Supports:
    - Client certificate validation
    - Certificate chain verification
    - Subject/CN extraction
    - Certificate fingerprint matching
    """

    def __init__(
        self,
        ca_cert_path: str | None = None,
        ca_cert_data: bytes | None = None,
        required_subjects: list[str] | None = None,
        required_issuers: list[str] | None = None,
        check_revocation: bool = True,
    ) -> None:
        """Initialize mTLS provider.

        Args:
            ca_cert_path: Path to CA certificate file.
            ca_cert_data: CA certificate data (PEM format).
            required_subjects: List of allowed subject CNs.
            required_issuers: List of allowed issuer CNs.
            check_revocation: Whether to check certificate revocation.
        """
        self.ca_cert_path = ca_cert_path
        self.ca_cert_data = ca_cert_data
        self.required_subjects = required_subjects
        self.required_issuers = required_issuers
        self.check_revocation = check_revocation

        # Allowed certificate fingerprints
        self._allowed_fingerprints: set[str] = set()

        # Certificate to scope mapping
        self._cert_scopes: dict[str, list[str]] = {}

    @property
    def auth_type(self) -> AuthType:
        return AuthType.MTLS

    def add_allowed_fingerprint(
        self,
        fingerprint: str,
        scopes: list[str] | None = None,
    ) -> None:
        """Add an allowed certificate fingerprint.

        Args:
            fingerprint: SHA-256 fingerprint of the certificate.
            scopes: Scopes to grant for this certificate.
        """
        fingerprint = fingerprint.lower().replace(":", "")
        self._allowed_fingerprints.add(fingerprint)
        if scopes:
            self._cert_scopes[fingerprint] = scopes

    def _get_cert_fingerprint(self, cert_der: bytes) -> str:
        """Get SHA-256 fingerprint of a certificate.

        Args:
            cert_der: DER-encoded certificate.

        Returns:
            Hex-encoded SHA-256 fingerprint.
        """
        return hashlib.sha256(cert_der).hexdigest()

    def _extract_cert_info(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Extract certificate info from request or credentials.

        Args:
            request: The HTTP request.
            credentials: Credential dictionary.

        Returns:
            Certificate info dictionary or None.
        """
        # Try credentials dict first (for pre-extracted cert info)
        if credentials and (cert_info := credentials.get("client_cert")):
            return cert_info

        # Try to get from request's transport
        if request:
            transport = request.transport
            if transport:
                ssl_object = transport.get_extra_info("ssl_object")
                if ssl_object:
                    peer_cert = ssl_object.getpeercert()
                    if peer_cert:
                        return peer_cert

        return None

    async def authenticate(
        self,
        request: web.Request | None = None,
        credentials: dict[str, Any] | None = None,
    ) -> AuthResult:
        """Authenticate using client certificate."""
        cert_info = self._extract_cert_info(request, credentials)

        if not cert_info:
            return AuthResult.failure("No client certificate provided", AuthType.MTLS)

        # Extract subject CN
        subject_cn = None
        if subject := cert_info.get("subject"):
            for rdn in subject:
                for attr_type, attr_value in rdn:
                    if attr_type == "commonName":
                        subject_cn = attr_value
                        break

        if not subject_cn:
            return AuthResult.failure("Certificate has no subject CN", AuthType.MTLS)

        # Check required subjects
        if self.required_subjects and subject_cn not in self.required_subjects:
            return AuthResult.failure(
                f"Subject CN '{subject_cn}' not in allowed list",
                AuthType.MTLS,
            )

        # Extract issuer CN
        issuer_cn = None
        if issuer := cert_info.get("issuer"):
            for rdn in issuer:
                for attr_type, attr_value in rdn:
                    if attr_type == "commonName":
                        issuer_cn = attr_value
                        break

        # Check required issuers
        if self.required_issuers and issuer_cn not in self.required_issuers:
            return AuthResult.failure(
                f"Issuer CN '{issuer_cn}' not in allowed list",
                AuthType.MTLS,
            )

        # Check fingerprint if we have the DER data
        fingerprint = None
        scopes: list[str] = []
        if cert_der := credentials.get("client_cert_der") if credentials else None:
            fingerprint = self._get_cert_fingerprint(cert_der)
            if self._allowed_fingerprints:
                if fingerprint not in self._allowed_fingerprints:
                    return AuthResult.failure(
                        "Certificate fingerprint not in allowed list",
                        AuthType.MTLS,
                    )
                scopes = self._cert_scopes.get(fingerprint, [])

        return AuthResult.success(
            auth_type=AuthType.MTLS,
            identity=subject_cn,
            scopes=scopes,
            metadata={
                "subject": cert_info.get("subject"),
                "issuer": cert_info.get("issuer"),
                "serial_number": cert_info.get("serialNumber"),
                "not_before": cert_info.get("notBefore"),
                "not_after": cert_info.get("notAfter"),
                "fingerprint": fingerprint,
            },
        )

    async def validate(self, token: str) -> AuthResult:
        """Validate a certificate fingerprint.

        Args:
            token: Certificate fingerprint to validate.

        Returns:
            AuthResult with validation outcome.
        """
        fingerprint = token.lower().replace(":", "")

        if not self._allowed_fingerprints:
            return AuthResult.failure(
                "No allowed fingerprints configured",
                AuthType.MTLS,
            )

        if fingerprint not in self._allowed_fingerprints:
            return AuthResult.failure(
                "Certificate fingerprint not in allowed list",
                AuthType.MTLS,
            )

        return AuthResult.success(
            auth_type=AuthType.MTLS,
            identity=fingerprint[:16],
            scopes=self._cert_scopes.get(fingerprint, []),
            metadata={"fingerprint": fingerprint},
        )

    def create_ssl_context(self, verify_client: bool = True) -> ssl.SSLContext:
        """Create an SSL context for mTLS.

        Args:
            verify_client: Whether to require client certificate.

        Returns:
            Configured SSL context.
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        if self.ca_cert_path:
            context.load_verify_locations(self.ca_cert_path)
        elif self.ca_cert_data:
            context.load_verify_locations(cadata=self.ca_cert_data.decode())

        if verify_client:
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_OPTIONAL

        return context
