"""Authentication middleware for Instanton.

Provides:
- AuthMiddleware for aiohttp
- Auth extraction from headers and query params
- Auth context injection
- Permission checking
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from aiohttp import web

from instanton.auth.providers import AuthProvider, AuthResult, AuthType

if TYPE_CHECKING:
    from instanton.auth.permissions import Permission


# ==============================================================================
# Auth Context
# ==============================================================================


@dataclass
class AuthContext:
    """Authentication context for a request.

    Stored in request state and accessible throughout the request lifecycle.

    Attributes:
        authenticated: Whether the request is authenticated.
        auth_type: Type of authentication used.
        identity: Authenticated identity (user ID, client ID, etc.).
        scopes: Granted scopes/permissions.
        metadata: Additional authentication metadata.
        expires_at: When the authentication expires.
        request_id: Unique request identifier.
    """

    authenticated: bool = False
    auth_type: AuthType = AuthType.ANONYMOUS
    identity: str | None = None
    scopes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    expires_at: datetime | None = None
    request_id: str | None = None

    @classmethod
    def from_auth_result(cls, result: AuthResult, request_id: str | None = None) -> AuthContext:
        """Create auth context from an auth result.

        Args:
            result: The authentication result.
            request_id: Optional request identifier.

        Returns:
            AuthContext instance.
        """
        return cls(
            authenticated=result.authenticated,
            auth_type=result.auth_type,
            identity=result.identity,
            scopes=result.scopes,
            metadata=result.metadata,
            expires_at=result.expires_at,
            request_id=request_id,
        )

    def has_scope(self, scope: str) -> bool:
        """Check if the context has a specific scope.

        Args:
            scope: The scope to check.

        Returns:
            True if scope is granted.
        """
        return scope in self.scopes

    def has_any_scope(self, scopes: list[str]) -> bool:
        """Check if the context has any of the specified scopes.

        Args:
            scopes: List of scopes to check.

        Returns:
            True if any scope is granted.
        """
        return bool(set(self.scopes) & set(scopes))

    def has_all_scopes(self, scopes: list[str]) -> bool:
        """Check if the context has all specified scopes.

        Args:
            scopes: List of scopes to check.

        Returns:
            True if all scopes are granted.
        """
        return set(scopes).issubset(set(self.scopes))

    def has_permission(self, permission: Permission) -> bool:
        """Check if the context has a specific permission.

        Args:
            permission: The permission to check.

        Returns:
            True if permission is granted.
        """
        return permission.value in self.scopes or f"permission:{permission.value}" in self.scopes


# Request key for storing auth context
AUTH_CONTEXT_KEY = "instanton_auth_context"


def get_auth_context(request: web.Request) -> AuthContext:
    """Get auth context from request.

    Args:
        request: The aiohttp request.

    Returns:
        AuthContext instance (anonymous if not authenticated).
    """
    return request.get(AUTH_CONTEXT_KEY, AuthContext())


def set_auth_context(request: web.Request, context: AuthContext) -> None:
    """Set auth context on request.

    Args:
        request: The aiohttp request.
        context: The auth context to set.
    """
    request[AUTH_CONTEXT_KEY] = context


# ==============================================================================
# Auth Middleware
# ==============================================================================


class AuthMiddleware:
    """Authentication middleware for aiohttp.

    Features:
    - Multiple auth provider support
    - Header and query param extraction
    - Anonymous access control
    - Path exclusion
    - Custom error handling
    """

    def __init__(
        self,
        providers: list[AuthProvider] | None = None,
        allow_anonymous: bool = False,
        excluded_paths: list[str] | None = None,
        error_handler: Callable[[web.Request, str], Awaitable[web.Response]] | None = None,
    ) -> None:
        """Initialize auth middleware.

        Args:
            providers: List of authentication providers to try.
            allow_anonymous: Whether to allow unauthenticated requests.
            excluded_paths: Paths that don't require authentication.
            error_handler: Custom error handler for auth failures.
        """
        self.providers = providers or []
        self.allow_anonymous = allow_anonymous
        self.excluded_paths = excluded_paths or []
        self.error_handler = error_handler

    def add_provider(self, provider: AuthProvider) -> None:
        """Add an authentication provider.

        Args:
            provider: The provider to add.
        """
        self.providers.append(provider)

    def exclude_path(self, path: str) -> None:
        """Add a path to the exclusion list.

        Args:
            path: Path pattern to exclude.
        """
        self.excluded_paths.append(path)

    def _is_excluded(self, path: str) -> bool:
        """Check if a path is excluded from authentication.

        Args:
            path: The request path.

        Returns:
            True if excluded.
        """
        for excluded in self.excluded_paths:
            if excluded.endswith("*"):
                if path.startswith(excluded[:-1]):
                    return True
            elif path == excluded:
                return True
        return False

    def _has_auth_header(self, request: web.Request) -> bool:
        """Check if request has any auth headers/params.

        Args:
            request: The aiohttp request.

        Returns:
            True if auth information is present.
        """
        # Check common auth headers
        if request.headers.get("Authorization"):
            return True
        if request.headers.get("X-API-Key"):
            return True

        # Check query params (for WebSocket)
        if request.query.get("token"):
            return True
        if request.query.get("access_token"):
            return True
        return bool(request.query.get("api_key"))

    async def _authenticate(self, request: web.Request) -> AuthResult:
        """Try to authenticate the request.

        Args:
            request: The aiohttp request.

        Returns:
            AuthResult from the first successful provider.
        """
        # Try each provider in order
        for provider in self.providers:
            result = await provider.authenticate(request=request)
            if result.authenticated:
                return result

        # Return failure with last error
        return AuthResult.failure("Authentication failed")

    async def _handle_error(
        self,
        request: web.Request,
        error: str,
    ) -> web.Response:
        """Handle authentication error.

        Args:
            request: The aiohttp request.
            error: Error message.

        Returns:
            HTTP response.
        """
        if self.error_handler:
            return await self.error_handler(request, error)

        return web.json_response(
            {"error": "unauthorized", "message": error},
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    @web.middleware
    async def middleware(
        self,
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.Response]],
    ) -> web.Response:
        """Middleware handler.

        Args:
            request: The aiohttp request.
            handler: The next handler in the chain.

        Returns:
            HTTP response.
        """
        import uuid

        # Generate request ID
        request_id = str(uuid.uuid4())

        # Check if path is excluded
        if self._is_excluded(request.path):
            set_auth_context(request, AuthContext(request_id=request_id))
            return await handler(request)

        # Check if request has auth information
        if not self._has_auth_header(request):
            if self.allow_anonymous:
                set_auth_context(request, AuthContext(request_id=request_id))
                return await handler(request)
            return await self._handle_error(request, "No authentication provided")

        # Try to authenticate
        result = await self._authenticate(request)

        if not result.authenticated:
            if self.allow_anonymous:
                set_auth_context(request, AuthContext(request_id=request_id))
                return await handler(request)
            return await self._handle_error(request, result.error or "Authentication failed")

        # Set auth context
        context = AuthContext.from_auth_result(result, request_id)
        set_auth_context(request, context)

        return await handler(request)

    def __call__(
        self,
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.Response]],
    ) -> Awaitable[web.Response]:
        """Make middleware callable.

        Args:
            request: The aiohttp request.
            handler: The next handler.

        Returns:
            Awaitable response.
        """
        return self.middleware(request, handler)


# ==============================================================================
# Auth Extractors
# ==============================================================================


def extract_bearer_token(request: web.Request) -> str | None:
    """Extract Bearer token from Authorization header.

    Args:
        request: The aiohttp request.

    Returns:
        The token or None.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def extract_basic_auth(request: web.Request) -> tuple[str, str] | None:
    """Extract Basic auth credentials from Authorization header.

    Args:
        request: The aiohttp request.

    Returns:
        Tuple of (username, password) or None.
    """
    import base64

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


def extract_api_key(
    request: web.Request,
    header_name: str = "X-API-Key",
    query_param: str = "api_key",
) -> str | None:
    """Extract API key from header or query param.

    Args:
        request: The aiohttp request.
        header_name: Header name to check.
        query_param: Query parameter to check.

    Returns:
        The API key or None.
    """
    # Check header first
    if key := request.headers.get(header_name):
        return key
    # Check query param
    if key := request.query.get(query_param):
        return key
    return None


def extract_token_from_query(
    request: web.Request,
    param_names: list[str] | None = None,
) -> str | None:
    """Extract token from query parameters.

    Useful for WebSocket connections where headers may not be available.

    Args:
        request: The aiohttp request.
        param_names: Query parameter names to check.

    Returns:
        The token or None.
    """
    param_names = param_names or ["token", "access_token", "jwt"]
    for param in param_names:
        if token := request.query.get(param):
            return token
    return None


# ==============================================================================
# Decorators
# ==============================================================================


def require_auth(
    scopes: list[str] | None = None,
    any_scope: bool = False,
) -> Callable:
    """Decorator to require authentication on a handler.

    Args:
        scopes: Required scopes.
        any_scope: If True, require any of the scopes (OR). Otherwise require all (AND).

    Returns:
        Decorator function.
    """

    def decorator(
        handler: Callable[[web.Request], Awaitable[web.Response]],
    ) -> Callable[[web.Request], Awaitable[web.Response]]:
        async def wrapper(request: web.Request) -> web.Response:
            context = get_auth_context(request)

            if not context.authenticated:
                return web.json_response(
                    {"error": "unauthorized", "message": "Authentication required"},
                    status=401,
                )

            if scopes:
                if any_scope:
                    if not context.has_any_scope(scopes):
                        return web.json_response(
                            {
                                "error": "forbidden",
                                "message": f"Requires one of scopes: {', '.join(scopes)}",
                            },
                            status=403,
                        )
                else:
                    if not context.has_all_scopes(scopes):
                        return web.json_response(
                            {
                                "error": "forbidden",
                                "message": f"Requires scopes: {', '.join(scopes)}",
                            },
                            status=403,
                        )

            return await handler(request)

        return wrapper

    return decorator


def require_scope(scope: str) -> Callable:
    """Decorator to require a specific scope.

    Args:
        scope: Required scope.

    Returns:
        Decorator function.
    """
    return require_auth(scopes=[scope])


def require_any_scope(*scopes: str) -> Callable:
    """Decorator to require any of the specified scopes.

    Args:
        scopes: Scopes (any one required).

    Returns:
        Decorator function.
    """
    return require_auth(scopes=list(scopes), any_scope=True)


# ==============================================================================
# Middleware Factory
# ==============================================================================


def create_auth_middleware(
    providers: list[AuthProvider] | None = None,
    allow_anonymous: bool = False,
    excluded_paths: list[str] | None = None,
) -> web.middleware:
    """Create auth middleware with configuration.

    Args:
        providers: Authentication providers.
        allow_anonymous: Whether to allow anonymous access.
        excluded_paths: Paths to exclude from auth.

    Returns:
        Configured middleware.
    """
    middleware = AuthMiddleware(
        providers=providers,
        allow_anonymous=allow_anonymous,
        excluded_paths=excluded_paths,
    )
    return middleware.middleware
