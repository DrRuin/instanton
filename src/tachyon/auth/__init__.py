"""Tachyon authentication system.

This module provides comprehensive authentication functionality including:
- Multiple auth providers (API keys, JWT, Basic Auth, OAuth2, mTLS)
- Token management (generation, validation, revocation)
- Auth middleware for aiohttp
- Permission and RBAC system
- Pluggable storage backends
"""

from tachyon.auth.middleware import AuthContext, AuthMiddleware
from tachyon.auth.permissions import Permission, Scope, check_permission, require_permission
from tachyon.auth.providers import (
    APIKeyProvider,
    AuthProvider,
    AuthResult,
    BasicAuthProvider,
    JWTProvider,
    MTLSProvider,
    OAuthProvider,
)
from tachyon.auth.tokens import (
    APIKeyManager,
    JWTManager,
    TokenRevocationList,
)

__all__ = [
    # Providers
    "AuthProvider",
    "AuthResult",
    "APIKeyProvider",
    "JWTProvider",
    "BasicAuthProvider",
    "OAuthProvider",
    "MTLSProvider",
    # Tokens
    "APIKeyManager",
    "JWTManager",
    "TokenRevocationList",
    # Middleware
    "AuthMiddleware",
    "AuthContext",
    # Permissions
    "Permission",
    "Scope",
    "check_permission",
    "require_permission",
]
