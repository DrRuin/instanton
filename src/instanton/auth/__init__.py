"""Instanton authentication system.

This module provides comprehensive authentication functionality including:
- Multiple auth providers (API keys, JWT, Basic Auth, OAuth2, mTLS)
- Token management (generation, validation, revocation)
- Auth middleware for aiohttp
- Permission and RBAC system
- Pluggable storage backends
"""

from instanton.auth.middleware import AuthContext, AuthMiddleware
from instanton.auth.permissions import Permission, Scope, check_permission, require_permission
from instanton.auth.providers import (
    APIKeyProvider,
    AuthProvider,
    AuthResult,
    BasicAuthProvider,
    JWTProvider,
    MTLSProvider,
    OAuthProvider,
)
from instanton.auth.tokens import (
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
