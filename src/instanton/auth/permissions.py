"""Permission system for Instanton.

Provides:
- Permission enum for tunnel operations
- Scope definitions
- RBAC (Role-Based Access Control) support
- Permission checking decorator
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    pass


# ==============================================================================
# Permissions
# ==============================================================================


class Permission(str, Enum):
    """Permissions for Instanton operations.

    Uses string values for easy scope matching.
    """

    # Tunnel permissions
    CREATE_TUNNEL = "tunnel:create"
    DELETE_TUNNEL = "tunnel:delete"
    VIEW_TUNNEL = "tunnel:view"
    MANAGE_TUNNEL = "tunnel:manage"

    # Stats permissions
    VIEW_STATS = "stats:view"
    VIEW_METRICS = "metrics:view"

    # Admin permissions
    ADMIN = "admin"
    MANAGE_USERS = "users:manage"
    MANAGE_API_KEYS = "apikeys:manage"

    # System permissions
    CONFIGURE = "system:configure"
    VIEW_LOGS = "logs:view"

    def __str__(self) -> str:
        return self.value


# ==============================================================================
# Scopes
# ==============================================================================


class Scope:
    """Predefined scopes for API access.

    Scopes are collections of permissions that can be granted to users or API keys.
    """

    # Basic read-only access
    READ = [
        Permission.VIEW_TUNNEL.value,
        Permission.VIEW_STATS.value,
    ]

    # Standard user access
    USER = [
        Permission.CREATE_TUNNEL.value,
        Permission.DELETE_TUNNEL.value,
        Permission.VIEW_TUNNEL.value,
        Permission.VIEW_STATS.value,
    ]

    # Extended access
    EXTENDED = [
        Permission.CREATE_TUNNEL.value,
        Permission.DELETE_TUNNEL.value,
        Permission.VIEW_TUNNEL.value,
        Permission.MANAGE_TUNNEL.value,
        Permission.VIEW_STATS.value,
        Permission.VIEW_METRICS.value,
    ]

    # Admin access (all permissions)
    ADMIN = [p.value for p in Permission]

    @classmethod
    def get(cls, scope_name: str) -> list[str]:
        """Get permissions for a scope name.

        Args:
            scope_name: Name of the scope.

        Returns:
            List of permission strings.
        """
        scope_map = {
            "read": cls.READ,
            "user": cls.USER,
            "extended": cls.EXTENDED,
            "admin": cls.ADMIN,
        }
        return scope_map.get(scope_name.lower(), [])

    @classmethod
    def expand(cls, scopes: list[str]) -> list[str]:
        """Expand scope names to individual permissions.

        Args:
            scopes: List of scope names or permissions.

        Returns:
            Expanded list of permissions.
        """
        result = set()
        for scope in scopes:
            # Check if it's a scope name
            expanded = cls.get(scope)
            if expanded:
                result.update(expanded)
            else:
                # It's an individual permission
                result.add(scope)
        return list(result)


# ==============================================================================
# Roles (RBAC)
# ==============================================================================


@dataclass
class Role:
    """A role with associated permissions.

    Roles provide a way to group permissions together for RBAC.
    """

    name: str
    description: str = ""
    permissions: list[str] = field(default_factory=list)
    inherits: list[str] = field(default_factory=list)

    def has_permission(self, permission: str | Permission) -> bool:
        """Check if role has a permission.

        Args:
            permission: The permission to check.

        Returns:
            True if role has the permission.
        """
        perm_str = permission.value if isinstance(permission, Permission) else permission
        return perm_str in self.permissions


class RoleManager:
    """Manages roles and role-based access control.

    Features:
    - Role definition and management
    - Role inheritance
    - Permission resolution
    """

    def __init__(self) -> None:
        """Initialize role manager."""
        self._roles: dict[str, Role] = {}
        self._setup_default_roles()

    def _setup_default_roles(self) -> None:
        """Set up default roles."""
        # Guest role - minimal access
        self.add_role(
            Role(
                name="guest",
                description="Guest with read-only access",
                permissions=[Permission.VIEW_TUNNEL.value],
            )
        )

        # User role - standard access
        self.add_role(
            Role(
                name="user",
                description="Standard user",
                permissions=Scope.USER,
                inherits=["guest"],
            )
        )

        # Power user role - extended access
        self.add_role(
            Role(
                name="power_user",
                description="Power user with extended access",
                permissions=Scope.EXTENDED,
                inherits=["user"],
            )
        )

        # Admin role - full access
        self.add_role(
            Role(
                name="admin",
                description="Administrator with full access",
                permissions=Scope.ADMIN,
            )
        )

    def add_role(self, role: Role) -> None:
        """Add a role.

        Args:
            role: The role to add.
        """
        self._roles[role.name] = role

    def get_role(self, name: str) -> Role | None:
        """Get a role by name.

        Args:
            name: Role name.

        Returns:
            The role or None.
        """
        return self._roles.get(name)

    def remove_role(self, name: str) -> bool:
        """Remove a role.

        Args:
            name: Role name.

        Returns:
            True if removed.
        """
        if name in self._roles:
            del self._roles[name]
            return True
        return False

    def get_permissions(self, role_name: str) -> set[str]:
        """Get all permissions for a role (including inherited).

        Args:
            role_name: Role name.

        Returns:
            Set of all permissions.
        """
        role = self._roles.get(role_name)
        if not role:
            return set()

        permissions = set(role.permissions)

        # Add inherited permissions
        for parent_name in role.inherits:
            permissions.update(self.get_permissions(parent_name))

        return permissions

    def has_permission(
        self,
        role_name: str,
        permission: str | Permission,
    ) -> bool:
        """Check if a role has a permission.

        Args:
            role_name: Role name.
            permission: The permission to check.

        Returns:
            True if role has the permission.
        """
        perm_str = permission.value if isinstance(permission, Permission) else permission
        permissions = self.get_permissions(role_name)
        return perm_str in permissions

    def get_all_roles(self) -> list[Role]:
        """Get all defined roles.

        Returns:
            List of all roles.
        """
        return list(self._roles.values())


# Global role manager instance
_role_manager = RoleManager()


def get_role_manager() -> RoleManager:
    """Get the global role manager.

    Returns:
        The RoleManager instance.
    """
    return _role_manager


# ==============================================================================
# Permission Checking
# ==============================================================================


def check_permission(
    scopes: list[str],
    permission: Permission | str,
    role_name: str | None = None,
) -> bool:
    """Check if scopes or role grant a permission.

    Args:
        scopes: List of granted scopes.
        permission: Permission to check.
        role_name: Optional role name.

    Returns:
        True if permission is granted.
    """
    perm_str = permission.value if isinstance(permission, Permission) else permission

    # Check direct scope match
    if perm_str in scopes:
        return True

    # Check expanded scopes
    expanded = Scope.expand(scopes)
    if perm_str in expanded:
        return True

    # Check admin scope
    if Permission.ADMIN.value in scopes or Permission.ADMIN.value in expanded:
        return True

    # Check role if provided
    if role_name:
        return _role_manager.has_permission(role_name, perm_str)

    return False


def check_permissions(
    scopes: list[str],
    permissions: list[Permission | str],
    require_all: bool = True,
    role_name: str | None = None,
) -> bool:
    """Check multiple permissions.

    Args:
        scopes: List of granted scopes.
        permissions: Permissions to check.
        require_all: If True, all permissions required. Otherwise, any one.
        role_name: Optional role name.

    Returns:
        True if permissions are granted.
    """
    if require_all:
        return all(check_permission(scopes, p, role_name) for p in permissions)
    return any(check_permission(scopes, p, role_name) for p in permissions)


# ==============================================================================
# Decorators
# ==============================================================================


def require_permission(
    permission: Permission | str,
    error_message: str | None = None,
) -> Callable:
    """Decorator to require a specific permission.

    Args:
        permission: Required permission.
        error_message: Custom error message.

    Returns:
        Decorator function.
    """
    perm_str = permission.value if isinstance(permission, Permission) else permission

    def decorator(
        handler: Callable[[web.Request], Awaitable[web.Response]],
    ) -> Callable[[web.Request], Awaitable[web.Response]]:
        @wraps(handler)
        async def wrapper(request: web.Request) -> web.Response:
            from instanton.auth.middleware import get_auth_context

            context = get_auth_context(request)

            if not context.authenticated:
                return web.json_response(
                    {"error": "unauthorized", "message": "Authentication required"},
                    status=401,
                )

            # Get role from metadata if available
            role_name = context.metadata.get("role")

            if not check_permission(context.scopes, permission, role_name):
                msg = error_message or f"Permission '{perm_str}' required"
                return web.json_response(
                    {"error": "forbidden", "message": msg},
                    status=403,
                )

            return await handler(request)

        return wrapper

    return decorator


def require_permissions(
    *permissions: Permission | str,
    require_all: bool = True,
    error_message: str | None = None,
) -> Callable:
    """Decorator to require multiple permissions.

    Args:
        permissions: Required permissions.
        require_all: If True, all required. Otherwise, any one.
        error_message: Custom error message.

    Returns:
        Decorator function.
    """
    perm_list = list(permissions)

    def decorator(
        handler: Callable[[web.Request], Awaitable[web.Response]],
    ) -> Callable[[web.Request], Awaitable[web.Response]]:
        @wraps(handler)
        async def wrapper(request: web.Request) -> web.Response:
            from instanton.auth.middleware import get_auth_context

            context = get_auth_context(request)

            if not context.authenticated:
                return web.json_response(
                    {"error": "unauthorized", "message": "Authentication required"},
                    status=401,
                )

            # Get role from metadata if available
            role_name = context.metadata.get("role")

            if not check_permissions(context.scopes, perm_list, require_all, role_name):
                if require_all:
                    msg = (
                        error_message
                        or f"Permissions required: {', '.join(str(p) for p in perm_list)}"
                    )
                else:
                    perm_names = ", ".join(str(p) for p in perm_list)
                    msg = error_message or f"One of these permissions required: {perm_names}"
                return web.json_response(
                    {"error": "forbidden", "message": msg},
                    status=403,
                )

            return await handler(request)

        return wrapper

    return decorator


def require_admin(
    handler: Callable[[web.Request], Awaitable[web.Response]],
) -> Callable[[web.Request], Awaitable[web.Response]]:
    """Decorator to require admin permission.

    Args:
        handler: Request handler.

    Returns:
        Wrapped handler.
    """
    return require_permission(Permission.ADMIN)(handler)


def require_role(
    role_name: str,
    error_message: str | None = None,
) -> Callable:
    """Decorator to require a specific role.

    Args:
        role_name: Required role name.
        error_message: Custom error message.

    Returns:
        Decorator function.
    """

    def decorator(
        handler: Callable[[web.Request], Awaitable[web.Response]],
    ) -> Callable[[web.Request], Awaitable[web.Response]]:
        @wraps(handler)
        async def wrapper(request: web.Request) -> web.Response:
            from instanton.auth.middleware import get_auth_context

            context = get_auth_context(request)

            if not context.authenticated:
                return web.json_response(
                    {"error": "unauthorized", "message": "Authentication required"},
                    status=401,
                )

            # Get user's role from metadata
            user_role = context.metadata.get("role")

            if user_role != role_name:
                # Check if user has a higher role (inheritance)
                # For simplicity, check if user's role contains all permissions of required role
                required_perms = _role_manager.get_permissions(role_name)
                if user_role:
                    user_perms = _role_manager.get_permissions(user_role)
                    if not required_perms.issubset(user_perms):
                        msg = error_message or f"Role '{role_name}' required"
                        return web.json_response(
                            {"error": "forbidden", "message": msg},
                            status=403,
                        )
                else:
                    msg = error_message or f"Role '{role_name}' required"
                    return web.json_response(
                        {"error": "forbidden", "message": msg},
                        status=403,
                    )

            return await handler(request)

        return wrapper

    return decorator


# ==============================================================================
# Permission Context Manager
# ==============================================================================


class PermissionContext:
    """Context for checking permissions.

    Provides a fluent interface for permission checking.
    """

    def __init__(
        self,
        scopes: list[str],
        role_name: str | None = None,
    ) -> None:
        """Initialize permission context.

        Args:
            scopes: Granted scopes.
            role_name: Optional role name.
        """
        self.scopes = scopes
        self.role_name = role_name
        self._expanded = Scope.expand(scopes)

    def can(self, permission: Permission | str) -> bool:
        """Check if permission is granted.

        Args:
            permission: Permission to check.

        Returns:
            True if granted.
        """
        return check_permission(self.scopes, permission, self.role_name)

    def can_any(self, *permissions: Permission | str) -> bool:
        """Check if any permission is granted.

        Args:
            permissions: Permissions to check.

        Returns:
            True if any is granted.
        """
        return check_permissions(
            self.scopes,
            list(permissions),
            require_all=False,
            role_name=self.role_name,
        )

    def can_all(self, *permissions: Permission | str) -> bool:
        """Check if all permissions are granted.

        Args:
            permissions: Permissions to check.

        Returns:
            True if all are granted.
        """
        return check_permissions(
            self.scopes,
            list(permissions),
            require_all=True,
            role_name=self.role_name,
        )

    @property
    def is_admin(self) -> bool:
        """Check if admin permission is granted."""
        return self.can(Permission.ADMIN)

    def assert_can(self, permission: Permission | str) -> None:
        """Assert permission is granted.

        Args:
            permission: Permission to check.

        Raises:
            PermissionError: If permission is not granted.
        """
        if not self.can(permission):
            perm_str = permission.value if isinstance(permission, Permission) else permission
            raise PermissionError(f"Permission '{perm_str}' required")


def create_permission_context(
    scopes: list[str],
    role_name: str | None = None,
) -> PermissionContext:
    """Create a permission context.

    Args:
        scopes: Granted scopes.
        role_name: Optional role name.

    Returns:
        PermissionContext instance.
    """
    return PermissionContext(scopes, role_name)
