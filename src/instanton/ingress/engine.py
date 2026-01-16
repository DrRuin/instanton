"""Instanton Ingress Rule Matching Engine.

Provides the core engine for matching incoming requests against configured
ingress rules and returning the appropriate routing target.

The engine evaluates rules in priority order (highest first) and returns
the first matching route.

Example:
    engine = IngressEngine()
    engine.add_route(IngressRoute(
        name="api-route",
        rules=[PathPrefixRule(prefix="/api/")],
        target=RouteTarget(tunnel_id="api-tunnel"),
        priority=100,
    ))

    # Match incoming request
    target = engine.match({
        "host": "example.com",
        "path": "/api/users",
        "method": "GET",
        "headers": {"Authorization": "Bearer token"},
    })

    if target:
        # Route to target.tunnel_id with optional path rewrite
        pass
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from instanton.ingress.rules import IngressRule, rule_from_dict


@dataclass
class RouteTarget:
    """Target configuration for a matched route.

    Specifies where to route matched requests and what
    transformations to apply.
    """

    tunnel_id: str
    """The tunnel ID to route this request to."""

    backend_path: str | None = None
    """If set, rewrite the request path before forwarding.

    Example: backend_path="/v2" with original path "/api/users"
    results in forwarding to "/v2/users".
    """

    strip_prefix: str | None = None
    """If set, strip this prefix from the path before forwarding.

    Example: strip_prefix="/api" with path "/api/users"
    results in forwarding to "/users".
    """

    headers_add: dict[str, str] = field(default_factory=dict)
    """Headers to add to the forwarded request."""

    headers_remove: list[str] = field(default_factory=list)
    """Headers to remove from the forwarded request."""

    timeout_seconds: int | None = None
    """Custom timeout for requests to this target."""

    def to_dict(self) -> dict[str, Any]:
        """Convert target to dictionary."""
        return {
            "tunnel_id": self.tunnel_id,
            "backend_path": self.backend_path,
            "strip_prefix": self.strip_prefix,
            "headers_add": self.headers_add,
            "headers_remove": self.headers_remove,
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RouteTarget:
        """Create target from dictionary."""
        return cls(
            tunnel_id=data["tunnel_id"],
            backend_path=data.get("backend_path"),
            strip_prefix=data.get("strip_prefix"),
            headers_add=data.get("headers_add", {}),
            headers_remove=data.get("headers_remove", []),
            timeout_seconds=data.get("timeout_seconds"),
        )

    def apply_path_rewrite(self, original_path: str) -> str:
        """Apply path transformations to the original path.

        Args:
            original_path: The original request path.

        Returns:
            The transformed path to use for the backend.
        """
        path = original_path

        # Strip prefix if configured
        if self.strip_prefix and path.startswith(self.strip_prefix):
            path = path[len(self.strip_prefix) :]
            if not path:
                path = "/"
            elif not path.startswith("/"):
                path = "/" + path

        # Apply backend path prefix if configured
        if self.backend_path:
            if path == "/":
                path = self.backend_path
            else:
                path = self.backend_path.rstrip("/") + path

        return path


@dataclass
class IngressRoute:
    """A complete routing rule combining conditions and target.

    A route consists of one or more rules that must all match (AND logic)
    for the route to be selected. Routes are evaluated in priority order.
    """

    name: str
    """Unique name for this route."""

    rules: list[IngressRule]
    """Rules that must all match for this route to be selected."""

    target: RouteTarget
    """Where to route matching requests."""

    priority: int = 0
    """Higher priority routes are evaluated first."""

    enabled: bool = True
    """Whether this route is active."""

    description: str = ""
    """Optional description of the route's purpose."""

    def matches(self, context: dict[str, Any]) -> bool:
        """Check if request matches all rules in this route.

        Args:
            context: Request context with path, method, host, headers, etc.

        Returns:
            True if all rules match.
        """
        if not self.enabled:
            return False
        if not self.rules:
            return True
        return all(rule.matches(context) for rule in self.rules)

    def to_dict(self) -> dict[str, Any]:
        """Convert route to dictionary."""
        return {
            "name": self.name,
            "rules": [rule.to_dict() for rule in self.rules],
            "target": self.target.to_dict(),
            "priority": self.priority,
            "enabled": self.enabled,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IngressRoute:
        """Create route from dictionary."""
        return cls(
            name=data["name"],
            rules=[rule_from_dict(r) for r in data.get("rules", [])],
            target=RouteTarget.from_dict(data["target"]),
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
            description=data.get("description", ""),
        )


class IngressEngine:
    """Engine for matching requests against ingress routes.

    Maintains a sorted list of routes and matches incoming requests
    against them in priority order.

    Thread-safe for concurrent access.
    """

    def __init__(self) -> None:
        """Initialize the ingress engine."""
        self._routes: list[IngressRoute] = []

    def add_route(self, route: IngressRoute) -> None:
        """Add a route to the engine.

        Routes are automatically sorted by priority (highest first).

        Args:
            route: The route to add.

        Raises:
            ValueError: If a route with the same name already exists.
        """
        # Check for duplicate names
        for existing in self._routes:
            if existing.name == route.name:
                raise ValueError(f"Route with name '{route.name}' already exists")

        self._routes.append(route)
        self._routes.sort(key=lambda r: r.priority, reverse=True)

    def update_route(self, route: IngressRoute) -> bool:
        """Update an existing route by name.

        Args:
            route: The updated route configuration.

        Returns:
            True if route was updated, False if not found.
        """
        for i, existing in enumerate(self._routes):
            if existing.name == route.name:
                self._routes[i] = route
                self._routes.sort(key=lambda r: r.priority, reverse=True)
                return True
        return False

    def remove_route(self, name: str) -> bool:
        """Remove a route by name.

        Args:
            name: Name of the route to remove.

        Returns:
            True if removed, False if not found.
        """
        for i, route in enumerate(self._routes):
            if route.name == name:
                del self._routes[i]
                return True
        return False

    def get_route(self, name: str) -> IngressRoute | None:
        """Get a route by name.

        Args:
            name: Name of the route.

        Returns:
            The route if found, None otherwise.
        """
        for route in self._routes:
            if route.name == name:
                return route
        return None

    def list_routes(self) -> list[IngressRoute]:
        """List all routes in priority order.

        Returns:
            List of all routes, sorted by priority (highest first).
        """
        return list(self._routes)

    def clear(self) -> None:
        """Remove all routes from the engine."""
        self._routes.clear()

    def match(self, context: dict[str, Any]) -> RouteTarget | None:
        """Find the first matching route for a request.

        Evaluates routes in priority order and returns the target
        of the first matching route.

        Args:
            context: Request context containing:
                - path (str): Request path, e.g., "/api/users"
                - method (str): HTTP method, e.g., "GET"
                - host (str): Host header value
                - headers (dict): Request headers
                - query_params (dict): Query parameters

        Returns:
            RouteTarget if a matching route is found, None otherwise.
        """
        for route in self._routes:
            if route.matches(context):
                return route.target
        return None

    def match_with_route(
        self, context: dict[str, Any]
    ) -> tuple[RouteTarget, IngressRoute] | None:
        """Find the first matching route and return both target and route.

        Args:
            context: Request context (same as match()).

        Returns:
            Tuple of (target, route) if found, None otherwise.
        """
        for route in self._routes:
            if route.matches(context):
                return route.target, route
        return None

    def to_dict(self) -> dict[str, Any]:
        """Export engine configuration to dictionary.

        Returns:
            Dictionary with all routes.
        """
        return {"routes": [route.to_dict() for route in self._routes]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IngressEngine:
        """Create engine from dictionary configuration.

        Args:
            data: Dictionary with routes configuration.

        Returns:
            New IngressEngine with loaded routes.
        """
        engine = cls()
        for route_data in data.get("routes", []):
            engine.add_route(IngressRoute.from_dict(route_data))
        return engine

    def __len__(self) -> int:
        """Return number of routes."""
        return len(self._routes)

    def __bool__(self) -> bool:
        """Return True if engine has any routes."""
        return bool(self._routes)


def create_request_context(
    path: str,
    method: str = "GET",
    host: str = "",
    headers: dict[str, str] | None = None,
    query_params: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Helper to create a request context dictionary.

    Args:
        path: Request path.
        method: HTTP method (default: GET).
        host: Host header value.
        headers: Request headers dictionary.
        query_params: Query parameters dictionary.

    Returns:
        Request context dictionary for use with IngressEngine.match().
    """
    return {
        "path": path,
        "method": method.upper(),
        "host": host,
        "headers": headers or {},
        "query_params": query_params or {},
    }
