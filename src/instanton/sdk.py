"""Instanton SDK - Embeddable tunnel integration for Python applications.

This module provides a simple API for embedding Instanton tunnels
directly into Python applications with minimal code.

Example usage:

    # Simple one-line tunnel
    import instanton
    listener = await instanton.forward(8000)
    print(f"Public URL: {listener.url}")

    # With configuration
    listener = await instanton.forward(
        8000,
        subdomain="myapp",
        auth_token="your-token",
    )

    # Context manager for automatic cleanup
    async with instanton.forward(8000) as listener:
        print(f"Tunnel active at {listener.url}")
        # Do work...
    # Tunnel automatically closed

    # For sync applications
    listener = instanton.forward_sync(8000)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from instanton.client.tunnel import TunnelClient
from instanton.core.config import ClientConfig

logger = structlog.get_logger()

# Default server - can be overridden via environment or config
DEFAULT_SERVER = os.environ.get("INSTANTON_SERVER", "instanton.dev:443")
DEFAULT_AUTH_TOKEN = os.environ.get("INSTANTON_AUTH_TOKEN")


@dataclass
class TunnelStats:
    """Statistics for an active tunnel."""

    requests_proxied: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    connected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_activity: datetime | None = None


@dataclass
class Listener:
    """Represents an active tunnel listener.

    This provides access to the tunnel's public URL and metadata,
    as well as methods to manage the tunnel lifecycle.
    """

    url: str
    """The public URL for this tunnel (e.g., https://myapp.instanton.dev)"""

    subdomain: str
    """The subdomain assigned to this tunnel"""

    local_port: int
    """The local port being forwarded"""

    tunnel_id: str | None
    """Unique identifier for this tunnel session"""

    _client: TunnelClient
    """Internal tunnel client instance"""

    _run_task: asyncio.Task | None = None
    """Background task running the tunnel"""

    @property
    def is_active(self) -> bool:
        """Check if the tunnel is currently active."""
        return self._client.is_connected

    @property
    def stats(self) -> TunnelStats:
        """Get tunnel statistics."""
        client_stats = self._client.stats
        return TunnelStats(
            requests_proxied=client_stats["requests_proxied"],
            bytes_sent=client_stats["bytes_sent"],
            bytes_received=client_stats["bytes_received"],
        )

    async def close(self) -> None:
        """Close the tunnel and release resources."""
        if self._run_task and not self._run_task.done():
            self._run_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._run_task
        await self._client.close()

    async def wait_closed(self) -> None:
        """Wait for the tunnel to be fully closed."""
        await self._client.close()

    async def __aenter__(self) -> Listener:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit - closes the tunnel."""
        await self.close()


class InstantonConfig:
    """Global configuration for Instanton SDK."""

    def __init__(self):
        self.server: str = DEFAULT_SERVER
        self.auth_token: str | None = DEFAULT_AUTH_TOKEN
        self.auto_reconnect: bool = True
        self.use_quic: bool = True
        self.connect_timeout: float = 10.0
        self.keepalive_interval: float = 30.0
        self.max_reconnect_attempts: int = 10

    def configure(
        self,
        server: str | None = None,
        auth_token: str | None = None,
        auto_reconnect: bool | None = None,
        use_quic: bool | None = None,
        connect_timeout: float | None = None,
        keepalive_interval: float | None = None,
        max_reconnect_attempts: int | None = None,
    ) -> None:
        """Update global configuration.

        Args:
            server: Instanton server address (host:port)
            auth_token: Authentication token for the server
            auto_reconnect: Enable automatic reconnection
            use_quic: Prefer QUIC transport over WebSocket
            connect_timeout: Connection timeout in seconds
            keepalive_interval: Keepalive ping interval in seconds
            max_reconnect_attempts: Maximum reconnection attempts
        """
        if server is not None:
            self.server = server
        if auth_token is not None:
            self.auth_token = auth_token
        if auto_reconnect is not None:
            self.auto_reconnect = auto_reconnect
        if use_quic is not None:
            self.use_quic = use_quic
        if connect_timeout is not None:
            self.connect_timeout = connect_timeout
        if keepalive_interval is not None:
            self.keepalive_interval = keepalive_interval
        if max_reconnect_attempts is not None:
            self.max_reconnect_attempts = max_reconnect_attempts


# Global configuration instance
config = InstantonConfig()


def _suggest_subdomain() -> str | None:
    """Suggest a subdomain based on the current project context.

    Looks at:
    1. Current directory name
    2. pyproject.toml project name
    3. setup.py name
    4. package.json name
    5. Git remote name
    """
    cwd = Path.cwd()

    # Try pyproject.toml
    pyproject = cwd / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib

            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
                name = data.get("project", {}).get("name")
                if name:
                    return _sanitize_subdomain(name)
        except Exception:
            pass

    # Try package.json
    package_json = cwd / "package.json"
    if package_json.exists():
        try:
            import json

            with open(package_json) as f:
                data = json.load(f)
                name = data.get("name")
                if name:
                    # Remove scope from npm packages
                    if name.startswith("@"):
                        name = name.split("/")[-1]
                    return _sanitize_subdomain(name)
        except Exception:
            pass

    # Try git remote
    git_config = cwd / ".git" / "config"
    if git_config.exists():
        try:
            with open(git_config) as f:
                content = f.read()
                # Extract repo name from remote URL
                match = re.search(r"/([^/]+?)(?:\.git)?$", content, re.MULTILINE)
                if match:
                    return _sanitize_subdomain(match.group(1))
        except Exception:
            pass

    # Fall back to directory name
    dir_name = cwd.name
    if dir_name and dir_name not in (".", "..", "src", "app", "project"):
        return _sanitize_subdomain(dir_name)

    return None


def _sanitize_subdomain(name: str) -> str:
    """Sanitize a name for use as a subdomain."""
    # Convert to lowercase
    name = name.lower()
    # Replace underscores and spaces with hyphens
    name = re.sub(r"[_\s]+", "-", name)
    # Remove invalid characters
    name = re.sub(r"[^a-z0-9-]", "", name)
    # Remove leading/trailing hyphens
    name = name.strip("-")
    # Limit length
    if len(name) > 63:
        name = name[:63].rstrip("-")
    # Ensure minimum length
    if len(name) < 3:
        return ""
    return name


def _find_available_port() -> int:
    """Find an available port to use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


async def forward(
    port: int | str | None = None,
    *,
    subdomain: str | None = None,
    server: str | None = None,
    auth_token: str | None = None,
    auto_reconnect: bool | None = None,
    use_quic: bool | None = None,
    connect_timeout: float | None = None,
    on_connect: Callable[[], Any] | None = None,
    on_disconnect: Callable[[], Any] | None = None,
    suggest_subdomain: bool = True,
) -> Listener:
    """Create a tunnel to forward traffic to a local port.

    This is the main entry point for the Instanton SDK. It creates a tunnel
    that forwards public traffic to your local service.

    Args:
        port: Local port to forward (defaults to finding available port)
        subdomain: Request a specific subdomain (e.g., "myapp" for myapp.instanton.dev)
        server: Override the default Instanton server
        auth_token: Authentication token for the server
        auto_reconnect: Enable automatic reconnection (default: True)
        use_quic: Use QUIC transport (default: True)
        connect_timeout: Connection timeout in seconds
        on_connect: Callback when tunnel connects
        on_disconnect: Callback when tunnel disconnects
        suggest_subdomain: Auto-suggest subdomain from project (default: True)

    Returns:
        A Listener object representing the active tunnel

    Example:
        async with await instanton.forward(8000) as listener:
            print(f"Forwarding {listener.url} -> localhost:8000")
            # Your application runs here
    """
    # Resolve port
    if port is None:
        local_port = _find_available_port()
    elif isinstance(port, str):
        local_port = int(port)
    else:
        local_port = port

    # Resolve subdomain
    if subdomain is None and suggest_subdomain:
        subdomain = _suggest_subdomain()

    # Resolve configuration
    server_addr = server or config.server
    _ = auth_token or config.auth_token  # Reserved for future auth implementation
    reconnect = auto_reconnect if auto_reconnect is not None else config.auto_reconnect
    quic = use_quic if use_quic is not None else config.use_quic
    timeout = connect_timeout if connect_timeout is not None else config.connect_timeout

    # Create client config
    client_config = ClientConfig(
        server_addr=server_addr,
        local_port=local_port,
        subdomain=subdomain,
        use_quic=quic,
        connect_timeout=timeout,
        auto_reconnect=reconnect,
        max_reconnect_attempts=config.max_reconnect_attempts,
        keepalive_interval=config.keepalive_interval,
    )

    # Create tunnel client
    client = TunnelClient(local_port=local_port, config=client_config)

    # Register callbacks
    if on_connect:
        client.add_state_hook(lambda state: on_connect() if state == "connected" else None)
    if on_disconnect:
        client.add_state_hook(lambda state: on_disconnect() if state == "disconnected" else None)

    # Connect
    logger.info(
        "Starting tunnel",
        local_port=local_port,
        subdomain=subdomain,
        server=server_addr,
    )

    url = await client.connect()

    # Start the background run loop
    run_task = asyncio.create_task(client.run())

    listener = Listener(
        url=url,
        subdomain=client.subdomain or "",
        local_port=local_port,
        tunnel_id=str(client._tunnel_id) if client._tunnel_id else None,
        _client=client,
        _run_task=run_task,
    )

    logger.info("Tunnel established", url=url, subdomain=listener.subdomain)

    return listener


def forward_sync(
    port: int | str | None = None,
    **kwargs: Any,
) -> Listener:
    """Synchronous version of forward() for non-async applications.

    This creates a new event loop if needed to establish the tunnel,
    but the tunnel runs in the background.

    Args:
        port: Local port to forward
        **kwargs: Additional arguments passed to forward()

    Returns:
        A Listener object representing the active tunnel
    """
    try:
        loop = asyncio.get_running_loop()
        # If we're in an async context, use it
        return loop.run_until_complete(forward(port, **kwargs))
    except RuntimeError:
        # No running loop, create one
        return asyncio.run(forward(port, **kwargs))


async def connect(
    addr: str = "localhost:8000",
    **kwargs: Any,
) -> Listener:
    """Connect to a local address and create a tunnel.

    Alternative API that takes an address string instead of port.

    Args:
        addr: Local address to forward (host:port or just port)
        **kwargs: Additional arguments passed to forward()

    Returns:
        A Listener object representing the active tunnel

    Example:
        listener = await instanton.connect("localhost:3000")
        listener = await instanton.connect("8080")
    """
    # Parse address
    if ":" in addr:
        host, port_str = addr.rsplit(":", 1)
        port = int(port_str)
    else:
        port = int(addr)

    return await forward(port, **kwargs)


def set_auth_token(token: str) -> None:
    """Set the global authentication token.

    Args:
        token: Authentication token for the Instanton server
    """
    config.auth_token = token


def set_server(server: str) -> None:
    """Set the global server address.

    Args:
        server: Instanton server address (host:port)
    """
    config.server = server


# Convenience alias for the forward function
listen = forward


__all__ = [
    "forward",
    "forward_sync",
    "connect",
    "listen",
    "Listener",
    "TunnelStats",
    "InstantonConfig",
    "config",
    "set_auth_token",
    "set_server",
]
