"""Instanton - Tunnel through barriers, instantly.

Simple SDK usage:

    import instanton

    # Create a tunnel to localhost:8000
    listener = await instanton.forward(8000)
    print(f"Public URL: {listener.url}")

    # Or with context manager
    async with await instanton.forward(8000) as listener:
        print(f"Tunnel active at {listener.url}")

For more control, use the TunnelClient directly:

    from instanton.client.tunnel import TunnelClient

    client = TunnelClient(local_port=8000)
    url = await client.connect()
"""

__version__ = "0.1.0"

# SDK exports map for lazy loading
_SDK_EXPORTS = {
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
}


# Lazy imports for SDK functions to avoid loading everything on import
def __getattr__(name: str):
    """Lazy load SDK functions."""
    if name in _SDK_EXPORTS:
        from instanton import sdk  # noqa: PLC0415

        return getattr(sdk, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "__version__",
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
