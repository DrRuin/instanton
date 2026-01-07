"""Web inspection interface for Instanton tunnel application.

Features:
- Real-time request/response capture
- Traffic inspection via web UI at localhost:4040
- Request replay with modifications
- Webhook testing support
- Traffic filtering and search
"""

from instanton.inspector.replay import (
    ReplayConfig,
    ReplayResult,
    RequestReplayer,
)
from instanton.inspector.server import (
    InspectorServer,
    get_inspector,
)
from instanton.inspector.storage import (
    CapturedRequest,
    CapturedResponse,
    RequestFilter,
    TrafficStorage,
)

__all__ = [
    # Storage
    "CapturedRequest",
    "CapturedResponse",
    "RequestFilter",
    "TrafficStorage",
    # Server
    "InspectorServer",
    "get_inspector",
    # Replay
    "ReplayConfig",
    "ReplayResult",
    "RequestReplayer",
]
