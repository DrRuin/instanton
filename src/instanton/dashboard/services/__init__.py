"""Dashboard services for data access."""

from instanton.dashboard.services.auth import AuthService, User, get_auth_service
from instanton.dashboard.services.supabase import (
    get_local_storage,
    get_supabase_client,
    init_storage,
)
from instanton.dashboard.services.tokens import TokenService, get_token_service
from instanton.dashboard.services.traffic import TrafficService, get_traffic_service
from instanton.dashboard.services.tunnels import TunnelService, get_tunnel_service

__all__ = [
    "AuthService",
    "User",
    "get_auth_service",
    "get_local_storage",
    "get_supabase_client",
    "init_storage",
    "TokenService",
    "get_token_service",
    "TrafficService",
    "get_traffic_service",
    "TunnelService",
    "get_tunnel_service",
]
