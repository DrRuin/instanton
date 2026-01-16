"""Instanton Tunnel Service.

Provides tunnel management functionality for the Instanton dashboard.
Handles tunnel creation, status tracking, and lifecycle management
for both cloud (Supabase) and self-hosted (SQLite/PostgreSQL) deployments.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from instanton.dashboard.services.supabase import (
    get_local_storage,
    get_supabase_client,
    is_cloud_mode,
)


@dataclass
class Tunnel:
    """Represents a tunnel connection."""

    id: str
    subdomain: str
    tunnel_type: str  # http, tcp, udp
    local_port: int
    public_url: str
    connected_at: datetime
    last_activity_at: datetime | None = None
    disconnected_at: datetime | None = None
    client_ip: str | None = None
    client_version: str | None = None
    status: str = "active"  # active, disconnected, reserved
    user_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Tunnel:
        """Create Tunnel from dictionary."""
        return cls(
            id=data["id"],
            subdomain=data["subdomain"],
            tunnel_type=data["tunnel_type"],
            local_port=data["local_port"],
            public_url=data["public_url"],
            connected_at=_parse_datetime(data["connected_at"]),
            last_activity_at=_parse_datetime(data.get("last_activity_at")),
            disconnected_at=_parse_datetime(data.get("disconnected_at")),
            client_ip=data.get("client_ip"),
            client_version=data.get("client_version"),
            status=data.get("status", "active"),
            user_id=data.get("user_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "subdomain": self.subdomain,
            "tunnel_type": self.tunnel_type,
            "local_port": self.local_port,
            "public_url": self.public_url,
            "connected_at": self.connected_at.isoformat(),
            "last_activity_at": self.last_activity_at.isoformat()
            if self.last_activity_at
            else None,
            "disconnected_at": self.disconnected_at.isoformat()
            if self.disconnected_at
            else None,
            "client_ip": self.client_ip,
            "client_version": self.client_version,
            "status": self.status,
            "user_id": self.user_id,
        }


def _parse_datetime(value: str | datetime | None) -> datetime | None:
    """Parse datetime from string or datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class TunnelService:
    """Instanton Tunnel Service.

    Manages tunnel lifecycle including creation, status tracking,
    and disconnection for the Instanton dashboard. Supports both
    cloud mode (Supabase) and self-hosted mode (SQLite/PostgreSQL).
    """

    async def create_tunnel(
        self,
        subdomain: str,
        tunnel_type: str,
        local_port: int,
        public_url: str,
        user_id: str | None = None,
        client_ip: str | None = None,
        client_version: str | None = None,
    ) -> Tunnel:
        """Create a new tunnel.

        Args:
            subdomain: Tunnel subdomain.
            tunnel_type: Type of tunnel (http, tcp, udp).
            local_port: Local port being tunneled.
            public_url: Public URL for the tunnel.
            user_id: Owner user ID (cloud mode).
            client_ip: Client IP address.
            client_version: Client version string.

        Returns:
            Created Tunnel object.
        """
        tunnel = Tunnel(
            id=str(uuid4()),
            subdomain=subdomain,
            tunnel_type=tunnel_type,
            local_port=local_port,
            public_url=public_url,
            connected_at=datetime.now(UTC),
            client_ip=client_ip,
            client_version=client_version,
            user_id=user_id,
        )

        if is_cloud_mode():
            client = get_supabase_client()
            client.table("tunnels").insert(tunnel.to_dict()).execute()
        else:
            storage = get_local_storage()
            storage.save_tunnel(tunnel.to_dict())

        return tunnel

    async def get_tunnel(self, tunnel_id: str) -> Tunnel | None:
        """Get tunnel by ID.

        Args:
            tunnel_id: Tunnel ID.

        Returns:
            Tunnel object or None if not found.
        """
        if is_cloud_mode():
            client = get_supabase_client()
            response = (
                client.table("tunnels")
                .select("*")
                .eq("id", tunnel_id)
                .single()
                .execute()
            )
            if response.data:
                return Tunnel.from_dict(response.data)
            return None
        else:
            storage = get_local_storage()
            data = storage.get_tunnel(tunnel_id)
            return Tunnel.from_dict(data) if data else None

    async def list_active(self, user_id: str | None = None) -> list[Tunnel]:
        """List active tunnels.

        Args:
            user_id: Filter by user ID (cloud mode).

        Returns:
            List of active Tunnel objects.
        """
        if is_cloud_mode():
            client = get_supabase_client()
            query = client.table("tunnels").select("*").eq("status", "active")
            if user_id and user_id != "local":
                query = query.eq("user_id", user_id)
            response = query.execute()
            return [Tunnel.from_dict(t) for t in response.data]
        else:
            storage = get_local_storage()
            data = storage.list_tunnels(status="active")
            return [Tunnel.from_dict(t) for t in data]

    async def list_all(self, user_id: str | None = None) -> list[Tunnel]:
        """List all tunnels.

        Args:
            user_id: Filter by user ID (cloud mode).

        Returns:
            List of Tunnel objects.
        """
        if is_cloud_mode():
            client = get_supabase_client()
            query = client.table("tunnels").select("*")
            if user_id and user_id != "local":
                query = query.eq("user_id", user_id)
            response = query.order("connected_at", desc=True).execute()
            return [Tunnel.from_dict(t) for t in response.data]
        else:
            storage = get_local_storage()
            data = storage.list_tunnels()
            return [Tunnel.from_dict(t) for t in data]

    async def count_active(self, user_id: str | None = None) -> int:
        """Count active tunnels.

        Args:
            user_id: Filter by user ID (cloud mode).

        Returns:
            Number of active tunnels.
        """
        tunnels = await self.list_active(user_id)
        return len(tunnels)

    async def update_status(
        self,
        tunnel_id: str,
        status: str,
    ) -> None:
        """Update tunnel status.

        Args:
            tunnel_id: Tunnel ID.
            status: New status (active, disconnected, reserved).
        """
        if is_cloud_mode():
            client = get_supabase_client()
            update_data: dict[str, Any] = {
                "status": status,
                "last_activity_at": datetime.now(UTC).isoformat(),
            }
            if status == "disconnected":
                update_data["disconnected_at"] = datetime.now(UTC).isoformat()
            client.table("tunnels").update(update_data).eq("id", tunnel_id).execute()
        else:
            storage = get_local_storage()
            storage.update_tunnel_status(tunnel_id, status)

    async def disconnect_tunnel(self, tunnel_id: str) -> None:
        """Mark tunnel as disconnected.

        Args:
            tunnel_id: Tunnel ID.
        """
        await self.update_status(tunnel_id, "disconnected")

    async def count_requests_today(self, user_id: str | None = None) -> int:
        """Count total requests processed through tunnels today.

        Queries traffic logs to count all requests from midnight UTC
        to now for the specified user (or all users in self-hosted mode).

        Args:
            user_id: User ID to filter by (cloud mode). Ignored in self-hosted.

        Returns:
            Total number of requests processed today.
        """
        today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)

        if is_cloud_mode():
            client = get_supabase_client()
            query = client.table("traffic_logs").select("id", count="exact")

            if user_id and user_id != "local":
                query = query.eq("user_id", user_id)

            query = query.gte("timestamp", today_start.isoformat())
            response = query.execute()
            return response.count or 0
        else:
            storage = get_local_storage()
            # Local storage: count logs since midnight
            all_logs = storage.list_traffic_logs(limit=100000)
            count = 0
            for log in all_logs:
                log_time = log.get("timestamp")
                if log_time:
                    if isinstance(log_time, str):
                        try:
                            log_dt = datetime.fromisoformat(log_time.replace("Z", "+00:00"))
                            if log_dt >= today_start:
                                count += 1
                        except Exception:
                            pass
                    elif isinstance(log_time, datetime):
                        if log_time >= today_start:
                            count += 1
            return count


# Singleton instance
_tunnel_service: TunnelService | None = None


def get_tunnel_service() -> TunnelService:
    """Get the Instanton tunnel service singleton instance.

    Returns:
        Global TunnelService instance for tunnel management.
    """
    global _tunnel_service
    if _tunnel_service is None:
        _tunnel_service = TunnelService()
    return _tunnel_service
