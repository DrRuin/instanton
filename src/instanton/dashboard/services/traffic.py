"""Instanton Traffic Logging Service.

Captures and stores HTTP request/response data flowing through Instanton tunnels.
Provides traffic inspection, search, replay, and analytics functionality
for both cloud (Supabase) and self-hosted (SQLite/PostgreSQL) deployments.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from instanton.dashboard.services.supabase import (
    get_config,
    get_local_storage,
    get_supabase_client,
    is_cloud_mode,
)


@dataclass
class TrafficLog:
    """Represents a traffic log entry."""

    id: str | int
    tunnel_id: str
    request_method: str
    request_path: str
    request_headers: dict[str, str] | None = None
    request_body: str | None = None
    request_size: int | None = None
    response_status: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    response_size: int | None = None
    response_time_ms: int | None = None
    client_ip: str | None = None
    timestamp: datetime = datetime.now(UTC)
    user_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrafficLog:
        """Create TrafficLog from dictionary."""
        return cls(
            id=data.get("id", ""),
            tunnel_id=data["tunnel_id"],
            request_method=data["request_method"],
            request_path=data["request_path"],
            request_headers=_parse_json(data.get("request_headers")),
            request_body=data.get("request_body"),
            request_size=data.get("request_size"),
            response_status=data.get("response_status"),
            response_headers=_parse_json(data.get("response_headers")),
            response_body=data.get("response_body"),
            response_size=data.get("response_size"),
            response_time_ms=data.get("response_time_ms"),
            client_ip=data.get("client_ip"),
            timestamp=_parse_datetime(data.get("timestamp")) or datetime.now(UTC),
            user_id=data.get("user_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tunnel_id": self.tunnel_id,
            "request_method": self.request_method,
            "request_path": self.request_path,
            "request_headers": json.dumps(self.request_headers)
            if self.request_headers
            else None,
            "request_body": self.request_body,
            "request_size": self.request_size,
            "response_status": self.response_status,
            "response_headers": json.dumps(self.response_headers)
            if self.response_headers
            else None,
            "response_body": self.response_body,
            "response_size": self.response_size,
            "response_time_ms": self.response_time_ms,
            "client_ip": self.client_ip,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
        }


def _parse_datetime(value: str | datetime | None) -> datetime | None:
    """Parse datetime from string or datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _parse_json(value: str | dict | None) -> dict[str, str] | None:
    """Parse JSON string to dict."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except Exception:
        return None


class TrafficService:
    """Instanton Traffic Logging Service.

    Manages traffic log capture, storage, retrieval, and replay for the
    Instanton dashboard. Supports filtering, searching, and analytics
    across both cloud and self-hosted deployments.
    """

    async def log_request(
        self,
        tunnel_id: str,
        request_method: str,
        request_path: str,
        request_headers: dict[str, str] | None = None,
        request_body: str | None = None,
        response_status: int | None = None,
        response_headers: dict[str, str] | None = None,
        response_body: str | None = None,
        response_time_ms: int | None = None,
        client_ip: str | None = None,
        user_id: str | None = None,
    ) -> TrafficLog:
        """Log a request/response.

        Args:
            tunnel_id: Associated tunnel ID.
            request_method: HTTP method (GET, POST, etc.).
            request_path: Request path.
            request_headers: Request headers.
            request_body: Request body (truncated to 10KB).
            response_status: Response status code.
            response_headers: Response headers.
            response_body: Response body (truncated to 10KB).
            response_time_ms: Response time in milliseconds.
            client_ip: Client IP address.
            user_id: User ID (cloud mode).

        Returns:
            Created TrafficLog object.
        """
        # Truncate bodies to 10KB
        max_body_size = 10240
        if request_body and len(request_body) > max_body_size:
            request_body = request_body[:max_body_size] + "... (truncated)"
        if response_body and len(response_body) > max_body_size:
            response_body = response_body[:max_body_size] + "... (truncated)"

        log = TrafficLog(
            id="",
            tunnel_id=tunnel_id,
            request_method=request_method,
            request_path=request_path,
            request_headers=request_headers,
            request_body=request_body,
            request_size=len(request_body) if request_body else 0,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            response_size=len(response_body) if response_body else 0,
            response_time_ms=response_time_ms,
            client_ip=client_ip,
            timestamp=datetime.now(UTC),
            user_id=user_id,
        )

        if is_cloud_mode():
            client = get_supabase_client()
            response = client.table("traffic_logs").insert(log.to_dict()).execute()
            if response.data:
                log.id = response.data[0].get("id", "")
        else:
            storage = get_local_storage()
            log_id = storage.log_traffic(log.to_dict())
            log.id = log_id

            # Cleanup old logs if needed
            config = get_config()
            storage.cleanup_old_logs(config.local_max_logs)

        return log

    async def list_recent(
        self,
        user_id: str | None = None,
        tunnel_id: str | None = None,
        status_filter: str | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TrafficLog]:
        """List recent traffic logs.

        Args:
            user_id: Filter by user ID (cloud mode).
            tunnel_id: Filter by tunnel ID.
            status_filter: Filter by status code range (2xx, 3xx, 4xx, 5xx).
            search: Search in path and method.
            limit: Maximum number of results.
            offset: Result offset.

        Returns:
            List of TrafficLog objects.
        """
        if is_cloud_mode():
            client = get_supabase_client()
            query = client.table("traffic_logs").select("*")

            if user_id and user_id != "local":
                query = query.eq("user_id", user_id)

            if tunnel_id:
                query = query.eq("tunnel_id", tunnel_id)

            if status_filter and status_filter != "all":
                if status_filter == "2xx":
                    query = query.gte("response_status", 200).lt("response_status", 300)
                elif status_filter == "3xx":
                    query = query.gte("response_status", 300).lt("response_status", 400)
                elif status_filter == "4xx":
                    query = query.gte("response_status", 400).lt("response_status", 500)
                elif status_filter == "5xx":
                    query = query.gte("response_status", 500).lt("response_status", 600)

            if search:
                query = query.or_(
                    f"request_path.ilike.%{search}%,request_method.ilike.%{search}%"
                )

            response = (
                query.order("timestamp", desc=True).range(offset, offset + limit - 1).execute()
            )
            return [TrafficLog.from_dict(d) for d in response.data]
        else:
            storage = get_local_storage()
            data = storage.list_traffic_logs(tunnel_id=tunnel_id, limit=limit, offset=offset)

            logs = [TrafficLog.from_dict(d) for d in data]

            # Apply filters in memory
            if status_filter and status_filter != "all":
                status_ranges = {
                    "2xx": (200, 300),
                    "3xx": (300, 400),
                    "4xx": (400, 500),
                    "5xx": (500, 600),
                }
                if status_filter in status_ranges:
                    low, high = status_ranges[status_filter]
                    logs = [
                        log
                        for log in logs
                        if log.response_status and low <= log.response_status < high
                    ]

            if search:
                search_lower = search.lower()
                logs = [
                    log
                    for log in logs
                    if search_lower in log.request_path.lower()
                    or search_lower in log.request_method.lower()
                ]

            return logs

    async def get_log(self, log_id: str | int) -> TrafficLog | None:
        """Get traffic log by ID.

        Args:
            log_id: Log ID.

        Returns:
            TrafficLog object or None if not found.
        """
        if is_cloud_mode():
            client = get_supabase_client()
            response = (
                client.table("traffic_logs")
                .select("*")
                .eq("id", str(log_id))
                .single()
                .execute()
            )
            if response.data:
                return TrafficLog.from_dict(response.data)
            return None
        else:
            storage = get_local_storage()
            data = storage.get_traffic_log(int(log_id))
            return TrafficLog.from_dict(data) if data else None

    async def get_by_index(
        self,
        user_id: str | None,
        index: int,
    ) -> TrafficLog | None:
        """Get traffic log by index in recent list.

        Args:
            user_id: User ID for filtering.
            index: Index in the recent list.

        Returns:
            TrafficLog object or None.
        """
        logs = await self.list_recent(user_id=user_id, limit=index + 1)
        if index < len(logs):
            return logs[index]
        return None

    async def replay_request(
        self,
        log: TrafficLog,
        target_url: str | None = None,
    ) -> httpx.Response:
        """Replay a recorded request through the original tunnel.

        Sends the recorded request to either the specified target URL,
        the tunnel's public URL, or falls back to localhost.

        Args:
            log: TrafficLog entry to replay.
            target_url: Optional override URL. If not provided, attempts
                to use the tunnel's public URL or localhost fallback.

        Returns:
            HTTP response from the replayed request.

        Raises:
            httpx.HTTPError: If the request fails.
        """
        # Determine the target URL
        base_url = target_url

        if not base_url:
            # Try to get the tunnel's public URL
            from instanton.dashboard.services.tunnels import get_tunnel_service

            tunnel_service = get_tunnel_service()
            tunnel = await tunnel_service.get_tunnel(log.tunnel_id)

            if tunnel and tunnel.public_url:
                base_url = tunnel.public_url.rstrip("/")
            else:
                # Fallback to localhost with the tunnel's local port
                local_port = tunnel.local_port if tunnel else 8080
                base_url = f"http://127.0.0.1:{local_port}"

        # Build full URL
        full_url = f"{base_url}{log.request_path}"

        # Filter out hop-by-hop headers that shouldn't be forwarded
        headers = dict(log.request_headers or {})
        hop_by_hop = {"connection", "keep-alive", "transfer-encoding", "host"}
        headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=log.request_method,
                url=full_url,
                headers=headers,
                content=log.request_body,
            )
            return response

    async def count_logs(
        self,
        user_id: str | None = None,
        tunnel_id: str | None = None,
    ) -> int:
        """Count traffic logs.

        Args:
            user_id: Filter by user ID.
            tunnel_id: Filter by tunnel ID.

        Returns:
            Number of logs.
        """
        if is_cloud_mode():
            client = get_supabase_client()
            query = client.table("traffic_logs").select("id", count="exact")

            if user_id and user_id != "local":
                query = query.eq("user_id", user_id)

            if tunnel_id:
                query = query.eq("tunnel_id", tunnel_id)

            response = query.execute()
            return response.count or 0
        else:
            storage = get_local_storage()
            return storage.count_traffic_logs(tunnel_id=tunnel_id)

    async def delete_all_logs(self, user_id: str | None = None) -> int:
        """Delete all traffic logs for a user.

        Permanently removes all traffic log entries. In cloud mode,
        deletes only the specified user's logs. In self-hosted mode,
        clears all traffic logs from local storage.

        Args:
            user_id: User ID whose logs to delete. Required in cloud mode.

        Returns:
            Number of logs deleted.
        """
        if is_cloud_mode():
            if not user_id or user_id == "local":
                return 0

            client = get_supabase_client()
            # First count, then delete
            count_response = (
                client.table("traffic_logs")
                .select("id", count="exact")
                .eq("user_id", user_id)
                .execute()
            )
            count = count_response.count or 0

            if count > 0:
                client.table("traffic_logs").delete().eq("user_id", user_id).execute()

            return count
        else:
            storage = get_local_storage()
            # Count before clearing
            count = storage.count_traffic_logs()
            # Clear all logs by setting limit to 0
            storage.cleanup_old_logs(max_logs=0)
            return count


# Singleton instance
_traffic_service: TrafficService | None = None


def get_traffic_service() -> TrafficService:
    """Get the Instanton traffic service singleton instance.

    Returns:
        Global TrafficService instance for traffic log management.
    """
    global _traffic_service
    if _traffic_service is None:
        _traffic_service = TrafficService()
    return _traffic_service
