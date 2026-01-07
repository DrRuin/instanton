"""Traffic storage for captured requests and responses."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class RequestStatus(str, Enum):
    """Status of a captured request."""

    PENDING = "pending"
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"


class CapturedRequest(BaseModel):
    """A captured HTTP request."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: UUID = Field(default_factory=uuid4)
    tunnel_id: UUID | None = None
    subdomain: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""
    body_json: dict[str, Any] | None = None
    content_type: str = ""
    content_length: int = 0
    source_ip: str = ""
    source_port: int = 0
    duration_ms: float | None = None
    status: RequestStatus = RequestStatus.PENDING
    is_replay: bool = False
    original_request_id: UUID | None = None

    def model_post_init(self, __context: Any) -> None:
        """Post-init processing."""
        # Extract content type
        self.content_type = self.headers.get("content-type", self.headers.get("Content-Type", ""))
        self.content_length = len(self.body)

        # Try to parse JSON body
        if self.body and "json" in self.content_type.lower():
            with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
                self.body_json = json.loads(self.body.decode("utf-8"))

        # Parse query string from path
        if "?" in self.path:
            path_part, query_string = self.path.split("?", 1)
            for param in query_string.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    self.query_params[key] = value

    def get_body_preview(self, max_length: int = 1000) -> str:
        """Get a preview of the body content."""
        if self.body_json is not None:
            text = json.dumps(self.body_json, indent=2)
        else:
            try:
                text = self.body.decode("utf-8")
            except UnicodeDecodeError:
                return f"<binary data: {len(self.body)} bytes>"

        if len(text) > max_length:
            return text[:max_length] + "..."
        return text

    def get_fingerprint(self) -> str:
        """Generate a fingerprint for this request (excluding timestamp)."""
        data = f"{self.method}:{self.path}:{sorted(self.headers.items())}:{self.body.hex()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": str(self.id),
            "tunnel_id": str(self.tunnel_id) if self.tunnel_id else None,
            "subdomain": self.subdomain,
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "query_params": self.query_params,
            "body": self.body.decode("utf-8", errors="replace") if self.body else "",
            "body_json": self.body_json,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "source_ip": self.source_ip,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "is_replay": self.is_replay,
            "original_request_id": str(self.original_request_id)
            if self.original_request_id
            else None,
        }


class CapturedResponse(BaseModel):
    """A captured HTTP response."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    request_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status_code: int = 200
    status_text: str = "OK"
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""
    body_json: dict[str, Any] | None = None
    content_type: str = ""
    content_length: int = 0
    error: str | None = None

    def model_post_init(self, __context: Any) -> None:
        """Post-init processing."""
        self.content_type = self.headers.get("content-type", self.headers.get("Content-Type", ""))
        self.content_length = len(self.body)

        # Try to parse JSON body
        if self.body and "json" in self.content_type.lower():
            with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
                self.body_json = json.loads(self.body.decode("utf-8"))

    def get_body_preview(self, max_length: int = 1000) -> str:
        """Get a preview of the body content."""
        if self.body_json is not None:
            text = json.dumps(self.body_json, indent=2)
        else:
            try:
                text = self.body.decode("utf-8")
            except UnicodeDecodeError:
                return f"<binary data: {len(self.body)} bytes>"

        if len(text) > max_length:
            return text[:max_length] + "..."
        return text

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "request_id": str(self.request_id),
            "timestamp": self.timestamp.isoformat(),
            "status_code": self.status_code,
            "status_text": self.status_text,
            "headers": self.headers,
            "body": self.body.decode("utf-8", errors="replace") if self.body else "",
            "body_json": self.body_json,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "error": self.error,
        }


@dataclass
class RequestFilter:
    """Filter for searching requests."""

    method: str | None = None
    path_pattern: str | None = None
    status: RequestStatus | None = None
    status_code: int | None = None
    subdomain: str | None = None
    source_ip: str | None = None
    content_type: str | None = None
    min_duration_ms: float | None = None
    max_duration_ms: float | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    body_contains: str | None = None
    header_name: str | None = None
    header_value: str | None = None

    def matches(self, request: CapturedRequest, response: CapturedResponse | None) -> bool:
        """Check if a request matches this filter."""
        if self.method and request.method.upper() != self.method.upper():
            return False

        if self.path_pattern:
            try:
                if not re.search(self.path_pattern, request.path):
                    return False
            except re.error:
                if self.path_pattern not in request.path:
                    return False

        if self.status and request.status != self.status:
            return False

        if self.status_code and response and response.status_code != self.status_code:
            return False

        if self.subdomain and request.subdomain != self.subdomain:
            return False

        if self.source_ip and request.source_ip != self.source_ip:
            return False

        if self.content_type and self.content_type.lower() not in request.content_type.lower():
            return False

        if (
            self.min_duration_ms
            and request.duration_ms
            and request.duration_ms < self.min_duration_ms
        ):
            return False

        if (
            self.max_duration_ms
            and request.duration_ms
            and request.duration_ms > self.max_duration_ms
        ):
            return False

        if self.start_time and request.timestamp < self.start_time:
            return False

        if self.end_time and request.timestamp > self.end_time:
            return False

        if self.body_contains:
            body_text = request.body.decode("utf-8", errors="replace")
            if self.body_contains.lower() not in body_text.lower():
                return False

        if self.header_name:
            header_found = False
            for key, value in request.headers.items():
                if key.lower() == self.header_name.lower() and (
                    self.header_value is None or self.header_value in value
                ):
                    header_found = True
                    break
            if not header_found:
                return False

        return True


@dataclass
class TrafficEntry:
    """A complete request/response pair."""

    request: CapturedRequest
    response: CapturedResponse | None = None


class TrafficStorage:
    """In-memory storage for captured traffic with LRU eviction."""

    def __init__(
        self,
        max_requests: int = 1000,
        max_body_size: int = 10 * 1024 * 1024,  # 10MB
        enable_body_capture: bool = True,
    ):
        self.max_requests = max_requests
        self.max_body_size = max_body_size
        self.enable_body_capture = enable_body_capture

        self._requests: dict[UUID, CapturedRequest] = {}
        self._responses: dict[UUID, CapturedResponse] = {}
        self._request_order: deque[UUID] = deque()
        self._lock = asyncio.Lock()

        # Real-time update subscribers
        self._subscribers: list[asyncio.Queue[TrafficEntry]] = []

    async def add_request(self, request: CapturedRequest) -> None:
        """Add a captured request."""
        async with self._lock:
            # Truncate body if too large
            if not self.enable_body_capture:
                request.body = b""
            elif len(request.body) > self.max_body_size:
                request.body = request.body[: self.max_body_size]

            # Evict old requests if at capacity
            while len(self._request_order) >= self.max_requests:
                old_id = self._request_order.popleft()
                self._requests.pop(old_id, None)
                self._responses.pop(old_id, None)

            self._requests[request.id] = request
            self._request_order.append(request.id)

        # Notify subscribers
        entry = TrafficEntry(request=request)
        for queue in self._subscribers:
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(entry)

    async def add_response(self, response: CapturedResponse) -> None:
        """Add a captured response for an existing request."""
        async with self._lock:
            if response.request_id not in self._requests:
                return

            # Truncate body if too large
            if not self.enable_body_capture:
                response.body = b""
            elif len(response.body) > self.max_body_size:
                response.body = response.body[: self.max_body_size]

            self._responses[response.request_id] = response

            # Update request status
            request = self._requests[response.request_id]
            if response.error:
                request.status = RequestStatus.ERROR
            else:
                request.status = RequestStatus.SUCCESS

        # Notify subscribers
        notify_request = self._requests.get(response.request_id)
        if notify_request:
            entry = TrafficEntry(request=notify_request, response=response)
            for queue in self._subscribers:
                with contextlib.suppress(asyncio.QueueFull):
                    queue.put_nowait(entry)

    async def get_request(self, request_id: UUID) -> CapturedRequest | None:
        """Get a request by ID."""
        async with self._lock:
            return self._requests.get(request_id)

    async def get_response(self, request_id: UUID) -> CapturedResponse | None:
        """Get a response by request ID."""
        async with self._lock:
            return self._responses.get(request_id)

    async def get_entry(self, request_id: UUID) -> TrafficEntry | None:
        """Get a complete request/response entry."""
        async with self._lock:
            request = self._requests.get(request_id)
            if not request:
                return None
            response = self._responses.get(request_id)
            return TrafficEntry(request=request, response=response)

    async def list_requests(
        self,
        filter: RequestFilter | None = None,
        offset: int = 0,
        limit: int = 50,
        descending: bool = True,
    ) -> list[TrafficEntry]:
        """List requests with optional filtering."""
        async with self._lock:
            # Get all entries in order
            entries = []
            order: list[UUID] = list(self._request_order)
            if descending:
                order = list(reversed(order))

            for req_id in order:
                request = self._requests.get(req_id)
                if not request:
                    continue
                response = self._responses.get(req_id)

                if filter and not filter.matches(request, response):
                    continue

                entries.append(TrafficEntry(request=request, response=response))

            # Apply pagination
            return entries[offset : offset + limit]

    async def get_stats(self) -> dict[str, Any]:
        """Get traffic statistics."""
        async with self._lock:
            total = len(self._requests)
            success = sum(1 for r in self._requests.values() if r.status == RequestStatus.SUCCESS)
            error = sum(1 for r in self._requests.values() if r.status == RequestStatus.ERROR)
            pending = sum(1 for r in self._requests.values() if r.status == RequestStatus.PENDING)
            timeout = sum(1 for r in self._requests.values() if r.status == RequestStatus.TIMEOUT)

            # Method distribution
            methods: dict[str, int] = {}
            for r in self._requests.values():
                methods[r.method] = methods.get(r.method, 0) + 1

            # Status code distribution
            status_codes: dict[int, int] = {}
            for resp in self._responses.values():
                status_codes[resp.status_code] = status_codes.get(resp.status_code, 0) + 1

            # Average duration
            durations = [
                r.duration_ms for r in self._requests.values() if r.duration_ms is not None
            ]
            avg_duration = sum(durations) / len(durations) if durations else 0

            return {
                "total_requests": total,
                "success": success,
                "error": error,
                "pending": pending,
                "timeout": timeout,
                "methods": methods,
                "status_codes": status_codes,
                "average_duration_ms": avg_duration,
                "max_requests": self.max_requests,
                "body_capture_enabled": self.enable_body_capture,
            }

    async def clear(self) -> None:
        """Clear all stored traffic."""
        async with self._lock:
            self._requests.clear()
            self._responses.clear()
            self._request_order.clear()

    async def delete_request(self, request_id: UUID) -> bool:
        """Delete a specific request."""
        async with self._lock:
            if request_id not in self._requests:
                return False
            del self._requests[request_id]
            self._responses.pop(request_id, None)
            # Remove from order (O(n) but rarely called)
            with contextlib.suppress(ValueError):
                self._request_order.remove(request_id)
            return True

    def subscribe(self) -> asyncio.Queue[TrafficEntry]:
        """Subscribe to real-time traffic updates."""
        queue: asyncio.Queue[TrafficEntry] = asyncio.Queue(maxsize=100)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[TrafficEntry]) -> None:
        """Unsubscribe from traffic updates."""
        with contextlib.suppress(ValueError):
            self._subscribers.remove(queue)


# Global storage instance
_storage: TrafficStorage | None = None


def get_traffic_storage() -> TrafficStorage:
    """Get or create the global traffic storage instance."""
    global _storage
    if _storage is None:
        _storage = TrafficStorage()
    return _storage


def set_traffic_storage(storage: TrafficStorage) -> None:
    """Set the global traffic storage instance."""
    global _storage
    _storage = storage
