"""Request replay functionality for the inspector."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel, Field

from instanton.inspector.storage import (
    CapturedRequest,
    CapturedResponse,
    RequestStatus,
    TrafficStorage,
    get_traffic_storage,
)


class ReplayMode(str, Enum):
    """Mode for replaying requests."""

    EXACT = "exact"  # Replay exactly as captured
    MODIFIED = "modified"  # Replay with modifications


@dataclass
class ReplayConfig:
    """Configuration for request replay."""

    # Timeout settings
    connect_timeout: float = 5.0
    read_timeout: float = 30.0
    total_timeout: float = 60.0

    # Retry settings
    max_retries: int = 0
    retry_delay: float = 1.0

    # Target override (use original target if None)
    target_host: str | None = None
    target_port: int | None = None
    target_scheme: str | None = None  # "http" or "https"

    # Request modifications
    modify_headers: dict[str, str | None] = field(default_factory=dict)  # None = remove
    modify_body: bytes | None = None
    modify_method: str | None = None
    modify_path: str | None = None

    # Behavior flags
    follow_redirects: bool = True
    verify_ssl: bool = False  # Usually replaying to localhost
    capture_result: bool = True  # Store replay result in traffic storage


class ReplayResult(BaseModel):
    """Result of a request replay."""

    model_config = {"arbitrary_types_allowed": True}

    success: bool = False
    original_request_id: UUID
    replay_request_id: UUID | None = None
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes = b""
    duration_ms: float = 0.0
    error: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "original_request_id": str(self.original_request_id),
            "replay_request_id": str(self.replay_request_id) if self.replay_request_id else None,
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body.decode("utf-8", errors="replace") if self.body else "",
            "duration_ms": self.duration_ms,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }


class RequestReplayer:
    """Replays captured HTTP requests."""

    def __init__(
        self,
        storage: TrafficStorage | None = None,
        default_target: str = "http://localhost:8000",
    ):
        self.storage = storage or get_traffic_storage()
        self.default_target = default_target
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self, config: ReplayConfig) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            timeout = httpx.Timeout(
                connect=config.connect_timeout,
                read=config.read_timeout,
                write=config.read_timeout,
                pool=config.connect_timeout,
            )
            self._client = httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=config.follow_redirects,
                verify=config.verify_ssl,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def replay(
        self,
        request_id: UUID,
        config: ReplayConfig | None = None,
    ) -> ReplayResult:
        """Replay a captured request.

        Args:
            request_id: ID of the captured request to replay
            config: Optional replay configuration

        Returns:
            ReplayResult with the outcome
        """
        config = config or ReplayConfig()

        # Get the original request
        original = await self.storage.get_request(request_id)
        if not original:
            return ReplayResult(
                success=False,
                original_request_id=request_id,
                error=f"Request {request_id} not found",
            )

        # Build the target URL
        url = self._build_url(original, config)

        # Build headers
        headers = dict(original.headers)

        # Remove hop-by-hop headers
        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "host",
        }
        headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop}

        # Apply header modifications
        for key, value in config.modify_headers.items():
            if value is None:
                headers.pop(key, None)
            else:
                headers[key] = value

        # Get method and body
        method = config.modify_method or original.method
        body = config.modify_body if config.modify_body is not None else original.body
        path = config.modify_path or original.path

        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path

        # Full URL
        full_url = url.rstrip("/") + path

        # Execute replay
        start_time = time.time()
        try:
            client = await self._get_client(config)

            for attempt in range(config.max_retries + 1):
                try:
                    response = await asyncio.wait_for(
                        client.request(
                            method=method,
                            url=full_url,
                            headers=headers,
                            content=body,
                        ),
                        timeout=config.total_timeout,
                    )

                    duration_ms = (time.time() - start_time) * 1000

                    # Create replay result
                    result = ReplayResult(
                        success=True,
                        original_request_id=request_id,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=response.content,
                        duration_ms=duration_ms,
                    )

                    # Store replay in traffic storage if enabled
                    if config.capture_result:
                        replay_request_id = await self._store_replay(
                            original, response, duration_ms, config
                        )
                        result.replay_request_id = replay_request_id

                    return result

                except (httpx.ConnectError, httpx.ReadTimeout):
                    if attempt < config.max_retries:
                        await asyncio.sleep(config.retry_delay)
                        continue
                    raise

            # If we get here, all retries were exhausted without success
            duration_ms = (time.time() - start_time) * 1000
            return ReplayResult(
                success=False,
                original_request_id=request_id,
                duration_ms=duration_ms,
                error="Max retries exhausted",
            )

        except TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            return ReplayResult(
                success=False,
                original_request_id=request_id,
                duration_ms=duration_ms,
                error="Request timed out",
            )
        except httpx.ConnectError as e:
            duration_ms = (time.time() - start_time) * 1000
            return ReplayResult(
                success=False,
                original_request_id=request_id,
                duration_ms=duration_ms,
                error=f"Connection error: {e}",
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return ReplayResult(
                success=False,
                original_request_id=request_id,
                duration_ms=duration_ms,
                error=str(e),
            )

    def _build_url(self, request: CapturedRequest, config: ReplayConfig) -> str:
        """Build the target URL for replay."""
        if config.target_host:
            scheme = config.target_scheme or "http"
            port = config.target_port or (443 if scheme == "https" else 80)
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                return f"{scheme}://{config.target_host}"
            return f"{scheme}://{config.target_host}:{port}"
        return self.default_target

    async def _store_replay(
        self,
        original: CapturedRequest,
        response: httpx.Response,
        duration_ms: float,
        config: ReplayConfig,
    ) -> UUID:
        """Store the replay request/response in traffic storage."""
        replay_id = uuid4()

        # Create replay request
        replay_request = CapturedRequest(
            id=replay_id,
            tunnel_id=original.tunnel_id,
            subdomain=original.subdomain,
            method=config.modify_method or original.method,
            path=config.modify_path or original.path,
            headers=dict(original.headers),
            body=config.modify_body if config.modify_body is not None else original.body,
            source_ip="127.0.0.1",  # Replay is local
            duration_ms=duration_ms,
            status=RequestStatus.SUCCESS,
            is_replay=True,
            original_request_id=original.id,
        )

        # Apply header modifications
        for key, value in config.modify_headers.items():
            if value is None:
                replay_request.headers.pop(key, None)
            else:
                replay_request.headers[key] = value

        await self.storage.add_request(replay_request)

        # Create replay response
        replay_response = CapturedResponse(
            request_id=replay_id,
            status_code=response.status_code,
            status_text=response.reason_phrase or "",
            headers=dict(response.headers),
            body=response.content,
        )

        await self.storage.add_response(replay_response)

        return replay_id

    async def replay_with_modifications(
        self,
        request_id: UUID,
        method: str | None = None,
        path: str | None = None,
        headers: dict[str, str | None] | None = None,
        body: bytes | None = None,
        target_host: str | None = None,
        target_port: int | None = None,
    ) -> ReplayResult:
        """Convenience method to replay with common modifications.

        Args:
            request_id: ID of the captured request to replay
            method: Override the HTTP method
            path: Override the path
            headers: Headers to add/modify (None value removes header)
            body: Override the body
            target_host: Override target host
            target_port: Override target port

        Returns:
            ReplayResult with the outcome
        """
        config = ReplayConfig(
            modify_method=method,
            modify_path=path,
            modify_headers=headers or {},
            modify_body=body,
            target_host=target_host,
            target_port=target_port,
        )
        return await self.replay(request_id, config)

    async def batch_replay(
        self,
        request_ids: list[UUID],
        config: ReplayConfig | None = None,
        concurrency: int = 5,
    ) -> list[ReplayResult]:
        """Replay multiple requests with concurrency control.

        Args:
            request_ids: List of request IDs to replay
            config: Replay configuration
            concurrency: Maximum concurrent replays

        Returns:
            List of ReplayResults
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def replay_with_semaphore(req_id: UUID) -> ReplayResult:
            async with semaphore:
                return await self.replay(req_id, config)

        tasks = [replay_with_semaphore(req_id) for req_id in request_ids]
        return await asyncio.gather(*tasks)


# Global replayer instance
_replayer: RequestReplayer | None = None


def get_request_replayer() -> RequestReplayer:
    """Get or create the global request replayer instance."""
    global _replayer
    if _replayer is None:
        _replayer = RequestReplayer()
    return _replayer


def set_request_replayer(replayer: RequestReplayer) -> None:
    """Set the global request replayer instance."""
    global _replayer
    _replayer = replayer
