"""Policy actions that can be executed when rules match."""

from __future__ import annotations

import asyncio
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Types of policy actions."""

    ALLOW = "allow"
    DENY = "deny"
    RATE_LIMIT = "rate_limit"
    ADD_HEADER = "add_header"
    REMOVE_HEADER = "remove_header"
    MODIFY_HEADER = "modify_header"
    REWRITE_PATH = "rewrite_path"
    REWRITE_HOST = "rewrite_host"
    REDIRECT = "redirect"
    TRANSFORM_REQUEST = "transform_request"
    TRANSFORM_RESPONSE = "transform_response"
    CIRCUIT_BREAKER = "circuit_breaker"
    LOG = "log"
    TAG = "tag"
    DELAY = "delay"


@dataclass
class ActionResult:
    """Result of executing a policy action."""

    success: bool = True
    action_type: ActionType = ActionType.ALLOW
    stop_request: bool = False  # Stop processing and return response
    response_status: int | None = None
    response_body: bytes | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    modified_request: dict[str, Any] | None = None
    modified_response: dict[str, Any] | None = None
    tags: list[str] = field(default_factory=list)
    log_message: str | None = None
    error: str | None = None


class PolicyActionBase(ABC, BaseModel):
    """Base class for policy actions."""

    id: str
    type: ActionType
    enabled: bool = True

    @abstractmethod
    async def execute(self, context: dict[str, Any]) -> ActionResult:
        """Execute this action."""
        pass


class AllowAction(PolicyActionBase):
    """Action that allows the request to proceed."""

    type: ActionType = ActionType.ALLOW

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        return ActionResult(success=True, action_type=ActionType.ALLOW)


class DenyAction(PolicyActionBase):
    """Action that denies the request."""

    type: ActionType = ActionType.DENY
    status_code: int = 403
    message: str = "Access denied"

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        return ActionResult(
            success=True,
            action_type=ActionType.DENY,
            stop_request=True,
            response_status=self.status_code,
            response_body=self.message.encode(),
            response_headers={"Content-Type": "text/plain"},
        )


class RateLimitAction(PolicyActionBase):
    """Action that enforces rate limiting."""

    model_config = {"arbitrary_types_allowed": True}

    type: ActionType = ActionType.RATE_LIMIT
    requests_per_window: int = 100
    window_seconds: int = 60
    key_field: str = "client.ip"  # Field to use as rate limit key
    burst_size: int | None = None  # Allow burst above limit
    retry_after_header: bool = True
    status_code: int = 429
    message: str = "Too many requests"

    # Internal state (not serialized)
    _buckets: dict[str, list[float]] = {}
    _lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        # Get rate limit key
        key = self._extract_key(context)
        now = time.time()
        window_start = now - self.window_seconds

        async with self._get_lock():
            # Initialize bucket if needed
            if key not in self._buckets:
                self._buckets[key] = []

            # Remove old entries
            self._buckets[key] = [t for t in self._buckets[key] if t > window_start]

            # Check limit
            current_count = len(self._buckets[key])
            limit = self.requests_per_window
            if self.burst_size:
                limit += self.burst_size

            if current_count >= limit:
                # Rate limit exceeded
                headers = {"Content-Type": "text/plain"}
                if self.retry_after_header:
                    # Calculate when the oldest request will expire
                    oldest = min(self._buckets[key]) if self._buckets[key] else now
                    retry_after = int(oldest + self.window_seconds - now) + 1
                    headers["Retry-After"] = str(max(1, retry_after))
                    headers["X-RateLimit-Limit"] = str(self.requests_per_window)
                    headers["X-RateLimit-Remaining"] = "0"
                    headers["X-RateLimit-Reset"] = str(int(oldest + self.window_seconds))

                return ActionResult(
                    success=True,
                    action_type=ActionType.RATE_LIMIT,
                    stop_request=True,
                    response_status=self.status_code,
                    response_body=self.message.encode(),
                    response_headers=headers,
                )

            # Add current request to bucket
            self._buckets[key].append(now)

            # Return success with rate limit headers
            return ActionResult(
                success=True,
                action_type=ActionType.RATE_LIMIT,
                response_headers={
                    "X-RateLimit-Limit": str(self.requests_per_window),
                    "X-RateLimit-Remaining": str(
                        max(0, self.requests_per_window - current_count - 1)
                    ),
                    "X-RateLimit-Reset": str(int(now + self.window_seconds)),
                },
            )

    def _extract_key(self, context: dict[str, Any]) -> str:
        """Extract the rate limit key from context."""
        parts = self.key_field.split(".")
        value = context
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, "")
            else:
                value = ""
                break
        return str(value) if value else "default"


class HeaderAction(PolicyActionBase):
    """Action that modifies request/response headers."""

    type: ActionType = ActionType.ADD_HEADER
    target: str = "request"  # "request" or "response"
    header_name: str
    header_value: str | None = None  # None = remove header
    overwrite: bool = True

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        if self.target == "request":
            headers = dict(context.get("req", {}).get("headers", {}))

            if self.header_value is None:
                # Remove header
                headers.pop(self.header_name, None)
                for key in list(headers.keys()):
                    if key.lower() == self.header_name.lower():
                        del headers[key]
            elif self.overwrite or self.header_name not in headers:
                headers[self.header_name] = self.header_value

            return ActionResult(
                success=True,
                action_type=self.type,
                modified_request={"headers": headers},
            )
        else:
            # Response header modification
            return ActionResult(
                success=True,
                action_type=self.type,
                response_headers={self.header_name: self.header_value or ""},
            )


class RewriteAction(PolicyActionBase):
    """Action that rewrites the request path or host."""

    type: ActionType = ActionType.REWRITE_PATH
    pattern: str  # Regex pattern to match
    replacement: str  # Replacement string (can use $1, $2, etc.)
    target: str = "path"  # "path" or "host"

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        req = context.get("req", {})

        if self.target == "path":
            original = req.get("path", "/")
            try:
                new_value = re.sub(self.pattern, self.replacement, original)
                return ActionResult(
                    success=True,
                    action_type=self.type,
                    modified_request={"path": new_value},
                )
            except re.error as e:
                return ActionResult(
                    success=False,
                    action_type=self.type,
                    error=f"Invalid regex pattern: {e}",
                )
        elif self.target == "host":
            original = req.get("host", "")
            try:
                new_value = re.sub(self.pattern, self.replacement, original)
                return ActionResult(
                    success=True,
                    action_type=self.type,
                    modified_request={"host": new_value},
                )
            except re.error as e:
                return ActionResult(
                    success=False,
                    action_type=self.type,
                    error=f"Invalid regex pattern: {e}",
                )

        return ActionResult(success=True, action_type=self.type)


class RedirectAction(PolicyActionBase):
    """Action that redirects the request."""

    type: ActionType = ActionType.REDIRECT
    target_url: str
    status_code: int = 302  # 301=permanent, 302=temporary, 307=temp preserve method
    preserve_path: bool = False
    preserve_query: bool = True

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        req = context.get("req", {})
        url = self.target_url

        if self.preserve_path:
            path = req.get("path", "/")
            # Remove leading slash if target_url ends with slash
            if url.endswith("/") and path.startswith("/"):
                path = path[1:]
            url = url.rstrip("/") + path

        if self.preserve_query:
            query = req.get("query", "")
            if query:
                separator = "&" if "?" in url else "?"
                url = url + separator + query

        return ActionResult(
            success=True,
            action_type=ActionType.REDIRECT,
            stop_request=True,
            response_status=self.status_code,
            response_headers={"Location": url},
            response_body=b"",
        )


class TransformAction(PolicyActionBase):
    """Action that transforms request or response body."""

    type: ActionType = ActionType.TRANSFORM_REQUEST
    target: str = "request"  # "request" or "response"
    json_path: str | None = None  # JSON path to modify
    json_value: Any = None  # Value to set
    find_replace: list[tuple[str, str]] = Field(default_factory=list)  # Find/replace pairs

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        if self.target == "request":
            req = context.get("req", {})
            body = req.get("body", b"")

            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")

            # Apply find/replace
            for find, replace in self.find_replace:
                body = body.replace(find, replace)

            # Apply JSON transformation
            if self.json_path and self.json_value is not None:
                import json

                try:
                    data = json.loads(body)
                    self._set_json_path(data, self.json_path, self.json_value)
                    body = json.dumps(data)
                except (json.JSONDecodeError, KeyError):
                    pass

            return ActionResult(
                success=True,
                action_type=self.type,
                modified_request={"body": body.encode()},
            )
        else:
            # Response transformation handled in response phase
            return ActionResult(
                success=True,
                action_type=self.type,
                modified_response={"transform": self.model_dump()},
            )

    def _set_json_path(self, data: dict, path: str, value: Any) -> None:
        """Set a value at a JSON path."""
        parts = path.split(".")
        current = data
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value


class CircuitBreakerAction(PolicyActionBase):
    """Action that implements circuit breaker pattern."""

    model_config = {"arbitrary_types_allowed": True}

    type: ActionType = ActionType.CIRCUIT_BREAKER
    failure_threshold: int = 5  # Failures to open circuit
    success_threshold: int = 3  # Successes to close circuit
    timeout_seconds: int = 30  # Time before half-open
    key_field: str = "conn.subdomain"  # Circuit key

    # Internal state
    _circuits: dict[str, dict[str, Any]] = {}
    _lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        key = self._extract_key(context)
        now = time.time()

        async with self._get_lock():
            if key not in self._circuits:
                self._circuits[key] = {
                    "state": "closed",
                    "failures": 0,
                    "successes": 0,
                    "last_failure": 0,
                }

            circuit = self._circuits[key]

            # Check circuit state
            if circuit["state"] == "open":
                # Check if timeout has passed
                if now - circuit["last_failure"] > self.timeout_seconds:
                    circuit["state"] = "half-open"
                    circuit["successes"] = 0
                else:
                    # Circuit is open, reject request
                    return ActionResult(
                        success=True,
                        action_type=ActionType.CIRCUIT_BREAKER,
                        stop_request=True,
                        response_status=503,
                        response_body=b"Service temporarily unavailable (circuit open)",
                        response_headers={
                            "Content-Type": "text/plain",
                            "Retry-After": str(
                                int(self.timeout_seconds - (now - circuit["last_failure"]))
                            ),
                        },
                    )

            # Allow request, but track for circuit state updates
            return ActionResult(
                success=True,
                action_type=ActionType.CIRCUIT_BREAKER,
                tags=[f"circuit:{key}:state:{circuit['state']}"],
            )

    async def record_success(self, key: str) -> None:
        """Record a successful request."""
        async with self._get_lock():
            if key not in self._circuits:
                return

            circuit = self._circuits[key]
            if circuit["state"] == "half-open":
                circuit["successes"] += 1
                if circuit["successes"] >= self.success_threshold:
                    circuit["state"] = "closed"
                    circuit["failures"] = 0
            elif circuit["state"] == "closed":
                circuit["failures"] = 0

    async def record_failure(self, key: str) -> None:
        """Record a failed request."""
        async with self._get_lock():
            if key not in self._circuits:
                self._circuits[key] = {
                    "state": "closed",
                    "failures": 0,
                    "successes": 0,
                    "last_failure": 0,
                }

            circuit = self._circuits[key]
            circuit["failures"] += 1
            circuit["last_failure"] = time.time()

            if circuit["state"] == "half-open":
                # Any failure in half-open goes back to open
                circuit["state"] = "open"
            elif circuit["state"] == "closed" and circuit["failures"] >= self.failure_threshold:
                circuit["state"] = "open"

    def _extract_key(self, context: dict[str, Any]) -> str:
        """Extract the circuit breaker key from context."""
        parts = self.key_field.split(".")
        value = context
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, "")
            else:
                value = ""
                break
        return str(value) if value else "default"


class DelayAction(PolicyActionBase):
    """Action that introduces artificial delay."""

    type: ActionType = ActionType.DELAY
    delay_ms: int = 100
    jitter_ms: int = 0  # Random jitter

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        import random

        delay = self.delay_ms
        if self.jitter_ms > 0:
            delay += random.randint(-self.jitter_ms, self.jitter_ms)

        if delay > 0:
            await asyncio.sleep(delay / 1000)

        return ActionResult(success=True, action_type=self.type)


class LogAction(PolicyActionBase):
    """Action that logs the request."""

    type: ActionType = ActionType.LOG
    message: str = "Request matched policy rule"
    include_headers: bool = False
    include_body: bool = False
    level: str = "info"

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        log_parts = [self.message]

        req = context.get("req", {})
        log_parts.append(f"method={req.get('method', 'UNKNOWN')}")
        log_parts.append(f"path={req.get('path', '/')}")
        log_parts.append(f"client_ip={context.get('client', {}).get('ip', 'unknown')}")

        if self.include_headers:
            log_parts.append(f"headers={req.get('headers', {})}")

        if self.include_body:
            body = req.get("body", b"")
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")[:500]
            log_parts.append(f"body={body}")

        return ActionResult(
            success=True,
            action_type=ActionType.LOG,
            log_message=" ".join(log_parts),
        )


class TagAction(PolicyActionBase):
    """Action that adds tags to the request for tracking."""

    type: ActionType = ActionType.TAG
    tags: list[str] = Field(default_factory=list)

    async def execute(self, context: dict[str, Any]) -> ActionResult:
        return ActionResult(
            success=True,
            action_type=ActionType.TAG,
            tags=self.tags.copy(),
        )


# Type alias for any action
PolicyAction = (
    AllowAction
    | DenyAction
    | RateLimitAction
    | HeaderAction
    | RewriteAction
    | RedirectAction
    | TransformAction
    | CircuitBreakerAction
    | DelayAction
    | LogAction
    | TagAction
)
