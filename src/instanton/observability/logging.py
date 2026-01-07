"""Structured logging for Instanton tunnel application.

This module provides comprehensive structured logging with:
- JSON log formatter
- Log correlation with trace IDs
- Request ID injection
- Log levels configuration
- Log sampling for high-volume
- Sensitive data redaction
"""

from __future__ import annotations

import json
import logging
import random
import re
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

# Try to import OpenTelemetry for trace correlation
try:
    from opentelemetry import trace  # noqa: F401
    from opentelemetry.trace import get_current_span

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


# Patterns for sensitive data redaction
SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    # API keys and tokens
    (r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?[\w\-]+', r"\1=***REDACTED***"),
    (
        r'(token|auth[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']?[\w\-\.]+',
        r"\1=***REDACTED***",
    ),
    (r"(bearer\s+)[\w\-\.]+", r"\1***REDACTED***"),
    # Passwords
    (r'(password|passwd|pwd)["\']?\s*[:=]\s*["\']?[^\s"\']+', r"\1=***REDACTED***"),
    # Secrets
    (r'(secret|client[_-]?secret)["\']?\s*[:=]\s*["\']?[\w\-]+', r"\1=***REDACTED***"),
    # Credit cards (basic pattern)
    (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "***CARD-REDACTED***"),
    # SSN
    (r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b", "***SSN-REDACTED***"),
    # Email addresses (optional)
    # (r'[\w\.-]+@[\w\.-]+\.\w+', '***EMAIL-REDACTED***'),
    # IP addresses (internal)
    (r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3})", "***INTERNAL-IP***"),
    (r"(192\.168\.\d{1,3}\.\d{1,3})", "***INTERNAL-IP***"),
    (r"(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})", "***INTERNAL-IP***"),
]


class SensitiveDataFilter:
    """Filter for redacting sensitive data from log messages."""

    def __init__(
        self,
        patterns: list[tuple[str, str]] | None = None,
        additional_keys: set[str] | None = None,
    ) -> None:
        """Initialize the filter.

        Args:
            patterns: List of (pattern, replacement) tuples
            additional_keys: Additional dictionary keys to redact
        """
        self.patterns = [
            (re.compile(p, re.IGNORECASE), r) for p, r in (patterns or SENSITIVE_PATTERNS)
        ]
        self.sensitive_keys = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "auth",
            "authorization",
            "credentials",
            "private_key",
            "access_token",
            "refresh_token",
            "session_id",
            "cookie",
        }
        if additional_keys:
            self.sensitive_keys.update(additional_keys)

    def redact_string(self, value: str) -> str:
        """Redact sensitive patterns from a string.

        Args:
            value: String to redact

        Returns:
            Redacted string
        """
        for pattern, replacement in self.patterns:
            value = pattern.sub(replacement, value)
        return value

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive keys from a dictionary.

        Args:
            data: Dictionary to redact

        Returns:
            Redacted dictionary
        """
        result: dict[str, Any] = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(sk in key_lower for sk in self.sensitive_keys):
                result[key] = "***REDACTED***"
            elif isinstance(value, dict):
                result[key] = self.redact_dict(value)
            elif isinstance(value, str):
                result[key] = self.redact_string(value)
            elif isinstance(value, list):
                result[key] = [
                    self.redact_dict(v)
                    if isinstance(v, dict)
                    else self.redact_string(v)
                    if isinstance(v, str)
                    else v
                    for v in value
                ]
            else:
                result[key] = value
        return result


class LogSampler:
    """Sampler for reducing log volume in high-throughput scenarios."""

    def __init__(
        self,
        sample_rate: float = 1.0,
        min_level: int = logging.WARNING,
    ) -> None:
        """Initialize the sampler.

        Args:
            sample_rate: Rate of logs to keep (0.0 to 1.0)
            min_level: Minimum level that always gets logged
        """
        self.sample_rate = sample_rate
        self.min_level = min_level
        self._counter = 0
        self._lock = threading.Lock()

    def should_log(self, level: int) -> bool:
        """Determine if a log message should be recorded.

        Args:
            level: Log level

        Returns:
            True if message should be logged
        """
        # Always log high-severity messages
        if level >= self.min_level:
            return True

        # Sample lower severity messages
        if self.sample_rate >= 1.0:
            return True
        if self.sample_rate <= 0.0:
            return False

        return random.random() < self.sample_rate


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def __init__(
        self,
        include_timestamp: bool = True,
        include_trace: bool = True,
        include_extra: bool = True,
        redact_sensitive: bool = True,
        timestamp_format: str = "iso",
    ) -> None:
        """Initialize the formatter.

        Args:
            include_timestamp: Include timestamp in output
            include_trace: Include trace/span IDs
            include_extra: Include extra fields from LogRecord
            redact_sensitive: Redact sensitive data
            timestamp_format: Timestamp format (iso, unix, unix_ms)
        """
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_trace = include_trace
        self.include_extra = include_extra
        self.redact_sensitive = redact_sensitive
        self.timestamp_format = timestamp_format
        self.sensitive_filter = SensitiveDataFilter() if redact_sensitive else None

        # Standard LogRecord attributes to exclude from extra
        self._builtin_attrs = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "exc_info",
            "exc_text",
            "thread",
            "threadName",
            "message",
            "asctime",
        }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON formatted string
        """
        log_data: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add timestamp
        if self.include_timestamp:
            log_data["timestamp"] = self._format_timestamp(record.created)

        # Add location info
        log_data["location"] = {
            "file": record.filename,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add process/thread info
        log_data["process"] = {
            "id": record.process,
            "name": record.processName,
        }
        log_data["thread"] = {
            "id": record.thread,
            "name": record.threadName,
        }

        # Add trace context
        if self.include_trace:
            trace_context = self._get_trace_context()
            if trace_context:
                log_data["trace"] = trace_context

        # Add exception info
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info),
            }

        # Add extra fields
        if self.include_extra:
            extra = self._extract_extra(record)
            if extra:
                log_data["extra"] = extra

        # Redact sensitive data
        if self.sensitive_filter:
            log_data = self.sensitive_filter.redact_dict(log_data)

        return json.dumps(log_data, default=str, ensure_ascii=False)

    def _format_timestamp(self, created: float) -> str | float:
        """Format timestamp according to configuration.

        Args:
            created: Unix timestamp

        Returns:
            Formatted timestamp
        """
        if self.timestamp_format == "unix":
            return created
        elif self.timestamp_format == "unix_ms":
            return int(created * 1000)
        else:  # iso
            dt = datetime.fromtimestamp(created, tz=UTC)
            return dt.isoformat()

    def _get_trace_context(self) -> dict[str, str] | None:
        """Get current trace context from OpenTelemetry.

        Returns:
            Trace context dict or None
        """
        if not OTEL_AVAILABLE:
            return None

        try:
            span = get_current_span()
            if span and span.is_recording():
                ctx = span.get_span_context()
                return {
                    "trace_id": format(ctx.trace_id, "032x"),
                    "span_id": format(ctx.span_id, "016x"),
                }
        except Exception:
            pass
        return None

    def _extract_extra(self, record: logging.LogRecord) -> dict[str, Any]:
        """Extract extra fields from log record.

        Args:
            record: Log record

        Returns:
            Dictionary of extra fields
        """
        extra = {}
        for key, value in record.__dict__.items():
            if key not in self._builtin_attrs and not key.startswith("_"):
                extra[key] = value
        return extra


class RequestContextFilter(logging.Filter):
    """Filter that adds request context to log records."""

    _context: dict[int, dict[str, Any]] = {}
    _lock = threading.Lock()

    @classmethod
    def set_context(cls, request_id: str, **kwargs: Any) -> None:
        """Set context for current thread.

        Args:
            request_id: Request ID
            **kwargs: Additional context values
        """
        thread_id = threading.current_thread().ident
        if thread_id is None:
            return
        with cls._lock:
            cls._context[thread_id] = {
                "request_id": request_id,
                **kwargs,
            }

    @classmethod
    def clear_context(cls) -> None:
        """Clear context for current thread."""
        thread_id = threading.current_thread().ident
        if thread_id is None:
            return
        with cls._lock:
            cls._context.pop(thread_id, None)

    @classmethod
    def get_context(cls) -> dict[str, Any]:
        """Get context for current thread.

        Returns:
            Context dictionary
        """
        thread_id = threading.current_thread().ident
        if thread_id is None:
            return {}
        with cls._lock:
            return cls._context.get(thread_id, {}).copy()

    def filter(self, record: logging.LogRecord) -> bool:
        """Add context to log record.

        Args:
            record: Log record to modify

        Returns:
            True (always allow)
        """
        context = self.get_context()
        for key, value in context.items():
            setattr(record, key, value)
        return True


class InstantonLogger:
    """Enhanced logger with structured logging capabilities."""

    _instance: InstantonLogger | None = None
    _lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls) -> InstantonLogger:
        """Singleton pattern for logger instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instance = instance
        return cls._instance

    def __init__(self) -> None:
        """Initialize the logger (called once due to singleton)."""
        if self._initialized:
            return

        self._loggers: dict[str, logging.Logger] = {}
        self._handler: logging.Handler | None = None
        self._formatter: JSONFormatter | None = None
        self._sampler: LogSampler | None = None
        self._default_level = logging.INFO
        self._initialized = True

    def setup(
        self,
        level: str | int = logging.INFO,
        json_output: bool = True,
        stream: Any = None,
        include_trace: bool = True,
        redact_sensitive: bool = True,
        sample_rate: float = 1.0,
        sample_min_level: int = logging.WARNING,
    ) -> None:
        """Configure the logging system.

        Args:
            level: Log level (name or number)
            json_output: Use JSON formatting
            stream: Output stream (defaults to stderr)
            include_trace: Include trace IDs
            redact_sensitive: Redact sensitive data
            sample_rate: Sampling rate for logs
            sample_min_level: Minimum level to always log
        """
        # Parse level
        if isinstance(level, str):
            self._default_level = getattr(logging, level.upper(), logging.INFO)
        else:
            self._default_level = level

        # Configure sampler
        if sample_rate < 1.0:
            self._sampler = LogSampler(sample_rate, sample_min_level)

        # Create handler
        self._handler = logging.StreamHandler(stream or sys.stderr)
        self._handler.setLevel(self._default_level)

        # Create formatter
        if json_output:
            self._formatter = JSONFormatter(
                include_trace=include_trace,
                redact_sensitive=redact_sensitive,
            )
        else:
            self._formatter = None
            self._handler.setFormatter(
                logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )

        if self._formatter:
            self._handler.setFormatter(self._formatter)

        # Add context filter
        self._handler.addFilter(RequestContextFilter())

        # Configure root logger
        root = logging.getLogger("instanton")
        root.setLevel(self._default_level)
        root.handlers.clear()
        root.addHandler(self._handler)
        root.propagate = False

    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance.

        Args:
            name: Logger name

        Returns:
            Configured logger
        """
        if name in self._loggers:
            return self._loggers[name]

        # Create logger under instanton namespace
        full_name = f"instanton.{name}" if not name.startswith("instanton") else name
        logger = logging.getLogger(full_name)

        # Add sampling filter if configured
        if self._sampler:

            class SamplingFilter(logging.Filter):
                def __init__(self, sampler: LogSampler):
                    super().__init__()
                    self.sampler = sampler

                def filter(self, record: logging.LogRecord) -> bool:
                    return self.sampler.should_log(record.levelno)

            logger.addFilter(SamplingFilter(self._sampler))

        self._loggers[name] = logger
        return logger

    def set_request_context(self, request_id: str, **kwargs: Any) -> None:
        """Set request context for logging.

        Args:
            request_id: Request ID
            **kwargs: Additional context
        """
        RequestContextFilter.set_context(request_id, **kwargs)

    def clear_request_context(self) -> None:
        """Clear request context."""
        RequestContextFilter.clear_context()

    def log_with_trace(
        self,
        logger: logging.Logger,
        level: int,
        message: str,
        **kwargs: Any,
    ) -> None:
        """Log with trace context.

        Args:
            logger: Logger to use
            level: Log level
            message: Log message
            **kwargs: Additional fields
        """
        # Add trace context to extra
        extra = kwargs.pop("extra", {})
        if OTEL_AVAILABLE:
            try:
                span = get_current_span()
                if span and span.is_recording():
                    ctx = span.get_span_context()
                    extra["trace_id"] = format(ctx.trace_id, "032x")
                    extra["span_id"] = format(ctx.span_id, "016x")
            except Exception:
                pass

        extra.update(kwargs)
        logger.log(level, message, extra=extra)


def setup_logging(
    level: str | int = logging.INFO,
    json_output: bool = True,
    include_trace: bool = True,
    redact_sensitive: bool = True,
    sample_rate: float = 1.0,
) -> InstantonLogger:
    """Setup logging with common configuration.

    Args:
        level: Log level
        json_output: Use JSON formatting
        include_trace: Include trace IDs
        redact_sensitive: Redact sensitive data
        sample_rate: Sampling rate

    Returns:
        Configured InstantonLogger instance
    """
    logger = InstantonLogger()
    logger.setup(
        level=level,
        json_output=json_output,
        include_trace=include_trace,
        redact_sensitive=redact_sensitive,
        sample_rate=sample_rate,
    )
    return logger


def get_logger(name: str = "main") -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    instanton_logger = InstantonLogger()
    return instanton_logger.get_logger(name)


class LoggingMiddleware:
    """ASGI middleware for request logging."""

    def __init__(
        self,
        app: Any,
        logger: logging.Logger | None = None,
    ) -> None:
        """Initialize middleware.

        Args:
            app: ASGI application
            logger: Logger instance
        """
        self.app = app
        self.logger = logger or get_logger("http")

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,
    ) -> None:
        """Process request with logging."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        import uuid

        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        # Extract request info
        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "/")
        dict(scope.get("headers", []))
        client = scope.get("client", ("unknown", 0))

        # Set request context
        RequestContextFilter.set_context(
            request_id=request_id,
            method=method,
            path=path,
            client_ip=client[0] if client else "unknown",
        )

        # Log request
        self.logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "method": method,
                "path": path,
                "client_ip": client[0] if client else "unknown",
            },
        )

        status_code = 500

        async def send_wrapper(message: dict[str, Any]) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 500)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as e:
            self.logger.exception(
                "Request failed",
                extra={
                    "request_id": request_id,
                    "error": str(e),
                },
            )
            raise
        finally:
            duration = time.perf_counter() - start_time
            self.logger.info(
                "Request completed",
                extra={
                    "request_id": request_id,
                    "status_code": status_code,
                    "duration_ms": round(duration * 1000, 2),
                },
            )
            RequestContextFilter.clear_context()
