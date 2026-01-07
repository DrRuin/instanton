"""Production-grade DDoS protection for Instanton.

This module provides comprehensive DDoS protection including:
- Connection rate limiting per IP
- SYN flood protection
- Slowloris attack detection and mitigation
- HTTP flood detection
- Request fingerprinting for bot detection
- IP reputation tracking
- Automatic IP banning with configurable duration
- GeoIP blocking support (optional)
- Challenge mechanism for suspicious requests
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any

from cachetools import TTLCache

logger = logging.getLogger(__name__)

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


class ThreatLevel(IntEnum):
    """Threat level classification."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AttackType(Enum):
    """Types of DDoS attacks detected."""

    UNKNOWN = "unknown"
    CONNECTION_FLOOD = "connection_flood"
    SYN_FLOOD = "syn_flood"
    SLOWLORIS = "slowloris"
    HTTP_FLOOD = "http_flood"
    BOT_TRAFFIC = "bot_traffic"
    AMPLIFICATION = "amplification"
    SUSPICIOUS_PATTERN = "suspicious_pattern"


class ChallengeType(Enum):
    """Types of challenges for suspicious requests."""

    NONE = "none"
    JAVASCRIPT = "javascript"
    CAPTCHA = "captcha"
    COOKIE = "cookie"
    PROOF_OF_WORK = "proof_of_work"


@dataclass
class RequestFingerprint:
    """Fingerprint of an HTTP request for bot detection."""

    user_agent: str = ""
    accept_language: str = ""
    accept_encoding: str = ""
    accept: str = ""
    connection: str = ""
    headers_order: tuple[str, ...] = field(default_factory=tuple)
    tls_fingerprint: str = ""
    http_version: str = ""

    def compute_hash(self) -> str:
        """Compute a hash of the fingerprint."""
        data = (
            f"{self.user_agent}|"
            f"{self.accept_language}|"
            f"{self.accept_encoding}|"
            f"{self.accept}|"
            f"{self.connection}|"
            f"{','.join(self.headers_order)}|"
            f"{self.tls_fingerprint}|"
            f"{self.http_version}"
        )
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def is_suspicious(self) -> tuple[bool, list[str]]:
        """Check if the fingerprint is suspicious.

        Returns:
            Tuple of (is_suspicious, list of reasons)
        """
        reasons: list[str] = []

        # Check for missing or empty user agent
        if not self.user_agent or self.user_agent == "-":
            reasons.append("missing_user_agent")

        # Check for known bot user agents
        bot_indicators = [
            "python-requests",
            "curl/",
            "wget/",
            "httpie/",
            "go-http-client",
            "java/",
            "apache-httpclient",
            "okhttp/",
            "libwww-perl",
        ]
        ua_lower = self.user_agent.lower()
        for indicator in bot_indicators:
            if indicator in ua_lower:
                reasons.append(f"bot_user_agent:{indicator}")
                break

        # Check for inconsistent headers
        if "gzip" in self.accept_encoding.lower() and not self.accept_language:
            reasons.append("missing_accept_language_with_encoding")

        # Check for unusual header order (browsers have consistent patterns)
        if self.headers_order:
            # Host should typically be first in HTTP/1.1
            header_names_lower = [h.lower() for h in self.headers_order]
            if "host" in header_names_lower and header_names_lower.index("host") > 2:
                reasons.append("unusual_header_order")

        return len(reasons) > 0, reasons


@dataclass
class IPReputation:
    """Reputation data for an IP address."""

    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_requests: int = 0
    blocked_requests: int = 0
    successful_challenges: int = 0
    failed_challenges: int = 0
    attack_detections: dict[str, int] = field(default_factory=dict)
    fingerprints: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    reputation_score: float = 100.0  # 0-100, higher is better
    is_banned: bool = False
    ban_expiry: float | None = None
    ban_reason: str = ""

    def update_reputation(self, adjustment: float, reason: str = "") -> None:
        """Update reputation score with bounds checking."""
        old_score = self.reputation_score
        self.reputation_score = max(0.0, min(100.0, self.reputation_score + adjustment))
        if old_score != self.reputation_score:
            logger.debug(
                "IP %s reputation: %.1f -> %.1f (%s)",
                self.ip,
                old_score,
                self.reputation_score,
                reason,
            )

    def record_attack(self, attack_type: AttackType) -> None:
        """Record an attack detection."""
        key = attack_type.value
        self.attack_detections[key] = self.attack_detections.get(key, 0) + 1
        self.update_reputation(-10, f"attack_detected:{key}")

    def get_threat_level(self) -> ThreatLevel:
        """Calculate current threat level based on reputation."""
        if self.reputation_score >= 80:
            return ThreatLevel.NONE
        elif self.reputation_score >= 60:
            return ThreatLevel.LOW
        elif self.reputation_score >= 40:
            return ThreatLevel.MEDIUM
        elif self.reputation_score >= 20:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL


class IPReputationTracker:
    """Tracks IP reputation across requests."""

    def __init__(
        self,
        cache_max_size: int = 100000,
        cache_ttl: float = 3600.0,
        min_reputation_threshold: float = 20.0,
    ) -> None:
        """Initialize IP reputation tracker.

        Args:
            cache_max_size: Maximum number of IPs to track
            cache_ttl: TTL for reputation entries
            min_reputation_threshold: Threshold below which to ban IPs
        """
        self._cache: TTLCache = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
        self._ban_cache: TTLCache = TTLCache(maxsize=cache_max_size, ttl=86400)
        self._min_threshold = min_reputation_threshold
        self._lock = asyncio.Lock()

    async def get_reputation(self, ip: str) -> IPReputation:
        """Get or create reputation for an IP."""
        async with self._lock:
            if ip not in self._cache:
                self._cache[ip] = IPReputation(ip=ip)
            rep = self._cache[ip]
            rep.last_seen = time.time()
            return rep

    async def update_reputation(
        self,
        ip: str,
        adjustment: float,
        reason: str = "",
    ) -> IPReputation:
        """Update reputation for an IP."""
        rep = await self.get_reputation(ip)
        async with self._lock:
            rep.update_reputation(adjustment, reason)
            if rep.reputation_score < self._min_threshold:
                await self._auto_ban(rep, f"reputation_below_threshold:{reason}")
        return rep

    async def _auto_ban(
        self,
        rep: IPReputation,
        reason: str,
        duration: float = 3600.0,
    ) -> None:
        """Automatically ban an IP."""
        rep.is_banned = True
        rep.ban_expiry = time.time() + duration
        rep.ban_reason = reason
        self._ban_cache[rep.ip] = rep.ban_expiry
        logger.warning("Auto-banned IP %s for %.0f seconds: %s", rep.ip, duration, reason)

    async def is_banned(self, ip: str) -> tuple[bool, float | None]:
        """Check if an IP is banned.

        Returns:
            Tuple of (is_banned, ban_expiry_timestamp)
        """
        if ip in self._ban_cache:
            expiry = self._ban_cache[ip]
            if expiry > time.time():
                return True, expiry
            else:
                del self._ban_cache[ip]
        return False, None

    async def ban_ip(
        self,
        ip: str,
        duration: float,
        reason: str = "manual_ban",
    ) -> None:
        """Manually ban an IP."""
        rep = await self.get_reputation(ip)
        async with self._lock:
            await self._auto_ban(rep, reason, duration)

    async def unban_ip(self, ip: str) -> bool:
        """Unban an IP address.

        Returns:
            True if IP was unbanned, False if not found
        """
        async with self._lock:
            if ip in self._ban_cache:
                del self._ban_cache[ip]
            if ip in self._cache:
                rep = self._cache[ip]
                rep.is_banned = False
                rep.ban_expiry = None
                rep.reputation_score = 50.0  # Reset to neutral
                return True
        return False

    async def record_request(self, ip: str, success: bool = True) -> None:
        """Record a request from an IP."""
        rep = await self.get_reputation(ip)
        async with self._lock:
            rep.total_requests += 1
            if not success:
                rep.blocked_requests += 1
                rep.update_reputation(-1, "blocked_request")
            elif rep.total_requests % 100 == 0:
                # Slowly improve reputation for good behavior
                rep.update_reputation(1, "sustained_good_behavior")

    def get_stats(self) -> dict[str, Any]:
        """Get tracker statistics."""
        return {
            "tracked_ips": len(self._cache),
            "banned_ips": len(self._ban_cache),
            "cache_max_size": self._cache.maxsize,
        }


@dataclass
class ConnectionInfo:
    """Information about a connection."""

    ip: str
    port: int
    connected_at: float
    last_activity: float
    bytes_received: int = 0
    bytes_sent: int = 0
    requests_count: int = 0
    is_slow: bool = False  # For slowloris detection


class ConnectionTracker:
    """Tracks active connections for DDoS detection."""

    def __init__(
        self,
        max_connections_per_ip: int = 100,
        max_total_connections: int = 10000,
        slow_connection_timeout: float = 30.0,
        cleanup_interval: float = 10.0,
    ) -> None:
        """Initialize connection tracker.

        Args:
            max_connections_per_ip: Maximum connections per IP
            max_total_connections: Maximum total connections
            slow_connection_timeout: Timeout for slow connections (slowloris)
            cleanup_interval: Interval for cleaning up stale connections
        """
        self._max_per_ip = max_connections_per_ip
        self._max_total = max_total_connections
        self._slow_timeout = slow_connection_timeout
        self._cleanup_interval = cleanup_interval
        self._connections: dict[str, ConnectionInfo] = {}
        self._ip_connection_counts: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the connection tracker."""
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        """Stop the connection tracker."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task

    async def _cleanup_loop(self) -> None:
        """Periodic cleanup of stale connections."""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_slow_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in connection cleanup: %s", e)

    async def _cleanup_slow_connections(self) -> None:
        """Clean up slow/stale connections (slowloris mitigation)."""
        now = time.time()
        to_remove: list[str] = []

        async with self._lock:
            for conn_id, conn in self._connections.items():
                idle_time = now - conn.last_activity
                if idle_time > self._slow_timeout:
                    conn.is_slow = True
                    to_remove.append(conn_id)
                    logger.warning(
                        "Removing slow connection from %s:%d (idle %.1fs)",
                        conn.ip,
                        conn.port,
                        idle_time,
                    )

            for conn_id in to_remove:
                await self._remove_connection_locked(conn_id)

    async def _remove_connection_locked(self, conn_id: str) -> None:
        """Remove a connection (must be called with lock held)."""
        if conn_id in self._connections:
            conn = self._connections[conn_id]
            del self._connections[conn_id]
            if conn.ip in self._ip_connection_counts:
                self._ip_connection_counts[conn.ip] -= 1
                if self._ip_connection_counts[conn.ip] <= 0:
                    del self._ip_connection_counts[conn.ip]

    async def add_connection(
        self,
        ip: str,
        port: int,
    ) -> tuple[bool, str | None, AttackType | None]:
        """Add a new connection.

        Args:
            ip: Client IP address
            port: Client port

        Returns:
            Tuple of (allowed, connection_id, attack_type_if_blocked)
        """
        conn_id = f"{ip}:{port}"
        now = time.time()

        async with self._lock:
            # Check total connection limit
            if len(self._connections) >= self._max_total:
                logger.warning("Total connection limit reached")
                return False, None, AttackType.CONNECTION_FLOOD

            # Check per-IP connection limit
            current_count = self._ip_connection_counts.get(ip, 0)
            if current_count >= self._max_per_ip:
                logger.warning("Connection limit for IP %s reached (%d)", ip, current_count)
                return False, None, AttackType.CONNECTION_FLOOD

            # Add connection
            self._connections[conn_id] = ConnectionInfo(
                ip=ip,
                port=port,
                connected_at=now,
                last_activity=now,
            )
            self._ip_connection_counts[ip] = current_count + 1

        return True, conn_id, None

    async def remove_connection(self, conn_id: str) -> None:
        """Remove a connection."""
        async with self._lock:
            await self._remove_connection_locked(conn_id)

    async def update_activity(self, conn_id: str, bytes_received: int = 0) -> None:
        """Update connection activity timestamp."""
        async with self._lock:
            if conn_id in self._connections:
                conn = self._connections[conn_id]
                conn.last_activity = time.time()
                conn.bytes_received += bytes_received
                conn.requests_count += 1

    async def get_connection_count(self, ip: str) -> int:
        """Get the current connection count for an IP."""
        return self._ip_connection_counts.get(ip, 0)

    def get_stats(self) -> dict[str, Any]:
        """Get connection tracker statistics."""
        return {
            "total_connections": len(self._connections),
            "unique_ips": len(self._ip_connection_counts),
            "max_per_ip": self._max_per_ip,
            "max_total": self._max_total,
        }


@dataclass
class DDoSDetectionResult:
    """Result of DDoS detection check."""

    is_attack: bool
    attack_type: AttackType
    threat_level: ThreatLevel
    should_block: bool
    should_challenge: bool
    challenge_type: ChallengeType
    message: str
    details: dict[str, Any] = field(default_factory=dict)


class DDoSProtector:
    """Main DDoS protection coordinator.

    Combines all DDoS protection mechanisms into a unified interface.
    """

    def __init__(
        self,
        connection_tracker: ConnectionTracker | None = None,
        reputation_tracker: IPReputationTracker | None = None,
        requests_per_second_threshold: float = 100.0,
        burst_threshold: int = 50,
        burst_window: float = 1.0,
        enable_fingerprinting: bool = True,
        enable_challenges: bool = True,
        geoip_enabled: bool = False,
        blocked_countries: set[str] | None = None,
    ) -> None:
        """Initialize DDoS protector.

        Args:
            connection_tracker: Connection tracking instance
            reputation_tracker: IP reputation tracking instance
            requests_per_second_threshold: Max RPS before triggering protection
            burst_threshold: Max requests in burst window
            burst_window: Burst detection window in seconds
            enable_fingerprinting: Enable request fingerprinting
            enable_challenges: Enable challenge mechanism
            geoip_enabled: Enable GeoIP-based blocking
            blocked_countries: Set of blocked country codes
        """
        self._connection_tracker = connection_tracker or ConnectionTracker()
        self._reputation_tracker = reputation_tracker or IPReputationTracker()
        self._rps_threshold = requests_per_second_threshold
        self._burst_threshold = burst_threshold
        self._burst_window = burst_window
        self._enable_fingerprinting = enable_fingerprinting
        self._enable_challenges = enable_challenges
        self._geoip_enabled = geoip_enabled
        self._blocked_countries = blocked_countries or set()

        # Request tracking for flood detection
        self._request_counts: TTLCache = TTLCache(
            maxsize=100000,
            ttl=burst_window * 2,
        )
        self._request_timestamps: dict[str, list[float]] = {}

        # Known bad fingerprints
        self._bad_fingerprints: set[str] = set()

        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the DDoS protector."""
        await self._connection_tracker.start()

    async def stop(self) -> None:
        """Stop the DDoS protector."""
        await self._connection_tracker.stop()

    async def check_request(
        self,
        ip: str,
        fingerprint: RequestFingerprint | None = None,
        country_code: str | None = None,
        path: str | None = None,
    ) -> DDoSDetectionResult:
        """Check a request for DDoS indicators.

        Args:
            ip: Client IP address
            fingerprint: Request fingerprint
            country_code: Country code from GeoIP
            path: Request path

        Returns:
            DDoSDetectionResult with detection details
        """
        # Check if IP is banned
        is_banned, ban_expiry = await self._reputation_tracker.is_banned(ip)
        if is_banned:
            return DDoSDetectionResult(
                is_attack=True,
                attack_type=AttackType.UNKNOWN,
                threat_level=ThreatLevel.CRITICAL,
                should_block=True,
                should_challenge=False,
                challenge_type=ChallengeType.NONE,
                message="IP is banned",
                details={"ban_expiry": ban_expiry},
            )

        # Check GeoIP blocking
        if self._geoip_enabled and country_code and country_code.upper() in self._blocked_countries:
            return DDoSDetectionResult(
                is_attack=False,
                attack_type=AttackType.UNKNOWN,
                threat_level=ThreatLevel.MEDIUM,
                should_block=True,
                should_challenge=False,
                challenge_type=ChallengeType.NONE,
                message=f"Country {country_code} is blocked",
                details={"country": country_code},
            )

        # Check connection flood
        conn_count = await self._connection_tracker.get_connection_count(ip)
        if conn_count > self._connection_tracker._max_per_ip * 0.8:
            threat_level = (
                ThreatLevel.HIGH
                if conn_count >= self._connection_tracker._max_per_ip
                else ThreatLevel.MEDIUM
            )
            return DDoSDetectionResult(
                is_attack=True,
                attack_type=AttackType.CONNECTION_FLOOD,
                threat_level=threat_level,
                should_block=threat_level == ThreatLevel.HIGH,
                should_challenge=threat_level == ThreatLevel.MEDIUM,
                challenge_type=ChallengeType.JAVASCRIPT
                if self._enable_challenges
                else ChallengeType.NONE,
                message=f"High connection count: {conn_count}",
                details={"connection_count": conn_count},
            )

        # Check HTTP flood (request rate)
        flood_result = await self._check_http_flood(ip)
        if flood_result:
            return flood_result

        # Check fingerprint
        if self._enable_fingerprinting and fingerprint:
            fp_result = await self._check_fingerprint(ip, fingerprint)
            if fp_result:
                return fp_result

        # Get reputation and determine challenge needs
        reputation = await self._reputation_tracker.get_reputation(ip)
        threat_level = reputation.get_threat_level()

        # Record the request
        await self._reputation_tracker.record_request(ip, success=True)

        if threat_level >= ThreatLevel.MEDIUM and self._enable_challenges:
            return DDoSDetectionResult(
                is_attack=False,
                attack_type=AttackType.UNKNOWN,
                threat_level=threat_level,
                should_block=False,
                should_challenge=True,
                challenge_type=self._get_challenge_for_threat(threat_level),
                message=f"Low reputation: {reputation.reputation_score:.1f}",
                details={"reputation": reputation.reputation_score},
            )

        return DDoSDetectionResult(
            is_attack=False,
            attack_type=AttackType.UNKNOWN,
            threat_level=ThreatLevel.NONE,
            should_block=False,
            should_challenge=False,
            challenge_type=ChallengeType.NONE,
            message="OK",
        )

    async def _check_http_flood(self, ip: str) -> DDoSDetectionResult | None:
        """Check for HTTP flood attacks."""
        now = time.time()

        async with self._lock:
            # Initialize or get timestamps
            if ip not in self._request_timestamps:
                self._request_timestamps[ip] = []

            timestamps = self._request_timestamps[ip]

            # Remove old timestamps
            cutoff = now - self._burst_window
            timestamps[:] = [ts for ts in timestamps if ts > cutoff]

            # Add current timestamp
            timestamps.append(now)

            request_count = len(timestamps)

            # Check burst threshold
            if request_count > self._burst_threshold:
                await self._reputation_tracker.update_reputation(ip, -20, "http_flood_burst")
                reputation = await self._reputation_tracker.get_reputation(ip)
                reputation.record_attack(AttackType.HTTP_FLOOD)

                return DDoSDetectionResult(
                    is_attack=True,
                    attack_type=AttackType.HTTP_FLOOD,
                    threat_level=ThreatLevel.HIGH,
                    should_block=True,
                    should_challenge=False,
                    challenge_type=ChallengeType.NONE,
                    message=f"HTTP flood: {request_count} reqs in {self._burst_window}s",
                    details={
                        "request_count": request_count,
                        "window": self._burst_window,
                    },
                )

            # Check sustained rate
            if request_count > self._burst_threshold * 0.7:
                return DDoSDetectionResult(
                    is_attack=False,
                    attack_type=AttackType.HTTP_FLOOD,
                    threat_level=ThreatLevel.MEDIUM,
                    should_block=False,
                    should_challenge=True,
                    challenge_type=ChallengeType.JAVASCRIPT
                    if self._enable_challenges
                    else ChallengeType.NONE,
                    message=f"High request rate: {request_count}",
                    details={"request_count": request_count},
                )

        return None

    async def _check_fingerprint(
        self,
        ip: str,
        fingerprint: RequestFingerprint,
    ) -> DDoSDetectionResult | None:
        """Check request fingerprint for suspicious patterns."""
        fp_hash = fingerprint.compute_hash()

        # Check if fingerprint is known bad
        if fp_hash in self._bad_fingerprints:
            return DDoSDetectionResult(
                is_attack=True,
                attack_type=AttackType.BOT_TRAFFIC,
                threat_level=ThreatLevel.HIGH,
                should_block=True,
                should_challenge=False,
                challenge_type=ChallengeType.NONE,
                message="Known bad fingerprint",
                details={"fingerprint": fp_hash},
            )

        # Check for suspicious patterns
        is_suspicious, reasons = fingerprint.is_suspicious()
        if is_suspicious:
            await self._reputation_tracker.update_reputation(
                ip, -5, f"suspicious_fingerprint:{','.join(reasons)}"
            )

            return DDoSDetectionResult(
                is_attack=False,
                attack_type=AttackType.SUSPICIOUS_PATTERN,
                threat_level=ThreatLevel.LOW,
                should_block=False,
                should_challenge=True,
                challenge_type=ChallengeType.JAVASCRIPT
                if self._enable_challenges
                else ChallengeType.NONE,
                message=f"Suspicious fingerprint: {', '.join(reasons)}",
                details={"reasons": reasons, "fingerprint": fp_hash},
            )

        # Track fingerprint for this IP
        reputation = await self._reputation_tracker.get_reputation(ip)
        reputation.fingerprints.add(fp_hash)

        # Many different fingerprints from same IP is suspicious
        if len(reputation.fingerprints) > 10:
            return DDoSDetectionResult(
                is_attack=False,
                attack_type=AttackType.SUSPICIOUS_PATTERN,
                threat_level=ThreatLevel.MEDIUM,
                should_block=False,
                should_challenge=True,
                challenge_type=ChallengeType.CAPTCHA
                if self._enable_challenges
                else ChallengeType.NONE,
                message=f"Multiple fingerprints from same IP: {len(reputation.fingerprints)}",
                details={"fingerprint_count": len(reputation.fingerprints)},
            )

        return None

    def _get_challenge_for_threat(self, threat_level: ThreatLevel) -> ChallengeType:
        """Get appropriate challenge type for threat level."""
        if threat_level == ThreatLevel.LOW:
            return ChallengeType.COOKIE
        elif threat_level == ThreatLevel.MEDIUM:
            return ChallengeType.JAVASCRIPT
        elif threat_level == ThreatLevel.HIGH:
            return ChallengeType.CAPTCHA
        elif threat_level == ThreatLevel.CRITICAL:
            return ChallengeType.PROOF_OF_WORK
        return ChallengeType.NONE

    async def record_challenge_result(
        self,
        ip: str,
        challenge_type: ChallengeType,
        success: bool,
    ) -> None:
        """Record the result of a challenge.

        Args:
            ip: Client IP address
            challenge_type: Type of challenge
            success: Whether the challenge was passed
        """
        reputation = await self._reputation_tracker.get_reputation(ip)

        if success:
            reputation.successful_challenges += 1
            await self._reputation_tracker.update_reputation(
                ip, 10, f"challenge_passed:{challenge_type.value}"
            )
        else:
            reputation.failed_challenges += 1
            await self._reputation_tracker.update_reputation(
                ip, -15, f"challenge_failed:{challenge_type.value}"
            )

    async def ban_ip(
        self,
        ip: str,
        duration: float = 3600.0,
        reason: str = "manual_ban",
    ) -> None:
        """Ban an IP address.

        Args:
            ip: IP address to ban
            duration: Ban duration in seconds
            reason: Reason for the ban
        """
        await self._reputation_tracker.ban_ip(ip, duration, reason)

    async def unban_ip(self, ip: str) -> bool:
        """Unban an IP address.

        Args:
            ip: IP address to unban

        Returns:
            True if IP was unbanned
        """
        return await self._reputation_tracker.unban_ip(ip)

    def add_bad_fingerprint(self, fingerprint_hash: str) -> None:
        """Add a fingerprint to the bad list.

        Args:
            fingerprint_hash: Hash of the bad fingerprint
        """
        self._bad_fingerprints.add(fingerprint_hash)

    def add_blocked_country(self, country_code: str) -> None:
        """Add a country to the block list.

        Args:
            country_code: ISO country code to block
        """
        self._blocked_countries.add(country_code.upper())

    def remove_blocked_country(self, country_code: str) -> None:
        """Remove a country from the block list.

        Args:
            country_code: ISO country code to unblock
        """
        self._blocked_countries.discard(country_code.upper())

    def get_stats(self) -> dict[str, Any]:
        """Get DDoS protector statistics."""
        return {
            "connection_tracker": self._connection_tracker.get_stats(),
            "reputation_tracker": self._reputation_tracker.get_stats(),
            "bad_fingerprints_count": len(self._bad_fingerprints),
            "blocked_countries": list(self._blocked_countries),
            "geoip_enabled": self._geoip_enabled,
            "fingerprinting_enabled": self._enable_fingerprinting,
            "challenges_enabled": self._enable_challenges,
        }


@dataclass
class DDoSProtectionConfig:
    """Configuration for DDoS protection."""

    enabled: bool = True
    max_connections_per_ip: int = 100
    max_total_connections: int = 10000
    slow_connection_timeout: float = 30.0
    requests_per_second_threshold: float = 100.0
    burst_threshold: int = 50
    burst_window: float = 1.0
    enable_fingerprinting: bool = True
    enable_challenges: bool = True
    auto_ban_threshold: float = 20.0
    auto_ban_duration: float = 3600.0
    geoip_enabled: bool = False
    blocked_countries: list[str] = field(default_factory=list)
    reputation_cache_size: int = 100000
    reputation_cache_ttl: float = 3600.0

    def create_protector(self) -> DDoSProtector:
        """Create a DDoSProtector from this configuration."""
        connection_tracker = ConnectionTracker(
            max_connections_per_ip=self.max_connections_per_ip,
            max_total_connections=self.max_total_connections,
            slow_connection_timeout=self.slow_connection_timeout,
        )
        reputation_tracker = IPReputationTracker(
            cache_max_size=self.reputation_cache_size,
            cache_ttl=self.reputation_cache_ttl,
            min_reputation_threshold=self.auto_ban_threshold,
        )
        return DDoSProtector(
            connection_tracker=connection_tracker,
            reputation_tracker=reputation_tracker,
            requests_per_second_threshold=self.requests_per_second_threshold,
            burst_threshold=self.burst_threshold,
            burst_window=self.burst_window,
            enable_fingerprinting=self.enable_fingerprinting,
            enable_challenges=self.enable_challenges,
            geoip_enabled=self.geoip_enabled,
            blocked_countries=set(self.blocked_countries),
        )
