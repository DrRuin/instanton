"""Tests for DDoS protection functionality."""

import asyncio

import pytest

from instanton.security.ddos import (
    AttackType,
    ChallengeType,
    ConnectionTracker,
    DDoSDetectionResult,
    DDoSProtectionConfig,
    DDoSProtector,
    IPReputation,
    IPReputationTracker,
    RequestFingerprint,
    ThreatLevel,
)


class TestRequestFingerprint:
    """Tests for RequestFingerprint."""

    def test_compute_hash(self) -> None:
        """Test fingerprint hash computation."""
        fingerprint = RequestFingerprint(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            accept_language="en-US,en;q=0.9",
            accept_encoding="gzip, deflate, br",
            accept="text/html",
        )

        hash1 = fingerprint.compute_hash()
        assert len(hash1) == 16
        assert hash1.isalnum()

        # Same fingerprint should produce same hash
        hash2 = fingerprint.compute_hash()
        assert hash1 == hash2

    def test_different_fingerprints_different_hash(self) -> None:
        """Test that different fingerprints produce different hashes."""
        fp1 = RequestFingerprint(user_agent="Mozilla/5.0")
        fp2 = RequestFingerprint(user_agent="Chrome/100.0")

        assert fp1.compute_hash() != fp2.compute_hash()

    def test_is_suspicious_missing_user_agent(self) -> None:
        """Test detection of missing user agent."""
        fingerprint = RequestFingerprint(user_agent="")
        is_suspicious, reasons = fingerprint.is_suspicious()

        assert is_suspicious is True
        assert "missing_user_agent" in reasons

    def test_is_suspicious_bot_user_agent(self) -> None:
        """Test detection of bot user agents."""
        bot_agents = [
            "python-requests/2.28.0",
            "curl/7.81.0",
            "Wget/1.21.2",
            "Go-http-client/1.1",
        ]

        for ua in bot_agents:
            fingerprint = RequestFingerprint(user_agent=ua)
            is_suspicious, reasons = fingerprint.is_suspicious()

            assert is_suspicious is True, f"Should detect {ua} as suspicious"
            assert any("bot_user_agent" in r for r in reasons)

    def test_is_suspicious_legitimate_browser(self) -> None:
        """Test that legitimate browsers are not flagged."""
        fingerprint = RequestFingerprint(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            accept_language="en-US,en;q=0.9",
            accept_encoding="gzip, deflate, br",
        )

        is_suspicious, reasons = fingerprint.is_suspicious()
        # Should not flag as bot
        assert not any("bot_user_agent" in r for r in reasons)


class TestIPReputation:
    """Tests for IPReputation."""

    def test_initial_reputation(self) -> None:
        """Test initial reputation values."""
        rep = IPReputation(ip="192.168.1.1")

        assert rep.ip == "192.168.1.1"
        assert rep.reputation_score == 100.0
        assert rep.is_banned is False
        assert rep.total_requests == 0

    def test_update_reputation_positive(self) -> None:
        """Test positive reputation adjustment."""
        rep = IPReputation(ip="192.168.1.1", reputation_score=50.0)

        rep.update_reputation(10, "good_behavior")
        assert rep.reputation_score == 60.0

    def test_update_reputation_negative(self) -> None:
        """Test negative reputation adjustment."""
        rep = IPReputation(ip="192.168.1.1", reputation_score=50.0)

        rep.update_reputation(-20, "bad_behavior")
        assert rep.reputation_score == 30.0

    def test_reputation_bounds(self) -> None:
        """Test that reputation stays within bounds."""
        rep = IPReputation(ip="192.168.1.1", reputation_score=95.0)

        # Should not exceed 100
        rep.update_reputation(20, "test")
        assert rep.reputation_score == 100.0

        # Should not go below 0
        rep.reputation_score = 5.0
        rep.update_reputation(-20, "test")
        assert rep.reputation_score == 0.0

    def test_record_attack(self) -> None:
        """Test recording an attack."""
        rep = IPReputation(ip="192.168.1.1")
        initial_score = rep.reputation_score

        rep.record_attack(AttackType.HTTP_FLOOD)

        assert rep.reputation_score < initial_score
        assert "http_flood" in rep.attack_detections
        assert rep.attack_detections["http_flood"] == 1

    def test_get_threat_level(self) -> None:
        """Test threat level calculation."""
        rep = IPReputation(ip="192.168.1.1")

        rep.reputation_score = 90
        assert rep.get_threat_level() == ThreatLevel.NONE

        rep.reputation_score = 70
        assert rep.get_threat_level() == ThreatLevel.LOW

        rep.reputation_score = 50
        assert rep.get_threat_level() == ThreatLevel.MEDIUM

        rep.reputation_score = 30
        assert rep.get_threat_level() == ThreatLevel.HIGH

        rep.reputation_score = 10
        assert rep.get_threat_level() == ThreatLevel.CRITICAL


class TestIPReputationTracker:
    """Tests for IPReputationTracker."""

    @pytest.mark.asyncio
    async def test_get_reputation_new_ip(self) -> None:
        """Test getting reputation for a new IP."""
        tracker = IPReputationTracker()

        rep = await tracker.get_reputation("192.168.1.1")

        assert rep.ip == "192.168.1.1"
        assert rep.reputation_score == 100.0

    @pytest.mark.asyncio
    async def test_get_reputation_existing_ip(self) -> None:
        """Test getting reputation for an existing IP."""
        tracker = IPReputationTracker()

        rep1 = await tracker.get_reputation("192.168.1.1")
        rep1.total_requests = 100

        rep2 = await tracker.get_reputation("192.168.1.1")

        assert rep2.total_requests == 100  # Same object

    @pytest.mark.asyncio
    async def test_update_reputation(self) -> None:
        """Test updating reputation."""
        tracker = IPReputationTracker()

        rep = await tracker.update_reputation("192.168.1.1", -30, "test")

        assert rep.reputation_score == 70.0

    @pytest.mark.asyncio
    async def test_auto_ban(self) -> None:
        """Test automatic banning on low reputation."""
        tracker = IPReputationTracker(min_reputation_threshold=20.0)

        # Lower reputation below threshold
        await tracker.update_reputation("192.168.1.1", -90, "test")

        is_banned, expiry = await tracker.is_banned("192.168.1.1")
        assert is_banned is True
        assert expiry is not None

    @pytest.mark.asyncio
    async def test_manual_ban(self) -> None:
        """Test manual banning."""
        tracker = IPReputationTracker()

        await tracker.ban_ip("192.168.1.1", duration=3600, reason="test_ban")

        is_banned, _ = await tracker.is_banned("192.168.1.1")
        assert is_banned is True

    @pytest.mark.asyncio
    async def test_unban(self) -> None:
        """Test unbanning an IP."""
        tracker = IPReputationTracker()

        await tracker.ban_ip("192.168.1.1", duration=3600, reason="test")

        is_banned, _ = await tracker.is_banned("192.168.1.1")
        assert is_banned is True

        result = await tracker.unban_ip("192.168.1.1")
        assert result is True

        is_banned, _ = await tracker.is_banned("192.168.1.1")
        assert is_banned is False

    @pytest.mark.asyncio
    async def test_record_request(self) -> None:
        """Test recording requests."""
        tracker = IPReputationTracker()

        await tracker.record_request("192.168.1.1", success=True)
        await tracker.record_request("192.168.1.1", success=True)

        rep = await tracker.get_reputation("192.168.1.1")
        assert rep.total_requests == 2

    @pytest.mark.asyncio
    async def test_stats(self) -> None:
        """Test getting tracker statistics."""
        tracker = IPReputationTracker()

        await tracker.get_reputation("192.168.1.1")
        await tracker.get_reputation("192.168.1.2")
        await tracker.ban_ip("192.168.1.3", 3600, "test")

        stats = tracker.get_stats()
        assert stats["tracked_ips"] >= 2
        assert stats["banned_ips"] >= 1


class TestConnectionTracker:
    """Tests for ConnectionTracker."""

    @pytest.mark.asyncio
    async def test_add_connection(self) -> None:
        """Test adding a connection."""
        tracker = ConnectionTracker(max_connections_per_ip=10)

        allowed, conn_id, attack_type = await tracker.add_connection("192.168.1.1", 12345)

        assert allowed is True
        assert conn_id == "192.168.1.1:12345"
        assert attack_type is None

    @pytest.mark.asyncio
    async def test_per_ip_limit(self) -> None:
        """Test per-IP connection limit."""
        tracker = ConnectionTracker(max_connections_per_ip=3)

        # Add 3 connections (should succeed)
        for port in range(3):
            allowed, _, _ = await tracker.add_connection("192.168.1.1", port)
            assert allowed is True

        # 4th connection should fail
        allowed, _, attack_type = await tracker.add_connection("192.168.1.1", 999)

        assert allowed is False
        assert attack_type == AttackType.CONNECTION_FLOOD

    @pytest.mark.asyncio
    async def test_total_connection_limit(self) -> None:
        """Test total connection limit."""
        tracker = ConnectionTracker(
            max_connections_per_ip=100,
            max_total_connections=5,
        )

        # Add connections from different IPs
        for i in range(5):
            allowed, _, _ = await tracker.add_connection(f"192.168.1.{i}", 12345)
            assert allowed is True

        # Total limit reached
        allowed, _, attack_type = await tracker.add_connection("192.168.1.100", 12345)

        assert allowed is False
        assert attack_type == AttackType.CONNECTION_FLOOD

    @pytest.mark.asyncio
    async def test_remove_connection(self) -> None:
        """Test removing a connection."""
        tracker = ConnectionTracker(max_connections_per_ip=2)

        # Add connections
        await tracker.add_connection("192.168.1.1", 12345)
        await tracker.add_connection("192.168.1.1", 12346)

        # Remove one
        await tracker.remove_connection("192.168.1.1:12345")

        # Should now allow a new connection
        allowed, _, _ = await tracker.add_connection("192.168.1.1", 12347)
        assert allowed is True

    @pytest.mark.asyncio
    async def test_get_connection_count(self) -> None:
        """Test getting connection count for an IP."""
        tracker = ConnectionTracker()

        await tracker.add_connection("192.168.1.1", 12345)
        await tracker.add_connection("192.168.1.1", 12346)

        count = await tracker.get_connection_count("192.168.1.1")
        assert count == 2

    @pytest.mark.asyncio
    async def test_stats(self) -> None:
        """Test getting connection tracker statistics."""
        tracker = ConnectionTracker()

        await tracker.add_connection("192.168.1.1", 12345)
        await tracker.add_connection("192.168.1.2", 12345)

        stats = tracker.get_stats()
        assert stats["total_connections"] == 2
        assert stats["unique_ips"] == 2


class TestDDoSProtector:
    """Tests for DDoSProtector."""

    @pytest.mark.asyncio
    async def test_basic_check_allowed(self) -> None:
        """Test basic request check that should be allowed."""
        protector = DDoSProtector(
            requests_per_second_threshold=100,
            burst_threshold=50,
            enable_fingerprinting=False,
            enable_challenges=False,
        )

        result = await protector.check_request(ip="192.168.1.1")

        assert result.is_attack is False
        assert result.should_block is False
        assert result.message == "OK"

    @pytest.mark.asyncio
    async def test_banned_ip_blocked(self) -> None:
        """Test that banned IPs are blocked."""
        protector = DDoSProtector()

        await protector.ban_ip("192.168.1.1", duration=3600, reason="test")

        result = await protector.check_request(ip="192.168.1.1")

        assert result.is_attack is True
        assert result.should_block is True
        assert result.threat_level == ThreatLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_http_flood_detection(self) -> None:
        """Test HTTP flood detection."""
        protector = DDoSProtector(
            burst_threshold=5,
            burst_window=1.0,
            enable_fingerprinting=False,
            enable_challenges=False,
        )

        # Send many requests quickly
        for _ in range(6):
            result = await protector.check_request(ip="192.168.1.1")

        # Should detect flood
        assert result.is_attack is True
        assert result.attack_type == AttackType.HTTP_FLOOD
        assert result.should_block is True

    @pytest.mark.asyncio
    async def test_suspicious_fingerprint(self) -> None:
        """Test suspicious fingerprint detection."""
        protector = DDoSProtector(
            enable_fingerprinting=True,
            enable_challenges=True,
        )

        fingerprint = RequestFingerprint(
            user_agent="python-requests/2.28.0",
        )

        result = await protector.check_request(
            ip="192.168.1.1",
            fingerprint=fingerprint,
        )

        # Should flag as suspicious (bot user agent)
        assert result.attack_type in (AttackType.SUSPICIOUS_PATTERN, AttackType.BOT_TRAFFIC)
        assert result.should_challenge is True or result.should_block is True

    @pytest.mark.asyncio
    async def test_geoip_blocking(self) -> None:
        """Test GeoIP-based blocking."""
        protector = DDoSProtector(
            geoip_enabled=True,
            blocked_countries={"CN", "RU"},
        )

        result = await protector.check_request(
            ip="192.168.1.1",
            country_code="CN",
        )

        assert result.should_block is True
        assert "blocked" in result.message.lower()

    @pytest.mark.asyncio
    async def test_challenge_for_low_reputation(self) -> None:
        """Test challenge mechanism for low reputation."""
        protector = DDoSProtector(
            enable_challenges=True,
        )

        # Lower the reputation
        await protector._reputation_tracker.update_reputation(
            "192.168.1.1", -50, "test"
        )

        result = await protector.check_request(ip="192.168.1.1")

        # Should challenge, not block
        assert result.should_block is False
        assert result.should_challenge is True
        assert result.challenge_type != ChallengeType.NONE

    @pytest.mark.asyncio
    async def test_record_challenge_result_success(self) -> None:
        """Test recording successful challenge."""
        protector = DDoSProtector()

        # Lower reputation first
        await protector._reputation_tracker.update_reputation(
            "192.168.1.1", -30, "test"
        )
        rep_info = await protector._reputation_tracker.get_reputation("192.168.1.1")
        initial_rep = rep_info.reputation_score

        await protector.record_challenge_result(
            ip="192.168.1.1",
            challenge_type=ChallengeType.JAVASCRIPT,
            success=True,
        )

        rep_info = await protector._reputation_tracker.get_reputation("192.168.1.1")
        final_rep = rep_info.reputation_score
        assert final_rep > initial_rep

    @pytest.mark.asyncio
    async def test_record_challenge_result_failure(self) -> None:
        """Test recording failed challenge."""
        protector = DDoSProtector()

        rep_info = await protector._reputation_tracker.get_reputation("192.168.1.1")
        initial_rep = rep_info.reputation_score

        await protector.record_challenge_result(
            ip="192.168.1.1",
            challenge_type=ChallengeType.JAVASCRIPT,
            success=False,
        )

        rep_info = await protector._reputation_tracker.get_reputation("192.168.1.1")
        final_rep = rep_info.reputation_score
        assert final_rep < initial_rep

    @pytest.mark.asyncio
    async def test_unban_ip(self) -> None:
        """Test unbanning an IP."""
        protector = DDoSProtector()

        await protector.ban_ip("192.168.1.1", duration=3600)

        result = await protector.check_request(ip="192.168.1.1")
        assert result.should_block is True

        await protector.unban_ip("192.168.1.1")

        result = await protector.check_request(ip="192.168.1.1")
        assert result.should_block is False

    @pytest.mark.asyncio
    async def test_add_bad_fingerprint(self) -> None:
        """Test adding a bad fingerprint."""
        protector = DDoSProtector(enable_fingerprinting=True)

        fp = RequestFingerprint(user_agent="Normal Browser")
        fp_hash = fp.compute_hash()

        # Initially should be OK
        result = await protector.check_request(
            ip="192.168.1.1",
            fingerprint=fp,
        )
        assert result.attack_type != AttackType.BOT_TRAFFIC

        # Add to bad list
        protector.add_bad_fingerprint(fp_hash)

        # Now should be blocked
        result = await protector.check_request(
            ip="192.168.1.2",
            fingerprint=fp,
        )
        assert result.should_block is True
        assert result.attack_type == AttackType.BOT_TRAFFIC

    @pytest.mark.asyncio
    async def test_add_remove_blocked_country(self) -> None:
        """Test adding and removing blocked countries."""
        protector = DDoSProtector(geoip_enabled=True)

        protector.add_blocked_country("XX")

        result = await protector.check_request(
            ip="192.168.1.1",
            country_code="XX",
        )
        assert result.should_block is True

        protector.remove_blocked_country("XX")

        result = await protector.check_request(
            ip="192.168.1.1",
            country_code="XX",
        )
        assert result.should_block is False

    @pytest.mark.asyncio
    async def test_stats(self) -> None:
        """Test getting DDoS protector statistics."""
        protector = DDoSProtector()

        await protector.check_request(ip="192.168.1.1")

        stats = protector.get_stats()

        assert "connection_tracker" in stats
        assert "reputation_tracker" in stats
        assert "bad_fingerprints_count" in stats
        assert "geoip_enabled" in stats


class TestDDoSProtectionConfig:
    """Tests for DDoSProtectionConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = DDoSProtectionConfig()

        assert config.enabled is True
        assert config.max_connections_per_ip == 100
        assert config.burst_threshold == 50
        assert config.enable_fingerprinting is True
        assert config.enable_challenges is True

    def test_create_protector(self) -> None:
        """Test creating a protector from config."""
        config = DDoSProtectionConfig(
            max_connections_per_ip=50,
            burst_threshold=20,
            blocked_countries=["XX", "YY"],
        )

        protector = config.create_protector()

        assert isinstance(protector, DDoSProtector)
        assert "XX" in protector._blocked_countries
        assert "YY" in protector._blocked_countries


class TestConcurrency:
    """Tests for concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_checks(self) -> None:
        """Test concurrent DDoS checks."""
        protector = DDoSProtector(
            burst_threshold=100,
            enable_fingerprinting=False,
        )

        async def check_task(ip: str) -> DDoSDetectionResult:
            return await protector.check_request(ip=ip)

        # Run many concurrent checks
        results = await asyncio.gather(*[
            check_task(f"192.168.1.{i % 10}") for i in range(50)
        ])

        # Most should succeed
        allowed_count = sum(1 for r in results if not r.should_block)
        assert allowed_count > 0

    @pytest.mark.asyncio
    async def test_concurrent_reputation_updates(self) -> None:
        """Test concurrent reputation updates."""
        tracker = IPReputationTracker()

        async def update_task(adjustment: float) -> IPReputation:
            return await tracker.update_reputation("192.168.1.1", adjustment, "test")

        # Concurrent positive and negative updates
        await asyncio.gather(*[
            update_task(1 if i % 2 == 0 else -1) for i in range(20)
        ])

        # Should not crash and reputation should be valid
        rep = await tracker.get_reputation("192.168.1.1")
        assert 0 <= rep.reputation_score <= 100


class TestMultipleFingerprints:
    """Tests for multiple fingerprints from same IP."""

    @pytest.mark.asyncio
    async def test_many_fingerprints_suspicious(self) -> None:
        """Test that many different fingerprints from same IP is suspicious."""
        protector = DDoSProtector(
            enable_fingerprinting=True,
            enable_challenges=True,
        )

        # Send requests with many different fingerprints
        for i in range(15):
            fingerprint = RequestFingerprint(
                user_agent=f"Browser/1.{i}",
                accept_language="en-US",
            )
            result = await protector.check_request(
                ip="192.168.1.1",
                fingerprint=fingerprint,
            )

        # After many fingerprints, should be challenged
        assert result.should_challenge is True or result.threat_level >= ThreatLevel.MEDIUM
