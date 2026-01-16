"""Instanton Geographic Routing Module.

Provides IP geolocation-based routing and blocking using MaxMind
GeoIP2 databases for geographic request distribution.

Features:
- MaxMind GeoIP2/GeoLite2 database support
- Country, continent, and region-based routing
- Geo-blocking with allowlist/blocklist modes
- IP range caching for performance
- Graceful fallback when database unavailable

Usage:
    from instanton.routing.geo import GeoRouter, GeoBlocker, GeoIPDatabase

    # Load GeoIP database
    db = GeoIPDatabase()
    db.load("/path/to/GeoLite2-Country.mmdb")

    # Lookup location
    location = db.lookup("203.0.113.1")
    print(f"Country: {location.country_code}")

    # Create geo router
    router = GeoRouter(database=db)
    router.add_rule(GeoRoutingRule(
        countries=["US", "CA", "MX"],
        target_tunnel="north-america-tunnel",
        priority=100,
    ))

    # Route by IP
    result = router.route("203.0.113.1")
    if result.target_tunnel:
        forward_to(result.target_tunnel)

Requires:
    pip install geoip2>=4.8.0

Database download:
    MaxMind GeoLite2 databases are free but require registration:
    https://dev.maxmind.com/geoip/geoip2/geolite2/
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any


# Check for geoip2 availability
def is_geoip_available() -> bool:
    """Check if geoip2 library is available.

    Returns:
        True if geoip2 package is installed.
    """
    import importlib.util

    return importlib.util.find_spec("geoip2") is not None


class GeoAction(Enum):
    """Action to take based on geo-routing."""

    ALLOW = "allow"
    BLOCK = "block"
    ROUTE = "route"
    DEFAULT = "default"


@dataclass
class GeoLocation:
    """Geographic location information from IP lookup."""

    ip_address: str
    """The IP address that was looked up."""

    country_code: str | None = None
    """ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB')."""

    country_name: str | None = None
    """Full country name."""

    continent_code: str | None = None
    """Continent code (AF, AN, AS, EU, NA, OC, SA)."""

    continent_name: str | None = None
    """Full continent name."""

    region_code: str | None = None
    """Region/subdivision code (e.g., 'CA' for California)."""

    region_name: str | None = None
    """Region/subdivision name."""

    city: str | None = None
    """City name."""

    postal_code: str | None = None
    """Postal/ZIP code."""

    latitude: float | None = None
    """Latitude coordinate."""

    longitude: float | None = None
    """Longitude coordinate."""

    time_zone: str | None = None
    """Time zone identifier (e.g., 'America/Los_Angeles')."""

    is_anonymous_proxy: bool = False
    """Whether IP is an anonymous proxy."""

    is_satellite_provider: bool = False
    """Whether IP is a satellite provider."""

    accuracy_radius: int | None = None
    """Accuracy radius in kilometers."""

    @property
    def is_valid(self) -> bool:
        """Check if location has meaningful data."""
        return self.country_code is not None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ip_address": self.ip_address,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "continent_code": self.continent_code,
            "continent_name": self.continent_name,
            "region_code": self.region_code,
            "region_name": self.region_name,
            "city": self.city,
            "postal_code": self.postal_code,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "time_zone": self.time_zone,
            "is_anonymous_proxy": self.is_anonymous_proxy,
            "is_satellite_provider": self.is_satellite_provider,
            "accuracy_radius": self.accuracy_radius,
        }


class GeoIPDatabase:
    """MaxMind GeoIP database wrapper.

    Supports GeoLite2-Country, GeoLite2-City, and commercial databases.
    """

    def __init__(self) -> None:
        """Initialize the database wrapper."""
        self._reader = None
        self._database_type: str | None = None
        self._database_path: str | None = None

    def load(self, path: str) -> None:
        """Load a MaxMind database file.

        Args:
            path: Path to .mmdb database file.

        Raises:
            ImportError: If geoip2 package is not installed.
            FileNotFoundError: If database file doesn't exist.
        """
        if not is_geoip_available():
            raise ImportError(
                "GeoIP routing requires 'geoip2' package. "
                "Install with: pip install geoip2"
            )

        if not os.path.exists(path):
            raise FileNotFoundError(f"Database not found: {path}")

        import geoip2.database

        self._reader = geoip2.database.Reader(path)
        self._database_path = path

        # Detect database type
        metadata = self._reader.metadata()
        self._database_type = metadata.database_type

    def close(self) -> None:
        """Close the database."""
        if self._reader:
            self._reader.close()
            self._reader = None

    @property
    def is_loaded(self) -> bool:
        """Check if database is loaded."""
        return self._reader is not None

    @property
    def database_type(self) -> str | None:
        """Get the database type."""
        return self._database_type

    @lru_cache(maxsize=10000)
    def lookup(self, ip: str) -> GeoLocation:
        """Look up geographic location for an IP address.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            GeoLocation with available data.
        """
        # Return empty location if database not loaded
        if not self._reader:
            return GeoLocation(ip_address=ip)

        # Check for private/reserved IPs
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                return GeoLocation(ip_address=ip)
        except ValueError:
            return GeoLocation(ip_address=ip)

        try:
            # Try city database first (has all data)
            if "City" in (self._database_type or ""):
                response = self._reader.city(ip)
                return GeoLocation(
                    ip_address=ip,
                    country_code=response.country.iso_code,
                    country_name=response.country.name,
                    continent_code=response.continent.code,
                    continent_name=response.continent.name,
                    region_code=(
                        response.subdivisions.most_specific.iso_code
                        if response.subdivisions
                        else None
                    ),
                    region_name=(
                        response.subdivisions.most_specific.name
                        if response.subdivisions
                        else None
                    ),
                    city=response.city.name if response.city else None,
                    postal_code=(
                        response.postal.code if response.postal else None
                    ),
                    latitude=response.location.latitude,
                    longitude=response.location.longitude,
                    time_zone=response.location.time_zone,
                    accuracy_radius=response.location.accuracy_radius,
                )
            else:
                # Country-only database
                response = self._reader.country(ip)
                return GeoLocation(
                    ip_address=ip,
                    country_code=response.country.iso_code,
                    country_name=response.country.name,
                    continent_code=response.continent.code,
                    continent_name=response.continent.name,
                )

        except Exception:
            # IP not found in database
            return GeoLocation(ip_address=ip)

    def clear_cache(self) -> None:
        """Clear the lookup cache."""
        self.lookup.cache_clear()


@dataclass
class GeoRoutingRule:
    """Rule for geographic routing."""

    name: str = ""
    """Rule name for identification."""

    target_tunnel: str | None = None
    """Tunnel to route to when rule matches."""

    countries: list[str] = field(default_factory=list)
    """Country codes to match (ISO 3166-1 alpha-2)."""

    continents: list[str] = field(default_factory=list)
    """Continent codes to match (AF, AN, AS, EU, NA, OC, SA)."""

    regions: list[str] = field(default_factory=list)
    """Region/subdivision codes to match."""

    exclude_countries: list[str] = field(default_factory=list)
    """Countries to exclude from match."""

    action: GeoAction = GeoAction.ROUTE
    """Action to take when rule matches."""

    priority: int = 0
    """Rule priority (higher evaluated first)."""

    enabled: bool = True
    """Whether rule is active."""

    def matches(self, location: GeoLocation) -> bool:
        """Check if location matches this rule.

        Args:
            location: GeoLocation to check.

        Returns:
            True if location matches rule criteria.
        """
        if not self.enabled:
            return False

        if not location.is_valid:
            return False

        # Check exclusions first
        if location.country_code in self.exclude_countries:
            return False

        # Check country match
        if self.countries:
            if location.country_code not in self.countries:
                return False

        # Check continent match
        if self.continents:
            if location.continent_code not in self.continents:
                return False

        # Check region match
        if self.regions:
            if location.region_code not in self.regions:
                return False

        # If we have any filter criteria and got here, it's a match
        return bool(self.countries or self.continents or self.regions)


@dataclass
class GeoRoutingResult:
    """Result of geo-routing evaluation."""

    action: GeoAction
    """Recommended action."""

    target_tunnel: str | None = None
    """Tunnel to route to (if action is ROUTE)."""

    matched_rule: GeoRoutingRule | None = None
    """Rule that matched (if any)."""

    location: GeoLocation | None = None
    """Looked up location."""

    error: str | None = None
    """Error message if lookup failed."""


class GeoRouter:
    """Geographic IP-based router.

    Routes requests to different tunnels based on client IP geolocation.
    """

    def __init__(
        self,
        database: GeoIPDatabase | None = None,
        *,
        default_tunnel: str | None = None,
    ) -> None:
        """Initialize the geo router.

        Args:
            database: GeoIP database instance.
            default_tunnel: Default tunnel when no rules match.
        """
        self.database = database or GeoIPDatabase()
        self.default_tunnel = default_tunnel
        self._rules: list[GeoRoutingRule] = []

    def add_rule(self, rule: GeoRoutingRule) -> None:
        """Add a routing rule.

        Args:
            rule: GeoRoutingRule to add.
        """
        self._rules.append(rule)
        # Keep rules sorted by priority (descending)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, name: str) -> bool:
        """Remove a rule by name.

        Args:
            name: Rule name to remove.

        Returns:
            True if rule was removed.
        """
        for i, rule in enumerate(self._rules):
            if rule.name == name:
                self._rules.pop(i)
                return True
        return False

    def route(self, ip: str) -> GeoRoutingResult:
        """Route a request based on IP geolocation.

        Args:
            ip: Client IP address.

        Returns:
            GeoRoutingResult with routing decision.
        """
        # Lookup location
        location = self.database.lookup(ip)

        if not location.is_valid:
            return GeoRoutingResult(
                action=GeoAction.DEFAULT,
                target_tunnel=self.default_tunnel,
                location=location,
            )

        # Evaluate rules in priority order
        for rule in self._rules:
            if rule.matches(location):
                return GeoRoutingResult(
                    action=rule.action,
                    target_tunnel=rule.target_tunnel,
                    matched_rule=rule,
                    location=location,
                )

        # No rule matched, use default
        return GeoRoutingResult(
            action=GeoAction.DEFAULT,
            target_tunnel=self.default_tunnel,
            location=location,
        )

    def clear_rules(self) -> None:
        """Remove all rules."""
        self._rules.clear()


class GeoBlocker:
    """Geographic IP-based request blocker.

    Blocks or allows requests based on client IP geolocation.
    Supports both allowlist and blocklist modes.
    """

    def __init__(
        self,
        database: GeoIPDatabase | None = None,
        *,
        mode: str = "blocklist",
    ) -> None:
        """Initialize the geo blocker.

        Args:
            database: GeoIP database instance.
            mode: 'blocklist' (block specified) or 'allowlist' (allow only specified).
        """
        self.database = database or GeoIPDatabase()
        self.mode = mode.lower()
        self._countries: set[str] = set()
        self._continents: set[str] = set()

    def block_country(self, country_code: str) -> None:
        """Add a country to block/allow list.

        In blocklist mode: blocks the country.
        In allowlist mode: allows the country.

        Args:
            country_code: ISO 3166-1 alpha-2 country code.
        """
        self._countries.add(country_code.upper())

    def unblock_country(self, country_code: str) -> None:
        """Remove a country from block/allow list.

        Args:
            country_code: ISO 3166-1 alpha-2 country code.
        """
        self._countries.discard(country_code.upper())

    def block_continent(self, continent_code: str) -> None:
        """Add a continent to block/allow list.

        Args:
            continent_code: Continent code (AF, AN, AS, EU, NA, OC, SA).
        """
        self._continents.add(continent_code.upper())

    def unblock_continent(self, continent_code: str) -> None:
        """Remove a continent from block/allow list.

        Args:
            continent_code: Continent code.
        """
        self._continents.discard(continent_code.upper())

    def is_blocked(self, ip: str) -> tuple[bool, GeoLocation]:
        """Check if an IP is blocked.

        Args:
            ip: Client IP address.

        Returns:
            Tuple of (is_blocked, location).
        """
        location = self.database.lookup(ip)

        # Can't make decision without location data
        if not location.is_valid:
            # In blocklist mode, allow unknown; in allowlist mode, block unknown
            return (self.mode == "allowlist", location)

        in_list = (
            location.country_code in self._countries
            or location.continent_code in self._continents
        )

        if self.mode == "blocklist":
            # Block if in blocklist
            return (in_list, location)
        else:
            # Block if NOT in allowlist
            return (not in_list, location)

    def clear(self) -> None:
        """Clear all block/allow entries."""
        self._countries.clear()
        self._continents.clear()

    @property
    def blocked_countries(self) -> set[str]:
        """Get set of blocked/allowed countries."""
        return self._countries.copy()

    @property
    def blocked_continents(self) -> set[str]:
        """Get set of blocked/allowed continents."""
        return self._continents.copy()


# Continent codes for reference
CONTINENTS = {
    "AF": "Africa",
    "AN": "Antarctica",
    "AS": "Asia",
    "EU": "Europe",
    "NA": "North America",
    "OC": "Oceania",
    "SA": "South America",
}

# Common country code groups
EU_COUNTRIES = {
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
    "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
    "NL", "PL", "PT", "RO", "SE", "SI", "SK",
}

FIVE_EYES = {"US", "GB", "CA", "AU", "NZ"}

FOURTEEN_EYES = FIVE_EYES | {
    "DE", "FR", "DK", "NL", "NO", "BE", "IT", "SE", "ES",
}
