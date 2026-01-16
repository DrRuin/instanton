"""Instanton Routing Module.

Provides advanced routing capabilities including geographic routing
and blocking based on IP geolocation.

Features:
- GeoIP lookup using MaxMind databases
- Country/region-based routing rules
- Geo-blocking (allowlist/blocklist modes)
- Continent and region matching
- Distance-based routing

Usage:
    from instanton.routing import GeoRouter, GeoBlocker

    # Create geo router
    router = GeoRouter()
    router.add_rule(GeoRoutingRule(
        countries=["US", "CA"],
        target_tunnel="us-tunnel",
    ))

    # Route request
    result = router.route("203.0.113.1")

    # Or use geo-blocker
    blocker = GeoBlocker(mode="blocklist")
    blocker.block_country("CN")
    blocker.block_country("RU")

    is_blocked, location = blocker.is_blocked("203.0.113.1")

Requires:
    pip install geoip2>=4.8.0
"""

from instanton.routing.geo import (
    GeoAction,
    GeoBlocker,
    GeoIPDatabase,
    GeoLocation,
    GeoRouter,
    GeoRoutingResult,
    GeoRoutingRule,
    is_geoip_available,
)

__all__ = [
    "GeoAction",
    "GeoBlocker",
    "GeoIPDatabase",
    "GeoLocation",
    "GeoRouter",
    "GeoRoutingResult",
    "GeoRoutingRule",
    "is_geoip_available",
]
