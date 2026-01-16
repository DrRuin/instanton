"""Instanton Wildcard Domain Pattern Matching.

Provides utilities for matching wildcard domain patterns (e.g., *.example.com)
against actual hostnames for flexible domain routing.

Wildcard domains allow a single registration to match multiple subdomains:
    - *.example.com matches: api.example.com, www.example.com, test.example.com
    - *.example.com does NOT match: deep.api.example.com (no nested wildcards)
    - *.example.com does NOT match: example.com (wildcard requires a subdomain)
"""

from __future__ import annotations

import re
from functools import lru_cache


def is_wildcard_pattern(domain: str) -> bool:
    """Check if a domain string is a wildcard pattern.

    A wildcard pattern starts with "*." to indicate it matches
    any single subdomain level.

    Args:
        domain: Domain string to check.

    Returns:
        True if domain is a wildcard pattern like *.example.com.

    Examples:
        >>> is_wildcard_pattern("*.example.com")
        True
        >>> is_wildcard_pattern("api.example.com")
        False
        >>> is_wildcard_pattern("example.com")
        False
    """
    return domain.startswith("*.")


def get_base_domain(wildcard_pattern: str) -> str:
    """Extract the base domain from a wildcard pattern.

    Args:
        wildcard_pattern: Wildcard pattern like *.example.com.

    Returns:
        Base domain without the wildcard prefix (example.com).

    Raises:
        ValueError: If pattern is not a valid wildcard.

    Examples:
        >>> get_base_domain("*.example.com")
        'example.com'
        >>> get_base_domain("*.api.example.com")
        'api.example.com'
    """
    if not is_wildcard_pattern(wildcard_pattern):
        raise ValueError(f"Not a wildcard pattern: {wildcard_pattern}")
    return wildcard_pattern[2:]  # Remove "*."


@lru_cache(maxsize=1000)
def _compile_wildcard_regex(pattern: str) -> re.Pattern[str]:
    """Compile a wildcard pattern to a regex (cached).

    Converts *.example.com to ^[^.]+\\.example\\.com$

    Args:
        pattern: Wildcard pattern to compile.

    Returns:
        Compiled regex pattern.
    """
    # Escape the pattern for regex
    escaped = re.escape(pattern)
    # Replace \* with [^.]+ to match exactly one subdomain level
    regex_pattern = escaped.replace(r"\*", r"[^.]+")
    return re.compile(f"^{regex_pattern}$", re.IGNORECASE)


def match_wildcard(host: str, pattern: str) -> bool:
    """Check if a hostname matches a wildcard pattern.

    Only matches single-level wildcards (no deep nesting).

    Args:
        host: Actual hostname to check (e.g., api.example.com).
        pattern: Wildcard pattern (e.g., *.example.com).

    Returns:
        True if host matches the wildcard pattern.

    Examples:
        >>> match_wildcard("api.example.com", "*.example.com")
        True
        >>> match_wildcard("www.example.com", "*.example.com")
        True
        >>> match_wildcard("deep.api.example.com", "*.example.com")
        False
        >>> match_wildcard("example.com", "*.example.com")
        False
        >>> match_wildcard("other.com", "*.example.com")
        False
    """
    if not is_wildcard_pattern(pattern):
        return False

    regex = _compile_wildcard_regex(pattern)
    return bool(regex.match(host.lower()))


def validate_wildcard_pattern(pattern: str) -> tuple[bool, str | None]:
    """Validate a wildcard domain pattern.

    Args:
        pattern: Wildcard pattern to validate.

    Returns:
        Tuple of (is_valid, error_message).
        If valid, error_message is None.

    Examples:
        >>> validate_wildcard_pattern("*.example.com")
        (True, None)
        >>> validate_wildcard_pattern("**.example.com")
        (False, 'Invalid wildcard: only single * prefix allowed')
        >>> validate_wildcard_pattern("example.com")
        (False, 'Not a wildcard pattern')
    """
    if not is_wildcard_pattern(pattern):
        return False, "Not a wildcard pattern"

    # Check for double wildcards
    if "**" in pattern:
        return False, "Invalid wildcard: only single * prefix allowed"

    # Check for wildcards in other positions
    base = pattern[2:]  # Remove "*."
    if "*" in base:
        return False, "Invalid wildcard: * only allowed as first component"

    # Check base domain has at least one component
    if "." not in base and base != "localhost":
        return False, "Invalid wildcard: base domain must have at least one dot"

    # Check for empty components
    if ".." in pattern or pattern.endswith("."):
        return False, "Invalid domain format"

    return True, None


def find_matching_wildcard(
    host: str,
    wildcards: list[str],
) -> str | None:
    """Find the first wildcard pattern that matches a hostname.

    Args:
        host: Hostname to match against.
        wildcards: List of wildcard patterns to check.

    Returns:
        The matching wildcard pattern, or None if no match.

    Examples:
        >>> patterns = ["*.example.com", "*.other.com"]
        >>> find_matching_wildcard("api.example.com", patterns)
        '*.example.com'
        >>> find_matching_wildcard("api.unknown.com", patterns)
        None
    """
    for pattern in wildcards:
        if match_wildcard(host, pattern):
            return pattern
    return None
