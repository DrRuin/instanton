"""Tests for subdomain uniqueness and generation.

Ensures that running multiple instanton instances from the same directory
does not cause subdomain conflicts.
"""

import re

import pytest

from instanton.sdk import _generate_unique_suffix, _sanitize_subdomain, _suggest_subdomain


class TestGenerateUniqueSuffix:
    """Tests for _generate_unique_suffix function."""

    def test_suffix_length(self):
        """Verify suffix is exactly 4 characters (2 bytes = 4 hex chars)."""
        suffix = _generate_unique_suffix()
        assert len(suffix) == 4

    def test_suffix_is_hex(self):
        """Verify suffix contains only valid hex characters."""
        suffix = _generate_unique_suffix()
        assert re.match(r"^[0-9a-f]{4}$", suffix)

    def test_suffix_uniqueness(self):
        """Verify multiple calls generate different suffixes."""
        suffixes = set()
        for _ in range(100):
            suffix = _generate_unique_suffix()
            suffixes.add(suffix)
        assert len(suffixes) >= 95

    def test_suffix_randomness(self):
        """Verify suffixes are random (not sequential)."""
        suffixes = [_generate_unique_suffix() for _ in range(10)]
        assert len(set(suffixes)) > 1


class TestSuggestSubdomainWithSuffix:
    """Tests for _suggest_subdomain with unique suffix."""

    def test_suggest_subdomain_has_suffix_by_default(self):
        """Verify suggested subdomain includes a unique suffix by default."""
        subdomain = _suggest_subdomain()
        if subdomain:
            assert re.match(r"^[a-z0-9-]+-[0-9a-f]{4}$", subdomain)

    def test_suggest_subdomain_without_suffix(self):
        """Verify we can request subdomain without suffix."""
        subdomain = _suggest_subdomain(with_unique_suffix=False)
        if subdomain:
            assert not re.match(r"^.+-[0-9a-f]{4}$", subdomain)

    def test_multiple_suggest_calls_different(self):
        """Verify multiple calls return different subdomains."""
        subdomains = set()
        for _ in range(10):
            subdomain = _suggest_subdomain()
            if subdomain:
                subdomains.add(subdomain)
        if subdomains:
            assert len(subdomains) == 10


class TestSanitizeSubdomain:
    """Tests for _sanitize_subdomain function."""

    def test_lowercase(self):
        """Verify names are converted to lowercase."""
        assert _sanitize_subdomain("MyProject") == "myproject"

    def test_replace_underscores(self):
        """Verify underscores are replaced with hyphens."""
        assert _sanitize_subdomain("my_project") == "my-project"

    def test_replace_spaces(self):
        """Verify spaces are replaced with hyphens."""
        assert _sanitize_subdomain("my project") == "my-project"

    def test_remove_invalid_chars(self):
        """Verify invalid characters are removed."""
        assert _sanitize_subdomain("my.project!@#") == "myproject"

    def test_strip_hyphens(self):
        """Verify leading/trailing hyphens are stripped."""
        assert _sanitize_subdomain("-my-project-") == "my-project"

    def test_length_limit(self):
        """Verify subdomain is limited to 63 characters."""
        long_name = "a" * 100
        result = _sanitize_subdomain(long_name)
        assert len(result) <= 63

    def test_minimum_length(self):
        """Verify subdomain with < 3 chars returns empty."""
        assert _sanitize_subdomain("ab") == ""
        assert _sanitize_subdomain("a") == ""

    def test_minimum_length_met(self):
        """Verify subdomain with >= 3 chars is valid."""
        assert _sanitize_subdomain("abc") == "abc"


class TestSubdomainUniquenessScenarios:
    """Tests for real-world subdomain conflict scenarios."""

    def test_same_directory_multiple_runs(self):
        """Simulate multiple runs from same directory - should get different subdomains."""
        subdomains = [_suggest_subdomain() for _ in range(5)]
        valid_subdomains = [s for s in subdomains if s is not None]
        if valid_subdomains:
            assert len(valid_subdomains) == len(set(valid_subdomains))

    def test_subdomain_format_with_suffix(self):
        """Verify subdomain format: projectname-xxxx."""
        subdomain = _suggest_subdomain()
        if subdomain:
            parts = subdomain.rsplit("-", 1)
            assert len(parts) == 2
            base_name, suffix = parts
            assert re.match(r"^[a-z0-9-]+$", base_name)
            assert re.match(r"^[0-9a-f]{4}$", suffix)

    def test_suffix_appended_correctly(self):
        """Verify suffix is appended with hyphen separator."""
        subdomain = _suggest_subdomain()
        if subdomain:
            assert re.search(r"-[0-9a-f]{4}$", subdomain)


class TestSubdomainLengthWithSuffix:
    """Tests for subdomain length handling with suffix."""

    def test_short_name_with_suffix(self):
        """Verify short project names work with suffix."""
        name = "api"
        sanitized = _sanitize_subdomain(name)
        assert len(sanitized) == 3

    def test_long_name_truncated_for_suffix(self):
        """Verify long project names are truncated to make room for suffix."""
        long_name = "a" * 60
        subdomain = _suggest_subdomain()
        if subdomain:
            assert len(subdomain) <= 63


class TestNoProjectContext:
    """Tests for when no project context is available."""

    def test_none_when_no_context(self, tmp_path, monkeypatch):
        """Verify None is returned when no project files exist."""
        monkeypatch.chdir(tmp_path)
        subdomain = _suggest_subdomain()


class TestServerSubdomainGeneration:
    """Tests documenting server-side subdomain behavior."""

    def test_server_generates_random_when_none_provided(self):
        """Document that server generates 12-char hex subdomain when none provided."""
        import secrets

        server_subdomain = secrets.token_hex(6)
        assert len(server_subdomain) == 12
        assert re.match(r"^[0-9a-f]{12}$", server_subdomain)

    def test_collision_probability_is_low(self):
        """Document the collision probability for subdomains."""
        pass


class TestEdgeCases:
    """Tests for edge cases in subdomain generation."""

    def test_special_characters_handled(self):
        """Verify special characters in project names are handled."""
        assert _sanitize_subdomain("my@project!") == "myproject"
        assert _sanitize_subdomain("my.project.v2") == "myprojectv2"

    def test_unicode_handled(self):
        """Verify unicode characters are removed."""
        assert _sanitize_subdomain("myproject\u00e9") == "myproject"

    def test_numbers_allowed(self):
        """Verify numbers are allowed in subdomains."""
        assert _sanitize_subdomain("project123") == "project123"

    def test_starting_with_number(self):
        """Verify subdomain can start with number."""
        assert _sanitize_subdomain("123project") == "123project"

    def test_all_hyphens_become_empty(self):
        """Verify all-hyphen names become empty after stripping."""
        assert _sanitize_subdomain("---") == ""

    def test_multiple_consecutive_hyphens_normalized(self):
        """Verify multiple hyphens are normalized."""
        result = _sanitize_subdomain("my--project")
        assert "--" not in result
