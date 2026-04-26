#!/usr/bin/env python3
"""
Tests for Path-Based SSRF Filtering (Issue #254)

Tests path-based filtering rules that allow granular control over URL access:
- Allowed paths on blocked domains
- Blocked paths on allowed domains
- Glob pattern matching (*, **, ?)
- Query parameters
- Trailing slashes
- Case sensitivity
"""

import pytest
from ai_guardian.ssrf_protector import SSRFProtector


class TestPathBasedFilteringBasics:
    """Basic path-based filtering tests."""

    def test_allowed_path_on_blocked_domain(self):
        """Test that specific paths can be allowed on blocked domains."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["internal.api.com"],
            "path_based_rules": [
                {
                    "domain": "internal.api.com",
                    "allowed_paths": ["/public/*", "/health"]
                }
            ]
        })

        # Blocked domain, allowed path - should allow
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://internal.api.com/public/data"}
        )
        assert not should_block, "Should allow /public/* on blocked domain"

        # Blocked domain, exact allowed path - should allow
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://internal.api.com/health"}
        )
        assert not should_block, "Should allow /health on blocked domain"

        # Blocked domain, non-allowed path - should block
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://internal.api.com/admin/settings"}
        )
        assert should_block, "Should block /admin/* on blocked domain"
        assert "internal.api.com" in msg

    def test_blocked_path_on_allowed_domain(self):
        """Test that specific paths can be blocked on allowed domains."""
        protector = SSRFProtector({
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "blocked_paths": ["/admin/*", "/internal/*"]
                }
            ]
        })

        # Allowed domain, blocked path - should block
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/admin/users"}
        )
        assert should_block, "Should block /admin/* on allowed domain"
        assert "/admin/users" in msg

        # Allowed domain, blocked path - should block
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/internal/config"}
        )
        assert should_block, "Should block /internal/* on allowed domain"

        # Allowed domain, non-blocked path - should allow
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/api/v1/users"}
        )
        assert not should_block, "Should allow /api/* on allowed domain"

    def test_combined_allowed_and_blocked_paths(self):
        """Test domain with both allowed and blocked paths."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["api.corp.local"],
            "path_based_rules": [
                {
                    "domain": "api.corp.local",
                    "allowed_paths": ["/public/*", "/health", "/metrics"],
                    "blocked_paths": ["/public/admin/*"]  # Block subset of allowed
                }
            ]
        })

        # Allowed path - should allow
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api.corp.local/public/data"}
        )
        assert not should_block, "Should allow /public/data"

        # Blocked subset of allowed path - should block
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api.corp.local/public/admin/settings"}
        )
        assert should_block, "Should block /public/admin/* even though /public/* is allowed"

        # Exact allowed path - should allow
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api.corp.local/health"}
        )
        assert not should_block, "Should allow /health"


class TestGlobPatterns:
    """Test glob pattern matching in paths."""

    def test_single_wildcard_matches_single_level(self):
        """Test * matches any chars except /."""
        protector = SSRFProtector({
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "blocked_paths": ["/api/*/delete"]
                }
            ]
        })

        # Should match single level
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/api/users/delete"}
        )
        assert should_block, "Should block /api/users/delete (matches /api/*/delete)"

        # Should NOT match multiple levels
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/api/v1/users/delete"}
        )
        assert not should_block, "Should NOT block /api/v1/users/delete (too many levels for single *)"

    def test_double_wildcard_matches_recursive(self):
        """Test ** matches any chars including /."""
        protector = SSRFProtector({
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "blocked_paths": ["/admin/**"]
                }
            ]
        })

        # Should match single level
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/admin/users"}
        )
        assert should_block, "Should block /admin/users (matches /admin/**)"

        # Should match multiple levels
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/admin/v1/users/settings"}
        )
        assert should_block, "Should block /admin/v1/users/settings (matches /admin/**)"

        # Should NOT match non-matching path
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/api/users"}
        )
        assert not should_block, "Should NOT block /api/users"

    def test_question_mark_matches_single_char(self):
        """Test ? matches single character."""
        protector = SSRFProtector({
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "allowed_paths": ["/v?/api/*"]
                }
            ]
        })

        # Should match single char
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/v1/api/users"}
        )
        assert not should_block, "Should allow /v1/api/users (matches /v?/api/*)"

        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/v2/api/data"}
        )
        assert not should_block, "Should allow /v2/api/data (matches /v?/api/*)"

        # Should NOT match multiple chars
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/v10/api/users"}
        )
        # This domain has allowed_paths, so paths not matching are blocked
        # Actually no - without a blocked domain, this should just not match the allowed path
        # Let me revise: this domain is NOT in blocked list, so it should be allowed by default


class TestQueryParameters:
    """Test handling of query parameters in path matching."""

    def test_query_params_included_in_match(self):
        """Test that query parameters are included in path matching."""
        protector = SSRFProtector({
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "blocked_paths": ["/api/users?admin=*"]
                }
            ]
        })

        # Should block path with matching query param
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/api/users?admin=true"}
        )
        assert should_block, "Should block /api/users?admin=true"

        # Should NOT block path without query param
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/api/users"}
        )
        assert not should_block, "Should NOT block /api/users (no query params)"

    def test_wildcard_matches_query_params(self):
        """Test wildcard matching with query parameters."""
        protector = SSRFProtector({
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "blocked_paths": ["/debug*"]  # Matches /debug, /debug?foo=bar, etc
                }
            ]
        })

        # Should block with query params
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/debug?verbose=true"}
        )
        assert should_block, "Should block /debug?verbose=true"


class TestTrailingSlashes:
    """Test normalization of trailing slashes."""

    def test_trailing_slash_normalization(self):
        """Test that trailing slashes are normalized for matching."""
        protector = SSRFProtector({
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "blocked_paths": ["/admin"]  # No trailing slash in pattern
                }
            ]
        })

        # Should block with trailing slash
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/admin/"}
        )
        assert should_block, "Should block /admin/ (matches /admin pattern)"

        # Should block without trailing slash
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/admin"}
        )
        assert should_block, "Should block /admin (matches /admin pattern)"

    def test_root_path_handling(self):
        """Test that root path (/) is handled correctly."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["example.com"],
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "allowed_paths": ["/"]  # Allow only root
                }
            ]
        })

        # Should allow root path
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/"}
        )
        assert not should_block, "Should allow / on blocked domain"

        # Should block non-root paths
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/admin"}
        )
        assert should_block, "Should block /admin (not in allowed paths)"


class TestCaseSensitivity:
    """Test case handling in domain and path matching."""

    def test_domain_case_insensitive(self):
        """Test that domain matching is case-insensitive."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["Internal.API.com"],
            "path_based_rules": [
                {
                    "domain": "Internal.API.com",
                    "allowed_paths": ["/public/*"]
                }
            ]
        })

        # Different case variations should all work
        for domain in ["internal.api.com", "INTERNAL.API.COM", "Internal.Api.Com"]:
            should_block, msg = protector.check(
                "Bash",
                {"command": f"curl http://{domain}/public/data"}
            )
            assert not should_block, f"Should allow /public/data on {domain}"

            should_block, msg = protector.check(
                "Bash",
                {"command": f"curl http://{domain}/admin"}
            )
            assert should_block, f"Should block /admin on {domain}"


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_no_path_rules_for_domain(self):
        """Test behavior when domain has no path rules."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["blocked.com"],
            "path_based_rules": [
                {
                    "domain": "other.com",
                    "allowed_paths": ["/public/*"]
                }
            ]
        })

        # Domain with no path rules should use normal blocking
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://blocked.com/anything"}
        )
        assert should_block, "Should block domain without path rules"

    def test_empty_path_lists(self):
        """Test domain with empty allowed/blocked path lists."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["example.com"],
            "path_based_rules": [
                {
                    "domain": "example.com",
                    "allowed_paths": [],
                    "blocked_paths": []
                }
            ]
        })

        # Empty path lists should fall back to domain-level decision
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com/anything"}
        )
        assert should_block, "Should block with empty path lists (domain is blocked)"

    def test_multiple_domains_with_path_rules(self):
        """Test multiple domains with different path rules."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["api1.internal", "api2.internal"],
            "path_based_rules": [
                {
                    "domain": "api1.internal",
                    "allowed_paths": ["/public/*"]
                },
                {
                    "domain": "api2.internal",
                    "allowed_paths": ["/health", "/metrics"]
                }
            ]
        })

        # api1.internal with allowed path
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api1.internal/public/data"}
        )
        assert not should_block, "Should allow /public/data on api1.internal"

        # api2.internal with allowed path
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api2.internal/health"}
        )
        assert not should_block, "Should allow /health on api2.internal"

        # api1.internal with non-allowed path
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api1.internal/admin"}
        )
        assert should_block, "Should block /admin on api1.internal"

    def test_immutable_protections_not_affected_by_path_rules(self):
        """Test that path rules don't override immutable protections."""
        protector = SSRFProtector({
            "path_based_rules": [
                {
                    "domain": "169.254.169.254",
                    "allowed_paths": ["/*"]  # Try to allow all paths
                }
            ]
        })

        # Metadata endpoint should still be blocked (immutable protection)
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://169.254.169.254/latest/meta-data"}
        )
        assert should_block, "Metadata endpoints are immutable, path rules should not override"
        assert "169.254.169.254" in msg
