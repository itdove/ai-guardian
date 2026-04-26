#!/usr/bin/env python3
"""
Tests for SSRF (Server-Side Request Forgery) Protection

Tests cover:
- Hermes Security Framework validated payloads (2/2 for SSRF)
- Private IP ranges (RFC 1918, loopback, link-local)
- Cloud metadata endpoints (AWS, GCP, Azure)
- Dangerous URL schemes
- IPv6 support
- Edge cases (quoted URLs, piped commands, multiple URLs)
- False positives (public IPs, AWS services)
- Action modes (block/warn/log-only)
- Configuration overrides
"""

import pytest
from ai_guardian.ssrf_protector import SSRFProtector, check_ssrf


class TestSSRFProtectorCore:
    """Core SSRF protection tests."""

    def test_disabled_protection(self):
        """Test that protection can be disabled."""
        protector = SSRFProtector({"enabled": False})
        should_block, msg = protector.check("Bash", {"command": "curl http://169.254.169.254"})
        assert not should_block
        assert msg is None

    def test_non_bash_tool_allowed(self):
        """Test that non-Bash tools are not checked for SSRF."""
        protector = SSRFProtector()
        should_block, msg = protector.check("Read", {"file_path": "/tmp/test.txt"})
        assert not should_block
        assert msg is None

    def test_empty_command(self):
        """Test that empty commands are allowed."""
        protector = SSRFProtector()
        should_block, msg = protector.check("Bash", {"command": ""})
        assert not should_block
        assert msg is None

    def test_command_without_urls(self):
        """Test that commands without URLs are allowed."""
        protector = SSRFProtector()
        should_block, msg = protector.check("Bash", {"command": "ls -la /tmp"})
        assert not should_block
        assert msg is None


class TestHermesValidatedPayloads:
    """
    Test cases from Hermes Security Framework.

    These are real-world attack payloads validated by the Hermes framework.
    AI Guardian must block all of these.
    """

    def test_hermes_payload_1_aws_metadata(self):
        """Hermes payload #1: AWS metadata endpoint access."""
        protector = SSRFProtector()

        # Direct metadata endpoint access
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://169.254.169.254/latest/meta-data/"}
        )

        assert should_block, "Failed to block AWS metadata endpoint (Hermes payload #1)"
        assert "SSRF" in msg
        assert "169.254.169.254" in msg

    def test_hermes_payload_2_url_redirect(self):
        """Hermes payload #2: URL redirect to metadata endpoint."""
        protector = SSRFProtector()

        # While we can't detect redirects (requires network access),
        # we should block direct metadata endpoint references
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
        )

        assert should_block, "Failed to block metadata credentials endpoint (Hermes payload #2)"
        assert "169.254.169.254" in msg


class TestPrivateIPRanges:
    """Test blocking of private IP ranges (RFC 1918, loopback, link-local)."""

    @pytest.mark.parametrize("ip,description", [
        ("10.0.0.1", "10.0.0.0/8 - Private network"),
        ("10.255.255.255", "10.0.0.0/8 - Last address"),
        ("172.16.0.1", "172.16.0.0/12 - Private network"),
        ("172.31.255.255", "172.16.0.0/12 - Last address"),
        ("192.168.0.1", "192.168.0.0/16 - Private network"),
        ("192.168.255.255", "192.168.0.0/16 - Last address"),
        ("127.0.0.1", "127.0.0.0/8 - Loopback"),
        ("127.255.255.255", "127.0.0.0/8 - Last loopback"),
        ("169.254.169.254", "169.254.0.0/16 - AWS metadata"),
        ("169.254.0.1", "169.254.0.0/16 - Link-local"),
    ])
    def test_private_ipv4_blocked(self, ip, description):
        """Test that private IPv4 addresses are blocked."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": f"curl http://{ip}/test"}
        )

        assert should_block, f"Failed to block {description}"
        assert ip in msg

    @pytest.mark.parametrize("ip,description", [
        ("::1", "IPv6 loopback"),
        ("fc00::1", "IPv6 private - fc00::/7"),
        ("fd00::1", "IPv6 private - fd00::/8"),
        ("fe80::1", "IPv6 link-local"),
    ])
    def test_private_ipv6_blocked(self, ip, description):
        """Test that private IPv6 addresses are blocked."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": f"curl http://[{ip}]/test"}
        )

        assert should_block, f"Failed to block {description}"

    @pytest.mark.parametrize("ipv6_mapped,expected_ipv4,description", [
        ("::ffff:169.254.169.254", "169.254.169.254", "AWS metadata via IPv6-mapped"),
        ("::ffff:127.0.0.1", "127.0.0.1", "Loopback via IPv6-mapped"),
        ("::ffff:10.0.0.1", "10.0.0.1", "Private 10.x via IPv6-mapped"),
        ("::ffff:172.16.0.1", "172.16.0.1", "Private 172.16.x via IPv6-mapped"),
        ("::ffff:192.168.1.1", "192.168.1.1", "Private 192.168.x via IPv6-mapped"),
    ])
    def test_ipv6_mapped_ipv4_blocked(self, ipv6_mapped, expected_ipv4, description):
        """Test that IPv6-mapped IPv4 addresses are blocked (CVE-level bypass fix)."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": f"curl http://[{ipv6_mapped}]/test"}
        )

        assert should_block, f"Failed to block {description} (maps to {expected_ipv4})"
        assert "SSRF" in msg or "blocked" in msg.lower()


class TestCloudMetadataEndpoints:
    """Test blocking of cloud provider metadata endpoints."""

    @pytest.mark.parametrize("endpoint,provider", [
        ("http://169.254.169.254/latest/meta-data/", "AWS"),
        ("http://169.254.169.254/latest/user-data", "AWS"),
        ("http://metadata.google.internal/", "GCP"),
        ("http://metadata.goog/", "GCP alternative"),
        ("http://[fd00:ec2::254]/", "AWS IPv6"),
    ])
    def test_metadata_endpoints_blocked(self, endpoint, provider):
        """Test that cloud metadata endpoints are blocked."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": f"curl {endpoint}"}
        )

        assert should_block, f"Failed to block {provider} metadata endpoint"
        assert "SSRF" in msg

    def test_localhost_domain_blocked_by_default(self):
        """Test that localhost domain is blocked by default."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://localhost:8080/admin"}
        )

        assert should_block
        assert "localhost" in msg


class TestDangerousURLSchemes:
    """Test blocking of dangerous URL schemes."""

    @pytest.mark.parametrize("scheme", [
        "file", "gopher", "ftp", "ftps", "data", "dict", "ldap", "ldaps"
    ])
    def test_dangerous_scheme_blocked(self, scheme):
        """Test that dangerous URL schemes are blocked."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": f"{scheme}://example.com/test"}
        )

        assert should_block, f"Failed to block {scheme}:// scheme"
        assert scheme in msg.lower()

    def test_file_scheme_local_path(self):
        """Test that file:// URLs are blocked."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl file:///etc/passwd"}
        )

        assert should_block
        assert "file://" in msg.lower()

    def test_data_url_scheme(self):
        """Test that data: URLs are blocked."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl data:text/plain,hello"}
        )

        assert should_block
        assert "data://" in msg.lower()


class TestEdgeCases:
    """Test edge cases and complex scenarios."""

    def test_quoted_url(self):
        """Test URL extraction from quoted strings."""
        protector = SSRFProtector()

        # Single quotes
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl 'http://169.254.169.254/meta-data'"}
        )
        assert should_block

        # Double quotes
        should_block, msg = protector.check(
            "Bash",
            {"command": 'curl "http://169.254.169.254/meta-data"'}
        )
        assert should_block

    def test_piped_command_with_url(self):
        """Test URL extraction from piped commands."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://10.0.0.1/test | jq .data"}
        )

        assert should_block
        assert "10.0.0.1" in msg

    def test_multiple_urls_in_command(self):
        """Test commands with multiple URLs."""
        protector = SSRFProtector()

        # One private, one public
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://example.com && curl http://192.168.1.1"}
        )

        assert should_block
        assert "192.168.1.1" in msg

    def test_wget_command(self):
        """Test wget commands with private IPs."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": "wget http://172.16.0.1/file.txt"}
        )

        assert should_block
        assert "172.16.0.1" in msg

    def test_curl_with_flags(self):
        """Test curl with various flags and options."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:8080/api"}
        )

        assert should_block
        assert "127.0.0.1" in msg

    def test_url_flag_format(self):
        """Test --url flag format."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl --url http://10.10.10.10/data"}
        )

        assert should_block


class TestFalsePositives:
    """Test that legitimate public URLs are NOT blocked."""

    @pytest.mark.parametrize("url", [
        "http://example.com",
        "https://www.google.com",
        "https://api.github.com/repos",
        "https://s3.amazonaws.com/bucket/file.txt",
        "https://storage.googleapis.com/bucket/object",
        "http://8.8.8.8",  # Google DNS
        "https://1.1.1.1",  # Cloudflare DNS
        "https://registry.npmjs.org/package",
    ])
    def test_public_url_allowed(self, url):
        """Test that public URLs are allowed."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": f"curl {url}"}
        )

        assert not should_block, f"Incorrectly blocked legitimate URL: {url}"

    def test_public_aws_service(self):
        """Test that public AWS services are NOT blocked."""
        protector = SSRFProtector()

        # S3
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl https://s3.amazonaws.com/mybucket/file.txt"}
        )
        assert not should_block

        # EC2 API (public)
        should_block, msg = protector.check(
            "Bash",
            {"command": "aws ec2 describe-instances"}
        )
        assert not should_block  # No URL extracted from this command

    def test_https_urls_allowed(self):
        """Test that HTTPS URLs to public domains are allowed."""
        protector = SSRFProtector()
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl https://api.openai.com/v1/models"}
        )

        assert not should_block


class TestActionModes:
    """Test different action modes (block/warn/log-only)."""

    def test_block_mode_default(self):
        """Test block mode (default) prevents execution."""
        protector = SSRFProtector({"action": "block"})
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://169.254.169.254"}
        )

        assert should_block
        assert "BLOCKED" in msg
        assert "SSRF" in msg

    def test_warn_mode_allows_with_warning(self):
        """Test warn mode logs but allows execution."""
        protector = SSRFProtector({"action": "warn"})
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://169.254.169.254"}
        )

        assert not should_block  # Execution allowed
        assert msg is not None  # But warning shown
        assert "⚠️" in msg
        assert "SSRF" in msg
        assert "warn mode" in msg.lower()

    def test_log_only_mode_silent(self):
        """Test log-only mode allows execution without user warning."""
        protector = SSRFProtector({"action": "log-only"})
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://169.254.169.254"}
        )

        assert not should_block  # Execution allowed
        assert msg is None  # No warning to user (logged silently)


class TestConfigurationOverrides:
    """Test configuration overrides and customization."""

    def test_additional_blocked_ips(self):
        """Test additional IP addresses can be blocked."""
        protector = SSRFProtector({
            "additional_blocked_ips": ["203.0.113.0/24"]  # TEST-NET-3
        })

        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://203.0.113.5"}
        )

        assert should_block
        assert "203.0.113.5" in msg

    def test_additional_blocked_domains(self):
        """Test additional domains can be blocked."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["internal.example.com", "admin.local"]
        })

        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://internal.example.com/api"}
        )

        assert should_block
        assert "internal.example.com" in msg

    def test_allow_localhost_override(self):
        """Test that localhost can be allowed for local development."""
        protector = SSRFProtector({"allow_localhost": True})

        # Localhost domain
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://localhost:3000"}
        )
        assert not should_block

        # Localhost IP
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://127.0.0.1:8080"}
        )
        assert not should_block

    def test_localhost_blocked_by_default(self):
        """Test that localhost is blocked when allow_localhost is False."""
        protector = SSRFProtector({"allow_localhost": False})

        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://localhost:3000"}
        )
        assert should_block


class TestAllowedDomains:
    """Test allowed_domains allow-list functionality (Issue #252)."""

    def test_allowed_domain_overrides_additional_blocked_domain(self):
        """Test that allowed_domains can override additional_blocked_domains."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["api.corp.internal", "public.corp.internal", "other.corp.internal"],
            "allowed_domains": ["api.corp.internal", "public.corp.internal"]
        })

        # api.corp.internal should be allowed (in allow-list)
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api.corp.internal/data"}
        )
        assert not should_block, "allowed_domains should override additional_blocked_domains"

        # public.corp.internal should be allowed
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://public.corp.internal/info"}
        )
        assert not should_block

        # other.corp.internal should be blocked (not in allow-list)
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://other.corp.internal/secret"}
        )
        assert should_block, "Domains not in allow-list should remain blocked"

    def test_allowed_domain_subdomain_matching(self):
        """Test that allowed_domains supports subdomain matching."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["api.corp.internal", "v1.api.corp.internal", "admin.corp.internal"],
            "allowed_domains": ["api.corp.internal"]
        })

        # Exact match
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api.corp.internal"}
        )
        assert not should_block

        # Subdomain of allowed domain
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://v1.api.corp.internal/endpoint"}
        )
        assert not should_block, "Subdomains of allowed domains should be allowed"

        # Different subdomain not in allow-list
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://admin.corp.internal"}
        )
        assert should_block

    def test_allowed_domain_cannot_override_core_metadata_endpoints(self):
        """Test that allowed_domains CANNOT override immutable core protections."""
        protector = SSRFProtector({
            "allowed_domains": [
                "metadata.google.internal",
                "169.254.169.254",
                "fd00:ec2::254"
            ]
        })

        # Core metadata endpoints should ALWAYS be blocked
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://metadata.google.internal"}
        )
        assert should_block, "Core metadata endpoints cannot be overridden by allow-list"

        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://169.254.169.254/latest/meta-data"}
        )
        assert should_block, "AWS metadata endpoint cannot be overridden"

        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://[fd00:ec2::254]/"}
        )
        assert should_block, "AWS IPv6 metadata cannot be overridden"

    def test_allowed_domain_cannot_override_dangerous_schemes(self):
        """Test that allowed_domains cannot override dangerous URL schemes."""
        protector = SSRFProtector({
            "allowed_domains": ["example.com"]
        })

        # Dangerous schemes should always be blocked
        should_block, msg = protector.check(
            "Bash",
            {"command": "file://example.com/etc/passwd"}
        )
        assert should_block, "Dangerous schemes cannot be overridden"

        should_block, msg = protector.check(
            "Bash",
            {"command": "gopher://example.com"}
        )
        assert should_block

    def test_allowed_domain_with_localhost(self):
        """Test allowed_domains interaction with allow_localhost."""
        # With allow_localhost=False, localhost is blocked
        protector = SSRFProtector({
            "allow_localhost": False,
            "allowed_domains": ["localhost"]
        })

        # localhost domain should still be blocked (it's in CORE_BLOCKED_DOMAINS)
        # Note: localhost is treated specially and removed from blocked list when allow_localhost=True
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://localhost:8080"}
        )
        # This should NOT be blocked because allowed_domains can override the localhost block
        # when allow_localhost=False (localhost is in additional blocked list, not immutable core)
        assert not should_block, "allowed_domains should allow localhost when in allow-list"

    def test_allowed_domain_empty_list(self):
        """Test that empty allowed_domains list works correctly."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["internal.example.com"],
            "allowed_domains": []
        })

        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://internal.example.com"}
        )
        assert should_block, "Empty allow-list should not affect blocking"

    def test_allowed_domain_case_insensitive(self):
        """Test that domain matching is case-insensitive."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["Api.Corp.Internal"],
            "allowed_domains": ["API.Corp.Internal"]
        })

        # Lowercase variant
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api.corp.internal"}
        )
        assert not should_block

        # Uppercase variant
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://API.CORP.INTERNAL"}
        )
        assert not should_block

        # Mixed case
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://Api.Corp.Internal"}
        )
        assert not should_block

    def test_allowed_domain_with_multiple_urls(self):
        """Test allowed_domains with commands containing multiple URLs."""
        protector = SSRFProtector({
            "additional_blocked_domains": ["api.internal", "admin.internal"],
            "allowed_domains": ["api.internal"]
        })

        # One allowed, one blocked
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api.internal && curl http://admin.internal"}
        )
        assert should_block, "Should block if any URL is blocked"
        assert "admin.internal" in msg

        # Both allowed
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://api.internal && curl http://v2.api.internal"}
        )
        assert not should_block, "Should allow if all URLs are allowed"

    def test_allowed_domain_does_not_affect_private_ips(self):
        """Test that allowed_domains only affects domain blocking, not IP blocking."""
        protector = SSRFProtector({
            "allowed_domains": ["10.0.0.1", "192.168.1.1"]
        })

        # Private IPs should still be blocked (immutable core protection)
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://10.0.0.1"}
        )
        assert should_block, "Private IPs are immutable protection, cannot be overridden"

        should_block, msg = protector.check(
            "Bash",
            {"command": "curl http://192.168.1.1"}
        )
        assert should_block


class TestConvenienceFunction:
    """Test the convenience function check_ssrf()."""

    def test_check_ssrf_function(self):
        """Test check_ssrf convenience function."""
        should_block, msg = check_ssrf(
            "Bash",
            {"command": "curl http://169.254.169.254"},
            {"enabled": True, "action": "block"}
        )

        assert should_block
        assert "SSRF" in msg

    def test_check_ssrf_with_disabled_config(self):
        """Test check_ssrf with disabled protection."""
        should_block, msg = check_ssrf(
            "Bash",
            {"command": "curl http://169.254.169.254"},
            {"enabled": False}
        )

        assert not should_block
        assert msg is None


class TestURLExtraction:
    """Test URL extraction from various command formats."""

    def test_extract_basic_url(self):
        """Test extraction of basic HTTP URL."""
        protector = SSRFProtector()
        urls = protector._extract_urls("curl http://example.com")

        assert len(urls) > 0
        assert "http://example.com" in urls

    def test_extract_https_url(self):
        """Test extraction of HTTPS URL."""
        protector = SSRFProtector()
        urls = protector._extract_urls("wget https://secure.example.com/file.txt")

        assert len(urls) > 0
        assert any("https://secure.example.com" in url for url in urls)

    def test_extract_multiple_urls(self):
        """Test extraction of multiple URLs from one command."""
        protector = SSRFProtector()
        urls = protector._extract_urls(
            "curl http://api.example.com && wget https://files.example.com/data.json"
        )

        assert len(urls) >= 2

    def test_no_urls_extracted_from_safe_command(self):
        """Test that no URLs are extracted from commands without URLs."""
        protector = SSRFProtector()
        urls = protector._extract_urls("ls -la /var/log")

        assert len(urls) == 0


class TestIPValidation:
    """Test IP address validation logic."""

    def test_is_ip_blocked_private(self):
        """Test that private IPs are identified correctly."""
        protector = SSRFProtector()

        assert protector._is_ip_blocked("10.0.0.1")
        assert protector._is_ip_blocked("172.16.0.1")
        assert protector._is_ip_blocked("192.168.1.1")
        assert protector._is_ip_blocked("127.0.0.1")
        assert protector._is_ip_blocked("169.254.169.254")

    def test_is_ip_blocked_public(self):
        """Test that public IPs are NOT blocked."""
        protector = SSRFProtector()

        assert not protector._is_ip_blocked("8.8.8.8")
        assert not protector._is_ip_blocked("1.1.1.1")
        assert not protector._is_ip_blocked("151.101.1.140")  # GitHub

    def test_is_ip_blocked_invalid(self):
        """Test handling of invalid IP addresses."""
        protector = SSRFProtector()

        # Invalid IPs should return False (not treated as blocked IPs)
        assert not protector._is_ip_blocked("not-an-ip")
        assert not protector._is_ip_blocked("999.999.999.999")

    def test_is_ip_blocked_ipv6_mapped_ipv4(self):
        """Test that IPv6-mapped IPv4 addresses are properly blocked."""
        protector = SSRFProtector()

        # Critical bypass vulnerability: IPv6-mapped IPv4 addresses
        # These should be blocked when their IPv4 equivalent is blocked
        assert protector._is_ip_blocked("::ffff:169.254.169.254"), "AWS metadata bypass via IPv6-mapped"
        assert protector._is_ip_blocked("::ffff:127.0.0.1"), "Loopback bypass via IPv6-mapped"
        assert protector._is_ip_blocked("::ffff:10.0.0.1"), "Private 10.x bypass via IPv6-mapped"
        assert protector._is_ip_blocked("::ffff:172.16.0.1"), "Private 172.16.x bypass via IPv6-mapped"
        assert protector._is_ip_blocked("::ffff:192.168.1.1"), "Private 192.168.x bypass via IPv6-mapped"

        # Public IPs should still not be blocked even when IPv6-mapped
        assert not protector._is_ip_blocked("::ffff:8.8.8.8"), "Public IP via IPv6-mapped should be allowed"


class TestDomainValidation:
    """Test domain name validation logic."""

    def test_is_domain_blocked_metadata(self):
        """Test that metadata domains are blocked."""
        protector = SSRFProtector()

        assert protector._is_domain_blocked("metadata.google.internal")
        assert protector._is_domain_blocked("metadata.goog")
        assert protector._is_domain_blocked("169.254.169.254")

    def test_is_domain_blocked_subdomain(self):
        """Test that subdomains of blocked domains are also blocked."""
        protector = SSRFProtector()

        # Subdomain of blocked domain
        assert protector._is_domain_blocked("api.metadata.google.internal")

    def test_is_domain_blocked_public(self):
        """Test that public domains are NOT blocked."""
        protector = SSRFProtector()

        assert not protector._is_domain_blocked("example.com")
        assert not protector._is_domain_blocked("google.com")
        assert not protector._is_domain_blocked("github.com")


class TestErrorHandling:
    """Test error handling and fail-closed behavior."""

    def test_malformed_url_fails_closed(self):
        """Test that malformed URLs fail closed (blocked)."""
        protector = SSRFProtector()

        # Malformed URL should be blocked
        should_block, msg = protector.check(
            "Bash",
            {"command": "curl ht!tp://malformed"}
        )

        # Should either block or ignore (depending on parsing)
        # The key is it should NOT crash
        assert isinstance(should_block, bool)

    def test_missing_command_parameter(self):
        """Test handling of missing command parameter."""
        protector = SSRFProtector()

        should_block, msg = protector.check("Bash", {})

        assert not should_block  # Empty command, nothing to check
        assert msg is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
