#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Protection Module

Prevents AI agents from accessing:
- Private network ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- Dangerous URL schemes (file://, gopher://, ftp://, data://)

Design Philosophy:
- Immutable core protections: Cannot be disabled via config
- Local-first: All checks run locally
- Fast: <1ms overhead per Bash command
- Fail-closed: Block on parsing errors

Inspired by Hermes Security Framework patterns.
NEW in v1.8.0: Optional pattern server support for enterprise SSRF pattern management.
"""

import ipaddress
import logging
import re
import urllib.parse
from typing import Tuple, Optional, Dict, Any, List, Set

logger = logging.getLogger(__name__)


class SSRFProtector:
    """
    Detects and blocks SSRF attacks in tool calls.

    Immutable Core Protections (cannot be disabled):
    - Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
    - Cloud metadata endpoints: 169.254.169.254, metadata.google.internal, fd00:ec2::254
    - Dangerous schemes: file://, gopher://, ftp://, data://

    Configurable Additions:
    - Additional blocked IPs/domains
    - Allow localhost (override default block)
    """

    # IMMUTABLE: Core private IP ranges (RFC 1918 + loopback + link-local)
    # These CANNOT be disabled via configuration
    CORE_BLOCKED_IP_RANGES = [
        "10.0.0.0/8",          # Private network (RFC 1918)
        "172.16.0.0/12",       # Private network (RFC 1918)
        "192.168.0.0/16",      # Private network (RFC 1918)
        "127.0.0.0/8",         # Loopback
        "169.254.0.0/16",      # Link-local (AWS metadata)
        "::1/128",             # IPv6 loopback
        "fc00::/7",            # IPv6 private network
        "fe80::/10",           # IPv6 link-local
    ]

    # IMMUTABLE: Core blocked domains (cloud metadata endpoints)
    # These CANNOT be disabled via configuration
    CORE_BLOCKED_DOMAINS = [
        "metadata.google.internal",        # GCP metadata
        "metadata.goog",                   # GCP metadata (alternative)
        "169.254.169.254",                 # AWS/Azure metadata IP as domain
        "fd00:ec2::254",                   # AWS IPv6 metadata
        "instance-data",                   # AWS instance metadata
        "localhost",                       # Localhost (unless allow_localhost is True)
    ]

    # IMMUTABLE: Dangerous URL schemes
    # These CANNOT be disabled via configuration
    DANGEROUS_SCHEMES = [
        "file",      # Local file access
        "gopher",    # Gopher protocol (legacy attack vector)
        "ftp",       # FTP protocol
        "ftps",      # Secure FTP
        "data",      # Data URLs (can encode arbitrary content)
        "dict",      # DICT protocol
        "ldap",      # LDAP protocol
        "ldaps",     # Secure LDAP
    ]

    # URL extraction patterns for Bash commands
    # Matches: http://, https://, curl, wget, etc.
    URL_PATTERNS = [
        # IPv6 URLs with brackets: http://[::1]/ or http://[fd00:ec2::254]/
        r'(?:https?|ftp|ftps|file|gopher)://\[[0-9a-fA-F:]+\][^\s\'"<>{}|\\^`]*',

        # Standard URLs (non-IPv6)
        r'(?:https?|ftp|ftps|file|gopher)://[^\s\'"<>{}|\\^`\[\]]+',

        # data: URLs (no //)
        r'data:[^\s\'"<>{}|\\^`]+',

        # dict, ldap, ldaps URLs
        r'(?:dict|ldap|ldaps)://[^\s\'"<>{}|\\^`\[\]]+',

        # curl/wget with URL argument
        r'(?:curl|wget)\s+(?:-[^\s]+\s+)*(["\']?)(?:https?|ftp)://[^\s\'"<>{}|\\^`\[\]]+\1',

        # URLs in quotes (including IPv6)
        r'["\'](?:https?|ftp|file|gopher|data|dict|ldap|ldaps)://?\[[0-9a-fA-F:]+\][^"\']*["\']',
        r'["\'](?:https?|ftp|file|gopher|dict|ldap|ldaps)://[^"\']+["\']',
        r'["\']data:[^"\']+["\']',

        # -u/--url flag (common in curl)
        r'--?url\s*[=\s]\s*(["\']?)(?:https?|ftp)://[^\s\'"<>{}|\\^`\[\]]+\1',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the SSRF protector.

        Args:
            config: Optional configuration dictionary with keys:
                - enabled: bool (default True)
                - action: str - "block", "warn", "log-only" (default "block")
                - additional_blocked_ips: list of IP addresses/ranges to block
                - additional_blocked_domains: list of domain names to block
                - allow_localhost: bool (default False) - allow localhost access
                - pattern_server: Dict - pattern server configuration (NEW in v1.8.0)
        """
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.action = self.config.get("action", "block")
        self.allow_localhost = self.config.get("allow_localhost", False)

        # Compile URL extraction patterns
        self._compiled_url_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.URL_PATTERNS
        ]

        # Load patterns using pattern loader if pattern_server configured
        pattern_server_config = self.config.get('pattern_server')
        if pattern_server_config:
            logger.info("SSRF Protection: Loading patterns via pattern server")
            merged_patterns = self._load_patterns_via_server(pattern_server_config)
            ip_ranges_to_use = merged_patterns.get('blocked_ip_ranges', [])
            domains_to_use = merged_patterns.get('blocked_domains', [])
        else:
            # Use hardcoded default patterns
            ip_ranges_to_use = [{"cidr": cidr} for cidr in self.CORE_BLOCKED_IP_RANGES]
            # Add additional IPs from local config
            for ip in self.config.get("additional_blocked_ips", []):
                ip_ranges_to_use.append({"cidr": ip})

            domains_to_use = [{"domain": d} for d in self.CORE_BLOCKED_DOMAINS]
            # Add additional domains from local config
            for domain in self.config.get("additional_blocked_domains", []):
                domains_to_use.append({"domain": domain})

        # Pre-parse IP ranges for performance
        self._blocked_ip_networks = []
        for ip_range in ip_ranges_to_use:
            try:
                # Handle both dict format (pattern server) and string format (legacy)
                if isinstance(ip_range, dict):
                    cidr = ip_range.get('cidr')
                else:
                    cidr = ip_range

                network = ipaddress.ip_network(cidr, strict=False)
                self._blocked_ip_networks.append(network)
            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid IP range in SSRF config: {ip_range} - {e}")

        # Build complete blocked domains list
        self._blocked_domains = set()
        for domain_entry in domains_to_use:
            # Handle both dict format (pattern server) and string format (legacy)
            if isinstance(domain_entry, dict):
                domain = domain_entry.get('domain')
            else:
                domain = domain_entry

            if domain:
                self._blocked_domains.add(domain)

        # Remove localhost from blocked list if allow_localhost is True
        if self.allow_localhost:
            self._blocked_domains.discard("localhost")
            # Also remove localhost IP range
            self._blocked_ip_networks = [
                net for net in self._blocked_ip_networks
                if str(net) not in ["127.0.0.0/8", "::1/128"]
            ]

        logger.info(f"SSRF Protection: Loaded {len(self._blocked_ip_networks)} IP ranges and {len(self._blocked_domains)} domains")

    def _load_patterns_via_server(self, pattern_server_config: Dict) -> Dict[str, Any]:
        """
        Load patterns via pattern server with fallback to defaults.

        Args:
            pattern_server_config: Pattern server configuration

        Returns:
            Dict with 'blocked_ip_ranges' and 'blocked_domains' lists
        """
        try:
            from ai_guardian.pattern_loader import SSRFPatternLoader

            loader = SSRFPatternLoader()
            merged_patterns = loader.load_patterns(
                pattern_server_config=pattern_server_config, local_config=self.config
            )

            logger.info(f"SSRF Protection: Loaded patterns from pattern server/cache/defaults")
            return merged_patterns

        except ImportError:
            logger.error("pattern_loader module not available, using hardcoded defaults")
            return {
                'blocked_ip_ranges': [{"cidr": cidr} for cidr in self.CORE_BLOCKED_IP_RANGES],
                'blocked_domains': [{"domain": d} for d in self.CORE_BLOCKED_DOMAINS]
            }
        except Exception as e:
            logger.error(f"Error loading patterns from pattern server: {e}")
            logger.info("Falling back to hardcoded default patterns")
            return {
                'blocked_ip_ranges': [{"cidr": cidr} for cidr in self.CORE_BLOCKED_IP_RANGES],
                'blocked_domains': [{"domain": d} for d in self.CORE_BLOCKED_DOMAINS]
            }

    def _extract_urls(self, command: str) -> List[str]:
        """
        Extract URLs from a Bash command string.

        Args:
            command: Bash command to extract URLs from

        Returns:
            List of extracted URLs

        Examples:
            >>> self._extract_urls("curl http://example.com")
            ["http://example.com"]

            >>> self._extract_urls("wget 'https://169.254.169.254/latest/meta-data/'")
            ["https://169.254.169.254/latest/meta-data/"]
        """
        urls = []

        for pattern in self._compiled_url_patterns:
            matches = pattern.findall(command)
            for match in matches:
                # Extract URL from match (may have capture groups)
                if isinstance(match, tuple):
                    # Pattern had capture groups, find the URL
                    for part in match:
                        if part and ('://' in part or part.startswith('http')):
                            urls.append(part.strip('\'"'))
                            break
                else:
                    urls.append(match.strip('\'"'))

        # Also extract any bare URLs (simpler fallback)
        simple_url_pattern = re.compile(
            r'(?:https?|ftp|ftps|file|gopher|data)://[^\s\'"<>{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        simple_matches = simple_url_pattern.findall(command)
        urls.extend(simple_matches)

        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            # Clean up URL
            url = url.strip('\'"')
            if url and url not in seen:
                seen.add(url)
                unique_urls.append(url)

        return unique_urls

    def _parse_url(self, url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse a URL into scheme, hostname, and full URL.

        Args:
            url: URL string to parse

        Returns:
            Tuple of (scheme, hostname, full_url) or (None, None, None) on error
        """
        try:
            parsed = urllib.parse.urlparse(url)
            scheme = parsed.scheme.lower() if parsed.scheme else None
            hostname = parsed.hostname  # Already handles IPv6 brackets
            return scheme, hostname, url
        except Exception as e:
            logger.debug(f"Failed to parse URL '{url}': {e}")
            return None, None, None

    def _is_ip_blocked(self, ip_str: str) -> bool:
        """
        Check if an IP address is in a blocked range.

        Args:
            ip_str: IP address string (IPv4 or IPv6)

        Returns:
            True if IP is blocked, False otherwise
        """
        try:
            ip_addr = ipaddress.ip_address(ip_str)

            for network in self._blocked_ip_networks:
                if ip_addr in network:
                    logger.debug(f"IP {ip_str} is in blocked range {network}")
                    return True

            return False
        except ValueError:
            # Not a valid IP address
            return False

    def _is_domain_blocked(self, domain: str) -> bool:
        """
        Check if a domain is in the blocked list.

        Args:
            domain: Domain name to check

        Returns:
            True if domain is blocked, False otherwise
        """
        if not domain:
            return False

        domain_lower = domain.lower()

        # Check exact match
        if domain_lower in self._blocked_domains:
            return True

        # Check if domain is an IP address
        if self._is_ip_blocked(domain_lower):
            return True

        # Check subdomain matching (e.g., foo.metadata.google.internal)
        for blocked in self._blocked_domains:
            if domain_lower.endswith('.' + blocked):
                return True

        return False

    def _check_url(self, url: str) -> Tuple[bool, str]:
        """
        Check if a URL is an SSRF attack.

        Args:
            url: URL to check

        Returns:
            Tuple of (is_ssrf, reason)
        """
        scheme, hostname, _ = self._parse_url(url)

        if not scheme:
            # Failed to parse - fail closed
            return True, "failed to parse URL"

        # Check dangerous schemes
        if scheme in self.DANGEROUS_SCHEMES:
            return True, f"dangerous URL scheme '{scheme}://'"

        if not hostname:
            # No hostname (e.g., data: URLs without hostname)
            # Already blocked by scheme check above
            return False, ""

        # Check if domain is blocked
        if self._is_domain_blocked(hostname):
            return True, f"blocked domain '{hostname}'"

        # Check if hostname is an IP in blocked range
        if self._is_ip_blocked(hostname):
            return True, f"private IP address '{hostname}'"

        # Try to resolve hostname to IP (if it looks like a domain name)
        # NOTE: We deliberately DO NOT do DNS resolution here to avoid:
        # 1. DNS rebinding attacks
        # 2. Performance overhead
        # 3. Network dependencies
        #
        # This means we rely on domain blocking and direct IP checking only.
        # An attacker using a public domain that resolves to a private IP would bypass this.
        # This is a known limitation - full protection requires DNS resolution + TOCTOU prevention.

        return False, ""

    def check(self, tool_name: str, tool_input: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Check if a tool call contains SSRF attempts.

        Args:
            tool_name: Name of the tool being called
            tool_input: Tool input parameters

        Returns:
            Tuple of (should_block, error_message)
            - should_block: Whether to block execution (False in log/warn mode, True in block mode)
            - error_message: Formatted error message if should_block is True, warning if warn mode, None if log-only
        """
        if not self.enabled:
            return False, None

        # Only check Bash tool (primary attack vector for SSRF)
        # Other tools (Read, Write, etc.) don't access network resources
        if tool_name != "Bash":
            return False, None

        # Extract command from tool input
        command = tool_input.get("command", "")
        if not command or not command.strip():
            return False, None

        try:
            # Extract URLs from command
            urls = self._extract_urls(command)

            if not urls:
                # No URLs found - allow
                return False, None

            # Check each URL for SSRF
            for url in urls:
                is_ssrf, reason = self._check_url(url)

                if is_ssrf:
                    # SSRF detected!
                    logger.error(f"SSRF attempt detected: {reason}, URL={url}")

                    # Format error message based on action
                    if self.action == "warn":
                        warn_msg = (
                            f"⚠️  SSRF Protection Warning: {reason}\n"
                            f"   URL: {url}\n"
                            f"   Execution allowed (warn mode)"
                        )
                        logger.warning(f"SSRF detected (warn mode): {reason}, URL={url} - execution allowed")
                        return False, warn_msg

                    elif self.action == "log-only":
                        logger.warning(f"SSRF detected (log-only mode): {reason}, URL={url} - execution allowed (silent)")
                        return False, None

                    else:  # block mode (default)
                        error_msg = (
                            f"\n{'='*70}\n"
                            f"🚨 BLOCKED BY POLICY\n"
                            f"🚨 SSRF ATTACK DETECTED\n"
                            f"{'='*70}\n\n"
                            "AI Guardian has detected a Server-Side Request Forgery (SSRF) attempt.\n"
                            "This operation has been blocked for security.\n\n"
                            f"Detected threat:\n"
                            f"  • Reason: {reason}\n"
                            f"  • URL: {url}\n"
                            f"  • Command: {command[:100]}{'...' if len(command) > 100 else ''}\n\n"
                            "SSRF attacks can:\n"
                            "  • Exfiltrate cloud credentials from metadata endpoints\n"
                            "  • Access internal network services\n"
                            "  • Read local files via file:// URLs\n"
                            "  • Bypass firewalls and network segmentation\n\n"
                            "Blocked resources:\n"
                            "  • Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)\n"
                            "  • Cloud metadata endpoints (169.254.169.254, metadata.google.internal)\n"
                            "  • Dangerous schemes (file://, gopher://, ftp://, data://)\n"
                            "  • Localhost (127.0.0.1, ::1)\n\n"
                            "If this is legitimate (e.g., local development):\n"
                            "  1. Set action to 'warn' in ~/.config/ai-guardian/ai-guardian.json\n"
                            "  2. Enable allow_localhost for local testing\n"
                            "  3. Temporarily disable: \"ssrf_protection\": {\"enabled\": false}\n\n"
                            "Public AWS services (s3.amazonaws.com, etc.) are NOT blocked.\n\n"
                            f"{'='*70}\n"
                        )

                        return True, error_msg

            # All URLs are safe
            return False, None

        except Exception as e:
            # Fail-closed: block on errors to prevent bypasses
            logger.error(f"Error during SSRF check: {e}")
            logger.debug("Failing closed - blocking operation")

            error_msg = (
                f"\n{'='*70}\n"
                f"🚨 BLOCKED BY POLICY\n"
                f"{'='*70}\n\n"
                f"SSRF protection encountered an error and blocked this operation.\n"
                f"Error: {str(e)}\n\n"
                f"{'='*70}\n"
            )

            return True, error_msg


def check_ssrf(tool_name: str, tool_input: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[str]]:
    """
    Convenience function to check for SSRF attacks.

    Args:
        tool_name: Name of the tool being called
        tool_input: Tool input parameters
        config: Optional configuration dictionary

    Returns:
        Tuple of (should_block, error_message)
        - should_block: Whether to block execution
        - error_message: Error/warning message if detected
    """
    protector = SSRFProtector(config)
    return protector.check(tool_name, tool_input)
