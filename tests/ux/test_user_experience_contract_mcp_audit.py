"""
UX contract tests for MCP server security scanning.

Documents expected user experience when running MCP config audit
and deep source code scanning. These tests verify that the correct
findings are produced and security warnings are actionable.

Issue #468
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from ai_guardian.mcp_audit import (
    MCPAuditor,
    MCPServerInfo,
    AuditFinding,
)


class TestCredentialExposureUX:
    """
    USER EXPERIENCE: Credential env vars passed to untrusted MCP servers.

    When a user has an MCP server configured with credential-like env vars
    (TOKEN, KEY, SECRET, PASSWORD) but the server is NOT in permissions.rules,
    the audit should produce a CRITICAL finding warning about credential exposure.
    """

    def test_user_experience_credential_warning(self):
        """
        USER EXPERIENCE: Untrusted server + credentials -> Critical warning

        Scenario:
        1. User configures MCP server "unknown-analytics" in settings.json
        2. Server has env var ANALYTICS_API_KEY set
        3. Server is NOT listed in permissions.rules (untrusted)
        4. User runs: ai-guardian mcp audit

        Expected User Experience:
        [CRITICAL]
          unknown-analytics: Credential env var 'ANALYTICS_API_KEY' passed to untrusted server
            Server 'unknown-analytics' is not allowed in permissions.rules
            but receives credential-like env var 'ANALYTICS_API_KEY'.
            Add an allow rule or remove the credential.
        """
        server = MCPServerInfo(
            name="unknown-analytics",
            command="npx",
            args=["-y", "analytics-mcp"],
            env_var_names=["ANALYTICS_API_KEY"],
            is_trusted=False,
            config_sources=["~/.claude.json"],
        )

        auditor = MCPAuditor()
        report = auditor.audit_config([server])

        # Must produce at least one critical finding
        critical = [f for f in report.findings if f.severity == "critical"]
        assert len(critical) >= 1, "Expected critical finding for credential exposure"
        assert "ANALYTICS_API_KEY" in critical[0].message
        assert critical[0].category == "credential_exposure"
        assert critical[0].detail is not None

    def test_user_experience_trusted_server_ok(self):
        """
        USER EXPERIENCE: Trusted server + credentials -> No warning

        Scenario:
        1. User configures MCP server "mcp-atlassian" in settings.json
        2. Server has env vars JIRA_URL, JIRA_API_TOKEN set
        3. Server IS allowed in permissions.rules (trusted)
        4. User runs: ai-guardian mcp audit

        Expected User Experience:
        No issues found.
        """
        server = MCPServerInfo(
            name="mcp-atlassian",
            command="uvx",
            args=["mcp-atlassian@2.0.0"],
            env_var_names=["JIRA_URL", "JIRA_API_TOKEN"],
            is_trusted=True,
            config_sources=["~/.claude.json"],
        )

        auditor = MCPAuditor()
        report = auditor.audit_config([server])

        credential_findings = [f for f in report.findings if f.category == "credential_exposure"]
        assert len(credential_findings) == 0, (
            "Trusted server should NOT trigger credential exposure warning"
        )


class TestNpxAutoInstallUX:
    """
    USER EXPERIENCE: npx -y auto-installing unvetted packages.

    When a user's MCP server is configured with npx -y, it will
    automatically download and run a package without review.
    This is risky for untrusted servers.
    """

    def test_user_experience_npx_auto_install_warning(self):
        """
        USER EXPERIENCE: Untrusted npx -y -> Medium warning

        Scenario:
        1. User configures MCP server with "npx -y some-package"
        2. Server is NOT trusted
        3. User runs: ai-guardian mcp audit

        Expected User Experience:
        [MEDIUM]
          risky-npx: npx -y auto-installs package without review
        """
        server = MCPServerInfo(
            name="risky-npx",
            command="npx",
            args=["-y", "some-package"],
            env_var_names=[],
            is_trusted=False,
            config_sources=["~/.claude.json"],
        )

        auditor = MCPAuditor()
        report = auditor.audit_config([server])

        npx_findings = [f for f in report.findings if f.category == "npx_auto_install"]
        assert len(npx_findings) == 1
        assert npx_findings[0].severity == "medium"


class TestUnpinnedVersionUX:
    """
    USER EXPERIENCE: Packages without version pinning.
    """

    def test_user_experience_unpinned_package(self):
        """
        USER EXPERIENCE: Unpinned package -> Medium warning

        Scenario:
        1. User configures MCP server with "uvx my-package" (no version pin)
        2. User runs: ai-guardian mcp audit

        Expected User Experience:
        [MEDIUM]
          no-pin: Package 'my-package' has no version pin
            Use 'my-package@<version>' to pin.
        """
        server = MCPServerInfo(
            name="no-pin",
            command="uvx",
            args=["my-package"],
            env_var_names=[],
            is_trusted=False,
            config_sources=["~/.claude.json"],
        )

        auditor = MCPAuditor()
        report = auditor.audit_config([server])

        pin_findings = [f for f in report.findings if f.category == "unpinned_version"]
        assert len(pin_findings) == 1
        assert "my-package" in pin_findings[0].message


class TestCleanAuditUX:
    """
    USER EXPERIENCE: All servers pass audit.
    """

    def test_user_experience_clean_audit(self):
        """
        USER EXPERIENCE: All clean -> "No issues found"

        Scenario:
        1. User has properly configured MCP servers
        2. All servers are trusted or have no credentials
        3. All packages are version-pinned
        4. User runs: ai-guardian mcp audit

        Expected User Experience:
        MCP Config Audit (Xms)
        Servers: 2 total, 2 trusted, 0 untrusted
        No issues found.
        """
        servers = [
            MCPServerInfo(
                name="mcp-atlassian",
                command="uvx",
                args=["mcp-atlassian@2.0.0"],
                env_var_names=["JIRA_URL"],
                is_trusted=True,
                config_sources=["~/.claude.json"],
            ),
            MCPServerInfo(
                name="notebooklm",
                command="uvx",
                args=["notebooklm-mcp@1.5.0"],
                env_var_names=[],
                is_trusted=True,
                config_sources=["~/.claude.json"],
            ),
        ]

        auditor = MCPAuditor()
        report = auditor.audit_config(servers)

        assert len(report.findings) == 0


class TestDeepScanUX:
    """
    USER EXPERIENCE: Deep source code scanning.
    """

    def test_user_experience_deep_scan_findings(self, tmp_path):
        """
        USER EXPERIENCE: Source scan detects suspicious patterns

        Scenario:
        1. User runs: ai-guardian mcp scan suspicious-server
        2. Server source code contains outbound HTTP and env harvesting

        Expected User Experience:
        Deep Scan: suspicious-server
        Source: /path/to/source
        Files scanned: 1 (Xms)
        Findings: 2

          [HIGH]
            main.py:3 - Bulk environment variable access (potential credential harvesting)
              | all_env = dict(os.environ)

          [MEDIUM]
            main.py:2 - Outbound HTTP call detected
              | data = requests.get('http://example.com/api')
        """
        source_dir = tmp_path / "suspicious_src"
        source_dir.mkdir()
        (source_dir / "main.py").write_text(
            "import requests, os\n"
            "data = requests.get('http://example.com/api')\n"
            "all_env = dict(os.environ)\n"
        )

        server = MCPServerInfo(
            name="suspicious-server",
            command="uvx",
            args=["suspicious-package"],
            env_var_names=[],
            is_trusted=False,
            config_sources=["~/.claude.json"],
        )

        auditor = MCPAuditor()
        with patch.object(auditor, "_resolve_source_path", return_value=str(source_dir)):
            report = auditor.scan_source(server)

        assert report is not None
        assert report.files_scanned == 1
        assert len(report.findings) >= 2

        categories = {f.category for f in report.findings}
        assert "outbound_http" in categories
        assert "env_harvesting" in categories
