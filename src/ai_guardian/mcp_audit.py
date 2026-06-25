"""
MCP Server Security Auditor for ai-guardian.

Scans MCP server configurations and source code for security issues:
credential leakage to untrusted servers, npx -y auto-install risks,
unpinned packages, suspicious URLs, and source code analysis.

Trust is derived from existing permissions.rules — any MCP server
with an allow rule is trusted. No separate trust list needed.

Usage:
    ai-guardian mcp list              # List servers with trust status
    ai-guardian mcp audit             # Config-only audit (fast)
    ai-guardian mcp scan [server]     # Deep source code scan

Issue #468
"""

import json
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from ai_guardian.language_patterns import SKIP_DIRS
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class MCPServerInfo:
    """Information about a discovered MCP server."""

    name: str
    command: str
    args: List[str]
    env_var_names: List[str]
    is_trusted: bool
    config_sources: List[str] = field(default_factory=list)


@dataclass
class AuditFinding:
    """A finding from config audit."""

    server_name: str
    severity: str  # critical, high, medium, low, info
    category: str
    message: str
    detail: Optional[str] = None


@dataclass
class ScanFinding:
    """A finding from deep source code scan."""

    server_name: str
    severity: str
    category: str
    file_path: str
    line_number: int
    message: str
    code_snippet: Optional[str] = None


@dataclass
class AuditReport:
    """Result of a config audit."""

    servers: List[MCPServerInfo]
    findings: List[AuditFinding]
    scan_time_ms: int


@dataclass
class ScanReport:
    """Result of a deep source code scan."""

    server_name: str
    source_path: str
    findings: List[ScanFinding]
    files_scanned: int
    scan_time_ms: int


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_CREDENTIAL_ENV_PATTERN = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API_KEY|APIKEY)", re.IGNORECASE
)

_SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"https?://localhost\b"),
    re.compile(r"https?://127\.0\.0\.1\b"),
    re.compile(r"https?://0\.0\.0\.0\b"),
    re.compile(r"ngrok\.io|ngrok-free\.app|localtunnel\.me|loca\.lt"),
]

_SCAN_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs"}

_MAX_LINES_PER_FILE = 10_000

# Deep scan patterns: (category, severity, regex, description)
_SOURCE_SCAN_PATTERNS = [
    (
        "outbound_http",
        "medium",
        re.compile(
            r"\b(requests\.(get|post|put|delete|patch|head)\b"
            r"|urllib\.request\.urlopen\b"
            r"|urllib3\b"
            r"|httpx\.(get|post|put|delete|patch)\b"
            r"|aiohttp\.ClientSession\b"
            r"|fetch\s*\("
            r"|http\.request\s*\("
            r"|axios\.(get|post|put|delete|patch)\b"
            r"|got\s*\()"
        ),
        "Outbound HTTP call detected",
    ),
    (
        "sensitive_file_read",
        "high",
        re.compile(
            r"""(~\/\.ssh|~\/\.aws|~\/\.gnupg|~\/\.kube|~\/\.docker"""
            r"""|\/etc\/shadow|\/etc\/passwd"""
            r"""|\.ssh\/id_rsa|\.ssh\/id_ed25519|\.ssh\/authorized_keys"""
            r"""|\.aws\/credentials|\.aws\/config"""
            r"""|\.npmrc|\.pypirc|\.netrc)"""
        ),
        "Access to sensitive file path",
    ),
    (
        "subprocess_exec",
        "high",
        re.compile(
            r"\b(subprocess\.(run|call|Popen|check_output|check_call)\s*\("
            r"|os\.system\s*\("
            r"|os\.popen\s*\("
            r"|eval\s*\("
            r"|exec\s*\("
            r"|child_process\.(exec|execSync|spawn|fork)\s*\()"
        ),
        "Subprocess or code execution call",
    ),
    (
        "base64_exfil",
        "medium",
        re.compile(
            r"\b(base64\.(b64encode|encodebytes|standard_b64encode)\s*\("
            r"|btoa\s*\("
            r"|Buffer\.from\s*\([^)]*,\s*['\"]base64['\"])"
        ),
        "Base64 encoding (potential exfiltration pattern)",
    ),
    (
        "env_harvesting",
        "high",
        re.compile(
            r"\b(dict\s*\(\s*os\.environ\s*\)"
            r"|os\.environ\.copy\s*\("
            r"|json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ"
            r"|Object\.keys\s*\(\s*process\.env\s*\)"
            r"|JSON\.stringify\s*\(\s*process\.env\s*\)"
            r"|\{?\s*\.\.\.\s*process\.env\s*\}?)"
        ),
        "Bulk environment variable access (potential credential harvesting)",
    ),
]


# ---------------------------------------------------------------------------
# MCPAuditor
# ---------------------------------------------------------------------------


class MCPAuditor:
    """Audits MCP server configurations and source code for security issues."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    # -- Server discovery --------------------------------------------------

    def discover_servers(self) -> List[MCPServerInfo]:
        """Discover MCP servers from IDE configuration files."""
        servers: Dict[str, MCPServerInfo] = {}
        config_paths = self._get_config_paths()

        for config_path in config_paths:
            path = Path(config_path).expanduser()
            if not path.exists():
                continue
            try:
                with open(path, "r") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                logger.debug("Could not read %s", path)
                continue

            mcp_servers = data.get("mcpServers", {})
            if not isinstance(mcp_servers, dict):
                continue

            for name, server_def in mcp_servers.items():
                if not isinstance(server_def, dict):
                    continue

                if name in servers:
                    servers[name].config_sources.append(str(path))
                    continue

                command = server_def.get("command", "")
                args = server_def.get("args", [])
                env = server_def.get("env", {})

                env_var_names = list(env.keys()) if isinstance(env, dict) else []
                is_trusted = self._check_trust(name)

                servers[name] = MCPServerInfo(
                    name=name,
                    command=str(command),
                    args=[str(a) for a in args] if isinstance(args, list) else [],
                    env_var_names=env_var_names,
                    is_trusted=is_trusted,
                    config_sources=[str(path)],
                )

        return list(servers.values())

    def _get_config_paths(self) -> List[str]:
        """Return list of IDE config file paths to check for MCP servers."""
        paths = []

        # Claude Code configs
        claude_config_dir = os.environ.get("CLAUDE_CONFIG_DIR", "")
        if claude_config_dir:
            paths.append(os.path.join(claude_config_dir, "settings.json"))
        paths.append("~/.claude.json")
        paths.append("~/.claude/settings.json")

        # Project-local Claude config
        project_local = Path.cwd() / ".claude" / "settings.json"
        if project_local.exists():
            paths.append(str(project_local))

        # Cursor
        paths.append("~/.cursor/mcp.json")

        # Windsurf
        paths.append("~/.windsurf/mcp.json")

        # Codex (project-local)
        codex_local = Path.cwd() / "codex.json"
        if codex_local.exists():
            paths.append(str(codex_local))

        return paths

    def _check_trust(self, server_name: str) -> bool:
        """Check if an MCP server is trusted via permissions.rules."""
        try:
            if not hasattr(self, "_policy_checker"):
                from ai_guardian.tool_policy import ToolPolicyChecker

                self._policy_checker = ToolPolicyChecker(
                    config=self.config if self.config else None
                )

            checker = self._policy_checker
            hook_data = {
                "tool_name": f"mcp__{server_name}__test",
                "parameters": {},
            }
            tp_logger = logging.getLogger("ai_guardian.tool_policy")
            original_level = tp_logger.level
            tp_logger.setLevel(logging.CRITICAL)
            try:
                allowed, _, _ = checker.check_tool_allowed(hook_data)
            finally:
                tp_logger.setLevel(original_level)
            return bool(allowed)
        except Exception:
            logger.debug("Could not check trust for %s", server_name)
            return False

    # -- Config audit ------------------------------------------------------

    def audit_config(
        self, servers: Optional[List[MCPServerInfo]] = None
    ) -> AuditReport:
        """Perform lightweight config audit on MCP server definitions."""
        start = time.monotonic()
        if servers is None:
            servers = self.discover_servers()

        findings: List[AuditFinding] = []

        for server in servers:
            findings.extend(self._audit_credentials(server))
            findings.extend(self._audit_npx(server))
            findings.extend(self._audit_unpinned(server))
            findings.extend(self._audit_urls(server))

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return AuditReport(servers=servers, findings=findings, scan_time_ms=elapsed_ms)

    def _audit_credentials(self, server: MCPServerInfo) -> List[AuditFinding]:
        if server.is_trusted:
            return []
        findings = []
        for var_name in server.env_var_names:
            if _CREDENTIAL_ENV_PATTERN.search(var_name):
                findings.append(
                    AuditFinding(
                        server_name=server.name,
                        severity="critical",
                        category="credential_exposure",
                        message=f"Credential env var '{var_name}' passed to untrusted server",
                        detail=(
                            f"Server '{server.name}' is not allowed in permissions.rules "
                            f"but receives credential-like env var '{var_name}'. "
                            f"Add an allow rule or remove the credential."
                        ),
                    )
                )
        return findings

    def _audit_npx(self, server: MCPServerInfo) -> List[AuditFinding]:
        findings = []
        if server.command != "npx":
            return findings
        if "-y" in server.args or "--yes" in server.args:
            if not server.is_trusted:
                findings.append(
                    AuditFinding(
                        server_name=server.name,
                        severity="medium",
                        category="npx_auto_install",
                        message="npx -y auto-installs package without review",
                        detail=(
                            f"Server '{server.name}' uses 'npx -y' which automatically "
                            f"downloads and runs a package. This is risky for untrusted servers. "
                            f"Consider pinning to a specific version or adding an allow rule."
                        ),
                    )
                )
        return findings

    def _audit_unpinned(self, server: MCPServerInfo) -> List[AuditFinding]:
        findings = []
        if server.command not in ("npx", "uvx"):
            return findings

        pkg_args = [a for a in server.args if not a.startswith("-")]
        for pkg in pkg_args:
            if pkg and "@" not in pkg:
                findings.append(
                    AuditFinding(
                        server_name=server.name,
                        severity="medium",
                        category="unpinned_version",
                        message=f"Package '{pkg}' has no version pin",
                        detail=(
                            f"Server '{server.name}' runs '{server.command} {pkg}' "
                            f"without a version pin. Use '{pkg}@<version>' to pin."
                        ),
                    )
                )
        return findings

    def _audit_urls(self, server: MCPServerInfo) -> List[AuditFinding]:
        findings = []
        all_args = " ".join(server.args)
        for pattern in _SUSPICIOUS_URL_PATTERNS:
            match = pattern.search(all_args)
            if match:
                findings.append(
                    AuditFinding(
                        server_name=server.name,
                        severity="high",
                        category="suspicious_url",
                        message=f"Suspicious URL in args: {match.group(0)}",
                        detail=(
                            f"Server '{server.name}' points to a suspicious URL. "
                            f"Raw IPs, localhost, and tunneling services may indicate "
                            f"data exfiltration or development-only configurations."
                        ),
                    )
                )
        return findings

    # -- Deep source scan --------------------------------------------------

    def scan_source(self, server: MCPServerInfo) -> Optional[ScanReport]:
        """Deep scan MCP server source code for suspicious patterns."""
        start = time.monotonic()
        source_path = self._resolve_source_path(server)
        if source_path is None:
            return None

        findings: List[ScanFinding] = []
        files_scanned = 0

        for root, dirs, files in os.walk(source_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = Path(fname).suffix
                if ext not in _SCAN_EXTENSIONS:
                    continue

                fpath = os.path.join(root, fname)
                files_scanned += 1
                try:
                    with open(fpath, "r", errors="replace") as f:
                        for line_num, line in enumerate(f, 1):
                            if line_num > _MAX_LINES_PER_FILE:
                                break
                            for (
                                category,
                                severity,
                                pattern,
                                desc,
                            ) in _SOURCE_SCAN_PATTERNS:
                                if pattern.search(line):
                                    rel_path = os.path.relpath(fpath, source_path)
                                    findings.append(
                                        ScanFinding(
                                            server_name=server.name,
                                            severity=severity,
                                            category=category,
                                            file_path=rel_path,
                                            line_number=line_num,
                                            message=desc,
                                            code_snippet=line.strip()[:120],
                                        )
                                    )
                except OSError:
                    logger.debug("Could not read %s", fpath)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return ScanReport(
            server_name=server.name,
            source_path=str(source_path),
            findings=findings,
            files_scanned=files_scanned,
            scan_time_ms=elapsed_ms,
        )

    def _resolve_source_path(self, server: MCPServerInfo) -> Optional[str]:
        """Try to find local source code for an MCP server."""
        cmd = server.command
        args = server.args

        # For python -m or python3 -m, try to find the module
        if cmd in ("python", "python3") and "-m" in args:
            idx = args.index("-m")
            if idx + 1 < len(args):
                module_name = args[idx + 1]
                return self._find_python_module_path(module_name)

        # For npx, try node_modules
        if cmd == "npx" and args:
            pkg_args = [a for a in args if not a.startswith("-")]
            if pkg_args:
                pkg_name = pkg_args[0].split("@")[0]
                return self._find_npx_package_path(pkg_name)

        # For uvx, try to find the installed package
        if cmd == "uvx" and args:
            pkg_args = [a for a in args if not a.startswith("-")]
            if pkg_args:
                pkg_name = pkg_args[0].split("@")[0]
                return self._find_uvx_package_path(pkg_name)

        # For direct commands, find binary and look for source
        binary_path = shutil.which(cmd)
        if binary_path:
            return self._find_source_from_binary(binary_path)

        return None

    def _find_python_module_path(self, module_name: str) -> Optional[str]:
        """Find installed Python module source path."""
        try:
            import importlib.util

            spec = importlib.util.find_spec(module_name)
            if spec and spec.origin:
                module_dir = Path(spec.origin).parent
                return str(module_dir)
        except (ModuleNotFoundError, ValueError):
            pass  # intentionally silent — optional dependency
        return None

    def _find_npx_package_path(self, pkg_name: str) -> Optional[str]:
        """Find npx package source in global or local node_modules."""
        search_paths = [
            Path.home() / ".npm" / "_npx",
            Path.cwd() / "node_modules" / pkg_name,
        ]
        for base in search_paths:
            if base.is_dir():
                for root, dirs, files in os.walk(base):
                    if "package.json" in files:
                        try:
                            with open(os.path.join(root, "package.json")) as f:
                                pkg_data = json.load(f)
                            if pkg_data.get("name") == pkg_name:
                                return root
                        except (json.JSONDecodeError, OSError) as e:
                            logger.warning("Failed to read config: %s", e)
                    if root.count(os.sep) - str(base).count(os.sep) > 3:
                        dirs.clear()
        return None

    def _find_uvx_package_path(self, pkg_name: str) -> Optional[str]:
        """Find uvx-installed package source."""
        # uvx installs into ~/.local/share/uv/tools/<pkg_name>/
        uv_tools = Path.home() / ".local" / "share" / "uv" / "tools" / pkg_name
        if uv_tools.is_dir():
            return str(uv_tools)
        return None

    def _find_source_from_binary(self, binary_path: str) -> Optional[str]:
        """Find source directory from a binary path."""
        bin_path = Path(binary_path).resolve()
        # Check if it's a Python script that imports a module
        try:
            with open(bin_path, "r") as f:
                first_lines = f.read(500)
            if "python" in first_lines[:50]:
                # Try to extract the module name from the script
                match = re.search(r"from\s+(\w+)", first_lines)
                if match:
                    return self._find_python_module_path(match.group(1))
        except (OSError, UnicodeDecodeError):
            pass  # intentionally silent — best-effort operation
        return None

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def ide_label(config_path: str) -> str:
        """Map a config file path to a human-readable IDE name."""
        p = config_path.replace("\\", "/")
        if ".claude.json" in p or ".claude/settings.json" in p or ".claude/" in p:
            return "Claude"
        if ".cursor/" in p:
            return "Cursor"
        if ".windsurf/" in p:
            return "Windsurf"
        if p.endswith("codex.json"):
            return "Codex"
        return "Unknown"

    # -- Output methods ----------------------------------------------------

    def print_server_list(
        self, servers: List[MCPServerInfo], verbose: bool = False
    ) -> None:
        """Print server list in human-readable format."""
        if not servers:
            print("No MCP servers found in IDE configuration files.")
            return

        print(f"\nMCP Servers ({len(servers)} found)\n")
        print(f"{'Server':<25} {'Command':<12} {'Trust':<12} {'Env Vars':<10}")
        print("-" * 59)

        for s in sorted(servers, key=lambda x: x.name):
            trust = "Trusted" if s.is_trusted else "Untrusted"
            cred_count = sum(
                1 for v in s.env_var_names if _CREDENTIAL_ENV_PATTERN.search(v)
            )
            env_info = str(len(s.env_var_names))
            if cred_count and not s.is_trusted:
                env_info += f" ({cred_count} credential)"

            print(f"{s.name:<25} {s.command:<12} {trust:<12} {env_info:<10}")

            if verbose:
                if s.args:
                    print(f"  args: {' '.join(s.args)}")
                if s.env_var_names:
                    print(f"  env:  {', '.join(s.env_var_names)}")
                sources_str = ", ".join(
                    f"{self.ide_label(p)}: {p}" for p in s.config_sources
                )
                print(f"  from: {sources_str}")

        print()

    def get_server_list_json(self, servers: List[MCPServerInfo]) -> str:
        """Return server list as JSON string."""
        data = [
            {
                "name": s.name,
                "command": s.command,
                "args": s.args,
                "env_var_names": s.env_var_names,
                "is_trusted": s.is_trusted,
                "config_sources": s.config_sources,
            }
            for s in servers
        ]
        return json.dumps(data, indent=2)

    def print_audit_report(self, report: AuditReport) -> None:
        """Print audit report in human-readable format."""
        trusted = sum(1 for s in report.servers if s.is_trusted)
        untrusted = len(report.servers) - trusted

        print(f"\nMCP Config Audit ({report.scan_time_ms}ms)\n")
        print(
            f"Servers: {len(report.servers)} total, {trusted} trusted, {untrusted} untrusted"
        )

        if not report.findings:
            print("\nNo issues found.\n")
            return

        print(f"Findings: {len(report.findings)}\n")

        by_severity = {}
        for f in report.findings:
            by_severity.setdefault(f.severity, []).append(f)

        for severity in ["critical", "high", "medium", "low", "info"]:
            items = by_severity.get(severity, [])
            if not items:
                continue
            label = severity.upper()
            print(f"  [{label}]")
            for finding in items:
                print(f"    {finding.server_name}: {finding.message}")
                if finding.detail:
                    for line in finding.detail.split(". "):
                        if line.strip():
                            print(f"      {line.strip()}.")
            print()

    def get_audit_report_json(self, report: AuditReport) -> str:
        """Return audit report as JSON string."""
        data = {
            "servers": len(report.servers),
            "trusted": sum(1 for s in report.servers if s.is_trusted),
            "untrusted": sum(1 for s in report.servers if not s.is_trusted),
            "scan_time_ms": report.scan_time_ms,
            "findings": [
                {
                    "server_name": f.server_name,
                    "severity": f.severity,
                    "category": f.category,
                    "message": f.message,
                    "detail": f.detail,
                }
                for f in report.findings
            ],
        }
        return json.dumps(data, indent=2)

    def print_scan_report(self, report: ScanReport) -> None:
        """Print deep scan report in human-readable format."""
        print(f"\nDeep Scan: {report.server_name}")
        print(f"Source: {report.source_path}")
        print(f"Files scanned: {report.files_scanned} ({report.scan_time_ms}ms)\n")

        if not report.findings:
            print("No suspicious patterns found.\n")
            return

        print(f"Findings: {len(report.findings)}\n")

        by_severity = {}
        for f in report.findings:
            by_severity.setdefault(f.severity, []).append(f)

        for severity in ["critical", "high", "medium", "low"]:
            items = by_severity.get(severity, [])
            if not items:
                continue
            label = severity.upper()
            print(f"  [{label}]")
            for finding in items:
                print(
                    f"    {finding.file_path}:{finding.line_number} - {finding.message}"
                )
                if finding.code_snippet:
                    print(f"      | {finding.code_snippet}")
            print()

    def get_scan_report_json(self, report: ScanReport) -> str:
        """Return deep scan report as JSON string."""
        data = {
            "server_name": report.server_name,
            "source_path": report.source_path,
            "files_scanned": report.files_scanned,
            "scan_time_ms": report.scan_time_ms,
            "findings": [
                {
                    "server_name": f.server_name,
                    "severity": f.severity,
                    "category": f.category,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "message": f.message,
                    "code_snippet": f.code_snippet,
                }
                for f in report.findings
            ],
        }
        return json.dumps(data, indent=2)
