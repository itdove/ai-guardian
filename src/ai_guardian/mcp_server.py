#!/usr/bin/env python3
"""
AI Guardian MCP Server — read-only security advisor for AI agents.

Exposes security check tools and information queries via the Model Context
Protocol (MCP). The AI can inspect everything, change nothing.

Principle: MCP server is a security advisor, not a security map.
It says yes/no — doesn't expose rules, patterns, or allowlists.

Usage:
    ai-guardian mcp-server              # Start via stdio transport

Issue #477
"""

import functools
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from mcp.server.fastmcp import FastMCP
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

DISABLED_RESPONSE = {
    "status": "disabled",
    "message": (
        "AI Guardian MCP is disabled. "
        "Enable via Console, tray, or: ai-guardian mcp enable"
    ),
}


def _load_mcp_config() -> Dict:
    """Load ai-guardian.json and return the mcp_server section."""
    from ai_guardian.config_utils import get_config_dir
    config_path = get_config_dir() / "ai-guardian.json"
    if not config_path.exists():
        config_path = Path.cwd() / ".ai-guardian.json"
    if not config_path.exists():
        return {}
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        return config.get("mcp_server", {})
    except Exception:
        return {}


def _is_mcp_enabled() -> bool:
    """Check if MCP server is enabled in config. Re-reads on every call."""
    mcp_config = _load_mcp_config()
    return mcp_config.get("enabled", False)


def _load_full_config() -> Optional[Dict]:
    """Load full ai-guardian.json config."""
    from ai_guardian.config_utils import get_config_dir
    config_path = get_config_dir() / "ai-guardian.json"
    if not config_path.exists():
        config_path = Path.cwd() / ".ai-guardian.json"
    if not config_path.exists():
        return None
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _disabled_check(func):
    """Decorator that returns disabled response when MCP is disabled."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not _is_mcp_enabled():
            return DISABLED_RESPONSE
        return func(*args, **kwargs)
    return wrapper


def _load_skill_instructions() -> str:
    """Load skill instructions to send during MCP initialization."""
    try:
        from importlib.resources import files as pkg_files
        skill_file = pkg_files("ai_guardian") / "skills" / "ai-guardian-security" / "SKILL.md"
        if hasattr(skill_file, "read_text"):
            content = skill_file.read_text()
            # Strip YAML frontmatter
            if content.startswith("---"):
                end = content.find("---", 3)
                if end != -1:
                    content = content[end + 3:].strip()
            return content
    except Exception:
        pass
    return (
        "AI Guardian security advisor. Use check_path before accessing unfamiliar files, "
        "check_command before running sensitive commands, sanitize_text before outputting "
        "sensitive content. Tools are advisory — hooks provide enforcement."
    )


def create_server() -> "FastMCP":
    """Create and configure the MCP server with all tools and resources."""
    server = FastMCP(
        "ai-guardian",
        instructions=_load_skill_instructions(),
        description="AI Guardian security advisor — read-only security checks and information",
    )

    # ─── Security Check Tools (proactive) ─────────────────────────

    @server.tool()
    @_disabled_check
    def check_path(path: str) -> Dict[str, str]:
        """Check if a file path is protected by directory rules. Call before Read/Write/Edit on unfamiliar paths. Returns allowed/denied/not_found so you can distinguish between protected paths and missing files."""
        try:
            resolved = Path(path).expanduser()
            if not resolved.exists():
                return {"status": "not_found"}

            from ai_guardian.tool_policy import ToolPolicyChecker
            checker = ToolPolicyChecker()
            hook_data = {
                "tool_name": "Write",
                "parameters": {"file_path": str(resolved)},
            }
            allowed, error_msg, _ = checker.check_tool_allowed(hook_data)
            if allowed:
                return {"status": "allowed"}
            return {"status": "denied"}
        except Exception as e:
            logger.error("check_path error: %s", e)
            return {"status": "error", "message": "Unable to check path"}

    @server.tool()
    @_disabled_check
    def check_command(command: str) -> Dict[str, str]:
        """Check if a Bash command would be blocked. Call before running commands with URLs or file paths. Results are advisory — hooks provide enforcement."""
        try:
            from ai_guardian.tool_policy import ToolPolicyChecker
            checker = ToolPolicyChecker()
            hook_data = {
                "tool_name": "Bash",
                "parameters": {"command": command},
            }
            allowed, error_msg, _ = checker.check_tool_allowed(hook_data)
            if allowed:
                return {"status": "allowed"}
            reason = "policy_denied"
            if error_msg:
                msg_lower = error_msg.lower()
                if "secret" in msg_lower:
                    reason = "secret_detected"
                elif "ssrf" in msg_lower:
                    reason = "ssrf_detected"
                elif "injection" in msg_lower:
                    reason = "prompt_injection"
                elif "directory" in msg_lower or "denied" in msg_lower:
                    reason = "directory_blocked"
            return {"status": "blocked", "reason": reason}
        except Exception as e:
            logger.error("check_command error: %s", e)
            return {"status": "error", "message": "Unable to check command"}

    @server.tool()
    @_disabled_check
    def check_mcp_trust(server_name: str) -> Dict[str, str]:
        """Check if an MCP server is trusted based on permission rules. Call before suggesting MCP server usage."""
        try:
            from ai_guardian.tool_policy import ToolPolicyChecker
            checker = ToolPolicyChecker()
            hook_data = {
                "tool_name": f"mcp__{server_name}__test",
                "parameters": {},
            }
            allowed, _, _ = checker.check_tool_allowed(hook_data)
            if allowed:
                return {"status": "trusted"}
            return {"status": "untrusted"}
        except Exception as e:
            logger.error("check_mcp_trust error: %s", e)
            return {"status": "error", "message": "Unable to check MCP trust"}

    @server.tool()
    @_disabled_check
    def sanitize_text(text: str) -> Dict[str, Any]:
        """Redact secrets and PII from text. Call before outputting potentially sensitive content."""
        try:
            from ai_guardian.sanitizer import sanitize_text as _sanitize
            result = _sanitize(text)
            return {
                "sanitized_text": result.get("sanitized_text", text),
                "redaction_count": result.get("stats", {}).get("total", 0),
                "types": [
                    k for k, v in result.get("stats", {}).items()
                    if k != "total" and isinstance(v, int) and v > 0
                ],
            }
        except Exception as e:
            logger.error("sanitize_text error: %s", e)
            return {"sanitized_text": text, "redaction_count": 0, "types": []}

    @server.tool()
    @_disabled_check
    def check_annotations(file_path: str) -> Dict[str, Any]:
        """Verify all begin/end-allow annotation pairs are matched in a file. Call after editing files with ai-guardian annotations."""
        try:
            from ai_guardian.annotations import process_annotations
            path = Path(file_path)
            if not path.exists():
                return {"valid": False, "warnings": [f"File not found: {file_path}"]}
            content = path.read_text(errors="replace")
            _, _, _, warnings = process_annotations(content, file_path)
            return {
                "valid": len(warnings) == 0,
                "warnings": warnings,
            }
        except Exception as e:
            logger.error("check_annotations error: %s", e)
            return {"valid": False, "warnings": [f"Error: {e}"]}

    # ─── Information Tools (query) ────────────────────────────────

    @server.tool()
    @_disabled_check
    def get_violations(
        violation_type: Optional[str] = None,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Get recent security violations. Filter by type (secret_detected, prompt_injection, directory_blocking, tool_permission, ssrf_blocked, config_file_exfil, pii_detected, jailbreak_detected)."""
        try:
            from ai_guardian.violation_logger import ViolationLogger
            vl = ViolationLogger()
            violations = vl.get_recent_violations(
                limit=min(limit, 100),
                violation_type=violation_type,
            )
            filtered = []
            for v in violations:
                blocked = v.get("blocked", {})
                if not isinstance(blocked, dict):
                    blocked = {}
                entry = {
                    "timestamp": v.get("timestamp", ""),
                    "type": v.get("violation_type", ""),
                    "severity": v.get("severity", ""),
                    "tool": v.get("context", {}).get("tool_name", ""),
                    "file": blocked.get("file_path", "") or v.get("context", {}).get("file_path", ""),
                    "action": "blocked" if v.get("blocked") else "logged",
                }
                if blocked.get("line_number"):
                    entry["line"] = blocked["line_number"]
                filtered.append(entry)
            return {"violations": filtered, "count": len(filtered)}
        except Exception as e:
            logger.error("get_violations error: %s", e)
            return {"violations": [], "count": 0}

    @server.tool()
    @_disabled_check
    def get_config() -> Dict[str, Any]:
        """Get current security posture summary. Returns feature enabled/disabled status only — no rules, patterns, or allowlists. Re-reads config on every call to reflect changes."""
        try:
            from ai_guardian.config_utils import is_feature_enabled
            config = _load_full_config() or {}
            features = {}

            feature_keys = [
                "secret_scanning", "scan_pii", "prompt_injection",
                "config_scanning", "violation_logging", "ssrf_protection",
                "secret_redaction", "transcript_scanning",
            ]
            for key in feature_keys:
                section = config.get(key, {})
                if isinstance(section, dict):
                    features[key] = is_feature_enabled(section.get("enabled", True))
                else:
                    features[key] = bool(section) if section is not None else True

            features["permissions"] = config.get("permissions", {}).get("enabled", True)

            action = config.get("action", "block")
            features["action_mode"] = action

            mcp_section = config.get("mcp_server", {})
            features["mcp_server"] = mcp_section.get("enabled", False)
            features["proactive_level"] = mcp_section.get("proactive_level", "low")

            return {"features": features}
        except Exception as e:
            logger.error("get_config error: %s", e)
            return {"features": {}}

    @server.tool()
    @_disabled_check
    def get_scanner_status() -> Dict[str, Any]:
        """Get installed scanner engines and their versions."""
        try:
            from ai_guardian.scanner_manager import ScannerManager
            sm = ScannerManager()
            installed = sm.list_installed()
            scanners = [
                {
                    "name": s.name,
                    "version": s.version,
                    "is_default": s.is_default,
                }
                for s in installed
            ]
            return {"scanners": scanners, "count": len(scanners)}
        except Exception as e:
            logger.error("get_scanner_status error: %s", e)
            return {"scanners": [], "count": 0}

    @server.tool()
    @_disabled_check
    def get_scanner_supported() -> Dict[str, Any]:
        """Get all supported scanner engines that can be installed."""
        try:
            from ai_guardian.scanner_manager import ScannerManager
            return {"scanners": list(ScannerManager.SUPPORTED_SCANNERS)}
        except Exception as e:
            logger.error("get_scanner_supported error: %s", e)
            return {"scanners": []}

    @server.tool()
    @_disabled_check
    def get_patterns_list() -> Dict[str, Any]:
        """Get active detection pattern categories and counts. Returns category names and pattern counts only — no regex patterns."""
        try:
            from ai_guardian.pattern_lister import PatternLister
            lister = PatternLister()
            categories = lister.get_categories()
            result = {}
            for cat in categories:
                count = sum(g.count for g in cat.built_in_groups)
                if count > 0:
                    result[cat.name] = count
            return {"categories": result}
        except Exception as e:
            logger.error("get_patterns_list error: %s", e)
            return {"categories": {}}

    @server.tool()
    @_disabled_check
    def get_metrics(since_days: Optional[int] = None) -> Dict[str, Any]:
        """Get violation statistics and trends. Optionally filter to last N days."""
        try:
            from ai_guardian.metrics import MetricsComputer
            mc = MetricsComputer(since_days=since_days)
            report = mc.compute()
            return {
                "total_violations": report.total_violations,
                "by_type": dict(report.by_type),
                "by_severity": dict(report.by_severity),
                "resolved": report.resolved_count,
                "unresolved": report.unresolved_count,
            }
        except Exception as e:
            logger.error("get_metrics error: %s", e)
            return {"total_violations": 0, "by_type": {}, "by_severity": {}}

    @server.tool()
    @_disabled_check
    def doctor() -> Dict[str, Any]:
        """Run health check on ai-guardian setup. Returns check results with pass/warn/fail status."""
        try:
            from ai_guardian.doctor import Doctor
            doc = Doctor()
            report = doc.run_all()
            checks = []
            for c in report.checks:
                entry = {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                }
                if c.status.value in ("warn", "fail"):
                    if c.detail:
                        entry["detail"] = c.detail
                    if c.fix_hint:
                        entry["fix_hint"] = c.fix_hint
                    entry["fixable"] = c.fixable
                checks.append(entry)
            return {
                "checks": checks,
                "has_errors": report.has_errors,
                "has_warnings": report.has_warnings,
            }
        except Exception as e:
            logger.error("doctor error: %s", e)
            return {"checks": [], "has_errors": True, "has_warnings": False}

    # ─── Support Bundle Tools ─────────────────────────────────────

    @server.tool()
    @_disabled_check
    def prepare_support_bundle() -> Dict[str, Any]:
        """Prepare a sanitized support bundle for review. Creates a temp directory (protected by .ai-read-deny) with sanitized copies of config, violations, metrics, doctor results, system info, and log. IMPORTANT: After calling this, you MUST (1) show the temp_path so the user can review and delete unwanted files, (2) present the file list with redaction counts, and (3) wait for the user to confirm before calling send_support_bundle. Only the user can access the temp directory — do not try to read or delete files in it."""
        try:
            from ai_guardian.support_bundle import prepare_bundle
            return prepare_bundle()
        except Exception as e:
            logger.error("prepare_support_bundle error: %s", e)
            return {"status": "error", "message": f"Failed to prepare bundle: {e}"}

    @server.tool()
    @_disabled_check
    def send_support_bundle(bundle_id: str) -> Dict[str, Any]:
        """Send a previously prepared support bundle to the preconfigured destination. Only call after the user has reviewed the temp directory, deleted any unwanted files, and explicitly approved sending. After sending, tell the user to contact support and give them the bundle_id as their reference number."""
        try:
            from ai_guardian.support_bundle import send_bundle
            return send_bundle(bundle_id)
        except Exception as e:
            logger.error("send_support_bundle error: %s", e)
            return {"status": "error", "message": f"Failed to send bundle: {e}"}

    # ─── Resources ────────────────────────────────────────────────

    @server.resource("ai-guardian://security-posture")
    def security_posture() -> str:
        """Summary of enabled security features, action modes, and scanner status."""
        try:
            features = get_config()
            scanners = get_scanner_status()
            result = {
                "features": features.get("features", {}),
                "scanners": scanners.get("scanners", []),
            }
            return json.dumps(result, indent=2)
        except Exception:
            return json.dumps({"error": "Unable to load security posture"})

    @server.resource("ai-guardian://protected-paths")
    def protected_paths() -> str:
        """List of directories with .ai-read-deny markers (paths only, no glob rules)."""
        try:
            from ai_guardian.config_utils import get_config_dir
            import os
            cwd = Path.cwd()
            protected = []
            for root, dirs, files in os.walk(cwd):
                if ".ai-read-deny" in files:
                    protected.append(str(Path(root).relative_to(cwd)))
                dirs[:] = [
                    d for d in dirs
                    if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}
                ]
            return json.dumps({"protected_directories": protected})
        except Exception:
            return json.dumps({"protected_directories": []})

    @server.resource("ai-guardian://recent-violations")
    def recent_violations() -> str:
        """Last 10 security violations with details."""
        try:
            result = get_violations(limit=10)
            return json.dumps(result, indent=2)
        except Exception:
            return json.dumps({"violations": [], "count": 0})

    return server


def run_mcp_server() -> int:
    """Start the MCP server via stdio transport. Called by CLI: ai-guardian mcp-server."""
    if not HAS_MCP:
        print(
            "Error: MCP SDK not available. Install with: pip install 'ai-guardian[mcp]' "
            "or pip install 'mcp>=1.8.0' (requires Python >=3.10)",
            file=sys.stderr,
        )
        return 1

    server = create_server()
    server.run(transport="stdio")
    return 0
