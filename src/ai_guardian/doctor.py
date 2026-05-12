#!/usr/bin/env python3
"""
AI Guardian Doctor — health check command.

Verifies the entire ai-guardian setup is working correctly.
One command to diagnose all common issues.

Usage:
    ai-guardian doctor              # Human-readable output
    ai-guardian doctor --json       # Machine-readable JSON
    ai-guardian doctor --fix        # Auto-fix what can be fixed
    ai-guardian doctor --quiet      # Exit codes only (0=ok, 1=warnings, 2=errors)
"""

import enum
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CheckStatus(enum.Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    message: str
    detail: Optional[str] = None
    fix_hint: Optional[str] = None
    fixable: bool = False
    fixed: bool = False


@dataclass
class DoctorReport:
    checks: List[CheckResult] = field(default_factory=list)
    version: str = ""

    @property
    def has_errors(self) -> bool:
        return any(c.status == CheckStatus.FAIL for c in self.checks)

    @property
    def has_warnings(self) -> bool:
        return any(c.status == CheckStatus.WARN for c in self.checks)

    @property
    def exit_code(self) -> int:
        if self.has_errors:
            return 2
        if self.has_warnings:
            return 1
        return 0


class Doctor:
    """Runs all health checks and produces a report."""

    def __init__(self, fix: bool = False, check_connectivity: bool = False):
        self.fix = fix
        self.check_connectivity = check_connectivity
        self._config: Optional[Dict] = None
        self._config_error: Optional[str] = None
        self._config_loaded = False

    def _ensure_config(self):
        if self._config_loaded:
            return
        self._config_loaded = True
        try:
            from ai_guardian import _load_config_file
            self._config, self._config_error = _load_config_file()
        except Exception as e:
            self._config_error = str(e)

    def run_all(self) -> DoctorReport:
        from ai_guardian import __version__
        self._ensure_config()
        report = DoctorReport(version=__version__)
        checks = [
            self.check_config_file,
            self.check_deprecated_fields,
            self.check_global_pattern_server,
            self.check_scanners,
            self.check_pattern_server,
            self.check_ps_cache_path,
            self.check_ps_auth,
            self.check_ps_url,
            self.check_ps_cache_freshness,
            self.check_hooks,
            self.check_state_dir,
            self.check_cache_dir,
            self.check_permissions,
            self.check_directory_rules,
            self.check_console_deps,
            self.check_gnome_tray_support,
            self.check_config_consistency,
            self.check_self_protection,
        ]
        for check_fn in checks:
            try:
                result = check_fn()
                report.checks.append(result)
            except Exception as e:
                fn_name = getattr(check_fn, "__name__", str(check_fn))
                report.checks.append(CheckResult(
                    name=fn_name.replace("check_", ""),
                    status=CheckStatus.FAIL,
                    message=f"Check crashed: {e}",
                ))
        return report

    def check_config_file(self) -> CheckResult:
        self._ensure_config()
        from ai_guardian.config_utils import get_config_dir

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            local_path = Path.cwd() / ".ai-guardian.json"
            if local_path.exists():
                config_path = local_path
            else:
                return CheckResult(
                    name="config_file",
                    status=CheckStatus.WARN,
                    message="No config file found (using defaults)",
                    fix_hint="Run: ai-guardian setup --create-config",
                )

        if self._config_error:
            return CheckResult(
                name="config_file",
                status=CheckStatus.FAIL,
                message=f"Config error: {self._config_error}",
                fix_hint="Fix the JSON syntax in your config file",
            )

        # Schema validation
        schema_errors = self._validate_config_schema(self._config or {})
        if schema_errors:
            detail = "\n".join(f"  - {e}" for e in schema_errors[:5])
            return CheckResult(
                name="config_file",
                status=CheckStatus.WARN,
                message=f"Config has {len(schema_errors)} schema warning(s)",
                detail=detail,
            )

        path_display = str(config_path).replace(str(Path.home()), "~")
        return CheckResult(
            name="config_file",
            status=CheckStatus.PASS,
            message=f"Valid config at {path_display}",
        )

    def _validate_config_schema(self, config: Dict) -> List[str]:
        try:
            from jsonschema import Draft7Validator
        except ImportError:
            return []

        schema_path = Path(__file__).parent / "schemas" / "ai-guardian-config.schema.json"
        if not schema_path.exists():
            return []

        try:
            with open(schema_path) as f:
                schema = json.load(f)
            validator = Draft7Validator(schema)
            return [e.message for e in validator.iter_errors(config)]
        except Exception:
            return []

    def check_deprecated_fields(self) -> CheckResult:
        self._ensure_config()
        if self._config is None:
            return CheckResult(
                name="deprecated_fields",
                status=CheckStatus.PASS,
                message="No config loaded (nothing to check)",
            )

        schema_path = Path(__file__).parent / "schemas" / "ai-guardian-config.schema.json"
        deprecated_keys = []
        try:
            with open(schema_path) as f:
                schema = json.load(f)
            for key, prop_schema in schema.get("properties", {}).items():
                if prop_schema.get("deprecated"):
                    deprecated_keys.append(key)
        except Exception:
            pass

        found = [k for k in deprecated_keys if k in self._config]
        if found:
            hints = {
                "pattern_server": "Run: ai-guardian setup --migrate-pattern-server",
                "directory_exclusions": "Migrate to 'directory_rules' format",
            }
            hint_parts = [hints.get(k, f"Remove '{k}'") for k in found]
            return CheckResult(
                name="deprecated_fields",
                status=CheckStatus.WARN,
                message=f"Deprecated field(s): {', '.join(found)}",
                fix_hint="; ".join(hint_parts),
            )

        return CheckResult(
            name="deprecated_fields",
            status=CheckStatus.PASS,
            message="No deprecated fields",
        )

    def check_global_pattern_server(self) -> CheckResult:
        """Check for deprecated global secret_scanning.pattern_server (Issue #530)."""
        self._ensure_config()
        if self._config is None:
            return CheckResult(
                name="global_pattern_server",
                status=CheckStatus.PASS,
                message="No config loaded",
            )

        ss = self._config.get("secret_scanning", {})
        if isinstance(ss, dict) and "pattern_server" in ss:
            ps = ss["pattern_server"]
            if ps is not None:
                if self.fix:
                    try:
                        from ai_guardian.setup import Setup
                        setup = Setup()
                        success, msg = setup.check_and_migrate_pattern_server(
                            dry_run=False, interactive=False
                        )
                        if success:
                            return CheckResult(
                                name="global_pattern_server",
                                status=CheckStatus.PASS,
                                message="Migrated to per-engine format",
                                fixable=True,
                                fixed=True,
                            )
                    except Exception as e:
                        return CheckResult(
                            name="global_pattern_server",
                            status=CheckStatus.WARN,
                            message=f"Migration failed: {e}",
                            fixable=True,
                        )

                return CheckResult(
                    name="global_pattern_server",
                    status=CheckStatus.WARN,
                    message="Deprecated: secret_scanning.pattern_server is global but only applies to gitleaks",
                    detail="Move to per-engine format: secret_scanning.engines[].pattern_server",
                    fix_hint="Run: ai-guardian doctor --fix  (or ai-guardian setup --migrate-pattern-server)",
                    fixable=True,
                )

        return CheckResult(
            name="global_pattern_server",
            status=CheckStatus.PASS,
            message="No global pattern_server (or using per-engine format)",
        )

    def check_scanners(self) -> CheckResult:
        try:
            from ai_guardian.scanner_manager import ScannerManager
        except ImportError:
            return CheckResult(
                name="scanners",
                status=CheckStatus.SKIP,
                message="Scanner manager not available",
            )

        manager = ScannerManager()
        installed = manager.list_installed()

        if not installed:
            return CheckResult(
                name="scanners",
                status=CheckStatus.FAIL,
                message="No scanners installed",
                fix_hint="Run: ai-guardian scanner install gitleaks",
            )

        names = [f"{s.name} {s.version}" for s in installed]
        unknown = [s for s in installed if s.version == "unknown"]
        if unknown:
            return CheckResult(
                name="scanners",
                status=CheckStatus.WARN,
                message=f"Installed: {', '.join(names)}",
                detail="Some scanners have unknown version",
            )

        return CheckResult(
            name="scanners",
            status=CheckStatus.PASS,
            message=", ".join(names),
        )

    def _get_ps_config(self) -> Optional[Dict]:
        """Extract pattern server config (per-engine, global, or root-level)."""
        self._ensure_config()
        if not self._config:
            return None
        ss = self._config.get("secret_scanning", {})
        if isinstance(ss, dict):
            # Priority 1: per-engine pattern_server
            for engine_spec in ss.get("engines", []):
                if isinstance(engine_spec, dict):
                    ps = engine_spec.get("pattern_server")
                    if isinstance(ps, dict) and ps.get("url"):
                        return ps
            # Priority 2: global secret_scanning.pattern_server (deprecated)
            if "pattern_server" in ss:
                ps = ss["pattern_server"]
                if isinstance(ps, dict) and ps.get("url"):
                    return ps
        # Priority 3: root-level pattern_server (deprecated)
        if "pattern_server" in self._config:
            ps = self._config["pattern_server"]
            if isinstance(ps, dict) and ps.get("url"):
                return ps
        return None

    def check_pattern_server(self) -> CheckResult:
        ps_config = self._get_ps_config()
        if not ps_config:
            return CheckResult(
                name="pattern_server",
                status=CheckStatus.SKIP,
                message="No pattern server configured",
            )
        return CheckResult(
            name="pattern_server",
            status=CheckStatus.PASS,
            message=f"Configured",
            detail=f"URL: {ps_config.get('url', 'unknown')}",
        )

    def check_ps_cache_path(self) -> CheckResult:
        ps_config = self._get_ps_config()
        if not ps_config:
            return CheckResult(
                name="ps_cache_path",
                status=CheckStatus.SKIP,
                message="No pattern server configured",
            )

        cache_config = ps_config.get("cache", {})
        if cache_config.get("path"):
            cache_dir = Path(cache_config["path"]).expanduser().parent
        else:
            from ai_guardian.config_utils import get_cache_dir
            cache_dir = get_cache_dir()

        if not cache_dir.exists():
            return CheckResult(
                name="ps_cache_path",
                status=CheckStatus.FAIL,
                message=f"{_tilde(cache_dir)} — does not exist",
                fix_hint="Run: ai-guardian doctor --fix  (or set cache.path / XDG_CACHE_HOME)",
                fixable=True,
            )

        if not os.access(cache_dir, os.W_OK):
            return CheckResult(
                name="ps_cache_path",
                status=CheckStatus.FAIL,
                message=f"{_tilde(cache_dir)} — not writable",
                fix_hint="Set cache.path to a writable location or set XDG_CACHE_HOME",
            )

        return CheckResult(
            name="ps_cache_path",
            status=CheckStatus.PASS,
            message=f"{_tilde(cache_dir)} (writable)",
        )

    def check_ps_auth(self) -> CheckResult:
        ps_config = self._get_ps_config()
        if not ps_config:
            return CheckResult(
                name="ps_auth",
                status=CheckStatus.SKIP,
                message="No pattern server configured",
            )

        auth_config = ps_config.get("auth", {})
        if not auth_config:
            return CheckResult(
                name="ps_auth",
                status=CheckStatus.SKIP,
                message="No auth configured (public server)",
            )

        token_env = auth_config.get("token_env", "AI_GUARDIAN_PATTERN_TOKEN")
        token_file = Path(auth_config.get("token_file", "~/.config/ai-guardian/pattern-token")).expanduser()

        if os.environ.get(token_env):
            return CheckResult(
                name="ps_auth",
                status=CheckStatus.PASS,
                message=f"Token found in ${token_env}",
            )

        if token_file.exists():
            try:
                content = token_file.read_text().strip()
                if content:
                    return CheckResult(
                        name="ps_auth",
                        status=CheckStatus.PASS,
                        message=f"Token found in {_tilde(token_file)}",
                    )
            except Exception:
                pass

        return CheckResult(
            name="ps_auth",
            status=CheckStatus.FAIL,
            message="Token not set",
            fix_hint=f"export {token_env}=your-token",
        )

    def check_ps_url(self) -> CheckResult:
        ps_config = self._get_ps_config()
        if not ps_config:
            return CheckResult(
                name="ps_url",
                status=CheckStatus.SKIP,
                message="No pattern server configured",
            )

        if not self.check_connectivity:
            return CheckResult(
                name="ps_url",
                status=CheckStatus.SKIP,
                message="Skipped (use --check-connectivity)",
            )

        url = ps_config.get("url", "").rstrip("/")
        endpoint = ps_config.get("patterns_endpoint", "/patterns/gitleaks/8.18.1")
        full_url = f"{url}{endpoint}"

        if full_url.startswith("http://"):
            return CheckResult(
                name="ps_url",
                status=CheckStatus.FAIL,
                message="HTTP not allowed (use HTTPS)",
                fix_hint="Change pattern server URL to https://",
            )

        try:
            import requests as req
        except ImportError:
            return CheckResult(
                name="ps_url",
                status=CheckStatus.FAIL,
                message="requests library not installed",
                fix_hint="pip install requests",
            )

        headers = {"User-Agent": "ai-guardian/doctor"}
        auth_config = ps_config.get("auth", {})
        token_env = auth_config.get("token_env", "AI_GUARDIAN_PATTERN_TOKEN")
        token = os.environ.get(token_env)
        if not token:
            token_file = Path(auth_config.get("token_file", "~/.config/ai-guardian/pattern-token")).expanduser()
            if token_file.exists():
                try:
                    token = token_file.read_text().strip()
                except Exception:
                    pass
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            resp = req.get(full_url, headers=headers, timeout=10, verify=True)
        except req.exceptions.Timeout:
            return CheckResult(
                name="ps_url",
                status=CheckStatus.WARN,
                message=f"Timeout ({url})",
                fix_hint="Using cached patterns if available",
            )
        except req.exceptions.ConnectionError:
            return CheckResult(
                name="ps_url",
                status=CheckStatus.FAIL,
                message=f"Connection failed ({url})",
            )
        except Exception as e:
            return CheckResult(
                name="ps_url",
                status=CheckStatus.FAIL,
                message=f"Error: {e}",
            )

        if resp.status_code == 401:
            return CheckResult(
                name="ps_url",
                status=CheckStatus.FAIL,
                message="401 Unauthorized",
                fix_hint=f"export {token_env}=your-token",
            )
        if resp.status_code != 200:
            return CheckResult(
                name="ps_url",
                status=CheckStatus.FAIL,
                message=f"{resp.status_code} from {url}",
            )

        rule_count = self._count_toml_rules(resp.text)
        msg = f"{url} (200 OK"
        if rule_count is not None:
            msg += f", {rule_count} rules"
        msg += ")"

        return CheckResult(
            name="ps_url",
            status=CheckStatus.PASS,
            message=msg,
        )

    def _count_toml_rules(self, text: str) -> Optional[int]:
        """Count rules in a TOML response (best effort)."""
        try:
            if sys.version_info >= (3, 11):
                import tomllib
            else:
                import tomli as tomllib  # type: ignore
            data = tomllib.loads(text)
            rules = data.get("rules", [])
            if isinstance(rules, list):
                return len(rules)
        except Exception:
            pass
        return None

    def check_ps_cache_freshness(self) -> CheckResult:
        ps_config = self._get_ps_config()
        if not ps_config:
            return CheckResult(
                name="ps_cache_freshness",
                status=CheckStatus.SKIP,
                message="No pattern server configured",
            )

        cache_config = ps_config.get("cache", {})
        if cache_config.get("path"):
            cache_file = Path(cache_config["path"]).expanduser()
        else:
            from ai_guardian.config_utils import get_cache_dir
            cache_file = get_cache_dir() / "patterns.toml"

        if not cache_file.exists():
            return CheckResult(
                name="ps_cache_freshness",
                status=CheckStatus.WARN,
                message="No cached patterns",
                fix_hint="Patterns will be fetched on next scan",
            )

        age_seconds = time.time() - cache_file.stat().st_mtime
        age_days = age_seconds / 86400

        expire_hours = cache_config.get("expire_after_hours", 168)
        expire_days = expire_hours / 24

        rule_count = None
        try:
            content = cache_file.read_text()
            rule_count = self._count_toml_rules(content)
        except Exception:
            pass

        age_str = f"{int(age_days)} days old" if age_days >= 1 else "< 1 day old"
        rule_str = f", {rule_count} rules" if rule_count is not None else ""

        if age_days > expire_days:
            return CheckResult(
                name="ps_cache_freshness",
                status=CheckStatus.FAIL,
                message=f"Expired ({age_str}{rule_str})",
                fix_hint="Refresh failed — check URL and auth settings",
            )

        refresh_hours = cache_config.get("refresh_interval_hours", 12)
        refresh_days = refresh_hours / 24

        if age_days > refresh_days:
            return CheckResult(
                name="ps_cache_freshness",
                status=CheckStatus.WARN,
                message=f"Stale ({age_str}{rule_str})",
                fix_hint="Patterns will refresh on next scan",
            )

        return CheckResult(
            name="ps_cache_freshness",
            status=CheckStatus.PASS,
            message=f"{cache_file.name} ({age_str}{rule_str})",
        )

    def check_hooks(self) -> CheckResult:
        try:
            from ai_guardian.setup import IDESetup
        except ImportError:
            return CheckResult(
                name="hooks",
                status=CheckStatus.SKIP,
                message="Setup module not available",
            )

        setup = IDESetup()
        detected = setup.list_detected_ides()

        if not detected:
            return CheckResult(
                name="hooks",
                status=CheckStatus.WARN,
                message="No IDEs detected",
                fix_hint="Install Claude Code, Cursor, or GitHub Copilot",
            )

        results = []
        all_configured = True
        any_configured = False

        for ide_type in detected:
            config_path = Path(setup.get_config_path(ide_type)).expanduser()
            ide_name = setup.IDE_CONFIGS[ide_type]["name"]

            if not config_path.exists():
                results.append(f"{ide_name}: no config file")
                all_configured = False
                continue

            configured = setup.check_hooks_configured(config_path, ide_type)
            if configured:
                # For Claude Code, check which hooks are present
                if ide_type == "claude":
                    hook_count = self._count_claude_hooks(config_path)
                    results.append(f"{ide_name}: {hook_count}/3 hooks")
                    if hook_count < 3:
                        all_configured = False
                else:
                    results.append(f"{ide_name}: configured")
                any_configured = True
            else:
                results.append(f"{ide_name}: not configured")
                all_configured = False

        detail = "; ".join(results)

        if all_configured:
            return CheckResult(
                name="hooks",
                status=CheckStatus.PASS,
                message=detail,
            )
        elif any_configured:
            return CheckResult(
                name="hooks",
                status=CheckStatus.WARN,
                message=detail,
                fix_hint="Run: ai-guardian setup",
            )
        else:
            return CheckResult(
                name="hooks",
                status=CheckStatus.FAIL,
                message=detail,
                fix_hint="Run: ai-guardian setup",
            )

    def _count_claude_hooks(self, config_path: Path) -> int:
        try:
            with open(config_path) as f:
                config = json.load(f)
            hooks = config.get("hooks", {})
            count = 0
            for hook_name in ["UserPromptSubmit", "PreToolUse", "PostToolUse"]:
                if hook_name in hooks:
                    hook_list = hooks[hook_name]
                    if isinstance(hook_list, list):
                        for entry in hook_list:
                            if isinstance(entry, dict) and "hooks" in entry:
                                for h in entry["hooks"]:
                                    if isinstance(h, dict) and h.get("command") == "ai-guardian":
                                        count += 1
                                        break
            return count
        except Exception:
            return 0

    def check_state_dir(self) -> CheckResult:
        from ai_guardian.config_utils import get_state_dir, get_config_dir

        state_dir = get_state_dir()
        config_dir = get_config_dir()

        if not state_dir.exists():
            if self.fix:
                try:
                    state_dir.mkdir(parents=True, exist_ok=True)
                    return CheckResult(
                        name="state_dir",
                        status=CheckStatus.PASS,
                        message=f"Created {_tilde(state_dir)}",
                        fixable=True,
                        fixed=True,
                    )
                except OSError as e:
                    return CheckResult(
                        name="state_dir",
                        status=CheckStatus.FAIL,
                        message=f"Cannot create: {e}",
                        fixable=True,
                    )
            return CheckResult(
                name="state_dir",
                status=CheckStatus.WARN,
                message=f"Missing: {_tilde(state_dir)}",
                fix_hint="Run: ai-guardian doctor --fix",
                fixable=True,
            )

        if not os.access(state_dir, os.W_OK):
            return CheckResult(
                name="state_dir",
                status=CheckStatus.FAIL,
                message=f"Not writable: {_tilde(state_dir)}",
            )

        # Check for old location files
        if config_dir != state_dir:
            old_files = [f for f in ["violations.jsonl", "ai-guardian.log"]
                         if (config_dir / f).exists()]
            if old_files:
                if self.fix:
                    from ai_guardian.config_utils import migrate_state_files
                    migrate_state_files()
                    # Remove old files after successful migration
                    removed = []
                    for f in old_files:
                        old_path = config_dir / f
                        new_path = state_dir / f
                        if new_path.exists() and old_path.exists():
                            try:
                                old_path.unlink()
                                removed.append(f)
                            except OSError:
                                pass
                    return CheckResult(
                        name="state_dir",
                        status=CheckStatus.PASS,
                        message=f"OK ({_tilde(state_dir)}), migrated old files",
                        fixable=True,
                        fixed=True,
                    )
                return CheckResult(
                    name="state_dir",
                    status=CheckStatus.WARN,
                    message=f"Old files in config dir: {', '.join(old_files)}",
                    fix_hint="Run: ai-guardian doctor --fix",
                    fixable=True,
                )

        # Count violations
        violations_file = state_dir / "violations.jsonl"
        detail = None
        if violations_file.exists():
            try:
                count = sum(1 for _ in open(violations_file))
                detail = f"{count} violations logged"
            except Exception:
                pass

        return CheckResult(
            name="state_dir",
            status=CheckStatus.PASS,
            message=f"OK ({_tilde(state_dir)})",
            detail=detail,
        )

    def check_cache_dir(self) -> CheckResult:
        from ai_guardian.config_utils import get_cache_dir

        cache_dir = get_cache_dir()

        if not cache_dir.exists():
            if self.fix:
                try:
                    cache_dir.mkdir(parents=True, exist_ok=True)
                    return CheckResult(
                        name="cache_dir",
                        status=CheckStatus.PASS,
                        message=f"Created {_tilde(cache_dir)}",
                        fixable=True,
                        fixed=True,
                    )
                except OSError as e:
                    return CheckResult(
                        name="cache_dir",
                        status=CheckStatus.FAIL,
                        message=f"Cannot create: {e}",
                        fixable=True,
                    )
            return CheckResult(
                name="cache_dir",
                status=CheckStatus.WARN,
                message=f"Missing: {_tilde(cache_dir)}",
                fix_hint="Run: ai-guardian doctor --fix",
                fixable=True,
            )

        if not os.access(cache_dir, os.W_OK):
            return CheckResult(
                name="cache_dir",
                status=CheckStatus.FAIL,
                message=f"Not writable: {_tilde(cache_dir)}",
            )

        # Check pattern cache freshness
        patterns_file = cache_dir / "patterns.toml"
        if patterns_file.exists():
            age_days = (time.time() - patterns_file.stat().st_mtime) / 86400
            if age_days > 7:
                return CheckResult(
                    name="cache_dir",
                    status=CheckStatus.WARN,
                    message=f"Pattern cache stale ({int(age_days)}d old)",
                )
            return CheckResult(
                name="cache_dir",
                status=CheckStatus.PASS,
                message=f"OK, patterns fresh ({int(age_days)}d old)",
            )

        return CheckResult(
            name="cache_dir",
            status=CheckStatus.PASS,
            message=f"OK ({_tilde(cache_dir)})",
        )

    def check_permissions(self) -> CheckResult:
        self._ensure_config()
        if self._config is None:
            return CheckResult(
                name="permissions",
                status=CheckStatus.WARN,
                message="No config loaded",
            )

        perms = self._config.get("permissions")
        if not isinstance(perms, dict):
            return CheckResult(
                name="permissions",
                status=CheckStatus.WARN,
                message="No permissions section configured",
            )

        rules = perms.get("rules", [])
        if not isinstance(rules, list) or len(rules) == 0:
            return CheckResult(
                name="permissions",
                status=CheckStatus.WARN,
                message="No permission rules defined",
            )

        # Validate rule structure
        invalid = []
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                invalid.append(f"Rule {i}: not a dict")
                continue
            if "matcher" not in rule:
                invalid.append(f"Rule {i}: missing 'matcher'")

        if invalid:
            return CheckResult(
                name="permissions",
                status=CheckStatus.FAIL,
                message=f"{len(invalid)} invalid rule(s)",
                detail="\n".join(f"  - {e}" for e in invalid[:5]),
            )

        return CheckResult(
            name="permissions",
            status=CheckStatus.PASS,
            message=f"{len(rules)} rule(s) configured",
        )

    def check_directory_rules(self) -> CheckResult:
        self._ensure_config()
        if self._config is None:
            return CheckResult(
                name="directory_rules",
                status=CheckStatus.WARN,
                message="No config loaded",
            )

        dir_rules = self._config.get("directory_rules")

        # Handle both array and object formats
        rules_list = []
        if isinstance(dir_rules, list):
            rules_list = dir_rules
        elif isinstance(dir_rules, dict):
            rules_list = dir_rules.get("rules", [])

        if not rules_list:
            return CheckResult(
                name="directory_rules",
                status=CheckStatus.PASS,
                message="No directory rules configured (using defaults)",
            )

        # Validate structure — rules can use "pattern", "paths", or "path"
        invalid = []
        user_count = 0
        generated_count = 0
        for i, rule in enumerate(rules_list):
            if not isinstance(rule, dict):
                invalid.append(f"Rule {i}: not a dict")
                continue
            has_target = any(k in rule for k in ("pattern", "paths", "path"))
            if not has_target:
                invalid.append(f"Rule {i}: missing 'pattern' or 'paths'")
            if rule.get("_generated"):
                generated_count += 1
            else:
                user_count += 1

        if invalid:
            return CheckResult(
                name="directory_rules",
                status=CheckStatus.FAIL,
                message=f"{len(invalid)} invalid rule(s)",
                detail="\n".join(f"  - {e}" for e in invalid[:5]),
            )

        return CheckResult(
            name="directory_rules",
            status=CheckStatus.PASS,
            message=f"{user_count} user, {generated_count} generated rule(s)",
        )

    def check_console_deps(self) -> CheckResult:
        missing = []

        try:
            import textual  # noqa: F401
        except ImportError:
            missing.append("textual")

        try:
            import tree_sitter  # noqa: F401
        except ImportError:
            missing.append("tree-sitter")

        try:
            import tree_sitter_json  # noqa: F401
        except ImportError:
            missing.append("tree-sitter-json")

        if missing:
            return CheckResult(
                name="console_deps",
                status=CheckStatus.WARN,
                message=f"Missing: {', '.join(missing)}",
                fix_hint=f"pip install {' '.join(missing)}",
            )

        return CheckResult(
            name="console_deps",
            status=CheckStatus.PASS,
            message="All console dependencies installed",
        )

    def check_config_consistency(self) -> CheckResult:
        schema_path = Path(__file__).parent / "schemas" / "ai-guardian-config.schema.json"
        if not schema_path.exists():
            return CheckResult(
                name="config_consistency",
                status=CheckStatus.SKIP,
                message="Schema file not found",
            )

        try:
            with open(schema_path) as f:
                schema = json.load(f)
        except Exception:
            return CheckResult(
                name="config_consistency",
                status=CheckStatus.SKIP,
                message="Cannot load schema",
            )

        # Check that all properties with defaults are consistent
        mismatches = []
        props = schema.get("properties", {})
        for key, prop_schema in props.items():
            if "default" in prop_schema and "type" in prop_schema:
                default_val = prop_schema["default"]
                expected_type = prop_schema["type"]
                type_map = {
                    "boolean": bool, "string": str, "integer": int,
                    "number": (int, float), "object": dict, "array": list,
                }
                py_type = type_map.get(expected_type)
                if py_type and not isinstance(default_val, py_type):
                    mismatches.append(f"{key}: default type mismatch")

        if mismatches:
            return CheckResult(
                name="config_consistency",
                status=CheckStatus.WARN,
                message=f"{len(mismatches)} mismatch(es)",
                detail="\n".join(f"  - {m}" for m in mismatches),
            )

        return CheckResult(
            name="config_consistency",
            status=CheckStatus.PASS,
            message="Schema defaults consistent",
        )

    def check_gnome_tray_support(self) -> CheckResult:
        """Check if GNOME has AppIndicator extension for system tray icon."""
        if platform.system() != "Linux":
            return CheckResult(
                name="gnome_tray",
                status=CheckStatus.SKIP,
                message="Not Linux",
            )

        desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
        if "GNOME" not in desktop.upper():
            return CheckResult(
                name="gnome_tray",
                status=CheckStatus.SKIP,
                message=f"Not GNOME ({desktop or 'unknown'})",
            )

        if not shutil.which("gnome-extensions"):
            return CheckResult(
                name="gnome_tray",
                status=CheckStatus.SKIP,
                message="gnome-extensions command not found",
            )

        try:
            result = subprocess.run(
                ["gnome-extensions", "list", "--enabled"],
                capture_output=True, text=True, timeout=5,
            )
            if "appindicatorsupport@rgcjonas.gmail.com" in result.stdout:
                return CheckResult(
                    name="gnome_tray",
                    status=CheckStatus.PASS,
                    message="AppIndicator extension enabled",
                )
        except (subprocess.TimeoutExpired, OSError):
            return CheckResult(
                name="gnome_tray",
                status=CheckStatus.SKIP,
                message="Could not query GNOME extensions",
            )

        return CheckResult(
            name="gnome_tray",
            status=CheckStatus.WARN,
            message="GNOME detected — AppIndicator extension required for tray icon",
            fix_hint=(
                "sudo dnf install gnome-shell-extension-appindicator.noarch && "
                "log out/in, then: gnome-extensions enable "
                "appindicatorsupport@rgcjonas.gmail.com"
            ),
        )

    def check_self_protection(self) -> CheckResult:
        """Verify immutable patterns protect config/state/cache from agent Read access."""
        from ai_guardian.tool_policy import IMMUTABLE_DENY_PATTERNS

        issues = []

        read_patterns = IMMUTABLE_DENY_PATTERNS.get("Read", [])
        if not read_patterns:
            issues.append("No Read patterns defined")
        else:
            for required in [
                "*/.config/ai-guardian/*",
                "*/.local/state/ai-guardian/*",
                "*/.cache/ai-guardian/*",
            ]:
                if required not in read_patterns:
                    issues.append(f"Missing Read pattern: {required}")

        bash_patterns = IMMUTABLE_DENY_PATTERNS.get("Bash", [])
        for required in [
            "*cat*/.config/ai-guardian/*",
            "*cat*/.local/state/ai-guardian/*",
        ]:
            if required not in bash_patterns:
                issues.append(f"Missing Bash pattern: {required}")

        if issues:
            return CheckResult(
                name="self_protection",
                status=CheckStatus.FAIL,
                message=f"{len(issues)} gap(s) in agent read protection",
                detail="\n".join(f"  - {i}" for i in issues),
            )

        return CheckResult(
            name="self_protection",
            status=CheckStatus.PASS,
            message="Config, state, cache read-protected from agent",
        )


# --- Output formatters ---

_STATUS_LABELS = {
    CheckStatus.PASS: "PASS",
    CheckStatus.WARN: "WARN",
    CheckStatus.FAIL: "FAIL",
    CheckStatus.SKIP: "SKIP",
}

_STATUS_COLORS = {
    CheckStatus.PASS: "\033[32m",  # green
    CheckStatus.WARN: "\033[33m",  # yellow
    CheckStatus.FAIL: "\033[31m",  # red
    CheckStatus.SKIP: "\033[90m",  # gray
}

_RESET = "\033[0m"

_CHECK_DISPLAY_NAMES = {
    "config_file": "Config file",
    "deprecated_fields": "Deprecated fields",
    "scanners": "Scanners",
    "pattern_server": "Pattern server",
    "ps_cache_path": "PS cache path",
    "ps_auth": "PS auth",
    "ps_url": "PS URL",
    "ps_cache_freshness": "PS cache freshness",
    "hooks": "Hooks",
    "state_dir": "State directory",
    "cache_dir": "Cache directory",
    "permissions": "Permissions",
    "directory_rules": "Directory rules",
    "console_deps": "Console deps",
    "gnome_tray": "System tray",
    "config_consistency": "Config consistency",
    "self_protection": "Self-protection",
}


def format_human(report: DoctorReport) -> str:
    use_color = sys.stdout.isatty()
    lines = [f"ai-guardian doctor v{report.version}", ""]

    for check in report.checks:
        label = _STATUS_LABELS[check.status]
        display_name = _CHECK_DISPLAY_NAMES.get(check.name, check.name)

        if use_color:
            color = _STATUS_COLORS[check.status]
            status_str = f"{color}[{label}]{_RESET}"
        else:
            status_str = f"[{label}]"

        line = f"  {status_str} {display_name:<20s} {check.message}"
        lines.append(line)

        if check.detail:
            for detail_line in check.detail.split("\n"):
                lines.append(f"       {' ' * 20} {detail_line}")

        if check.fix_hint:
            prefix = "Fixed" if check.fixed else "Hint"
            lines.append(f"       {' ' * 20} {prefix}: {check.fix_hint}")

    # Summary
    pass_count = sum(1 for c in report.checks if c.status == CheckStatus.PASS)
    warn_count = sum(1 for c in report.checks if c.status == CheckStatus.WARN)
    fail_count = sum(1 for c in report.checks if c.status == CheckStatus.FAIL)
    skip_count = sum(1 for c in report.checks if c.status == CheckStatus.SKIP)
    fixed_count = sum(1 for c in report.checks if c.fixed)

    parts = []
    if pass_count:
        parts.append(f"{pass_count} passed")
    if warn_count:
        parts.append(f"{warn_count} warning(s)")
    if fail_count:
        parts.append(f"{fail_count} error(s)")
    if skip_count:
        parts.append(f"{skip_count} skipped")
    if fixed_count:
        parts.append(f"{fixed_count} fixed")

    lines.append("")
    lines.append(f"  {', '.join(parts)}")

    return "\n".join(lines)


def format_json(report: DoctorReport) -> str:
    checks_data = []
    for check in report.checks:
        checks_data.append({
            "name": check.name,
            "status": check.status.value,
            "message": check.message,
            "detail": check.detail,
            "fix_hint": check.fix_hint,
            "fixable": check.fixable,
            "fixed": check.fixed,
        })

    pass_count = sum(1 for c in report.checks if c.status == CheckStatus.PASS)
    warn_count = sum(1 for c in report.checks if c.status == CheckStatus.WARN)
    fail_count = sum(1 for c in report.checks if c.status == CheckStatus.FAIL)
    skip_count = sum(1 for c in report.checks if c.status == CheckStatus.SKIP)
    fixed_count = sum(1 for c in report.checks if c.fixed)

    output = {
        "version": report.version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(report.checks),
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
            "skip": skip_count,
            "fixed": fixed_count,
        },
        "checks": checks_data,
    }

    return json.dumps(output, indent=2)


# --- Helpers ---

def _tilde(path: Path) -> str:
    """Replace home directory with ~ for display."""
    try:
        return str(path).replace(str(Path.home()), "~")
    except Exception:
        return str(path)


# --- CLI entry point ---

def doctor_command(args) -> int:
    doctor = Doctor(
        fix=getattr(args, "fix", False),
        check_connectivity=getattr(args, "check_connectivity", False),
    )
    report = doctor.run_all()

    if getattr(args, "quiet", False):
        return report.exit_code

    if getattr(args, "json", False):
        print(format_json(report))
    else:
        print(format_human(report))

    return report.exit_code
