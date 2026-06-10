"""
Configuration loading functions for AI Guardian.

Handles loading and caching of ai-guardian.json configuration sections.
All _load_*_config() functions share a single mtime-based cache to avoid
redundant file reads within the same hook invocation.
"""

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple, Any

from ai_guardian.config_utils import (
    get_config_dir,
    get_project_config_path,
    _clear_project_config_cache,
    deep_merge,
    is_feature_enabled,
)

try:
    from ai_guardian import aiguardignore as _aiguardignore_cfg
    HAS_AIGUARDIGNORE = True
except ImportError:
    HAS_AIGUARDIGNORE = False

logger = logging.getLogger(__name__)


def _merge_aiguardignore(scanner_config, scanner_type):
    """Merge .aiguardignore.toml paths into a scanner config dict's ignore_files."""
    if not HAS_AIGUARDIGNORE:
        return scanner_config
    extra = _aiguardignore_cfg.get_ignore_paths(scanner_type)
    if not extra:
        return scanner_config
    if scanner_config is None:
        return {"ignore_files": list(extra)}
    result = dict(scanner_config)
    result["ignore_files"] = list(result.get("ignore_files", [])) + list(extra)
    return result


@dataclass
class _ConfigCacheEntry:
    """Cached config state to avoid redundant file reads."""
    result: Any = None  # (config_dict, error_msg) tuple or None
    global_mtime: Optional[float] = None
    project_mtime: Optional[float] = None
    global_path: Optional[Path] = None
    project_path: Optional[Path] = None


_cache = _ConfigCacheEntry()


def _clear_config_cache():
    """Clear the config file cache, forcing a re-read on next call."""
    global _cache
    _cache = _ConfigCacheEntry()
    _clear_project_config_cache()


def _get_mtime(path):
    """Get file mtime, or None if the file doesn't exist."""
    if not path:
        return None
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _normalize_permissions(config):
    """Normalize old list-format permissions to new dict format before merge.

    Converts ``"permissions": [...]`` (deprecated) to
    ``"permissions": {"enabled": true, "rules": [...]}``.
    """
    if config is None:
        return config
    permissions = config.get("permissions")
    if isinstance(permissions, list):
        logger.warning(
            "DEPRECATED: permissions as array format detected. "
            "Update to: {\"permissions\": {\"enabled\": true, \"rules\": [...]}}"
        )
        config = dict(config)
        config["permissions"] = {
            "enabled": True,
            "rules": permissions,
        }
    return config


def _load_config_file():
    """
    Load ai-guardian.json configuration with project-level overlay.

    Loads the global config from ``~/.config/ai-guardian/ai-guardian.json``
    and, if present, merges a project-level ``ai-guardian.json`` from the
    repository root on top of it.  Project config wins for non-immutable,
    non-global-only fields.

    Uses mtime-based caching to avoid redundant file reads when multiple
    _load_*_config() functions are called within the same hook invocation.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    global _cache

    try:
        # Resolve paths
        config_dir = get_config_dir()
        global_path = config_dir / "ai-guardian.json"

        if _get_mtime(global_path) is None:
            global_path = None

        project_path = get_project_config_path()

        # Legacy fallback: if no global AND no project config, try CWD/.ai-guardian.json
        # DEPRECATED: will be removed in v2.0.0 — use .ai-guardian/ai-guardian.json instead
        if global_path is None and project_path is None:
            legacy_path = Path.cwd() / ".ai-guardian.json"
            if legacy_path.exists():
                logging.warning(
                    "DEPRECATED: Using legacy '.ai-guardian.json' in project root. "
                    "Move to '.ai-guardian/ai-guardian.json' instead. "
                    "Legacy support will be removed in v2.0.0."
                )
                global_path = legacy_path

        # No config files at all
        if global_path is None and project_path is None:
            _cache = _ConfigCacheEntry(result=(None, None))
            return _cache.result

        # Check mtime cache
        global_mtime = _get_mtime(global_path)
        project_mtime = _get_mtime(project_path)

        if (
            _cache.result is not None
            and _cache.global_path == global_path
            and _cache.project_path == project_path
            and _cache.global_mtime == global_mtime
            and _cache.project_mtime == project_mtime
        ):
            return _cache.result

        # Load global config
        global_config = None
        if global_path:
            global_config, error_msg = _load_json_config(global_path)
            if error_msg:
                _cache = _ConfigCacheEntry(
                    result=(None, error_msg),
                    global_mtime=global_mtime,
                    project_mtime=project_mtime,
                    global_path=global_path,
                    project_path=project_path,
                )
                return _cache.result

        # Load project config
        project_config = None
        if project_path:
            project_config, error_msg = _load_json_config(project_path)
            if error_msg:
                logger.warning(f"Ignoring invalid project config: {error_msg}")
                project_config = None

        # Normalize permissions format before merge (list → dict)
        global_config = _normalize_permissions(global_config)
        project_config = _normalize_permissions(project_config)

        # Merge (use `is not None` — empty dict {} is a valid config)
        if global_config is not None and project_config is not None:
            logger.debug(
                f"Config merge: global={global_path}, project={project_path}"
            )
            effective = deep_merge(global_config, project_config)
        elif global_config is not None:
            effective = global_config
        elif project_config is not None:
            effective = project_config
        else:
            effective = None

        _cache = _ConfigCacheEntry(
            result=(effective, None),
            global_mtime=global_mtime,
            project_mtime=project_mtime,
            global_path=global_path,
            project_path=project_path,
        )
        return _cache.result

    except Exception as e:
        error_msg = f"⚠️  Configuration Error: {str(e)}"
        logging.error(f"Unexpected error loading config: {e}")
        return None, error_msg


def _load_json_config(config_path):
    """
    Load and parse a single JSON config file.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config, None
    except json.JSONDecodeError as e:
        error_msg = (
            f"⚠️  Configuration Error: Failed to parse {config_path}\n"
            f"JSON Error: {e.msg} (line {e.lineno}, column {e.colno})\n"
            f"Using default configuration. Please fix the config file."
        )
        logging.error(f"JSON parse error in {config_path}: {e}")
        print(error_msg, file=sys.stderr)
        return None, error_msg
    except Exception as e:
        error_msg = (
            f"⚠️  Configuration Error: Failed to read {config_path}\n"
            f"Error: {str(e)}\n"
            f"Using default configuration."
        )
        logging.error(f"Error reading config {config_path}: {e}")
        return None, error_msg


def _load_pattern_server_config():
    """
    Load pattern server configuration from ai-guardian.json.

    NEW in v1.7.0: Checks secret_scanning.pattern_server first (new location),
    then falls back to root-level pattern_server (deprecated, backward compatibility).

    Returns:
        dict: Pattern server configuration or None
    """
    try:
        config, error_msg = _load_config_file()
        if error_msg or config is None:
            return None

        secret_scanning = config.get("secret_scanning", {})
        if "pattern_server" in secret_scanning:
            pattern_config = secret_scanning["pattern_server"]

            logging.warning(
                "DEPRECATED: 'secret_scanning.pattern_server' is a global setting "
                "but only applies to gitleaks. Move to per-engine format:\n"
                "  \"secret_scanning\": {\n"
                "    \"engines\": [\n"
                "      {\"type\": \"gitleaks\", \"pattern_server\": {...}}\n"
                "    ]\n"
                "  }\n"
                "Run: ai-guardian setup --migrate-pattern-server\n"
                "Global pattern_server support will be removed in v2.0.0."
            )

            if pattern_config is None:
                logging.debug("Pattern server explicitly disabled (secret_scanning.pattern_server = null)")
                return None

            if isinstance(pattern_config, dict):
                if "enabled" in pattern_config:
                    if not is_feature_enabled(pattern_config["enabled"]):
                        logging.debug("Pattern server disabled via enabled field")
                        return None

                if pattern_config.get("url"):
                    logging.debug("Using pattern server from secret_scanning.pattern_server")
                    return pattern_config
                else:
                    logging.debug("Pattern server section present but no URL configured")
                    return None

        if "pattern_server" in config:
            pattern_config = config["pattern_server"]

            logging.warning(
                "DEPRECATED: Root-level 'pattern_server' configuration. "
                "Move to 'secret_scanning.pattern_server' instead. "
                "Example:\n"
                "  \"secret_scanning\": {\n"
                "    \"enabled\": true,\n"
                "    \"pattern_server\": {...}\n"
                "  }\n"
                "Root-level support will be removed in v2.0.0."
            )

            if isinstance(pattern_config, dict):
                if "enabled" in pattern_config:
                    if not is_feature_enabled(pattern_config["enabled"]):
                        logging.debug("Pattern server disabled via enabled field")
                        return None

                if pattern_config.get("url"):
                    return pattern_config

        return None

    except Exception as e:
        logging.debug(f"Error loading pattern server config: {e}")
        return None


def _load_config_section(key, defaults=None, merge_ignore=False):
    """Load a config section from ai-guardian.json with optional defaults and .aiguardignore merge."""
    config, error_msg = _load_config_file()
    if error_msg:
        return (defaults or None), error_msg
    if config is None:
        return (defaults or None), None
    section = config.get(key, defaults) if defaults else config.get(key)
    if merge_ignore and section is not None:
        section = _merge_aiguardignore(section, key)
    return section, None


def _load_prompt_injection_config():
    """Load prompt injection configuration from ai-guardian.json."""
    return _load_config_section("prompt_injection", merge_ignore=True)


def _load_config_scanner_config():
    """Load config file scanning configuration from ai-guardian.json."""
    return _load_config_section("config_file_scanning", merge_ignore=True)


def _load_permissions_config():
    """Load permissions configuration from ai-guardian.json."""
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None

    permissions = config.get("permissions")
    if isinstance(permissions, dict):
        return {"enabled": permissions.get("enabled", True)}, None

    return {"enabled": True}, None


def _load_secret_scanning_config():
    """Load secret scanning configuration from ai-guardian.json."""
    return _load_config_section("secret_scanning", merge_ignore=True)


def _load_secret_redaction_config():
    """Load secret redaction configuration from ai-guardian.json."""
    return _load_config_section("secret_redaction")


_PII_DEFAULTS = {
    'enabled': True,
    'pii_types': ['ssn', 'credit_card', 'phone', 'us_passport', 'iban', 'intl_phone', 'medical_id', 'passport', 'uk_nin'],
    'action': 'block',
    'ignore_files': [],
    'ignore_tools': [],
    'allowlist_patterns': [],
    'pattern_server': None,
}


def _load_pii_config():
    """Load PII scanning configuration. Returns defaults when scan_pii section is absent."""
    return _load_config_section("scan_pii", defaults=_PII_DEFAULTS, merge_ignore=True)


def _load_transcript_scanning_config():
    """Load transcript scanning configuration. Returns defaults when section is absent."""
    return _load_config_section("transcript_scanning", defaults={'enabled': True})


def _load_annotations_config():
    """Load annotations configuration. Returns defaults when section is absent."""
    return _load_config_section("annotations", defaults={"enabled": True})


_IMAGE_SCANNING_DEFAULTS = {
    'enabled': True,
    'action': 'block',
    'scan_types': ['secrets', 'pii'],
    'max_processing_ms': 1500,
    'min_confidence': 0.5,
    'redaction_method': 'blur',
    'qr_scanning': False,
    'face_detection': False,
    'ignore_files': [],
    'ignore_tools': [],
    'max_image_size_mb': 10,
}


def _load_image_scanning_config():
    """Load image scanning configuration. Returns defaults when section is absent."""
    return _load_config_section("image_scanning", defaults=_IMAGE_SCANNING_DEFAULTS, merge_ignore=True)


_CONTEXT_POISONING_DEFAULTS = {
    'enabled': True,
    'action': 'warn',
    'allowlist_patterns': [],
    'custom_patterns': [],
    'sensitivity': 'medium',
}


def _load_context_poisoning_config():
    """Load context poisoning configuration. Returns defaults when section is absent."""
    return _load_config_section("context_poisoning", defaults=_CONTEXT_POISONING_DEFAULTS)


_SUPPLY_CHAIN_DEFAULTS = {
    'enabled': True,
    'action': 'block',
    'scan_hooks': True,
    'scan_mcp_configs': True,
    'scan_plugins': True,
    'allowlist_paths': [],
}


def _load_supply_chain_config():
    """Load supply chain scanning configuration. Returns defaults when section is absent."""
    return _load_config_section("supply_chain", defaults=_SUPPLY_CHAIN_DEFAULTS)


def _load_security_instructions_config():
    """Load security instructions configuration from ai-guardian.json."""
    return _load_config_section("security_instructions")


def _get_on_scan_error_action() -> str:
    """
    Load the global on_scan_error setting from ai-guardian.json.

    Returns:
        str: "allow" (default, fail-open) or "block" (fail-closed)
    """
    config, _ = _load_config_file()
    if config:
        value = config.get("on_scan_error", "allow")
        if value in ("allow", "block"):
            return value
    return "allow"
