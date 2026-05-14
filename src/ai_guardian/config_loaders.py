"""
Configuration loading functions for AI Guardian.

Handles loading and caching of ai-guardian.json configuration sections.
All _load_*_config() functions share a single mtime-based cache to avoid
redundant file reads within the same hook invocation.
"""

import json
import logging
import sys
from pathlib import Path

from ai_guardian.config_utils import get_config_dir, is_feature_enabled

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


_config_cache = None
_config_cache_mtime = None
_config_cache_path = None


def _clear_config_cache():
    """Clear the config file cache, forcing a re-read on next call."""
    global _config_cache, _config_cache_mtime, _config_cache_path
    _config_cache = None
    _config_cache_mtime = None
    _config_cache_path = None


def _load_config_file():
    """
    Load ai-guardian.json configuration file with detailed error reporting.

    Uses mtime-based caching to avoid redundant file reads when multiple
    _load_*_config() functions are called within the same hook invocation.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    global _config_cache, _config_cache_mtime, _config_cache_path
    try:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            config_path = Path.cwd() / ".ai-guardian.json"

        if not config_path.exists():
            if _config_cache_path is None and _config_cache is not None:
                return _config_cache
            _config_cache = (None, None)
            _config_cache_mtime = None
            _config_cache_path = None
            return _config_cache

        try:
            current_mtime = config_path.stat().st_mtime
        except OSError:
            current_mtime = None

        if (
            _config_cache is not None
            and _config_cache_path == config_path
            and _config_cache_mtime is not None
            and current_mtime == _config_cache_mtime
        ):
            return _config_cache

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            _config_cache = (config, None)
            _config_cache_mtime = current_mtime
            _config_cache_path = config_path
            return _config_cache

        except json.JSONDecodeError as e:
            error_msg = (
                f"⚠️  Configuration Error: Failed to parse {config_path}\n"
                f"JSON Error: {e.msg} (line {e.lineno}, column {e.colno})\n"
                f"Using default configuration. Please fix the config file."
            )
            logging.error(f"JSON parse error in {config_path}: {e}")
            print(error_msg, file=sys.stderr)
            _config_cache = (None, error_msg)
            _config_cache_mtime = current_mtime
            _config_cache_path = config_path
            return _config_cache

        except Exception as e:
            error_msg = (
                f"⚠️  Configuration Error: Failed to read {config_path}\n"
                f"Error: {str(e)}\n"
                f"Using default configuration."
            )
            logging.error(f"Error reading config {config_path}: {e}")
            _config_cache = (None, error_msg)
            _config_cache_mtime = current_mtime
            _config_cache_path = config_path
            return _config_cache

    except Exception as e:
        error_msg = f"⚠️  Configuration Error: {str(e)}"
        logging.error(f"Unexpected error loading config: {e}")
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


def _load_prompt_injection_config():
    """
    Load prompt injection configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return _merge_aiguardignore(config.get("prompt_injection"), "prompt_injection"), None


def _load_config_scanner_config():
    """
    Load config file scanning configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return _merge_aiguardignore(config.get("config_file_scanning"), "config_file_scanning"), None


def _load_permissions_config():
    """
    Load permissions configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
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
    """
    Load secret scanning configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return _merge_aiguardignore(config.get("secret_scanning"), "secret_scanning"), None


def _load_secret_redaction_config():
    """
    Load secret redaction configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return config.get("secret_redaction"), None


def _load_pii_config():
    """
    Load PII scanning configuration from ai-guardian.json.

    Returns defaults (enabled=True) when the scan_pii section is absent.

    Returns:
        tuple: (config_dict, error_message or None)
    """
    _PII_DEFAULTS = {
        'enabled': True,
        'pii_types': ['ssn', 'credit_card', 'phone', 'us_passport', 'iban', 'intl_phone'],
        'action': 'block',
        'ignore_files': [],
        'ignore_tools': [],
        'allowlist_patterns': []
    }
    config, error_msg = _load_config_file()
    if error_msg:
        return _PII_DEFAULTS, error_msg
    if config is None:
        return _PII_DEFAULTS, None
    return _merge_aiguardignore(config.get("scan_pii", _PII_DEFAULTS), "scan_pii"), None


def _load_transcript_scanning_config():
    """
    Load transcript scanning configuration from ai-guardian.json.

    Returns defaults (enabled=True) when the transcript_scanning section is absent.

    Returns:
        tuple: (config_dict, error_message or None)
    """
    _DEFAULTS = {
        'enabled': True,
    }
    config, error_msg = _load_config_file()
    if error_msg:
        return _DEFAULTS, error_msg
    if config is None:
        return _DEFAULTS, None
    return config.get("transcript_scanning", _DEFAULTS), None


def _load_annotations_config():
    """
    Load annotations configuration from ai-guardian.json.

    Returns defaults (enabled=True) when the annotations section is absent.

    Returns:
        tuple: (config_dict, error_message or None)
    """
    _DEFAULTS = {"enabled": True}
    config, error_msg = _load_config_file()
    if error_msg:
        return _DEFAULTS, error_msg
    if config is None:
        return _DEFAULTS, None
    return config.get("annotations", _DEFAULTS), None


def _load_security_instructions_config():
    """
    Load security instructions configuration from ai-guardian.json.

    Returns:
        tuple: (config_dict or None, error_message or None)
    """
    config, error_msg = _load_config_file()
    if error_msg:
        return None, error_msg
    if config is None:
        return None, None
    return config.get("security_instructions"), None


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
