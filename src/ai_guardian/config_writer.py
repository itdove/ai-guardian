"""Safe config file writer with file locking for allowlist pattern management.

Used by the ask dialog to atomically add allowlist patterns to ai-guardian.json
without corrupting the config when multiple hook subprocesses write concurrently.
"""

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

from ai_guardian.allowlist_utils import validate_allowlist_patterns
from ai_guardian.config_utils import get_config_dir

logger = logging.getLogger(__name__)


def add_allowlist_pattern(
    config_section: str,
    pattern: str,
    valid_until: Optional[str] = None,
    config_path: Optional[Path] = None,
) -> bool:
    """Add a pattern to a section's allowlist_patterns array in ai-guardian.json.

    Uses file locking for concurrent write safety and atomic writes to prevent
    partial file corruption.

    Args:
        config_section: Config section key (e.g. "secret_scanning", "prompt_injection").
        pattern: Regex pattern string to add.
        valid_until: Optional ISO 8601 expiration timestamp.
        config_path: Override config file path (defaults to global config).

    Returns:
        True if pattern was added successfully, False on failure.
    """
    if not pattern or not config_section:
        return False

    if config_path is None:
        config_path = get_config_dir() / "ai-guardian.json"

    pattern_entry = pattern
    if valid_until:
        pattern_entry = {"pattern": pattern, "valid_until": valid_until}

    if not validate_allowlist_patterns([pattern_entry]):
        logger.error(f"Pattern rejected by safety validation: {pattern}")
        return False

    lock_path = str(config_path) + ".lock"

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            if HAS_FCNTL:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)

            config = {}
            if config_path.exists():
                try:
                    with open(config_path, "r", encoding="utf-8") as f:
                        config = json.load(f)
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning(f"Could not read config, starting fresh: {e}")
                    config = {}

            if config_section not in config:
                config[config_section] = {}
            section = config[config_section]
            if not isinstance(section, dict):
                section = {}
                config[config_section] = section

            patterns = section.get("allowlist_patterns", [])
            if not isinstance(patterns, list):
                patterns = []

            for existing in patterns:
                existing_str = existing if isinstance(existing, str) else existing.get("pattern", "")
                if existing_str == pattern:
                    logger.info(f"Pattern already exists in {config_section}.allowlist_patterns")
                    return True

            patterns.append(pattern_entry)
            section["allowlist_patterns"] = patterns

            fd, tmp_path = tempfile.mkstemp(
                dir=str(config_path.parent),
                prefix=".ai-guardian-",
                suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2)
                    f.write("\n")
                os.replace(tmp_path, str(config_path))
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

            try:
                from ai_guardian.config_loaders import _clear_config_cache
                _clear_config_cache()
            except ImportError:
                pass

            logger.info(f"Added pattern to {config_section}.allowlist_patterns: {pattern}")
            return True

        finally:
            if HAS_FCNTL:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    except OSError as e:
        logger.error(f"Failed to write config: {e}")
        return False
