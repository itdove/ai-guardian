"""
Parse project .aiguardignore.toml for per-project ignore_files patterns.

This module reads .aiguardignore.toml from the project root once, caches
the result by mtime, and provides helpers that config loaders call to
merge project-level ignore paths into scanner configurations.

File format (consistent with .gitleaks.toml allowlist style):

    [allowlist]
        paths = ["tests/fixtures/**"]          # all scanners

    [secret_scanning.allowlist]
        paths = ["tests/integration/**"]       # secret scanning only

    [scan_pii.allowlist]
        paths = ["tests/unit/test_pii*.py"]    # PII scanning only

    [prompt_injection.allowlist]
        paths = ["docs/security-patterns.md"]  # prompt injection only

    [config_file_scanning.allowlist]
        paths = ["examples/*.json"]            # config scanning only
"""

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ai_guardian.gitleaks_config import find_project_root

logger = logging.getLogger(__name__)

try:
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib  # type: ignore
    HAS_TOML = True
except ImportError:
    HAS_TOML = False

SCANNER_TYPES = frozenset({
    "secret_scanning",
    "scan_pii",
    "prompt_injection",
    "config_file_scanning",
})

_cached_config: Optional[tuple] = None  # (path, mtime, AiguardignoreConfig)


@dataclass
class AiguardignoreConfig:
    """Parsed .aiguardignore.toml data."""
    global_paths: List[str] = field(default_factory=list)
    scanner_paths: Dict[str, List[str]] = field(default_factory=dict)


def _validate_paths(raw: List[str]) -> List[str]:
    safe = []
    for p in raw:
        if ".." in p.split("/"):
            logger.warning(
                f"Blocked .aiguardignore.toml path with '..': '{p}'"
            )
            continue
        safe.append(p)
    return safe


def load_aiguardignore(
    project_root: Optional[Path] = None,
) -> Optional[AiguardignoreConfig]:
    """Load and cache .aiguardignore.toml from the project root.

    Returns None when the file is absent, TOML is unavailable, or parsing fails.
    """
    global _cached_config

    if not HAS_TOML:
        return None

    root = project_root or find_project_root()
    if root is None:
        return None

    toml_path = root / ".aiguardignore.toml"
    if not toml_path.is_file():
        return None

    try:
        mtime = os.path.getmtime(toml_path)
    except OSError:
        return None

    if _cached_config is not None:
        cached_path, cached_mtime, cached_obj = _cached_config
        if cached_path == toml_path and cached_mtime == mtime:
            return cached_obj

    try:
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        logger.warning(f"Failed to parse .aiguardignore.toml: {exc}")
        return None

    # Global allowlist
    al_section = data.get("allowlist", {})
    if not isinstance(al_section, dict):
        al_section = {}
    global_paths = _validate_paths(al_section.get("paths", []))

    # Per-scanner allowlists
    scanner_paths: Dict[str, List[str]] = {}
    for scanner_type in SCANNER_TYPES:
        scanner_section = data.get(scanner_type, {})
        if not isinstance(scanner_section, dict):
            continue
        scanner_al = scanner_section.get("allowlist", {})
        if not isinstance(scanner_al, dict):
            continue
        paths = _validate_paths(scanner_al.get("paths", []))
        if paths:
            scanner_paths[scanner_type] = paths

    result = AiguardignoreConfig(
        global_paths=global_paths,
        scanner_paths=scanner_paths,
    )

    _cached_config = (toml_path, mtime, result)
    return result


def get_ignore_paths(scanner_type: str) -> List[str]:
    """Return combined global + scanner-specific paths for a scanner type.

    Returns an empty list when no .aiguardignore.toml exists or when
    there are no matching paths.
    """
    config = load_aiguardignore()
    if config is None:
        return []

    combined = list(config.global_paths)
    scanner_specific = config.scanner_paths.get(scanner_type, [])
    if scanner_specific:
        combined.extend(scanner_specific)
    return combined


def reset_cache():
    """Clear all module-level caches (for testing)."""
    global _cached_config
    _cached_config = None
