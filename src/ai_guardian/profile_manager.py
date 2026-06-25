#!/usr/bin/env python3
"""
Security profile manager for ai-guardian.

Handles built-in (@minimal, @standard, @strict) and custom security profiles.
Built-in profiles are immutable JSON data files shipped with the package.
Custom profiles are stored in ~/.config/ai-guardian/profiles/.
"""

import json
import re
from importlib.resources import files
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ai_guardian.config_utils import get_cache_dir, get_profiles_dir

BUILT_IN_PROFILES = ("minimal", "standard", "strict")

PROFILE_DESCRIPTIONS = {
    "minimal": "Personal projects, low friction",
    "standard": "Team development, moderate security",
    "strict": "Enterprise SOC2/compliance, fail-closed",
}

SCHEMA_PLACEHOLDER = "__SCHEMA_URI__"
CACHE_DIR_PLACEHOLDER = "__CACHE_DIR__"

_PROFILE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")


class ProfileNotFoundError(ValueError):
    """Raised when a profile cannot be resolved."""


def get_schema_uri() -> str:
    """Resolve the JSON schema URI via importlib.resources."""
    schema_path = files("ai_guardian") / "schemas" / "ai-guardian-config.schema.json"
    return Path(str(schema_path)).as_uri()


def _get_builtin_profile_path(name: str) -> Path:
    """Get the path to a built-in profile JSON file."""
    return Path(str(files("ai_guardian") / "templates" / "profiles" / f"{name}.json"))


def resolve_profile(profile_name: str) -> Tuple[str, Path]:
    """
    Resolve a profile name to its type and file path.

    Resolution order:
    1. @-prefixed names -> built-in profiles
    2. Non-@ names -> custom profiles dir -> file path

    Args:
        profile_name: Profile name (@minimal, @standard, @strict, custom name, or file path)

    Returns:
        Tuple of (profile_type, path) where profile_type is "builtin", "custom", or "file"

    Raises:
        ProfileNotFoundError: If profile cannot be found
    """
    if profile_name.startswith("@"):
        name = profile_name[1:]
        if name not in BUILT_IN_PROFILES:
            raise ProfileNotFoundError(
                f"Unknown built-in profile: {profile_name}\n"
                f"Available: {', '.join('@' + p for p in BUILT_IN_PROFILES)}"
            )
        path = _get_builtin_profile_path(name)
        if not path.exists():
            raise ProfileNotFoundError(f"Built-in profile file not found: {path}")
        return "builtin", path

    # Check if it's a file path (contains / or \, or ends with .json)
    if "/" in profile_name or "\\" in profile_name or profile_name.endswith(".json"):
        path = Path(profile_name).expanduser()
        if not path.exists():
            raise ProfileNotFoundError(f"Profile file not found: {path}")
        return "file", path

    # Check custom profiles directory
    profiles_dir = get_profiles_dir()
    path = profiles_dir / f"{profile_name}.json"
    if path.exists():
        return "custom", path

    raise ProfileNotFoundError(
        f"Profile not found: {profile_name}\n"
        f"Checked: {path}\n"
        f"Built-in profiles: {', '.join('@' + p for p in BUILT_IN_PROFILES)}"
    )


def load_profile(profile_name: str) -> Dict:
    """
    Load and return a profile config dict.

    Resolves the profile, reads the JSON, and replaces placeholders
    with runtime-computed values.

    Args:
        profile_name: Profile name to load

    Returns:
        Config dict ready for writing

    Raises:
        ProfileNotFoundError: If profile cannot be found
        json.JSONDecodeError: If profile JSON is invalid
    """
    _, path = resolve_profile(profile_name)

    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    raw = raw.replace(SCHEMA_PLACEHOLDER, get_schema_uri())
    raw = raw.replace(CACHE_DIR_PLACEHOLDER, str(get_cache_dir()))

    return json.loads(raw)


def save_profile(name: str, config: Dict) -> Tuple[bool, str]:
    """
    Save a config dict as a named custom profile.

    Args:
        name: Profile name (alphanumeric, hyphens, underscores)
        config: Config dict to save

    Returns:
        Tuple of (success, message)
    """
    if name.startswith("@"):
        return (
            False,
            "Profile name cannot start with '@' (reserved for built-in profiles)",
        )

    if name in BUILT_IN_PROFILES:
        return False, (
            f"Cannot overwrite built-in profile '{name}'\n"
            f"Choose a different name for your custom profile"
        )

    if not _PROFILE_NAME_RE.match(name):
        return False, (
            f"Invalid profile name: {name}\n"
            "Names must be 1-64 characters: letters, digits, hyphens, underscores"
        )

    profiles_dir = get_profiles_dir()
    profiles_dir.mkdir(parents=True, exist_ok=True)

    profile_path = profiles_dir / f"{name}.json"

    with open(profile_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

    return True, f"Saved profile: {profile_path}"


def list_profiles() -> List[Dict[str, str]]:
    """
    List all available profiles (built-in + custom).

    Returns:
        List of dicts with keys: name, type, description, path
    """
    result = []

    for name in BUILT_IN_PROFILES:
        path = _get_builtin_profile_path(name)
        result.append(
            {
                "name": f"@{name}",
                "type": "builtin",
                "description": PROFILE_DESCRIPTIONS.get(name, ""),
                "path": str(path),
            }
        )

    profiles_dir = get_profiles_dir()
    if profiles_dir.exists():
        for f in sorted(profiles_dir.iterdir()):
            if f.suffix == ".json" and f.is_file():
                stem = f.stem
                result.append(
                    {
                        "name": stem,
                        "type": "custom",
                        "description": str(f),
                        "path": str(f),
                    }
                )

    return result


def format_profile_list(profiles: Optional[List[Dict[str, str]]] = None) -> str:
    """Format profiles list for CLI output."""
    if profiles is None:
        profiles = list_profiles()

    lines = []
    builtins = [p for p in profiles if p["type"] == "builtin"]
    customs = [p for p in profiles if p["type"] == "custom"]

    lines.append("Built-in:")
    for p in builtins:
        lines.append(f"  {p['name']:12s} - {p['description']}")

    if customs:
        lines.append("")
        lines.append("Custom:")
        for p in customs:
            lines.append(f"  {p['name']:12s} - {p['description']}")

    return "\n".join(lines)
