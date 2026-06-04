"""Shared config load/save helpers for web console pages."""

import json


def load_web_config() -> dict:
    """Load the global ai-guardian.json config. Returns {} on missing/invalid."""
    from ai_guardian.config_utils import get_config_dir

    path = get_config_dir() / "ai-guardian.json"
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_web_config(config: dict) -> None:
    """Write config dict to ai-guardian.json with indent=2 and trailing newline."""
    from ai_guardian.config_utils import get_config_dir

    path = get_config_dir() / "ai-guardian.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
