"""Shared config load/save helpers for web console pages.

Supports Global/Project scope via session state. When a scope is set in
the NiceGUI session (via the header toggle), load/save automatically route
to the correct config file. Backward compatible — defaults to global scope.
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _get_current_scope() -> str:
    """Get the current config scope from NiceGUI session state."""
    try:
        from nicegui import app
        return app.storage.user.get("config_scope", "global")
    except Exception:
        return "global"


def _get_project_dir() -> Optional[str]:
    """Get the project directory from NiceGUI session state."""
    try:
        from nicegui import app
        return app.storage.user.get("project_dir")
    except Exception:
        return None


def load_web_config() -> dict:
    """Load merged/effective ai-guardian.json config.

    Always returns merged config (global + project overrides) regardless of
    current scope. The scope only affects where saves go, not what is displayed.
    Returns {} on missing/invalid.
    """
    from ai_guardian.config_utils import get_config_dir, get_project_config_path
    from ai_guardian.config_writer import _load_json_file

    global_path = get_config_dir() / "ai-guardian.json"
    global_cfg = _load_json_file(global_path)

    project_path = get_project_config_path()
    if project_path:
        project_cfg = _load_json_file(project_path)
        if project_cfg:
            from ai_guardian.config_utils import deep_merge
            return deep_merge(global_cfg, project_cfg)

    return global_cfg


def load_web_config_global() -> dict:
    """Load global config regardless of current scope.

    Used when pages need to show global defaults alongside project overrides.
    """
    try:
        from ai_guardian.config_writer import load_scoped_config
        return load_scoped_config("global")
    except Exception:
        pass

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
    """Write config dict to ai-guardian.json for the current scope.

    Reads scope from NiceGUI session state. Falls back to direct filesystem
    write to global config when scope functions are unavailable.
    """
    scope = _get_current_scope()
    project_dir = _get_project_dir()

    try:
        from ai_guardian.config_writer import _resolve_config_path, _atomic_config_update
        config_path = _resolve_config_path(scope, project_dir)

        def updater(existing_config):
            existing_config.clear()
            existing_config.update(config)
            return False, f"Saved web config [{scope}]"

        _atomic_config_update(config_path, updater)
        _invalidate_config_cache_after_save(scope, project_dir)
        return
    except Exception:
        pass

    from ai_guardian.config_utils import get_config_dir
    path = get_config_dir() / "ai-guardian.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    _invalidate_config_cache_after_save("global", None)


def _invalidate_config_cache_after_save(scope: str, project_dir: Optional[str]) -> None:
    """Invalidate the daemon config cache after a web console save."""
    try:
        from ai_guardian.config_loaders import _clear_config_cache
        if scope == "project" and project_dir:
            _clear_config_cache(project_key=project_dir)
        else:
            _clear_config_cache()
    except Exception:
        pass


def get_web_config_provenance() -> dict:
    """Get provenance information for the current config."""
    try:
        from ai_guardian.config_writer import compute_provenance
        return compute_provenance(_get_project_dir())
    except Exception:
        return {}


def get_web_config_scope_label() -> str:
    """Return human-readable label for the current scope."""
    scope = _get_current_scope()
    return "Project" if scope == "project" else "Global"
