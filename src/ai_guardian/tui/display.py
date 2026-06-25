"""Shared display tier detection for prompt dialogs.

Cascade: tkinter (native popup) -> NiceGUI (browser) -> Textual (terminal) -> headless.

Environment overrides (useful for testing or user preference):
  AI_GUARDIAN_NO_TKINTER=1   skip tkinter even when installed
  AI_GUARDIAN_NO_NICEGUI=1   skip NiceGUI even when installed
"""

import json
import logging
import os
import platform

logger = logging.getLogger(__name__)

VALID_PREFERRED_UI = {"auto", "tkinter", "nicegui", "textual", "headless"}


def get_preferred_ui() -> str:
    """Return the preferred UI toolkit from env var or config.

    Priority: AI_GUARDIAN_PREFERRED_UI env var > console.preferred_ui config > "auto".
    """
    env_val = os.environ.get("AI_GUARDIAN_PREFERRED_UI", "").strip().lower()
    if env_val in VALID_PREFERRED_UI:
        return env_val

    try:
        from ai_guardian.config_utils import get_config_dir

        config_path = get_config_dir() / "ai-guardian.json"
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            val = config.get("console", {}).get("preferred_ui", "auto")
            if val in VALID_PREFERRED_UI:
                return val
    except Exception:
        pass  # intentionally silent — optional dependency

    return "auto"


def _tkinter_available():
    """Return True if tkinter can be imported.

    Runtime failures (broken Tcl/Tk, no display, etc.) are caught by
    the try/except cascade in the caller which falls through to
    NiceGUI or Textual automatically.
    """
    if os.environ.get("AI_GUARDIAN_NO_TKINTER"):
        return False
    try:
        import tkinter  # noqa: F401

        return True
    except ImportError:
        return False


def _nicegui_available():
    """Return True if NiceGUI can be imported and is not suppressed."""
    if os.environ.get("AI_GUARDIAN_NO_NICEGUI"):
        return False
    try:
        import nicegui  # noqa: F401

        return True
    except ImportError:
        return False


def _textual_available():
    """Return True if Textual can be imported and a TTY is present."""
    try:
        import textual  # noqa: F401

        return os.isatty(0)
    except ImportError:
        return False


def is_interactive_available() -> bool:
    """Return True if any interactive dialog tier is available."""
    return _tkinter_available() or _nicegui_available() or _textual_available()


def _ensure_tcl_library():
    """Set TCL_LIBRARY if not already set, searching common install locations.

    uv/pyenv venvs often can't find the system Tcl/Tk — this resolves the
    "Can't find a usable init.tcl" error at tk.Tk() time.
    """
    if os.environ.get("TCL_LIBRARY"):
        return

    import pathlib
    import sys

    candidates = []
    real_exe = pathlib.Path(sys.executable).resolve()
    candidates.append(real_exe.parent.parent / "lib" / "tcl8.6")

    if platform.system() == "Darwin":
        candidates += [
            pathlib.Path("/opt/homebrew/Cellar/tcl-tk@8") / "8.6.18" / "lib" / "tcl8.6",
            pathlib.Path("/opt/homebrew/opt/tcl-tk@8/lib/tcl8.6"),
            pathlib.Path("/opt/homebrew/opt/tcl-tk/lib/tcl8.6"),
            pathlib.Path("/usr/local/opt/tcl-tk/lib/tcl8.6"),
        ]
        import glob

        for match in glob.glob("/opt/homebrew/Cellar/tcl-tk@8/*/lib/tcl8.6"):
            candidates.append(pathlib.Path(match))
    elif platform.system() == "Linux":
        candidates += [
            pathlib.Path("/usr/lib/tcl8.6"),
            pathlib.Path("/usr/share/tcltk/tcl8.6"),
        ]

    for path in candidates:
        if (path / "init.tcl").exists():
            os.environ["TCL_LIBRARY"] = str(path)
            return
