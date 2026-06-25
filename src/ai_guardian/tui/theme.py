"""Console Theme — backward-compatibility shim.

All theme definitions live in ai_guardian.theme (top-level).
This module re-exports names for any existing imports.
"""

from ai_guardian.theme import (
    ANNOTATION_FG,
    CODE_BG,
    ERROR,
    HIGHLIGHT_BG,
    INFO,
    PRIMARY,
    SUCCESS,
    SURFACE,
    SURFACE_ALT,
    TEXT,
    TEXT_DIM,
    TEXT_MUTED,
    WARNING,
)

ACCENT = PRIMARY
ACCENT_DIM = "#0D47A1"
EVERGLADE = "#123123"
BORDER_MUTED = "#2a4a2a"

STATUS_OK = SUCCESS
STATUS_WARN = WARNING
STATUS_ERROR = ERROR

TEXT_PRIMARY = TEXT

SELECTION_BG = "#1e3c2d"
CURSOR_INDICATOR = PRIMARY
ACTIVE_INDICATOR = PRIMARY

SIDEBAR_WIDTH = 28
SIDEBAR_BG = SURFACE_ALT
SIDEBAR_SELECTED = PRIMARY
SIDEBAR_CATEGORY = TEXT_MUTED

PANEL_BG = "$panel"
SURFACE_BG = "$surface"

__all__ = [
    "ACCENT",
    "ACCENT_DIM",
    "EVERGLADE",
    "BORDER_MUTED",
    "STATUS_OK",
    "STATUS_WARN",
    "STATUS_ERROR",
    "TEXT_PRIMARY",
    "TEXT_MUTED",
    "TEXT_DIM",
    "SELECTION_BG",
    "CURSOR_INDICATOR",
    "ACTIVE_INDICATOR",
    "SIDEBAR_WIDTH",
    "SIDEBAR_BG",
    "SIDEBAR_SELECTED",
    "SIDEBAR_CATEGORY",
    "PANEL_BG",
    "SURFACE_BG",
    "PRIMARY",
    "SUCCESS",
    "ERROR",
    "WARNING",
    "INFO",
    "SURFACE",
    "SURFACE_ALT",
    "TEXT",
    "CODE_BG",
    "HIGHLIGHT_BG",
    "ANNOTATION_FG",
]
