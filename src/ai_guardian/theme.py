"""Unified visual theme for all AI Guardian UI toolkits.

Single source of truth for colors, severity badges, violation icons,
and button semantics. Imported by tkinter, NiceGUI, and Textual UIs.
"""

from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Core palette
# ---------------------------------------------------------------------------
PRIMARY = "#1976D2"
SURFACE = "#1E1E1E"
SURFACE_ALT = "#1A1A2E"
TEXT = "#E0E0E0"
TEXT_MUTED = "#B0B0B0"
TEXT_DIM = "#888888"

# Semantic colors
SUCCESS = "#388E3C"
ERROR = "#D32F2F"
WARNING = "#F57C00"
CAUTION = "#FBC02D"
INFO = "#546E7A"

# Editor / code viewer
HIGHLIGHT_BG = "#2A3A00"
CODE_BG = "#2A2A2A"
ANNOTATION_FG = "#4EC9B0"

# ---------------------------------------------------------------------------
# Severity → color mapping
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {
    "critical": ERROR,
    "high": WARNING,
    "warning": CAUTION,
    "medium": CAUTION,
    "low": INFO,
    "info": INFO,
}

# ---------------------------------------------------------------------------
# Violation badges: type → {"color": hex, "icon": emoji}
# ---------------------------------------------------------------------------
VIOLATION_BADGES = {
    "secret_detected": {"color": ERROR, "icon": "\U0001f511"},
    "prompt_injection": {"color": WARNING, "icon": "\U0001f6e1️"},
    "pii_detected": {"color": CAUTION, "icon": "\U0001f512"},
    "ssrf_blocked": {"color": INFO, "icon": "\U0001f310"},
    "config_file_exfil": {"color": WARNING, "icon": "⚙️"},
    "context_poisoning": {"color": WARNING, "icon": "☠️"},
    "supply_chain": {"color": ERROR, "icon": "\U0001f4e6"},
    "directory_blocking": {"color": INFO, "icon": "\U0001f4c1"},
    "jailbreak_detected": {"color": ERROR, "icon": "\U0001f6a8"},
    "tool_permission": {"color": WARNING, "icon": "\U0001f527"},
    "secret_redaction": {"color": CAUTION, "icon": "✂️"},
    "secret_in_transcript": {"color": ERROR, "icon": "\U0001f511"},
    "pii_in_transcript": {"color": CAUTION, "icon": "\U0001f512"},
    "prompt_injection_in_transcript": {"color": WARNING, "icon": "\U0001f6e1️"},
    "annotation_suppressed": {"color": INFO, "icon": "✔️"},
    "image_secret_detected": {"color": ERROR, "icon": "\U0001f511"},
    "image_pii_detected": {"color": CAUTION, "icon": "\U0001f512"},
}

# ---------------------------------------------------------------------------
# Button semantic colors
# ---------------------------------------------------------------------------
BUTTON_COLORS = {
    "block": ERROR,
    "allow_once": SUCCESS,
    "allow_always": PRIMARY,
    "suppress_in_source": WARNING,
    "ignore_file": INFO,
    "view_file": None,
    "save": SUCCESS,
    "cancel": None,
}

# ---------------------------------------------------------------------------
# Quasar / NiceGUI adapter
# ---------------------------------------------------------------------------
_QUASAR_MAP = {
    ERROR: "red-8",
    WARNING: "orange-8",
    CAUTION: "amber-8",
    SUCCESS: "green-8",
    PRIMARY: "blue-8",
    INFO: "blue-grey-7",
}


def quasar_color(hex_color: Optional[str]) -> str:
    """Map a theme hex color to the nearest Quasar color name."""
    if hex_color is None:
        return "grey"
    return _QUASAR_MAP.get(hex_color, "grey")


def quasar_severity(severity: str) -> str:
    """Map a severity level to a Quasar color name."""
    return quasar_color(SEVERITY_COLORS.get(severity, INFO))


def quasar_button(button_key: str) -> str:
    """Map a button semantic key to a Quasar color name."""
    return quasar_color(BUTTON_COLORS.get(button_key))


def violation_badge(violation_type: str) -> tuple:
    """Return (icon, color_hex) for a violation type."""
    badge = VIOLATION_BADGES.get(violation_type, {"color": INFO, "icon": "❓"})
    return badge["icon"], badge["color"]


# ---------------------------------------------------------------------------
# Textual CSS adapter
# ---------------------------------------------------------------------------
def textual_severity_class(severity: str) -> str:
    """Map a severity to a Textual CSS class name."""
    _map = {
        "critical": "status-error",
        "high": "status-error",
        "warning": "status-warn",
        "medium": "status-warn",
        "low": "status-info",
        "info": "status-info",
    }
    return _map.get(severity, "")


# ---------------------------------------------------------------------------
# Image path resolution
# ---------------------------------------------------------------------------
def get_images_dir() -> Optional[Path]:
    """Resolve the images directory (works in dev layout and installed)."""
    pkg_dir = Path(__file__).resolve().parent
    candidates = [
        pkg_dir / "images",
        pkg_dir.parent.parent / "images",
    ]
    for d in candidates:
        if d.is_dir():
            return d
    return None


def get_image_path(name: str) -> Optional[Path]:
    """Get the path to a specific image file."""
    d = get_images_dir()
    if d is not None:
        p = d / name
        if p.exists():
            return p
    return None
