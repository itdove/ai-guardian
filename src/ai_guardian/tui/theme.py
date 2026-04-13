#!/usr/bin/env python3
"""
TUI Theme

Centralized color scheme and styling inspired by OpenShell TUI.
Provides semantic color names for consistent visual hierarchy.
"""

# Color palette
ACCENT = "#76b900"  # AI Guardian green
ACCENT_DIM = "#508c00"
EVERGLADE = "#123123"  # Dark green
BORDER_MUTED = "#2a4a2a"

# Status colors
STATUS_OK = "#76b900"  # Green
STATUS_WARN = "#d4aa00"  # Yellow
STATUS_ERROR = "#e03131"  # Red

# Text colors (for dark theme)
TEXT_PRIMARY = "white"
TEXT_MUTED = "grey70"
TEXT_DIM = "grey50"

# Selection/Focus
SELECTION_BG = "#1e3c2d"
CURSOR_INDICATOR = ACCENT
ACTIVE_INDICATOR = ACCENT

# UI Chrome
PANEL_BG = "$panel"
SURFACE_BG = "$surface"
