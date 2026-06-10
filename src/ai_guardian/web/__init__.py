"""
Web-based Console for AI Guardian (NiceGUI).

Provides a browser-based dashboard as an alternative to the TUI console.
Connects to daemons via their REST APIs using MultiDaemonClient.

Requires NiceGUI (Python >= 3.10).
"""

try:
    from ai_guardian.web.app import WebConsole
    HAS_NICEGUI = True
except ImportError:
    HAS_NICEGUI = False
    WebConsole = None

__all__ = ["WebConsole", "HAS_NICEGUI"]
