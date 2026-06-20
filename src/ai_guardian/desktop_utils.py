"""Desktop integration utilities for opening browser URLs."""

from __future__ import annotations

import platform
import subprocess
import threading
import time
import webbrowser

_BROWSER_CLASSES = "firefox|chrom|brave|vivaldi|opera|msedge"


def open_url(url: str) -> None:
    """Open *url* in the default browser and raise the window on Linux.

    On KDE/GNOME the browser may stay minimized after ``xdg-open``
    navigates to the URL.  This function opens the URL normally, then
    attempts to raise the browser window in a background thread using
    (in order): ``kdotool`` (KDE Wayland), ``xdotool`` (X11), or
    ``wmctrl`` (X11).  Silently continues if none is installed.

    No-op on macOS and Windows beyond the normal ``webbrowser.open()``.
    """
    if platform.system() == "Linux":
        browser = _get_default_browser()
        if browser:
            try:
                subprocess.Popen([browser, url])
            except OSError:
                webbrowser.open(url)
        else:
            webbrowser.open(url)
        _raise_browser_window()
        return

    webbrowser.open(url)


def _raise_browser_window(delay: float = 0.5) -> None:
    """Try to raise the browser window after a short delay."""
    threading.Thread(target=_activate, args=(delay,), daemon=True).start()


def _activate(delay: float) -> None:
    time.sleep(delay)
    if _try_kdotool():
        return
    if _try_xdotool():
        return
    _try_wmctrl()


def _try_kdotool() -> bool:
    try:
        subprocess.run(
            ["kdotool", "search", "--class", _BROWSER_CLASSES,
             "windowactivate"],
            capture_output=True, timeout=3,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    except Exception:
        return False


def _try_xdotool() -> bool:
    try:
        subprocess.run(
            ["xdotool", "search", "--limit", "1",
             "--class", _BROWSER_CLASSES, "windowactivate"],
            capture_output=True, timeout=3,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    except Exception:
        return False


def _try_wmctrl() -> bool:
    for name in ("firefox", "chrome", "chromium", "brave"):
        try:
            result = subprocess.run(
                ["wmctrl", "-xa", name],
                capture_output=True, timeout=3,
            )
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            return False
        except Exception:
            continue
    return False


def _get_default_browser() -> str | None:
    """Return the default browser executable name, or ``None``."""
    import shutil

    try:
        result = subprocess.run(
            ["xdg-settings", "get", "default-web-browser"],
            capture_output=True, text=True, timeout=3,
        )
        desktop = result.stdout.strip()
        if not desktop.endswith(".desktop"):
            return None
        name = desktop.removesuffix(".desktop")
        if shutil.which(name):
            return name
    except (OSError, subprocess.TimeoutExpired):
        pass  # intentionally silent — subprocess may fail
    return None
