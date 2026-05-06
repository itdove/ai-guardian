"""
System tray integration using pystray (optional dependency).

Provides a system tray icon with status indicator, violation count, and
menu for pause/resume/quit. Gracefully degrades to no-op if pystray
is not installed.
"""

import logging
import threading

logger = logging.getLogger(__name__)

try:
    import pystray
    from PIL import Image, ImageDraw

    HAS_PYSTRAY = True
except Exception:
    HAS_PYSTRAY = False


def is_tray_available():
    """Check if system tray can be displayed (dependencies + display)."""
    if not HAS_PYSTRAY:
        return False
    # Check for display availability (headless servers have no display)
    import os
    if os.environ.get("DISPLAY") is None and os.environ.get("WAYLAND_DISPLAY") is None:
        import platform
        if platform.system() == "Linux":
            return False
    return True


class DaemonTray:
    """System tray icon for ai-guardian daemon."""

    def __init__(self, get_stats_callback, stop_callback, pause_callback):
        """Initialize tray icon.

        Args:
            get_stats_callback: Callable returning daemon stats dict
            stop_callback: Callable to stop the daemon
            pause_callback: Callable to toggle pause/resume
        """
        self._get_stats = get_stats_callback
        self._stop = stop_callback
        self._pause = pause_callback
        self._icon = None
        self._thread = None
        self._pause_timer = None
        self._status = "running"
        self._current_mode = self._read_mode_from_config()

    def start(self):
        """Start tray icon in a background thread."""
        if not HAS_PYSTRAY:
            logger.info("System tray not available (install pystray and Pillow)")
            return

        self._thread = threading.Thread(
            target=self._run, daemon=True, name="tray-icon"
        )
        self._thread.start()

    def run_blocking(self):
        """Run tray icon on the current thread (blocks).

        Required on macOS where AppKit needs the main thread.
        """
        if not HAS_PYSTRAY:
            logger.info("System tray not available")
            return
        self._run()

    def stop(self):
        """Stop tray icon."""
        self._stats_refresh_running = False
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass

    def update_status(self, status):
        """Update tray icon status (changes icon color).

        Args:
            status: "running", "paused", or "error"
        """
        self._status = status
        if self._icon and HAS_PYSTRAY:
            try:
                self._icon.icon = self._create_icon()
            except Exception:
                pass

    def _run(self):
        """Run tray icon (blocking, called in thread)."""
        menu = pystray.Menu(
            pystray.MenuItem("AI Guardian Daemon", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Console", self._on_open_console),
            pystray.MenuItem("Violations", self._on_open_violations),
            pystray.MenuItem("Daemon", self._on_open_daemon),
            pystray.MenuItem("Reload Config", self._on_reload_config),
            pystray.MenuItem(
                lambda _: f"Mode: {self._current_mode}",
                pystray.Menu(
                    pystray.MenuItem(
                        "auto",
                        lambda _, __: self._on_change_mode("auto"),
                        checked=lambda _: self._current_mode == "auto",
                        radio=True,
                    ),
                    pystray.MenuItem(
                        "local",
                        lambda _, __: self._on_change_mode("local"),
                        checked=lambda _: self._current_mode == "local",
                        radio=True,
                    ),
                    pystray.MenuItem(
                        "daemon",
                        lambda _, __: self._on_change_mode("daemon"),
                        checked=lambda _: self._current_mode == "daemon",
                        radio=True,
                    ),
                ),
            ),
            pystray.MenuItem(
                lambda _: self._proxy_text(),
                pystray.Menu(
                    pystray.MenuItem(
                        "Enabled",
                        lambda _, __: self._on_toggle_proxy(True),
                        checked=lambda _: self._is_proxy_enabled(),
                        radio=True,
                    ),
                    pystray.MenuItem(
                        "Disabled",
                        lambda _, __: self._on_toggle_proxy(False),
                        checked=lambda _: not self._is_proxy_enabled(),
                        radio=True,
                    ),
                ),
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                lambda _: self._pause_menu_label(),
                pystray.Menu(
                    pystray.MenuItem("5 minutes", lambda _, __: self._on_pause(5)),
                    pystray.MenuItem("15 minutes", lambda _, __: self._on_pause(15)),
                    pystray.MenuItem("30 minutes", lambda _, __: self._on_pause(30)),
                    pystray.MenuItem("1 hour", lambda _, __: self._on_pause(60)),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem("Until resumed", lambda _, __: self._on_pause(-1)),
                ),
                visible=lambda _: self._status != "paused",
            ),
            pystray.MenuItem(
                lambda _: self._resume_menu_label(),
                self._on_resume,
                visible=lambda _: self._status == "paused",
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                lambda _: self._status_text(), None, enabled=False
            ),
            pystray.MenuItem(
                lambda _: self._requests_text(), None, enabled=False
            ),
            pystray.MenuItem(
                lambda _: self._blocked_text(), None, enabled=False
            ),
            pystray.MenuItem(
                lambda _: self._warnings_text(), None, enabled=False
            ),
            pystray.MenuItem(
                lambda _: self._log_only_text(), None, enabled=False
            ),
            pystray.MenuItem(
                lambda _: self._violations_text(), None, enabled=False
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Restart", self._on_restart),
            pystray.MenuItem("Quit", self._on_quit),
        )
        self._icon = pystray.Icon(
            "ai-guardian", self._create_icon(), "AI Guardian", menu
        )
        self._start_stats_refresh()
        self._icon.run()

    def _create_icon(self):
        """Create tray icon from the project's shield image with status tint."""
        size = 64
        icon_img = self._load_project_icon(size)
        if icon_img is not None:
            return self._apply_status_tint(icon_img)
        return self._create_fallback_icon(size)

    def _load_project_icon(self, size):
        """Load the ai-guardian shield icon from the bundled images."""
        try:
            icon_path = self._find_icon_path()
            if icon_path is None:
                return None

            img = Image.open(icon_path).convert("RGBA")

            # The banner is wide — crop the shield from the center
            w, h = img.size
            # Shield is roughly centered horizontally, top 80% of height
            shield_size = min(w, h)
            left = (w - shield_size) // 2
            top = 0
            img = img.crop((left, top, left + shield_size, top + shield_size))

            img = img.resize((size, size), Image.LANCZOS)
            return img
        except Exception:
            return None

    @staticmethod
    def _find_icon_path():
        """Find the project icon file."""
        from pathlib import Path
        import importlib.resources

        # Try importlib.resources (works for installed packages)
        try:
            ref = importlib.resources.files("ai_guardian") / "images" / "ai-guardian.png"
            with importlib.resources.as_file(ref) as p:
                if p.exists():
                    return str(p)
        except Exception:
            pass

        # Fallback: relative to this source file
        src_dir = Path(__file__).resolve().parent.parent
        candidates = [
            src_dir / "images" / "ai-guardian.png",
            src_dir.parent.parent / "images" / "ai-guardian.png",
        ]
        for path in candidates:
            if path.exists():
                return str(path)

        return None

    def _apply_status_tint(self, img):
        """Apply a red tint overlay on top of the icon when paused/error."""
        if self._status == "running":
            return img

        tints = {
            "paused": (200, 30, 30, 140),
            "error": (200, 30, 30, 160),
        }
        tint = tints.get(self._status)
        if tint is None:
            return img

        overlay = Image.new("RGBA", img.size, tint)
        return Image.alpha_composite(img, overlay)

    @staticmethod
    def _create_fallback_icon(size):
        """Create a simple fallback icon if the project icon is not found."""
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse([4, 4, size - 4, size - 4], fill=(0, 160, 220, 255))
        try:
            draw.text((size // 4, size // 6), "G", fill=(255, 255, 255, 255))
        except Exception:
            pass
        return image

    def _status_text(self):
        return f"Status: {self._status}"

    def _requests_text(self):
        stats = self._get_stats()
        return f"Requests: {stats.get('request_count', 0)}"

    def _blocked_text(self):
        stats = self._get_stats()
        return f"Blocked: {stats.get('blocked_count', 0)}"

    def _warnings_text(self):
        stats = self._get_stats()
        return f"Warnings: {stats.get('warning_count', 0)}"

    def _log_only_text(self):
        stats = self._get_stats()
        return f"Log-only: {stats.get('log_only_count', 0)}"

    def _violations_text(self):
        stats = self._get_stats()
        return f"Violations: {stats.get('violation_count', 0)}"

    def _on_change_mode(self, mode):
        """Change daemon mode in config file."""
        try:
            import json
            from ai_guardian.config_utils import get_config_dir

            config_path = get_config_dir() / "ai-guardian.json"
            if config_path.exists():
                config = json.loads(config_path.read_text(encoding="utf-8"))
            else:
                config = {}

            if "daemon" not in config:
                config["daemon"] = {}
            config["daemon"]["mode"] = mode

            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                json.dumps(config, indent=2) + "\n", encoding="utf-8"
            )
            self._current_mode = mode
            logger.info(f"Daemon mode changed to '{mode}'")

            from ai_guardian.daemon.client import send_reload_config
            send_reload_config()
        except Exception as e:
            logger.debug(f"Failed to change mode: {e}")

    @staticmethod
    def _read_mode_from_config():
        """Read current daemon mode from config file."""
        try:
            import json
            from ai_guardian.config_utils import get_config_dir

            config_path = get_config_dir() / "ai-guardian.json"
            if config_path.exists():
                config = json.loads(config_path.read_text(encoding="utf-8"))
                return config.get("daemon", {}).get("mode", "auto")
        except Exception:
            pass
        return "auto"

    def _on_open_violations(self, icon, item):
        """Launch the console directly to the Violations panel."""
        self._launch_console("panel-violations")

    def _on_open_daemon(self, icon, item):
        """Launch the console directly to the Daemon panel."""
        self._launch_console("panel-daemon")

    def _on_open_console(self, icon, item):
        """Launch the console."""
        self._launch_console()

    def _launch_console(self, panel=None):
        """Launch the ai-guardian console in a new terminal window.

        Args:
            panel: Optional panel ID to open (e.g., 'panel-violations')
        """
        import subprocess
        import platform
        import shutil

        executable = shutil.which("ai-guardian")
        cmd_str = f"{executable} console" if executable else "python -m ai_guardian console"
        if panel:
            cmd_str += f" --panel {panel}"

        try:
            system = platform.system()
            if system == "Darwin":
                script = (
                    'tell application "Terminal"\n'
                    f'    set currentTab to do script "{cmd_str}"\n'
                    '    activate\n'
                    '    set zoomed of front window to true\n'
                    '    repeat\n'
                    '        delay 1\n'
                    '        if not busy of currentTab then\n'
                    '            close (every window whose tabs contains currentTab)\n'
                    '            exit repeat\n'
                    '        end if\n'
                    '    end repeat\n'
                    'end tell'
                )
                subprocess.Popen(["osascript", "-e", script])
            elif system == "Windows":
                subprocess.Popen(
                    f'start /max cmd /c "{cmd_str}"', shell=True
                )
            else:
                for term, args in [
                    ("gnome-terminal", ["--maximize", "--"]),
                    ("konsole", ["--fullscreen", "-e"]),
                    ("xfce4-terminal", ["--maximize", "-e"]),
                    ("xterm", ["-maximized", "-e"]),
                ]:
                    if shutil.which(term):
                        subprocess.Popen([term] + args + cmd_str.split())
                        break
        except Exception as e:
            logger.debug(f"Failed to open console: {e}")

    def _on_reload_config(self, icon, item):
        """Request daemon to reload its configuration file."""
        try:
            from ai_guardian.daemon.client import send_reload_config
            send_reload_config()
            logger.info("Config reload requested from tray menu")
        except Exception as e:
            logger.debug(f"Config reload failed: {e}")

    def _on_pause(self, minutes):
        """Pause scanning for a specified duration (called from menu = main thread)."""
        self._stop_pause_timer()
        self._pause(minutes)
        self._status = "paused"
        self._update_icon()
        if self._icon:
            self._icon.update_menu()
        if minutes > 0:
            self._start_pause_timer()

    def _on_resume(self, icon, item):
        """Resume scanning immediately (called from menu = main thread)."""
        self._stop_pause_timer()
        self._pause(0)
        self._status = "running"
        self._update_icon()
        icon.update_menu()

    def _start_pause_timer(self):
        """Start a background thread that updates the countdown and auto-resumes.

        Uses PyObjCTools.AppHelper.callAfter() to dispatch UI updates
        (update_menu, icon change) to the main thread on macOS.
        """
        self._pause_timer_running = True

        def _tick():
            import time
            while self._pause_timer_running and self._status == "paused":
                stats = self._get_stats()
                remaining = stats.get("pause_remaining_seconds", 0)
                if remaining <= 0 and self._status == "paused":
                    self._status = "running"
                    self._pause(0)
                    self._dispatch_to_main(self._refresh_icon_running)
                    break
                self._dispatch_to_main(self._refresh_menu)
                time.sleep(1)

        self._pause_timer = threading.Thread(
            target=_tick, daemon=True, name="pause-timer"
        )
        self._pause_timer.start()

    @staticmethod
    def _dispatch_to_main(func):
        """Dispatch a callable to the main thread (macOS-safe)."""
        try:
            from PyObjCTools.AppHelper import callAfter
            callAfter(func)
        except ImportError:
            # Not on macOS or PyObjC not available — call directly
            try:
                func()
            except Exception:
                pass

    def _update_icon(self):
        """Update the tray icon image."""
        if not self._icon:
            return
        self._icon.icon = self._create_icon()

    def _refresh_menu(self):
        """Refresh the tray menu (must be called on main thread)."""
        if self._icon:
            try:
                self._icon.update_menu()
            except Exception:
                pass

    def _refresh_icon_running(self):
        """Update icon and menu to reflect resumed state (main thread)."""
        if self._icon:
            try:
                self._update_icon()
                self._icon.update_menu()
            except Exception:
                pass

    def _stop_pause_timer(self):
        """Stop the pause countdown timer."""
        self._pause_timer_running = False
        self._pause_timer = None

    def _start_stats_refresh(self):
        """Start a background thread that refreshes menu counters periodically."""
        self._stats_refresh_running = True

        def _refresh():
            import time
            while self._stats_refresh_running:
                time.sleep(10)
                if self._stats_refresh_running and self._icon:
                    self._dispatch_to_main(self._refresh_menu)

        thread = threading.Thread(
            target=_refresh, daemon=True, name="stats-refresh"
        )
        thread.start()

    def _pause_menu_label(self):
        return "Pause..."

    def _resume_menu_label(self):
        stats = self._get_stats()
        remaining = stats.get("pause_remaining_seconds", 0)
        if remaining > 0:
            mins = int(remaining // 60)
            secs = int(remaining % 60)
            return f"Resume ({mins}m {secs}s left)"
        return "Resume (paused)"

    def _on_restart(self, icon, item):
        """Restart the daemon (stop + start)."""
        import subprocess
        import shutil

        executable = shutil.which("ai-guardian")
        if executable:
            cmd = [executable, "daemon", "restart"]
        else:
            import sys
            cmd = [sys.executable, "-m", "ai_guardian", "daemon", "restart"]

        self._stop()
        try:
            subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            logger.debug(f"Failed to restart daemon: {e}")

    def _proxy_text(self):
        stats = self._get_stats()
        proxy_port = stats.get("proxy_port", 0)
        if proxy_port:
            reqs = stats.get("proxy_request_count", 0)
            return f"Proxy: port {proxy_port} ({reqs} reqs)"
        return "Proxy: disabled"

    def _is_proxy_enabled(self):
        try:
            import json
            from ai_guardian.config_utils import get_config_dir
            config_path = get_config_dir() / "ai-guardian.json"
            if config_path.exists():
                config = json.loads(config_path.read_text(encoding="utf-8"))
                return config.get("daemon", {}).get("proxy", {}).get("enabled", False)
        except Exception:
            pass
        return False

    def _on_toggle_proxy(self, enabled):
        try:
            import json
            from ai_guardian.config_utils import get_config_dir

            config_path = get_config_dir() / "ai-guardian.json"
            if config_path.exists():
                config = json.loads(config_path.read_text(encoding="utf-8"))
            else:
                config = {}

            if "daemon" not in config:
                config["daemon"] = {}
            if "proxy" not in config["daemon"]:
                config["daemon"]["proxy"] = {}

            # Validate before enabling
            if enabled:
                proxy_cfg = dict(config["daemon"]["proxy"])
                proxy_cfg["enabled"] = True
                try:
                    from ai_guardian.daemon.proxy import validate_proxy_config
                    errors = validate_proxy_config(proxy_cfg)
                    if errors:
                        logger.error(
                            "Cannot enable proxy - config invalid: "
                            + "; ".join(errors)
                        )
                        return
                except ImportError:
                    pass

            config["daemon"]["proxy"]["enabled"] = enabled

            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                json.dumps(config, indent=2) + "\n", encoding="utf-8"
            )
            logger.info(f"Proxy {'enabled' if enabled else 'disabled'} in config")

            from ai_guardian.daemon.client import send_reload_config
            send_reload_config()
        except Exception as e:
            logger.debug(f"Failed to toggle proxy: {e}")

    def _on_quit(self, icon, item):
        self._stop()
