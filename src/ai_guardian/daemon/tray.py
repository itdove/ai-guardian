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


def _suppress_gtk_stderr():
    """Redirect stderr fd to suppress C-level GTK warnings during init."""
    import platform
    if platform.system() != "Linux":
        return None
    try:
        import os
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        saved_fd = os.dup(2)
        os.dup2(devnull_fd, 2)
        os.close(devnull_fd)
        return saved_fd
    except OSError:
        return None


def _restore_stderr(saved_fd):
    """Restore stderr after GTK init completes."""
    if saved_fd is not None:
        try:
            import os
            os.dup2(saved_fd, 2)
            os.close(saved_fd)
        except OSError:
            pass


def is_tray_available():
    """Check if system tray can be displayed (dependencies + display)."""
    if not HAS_PYSTRAY:
        return False
    import os
    import platform
    if os.environ.get("DISPLAY") is None and os.environ.get("WAYLAND_DISPLAY") is None:
        if platform.system() == "Linux":
            return False
    if platform.system() == "Linux" and not _check_gnome_appindicator():
        return False
    return True


def _check_gnome_appindicator():
    """Check if GNOME has the AppIndicator extension enabled.

    Returns True if not GNOME, or if the extension is enabled.
    Returns False if GNOME is detected without the extension.
    """
    import os
    import shutil
    import subprocess

    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
    if "GNOME" not in desktop.upper():
        return True

    if not shutil.which("gnome-extensions"):
        return True

    try:
        result = subprocess.run(
            ["gnome-extensions", "list", "--enabled"],
            capture_output=True, text=True, timeout=5,
        )
        if "appindicatorsupport@rgcjonas.gmail.com" in result.stdout:
            return True
    except (subprocess.TimeoutExpired, OSError):
        return True

    logger.warning(
        "GNOME detected but AppIndicator extension not enabled — "
        "tray icon will not appear. Fix: "
        "sudo dnf install gnome-shell-extension-appindicator.noarch && "
        "log out/in, then: gnome-extensions enable "
        "appindicatorsupport@rgcjonas.gmail.com"
    )
    return False


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
        self._proactive_level = self._read_proactive_level()

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

    def flash_reload(self):
        """Briefly flash the icon yellow to indicate config reload."""
        if not self._icon:
            return
        prev = self._status
        self._status = "reloading"
        self._dispatch_to_main(self._update_icon)

        def _revert():
            if self._status == "reloading":
                self._status = prev
            self._dispatch_to_main(self._update_icon)

        threading.Timer(1.0, _revert).start()

    def _run(self):
        """Run tray icon (blocking, called in thread)."""
        menu = pystray.Menu(
            pystray.MenuItem(
                lambda _: self._header_text(),
                pystray.Menu(
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
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem(
                        lambda _: self._violations_text(), None, enabled=False
                    ),
                    pystray.MenuItem(
                        lambda _: self._critical_text(), None, enabled=False
                    ),
                    pystray.MenuItem(
                        lambda _: self._warning_severity_text(), None, enabled=False
                    ),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem(
                        lambda _: self._last_block_text(), None, enabled=False
                    ),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem(
                        lambda _: self._config_reload_text(), None, enabled=False
                    ),
                ),
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Console", self._on_open_console),
            pystray.MenuItem("Violations", self._on_open_violations),
            pystray.MenuItem("Metrics", self._on_open_metrics),
            pystray.MenuItem("Daemon", self._on_open_daemon),
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
                lambda _: f"MCP Proactive: {self._proactive_level}",
                pystray.Menu(
                    pystray.MenuItem(
                        "low",
                        lambda _, __: self._on_change_proactive("low"),
                        checked=lambda _: self._proactive_level == "low",
                        radio=True,
                    ),
                    pystray.MenuItem(
                        "medium",
                        lambda _, __: self._on_change_proactive("medium"),
                        checked=lambda _: self._proactive_level == "medium",
                        radio=True,
                    ),
                    pystray.MenuItem(
                        "high",
                        lambda _, __: self._on_change_proactive("high"),
                        checked=lambda _: self._proactive_level == "high",
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
            pystray.MenuItem("Restart", self._on_restart),
            pystray.MenuItem("Quit", self._on_quit),
        )
        self._icon = pystray.Icon(
            "ai-guardian", self._create_icon(), "AI Guardian", menu
        )
        self._start_stats_refresh()
        import platform
        if platform.system() == "Linux":
            saved_fd = _suppress_gtk_stderr()
            threading.Timer(2.0, _restore_stderr, args=[saved_fd]).start()
            self._icon.run()
        else:
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
        """Apply a color tint overlay on top of the icon for status."""
        if self._status == "running":
            return img

        tints = {
            "paused": (200, 30, 30, 140),
            "error": (200, 30, 30, 160),
            "reloading": (220, 180, 30, 140),
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

    def _header_text(self):
        status = "Running" if self._status == "running" else self._status.title()
        return f"● AI Guardian — {status}"

    def _requests_text(self):
        stats = self._get_stats()
        count = stats.get('request_count', 0)
        return f"Requests: {count:,}"

    def _blocked_text(self):
        stats = self._get_stats()
        blocked = stats.get('blocked_count', 0)
        total = stats.get('request_count', 0)
        if total > 0:
            pct = blocked / total * 100
            return f"Blocked: {blocked:,} ({pct:.1f}%)"
        return f"Blocked: {blocked:,}"

    def _warnings_text(self):
        stats = self._get_stats()
        count = stats.get('warning_count', 0)
        return f"Warned: {count:,}"

    def _log_only_text(self):
        stats = self._get_stats()
        count = stats.get('log_only_count', 0)
        return f"Logged: {count:,}"

    def _violations_text(self):
        stats = self._get_stats()
        count = stats.get('violation_count', 0)
        return f"Violations: {count:,}"

    def _critical_text(self):
        stats = self._get_stats()
        count = stats.get('critical_count', 0)
        return f"  Critical: {count:,}"

    def _warning_severity_text(self):
        stats = self._get_stats()
        count = stats.get('warning_severity_count', 0)
        return f"  Warning: {count:,}"

    def _last_block_text(self):
        stats = self._get_stats()
        block_type = stats.get('last_block_type')
        seconds_ago = stats.get('last_block_seconds_ago')
        if block_type is None:
            return "Last block: none"
        return f"Last block: {block_type} {self._format_time_ago(seconds_ago)}"

    def _config_reload_text(self):
        stats = self._get_stats()
        seconds_ago = stats.get('last_config_reload_seconds_ago')
        project_count = stats.get('project_configs_tracked', 0)
        project_ago = stats.get('last_project_config_reload_seconds_ago')

        parts = []
        if seconds_ago is not None:
            parts.append(f"Config reloaded: {self._format_time_ago(seconds_ago)}")
        else:
            parts.append("Config: loaded")

        if project_count > 0:
            suffix = f" (reload: {self._format_time_ago(project_ago)})" if project_ago is not None else ""
            parts.append(f"Projects: {project_count}{suffix}")

        return " | ".join(parts)

    @staticmethod
    def _format_time_ago(seconds):
        if seconds is None:
            return ""
        seconds = int(seconds)
        if seconds < 60:
            return f"{seconds}s ago"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m ago"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h ago"
        days = hours // 24
        return f"{days}d ago"

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

    def _on_change_proactive(self, level):
        """Change MCP proactive check level in config file."""
        try:
            import json
            from ai_guardian.config_utils import get_config_dir

            config_path = get_config_dir() / "ai-guardian.json"
            if config_path.exists():
                config = json.loads(config_path.read_text(encoding="utf-8"))
            else:
                config = {}

            if "mcp_server" not in config:
                config["mcp_server"] = {}
            config["mcp_server"]["proactive_level"] = level

            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                json.dumps(config, indent=2) + "\n", encoding="utf-8"
            )
            self._proactive_level = level
            logger.info(f"MCP proactive level changed to '{level}'")
        except Exception as e:
            logger.debug(f"Failed to change proactive level: {e}")

    @staticmethod
    def _read_proactive_level():
        """Read current MCP proactive level from config file."""
        try:
            import json
            from ai_guardian.config_utils import get_config_dir

            config_path = get_config_dir() / "ai-guardian.json"
            if config_path.exists():
                config = json.loads(config_path.read_text(encoding="utf-8"))
                return config.get("mcp_server", {}).get("proactive_level", "low")
        except Exception:
            pass
        return "medium"

    def _on_open_violations(self, icon, item):
        """Launch the console directly to the Violations panel."""
        self._launch_console("panel-violations")

    def _on_open_metrics(self, icon, item):
        """Launch the console directly to the Metrics panel."""
        self._launch_console("panel-metrics")

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
        import os
        import shlex
        import subprocess
        import sys
        import platform
        import shutil

        executable = shutil.which("ai-guardian")
        if executable:
            executable = os.path.abspath(executable)
            cmd_parts = [executable, "console"]
        else:
            cmd_parts = [sys.executable, "-m", "ai_guardian", "console"]
        if panel:
            cmd_parts.extend(["--panel", panel])

        cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
        logger.debug("Console launch cmd: %s", cmd_str)

        try:
            system = platform.system()
            if system == "Darwin":
                script = (
                    'tell application "Terminal"\n'
                    '    set currentTab to do script ""\n'
                    '    delay 2\n'
                    f'    do script "{cmd_str}" in currentTab\n'
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
                    ("kgx", ["-e"]),
                    ("konsole", ["--fullscreen", "-e"]),
                    ("xfce4-terminal", ["--maximize", "-e"]),
                    ("xterm", ["-maximized", "-e"]),
                ]:
                    if shutil.which(term):
                        subprocess.Popen([term] + args + cmd_parts)
                        break
        except Exception as e:
            logger.debug(f"Failed to open console: {e}")

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

    def _on_quit(self, icon, item):
        self._stop()
