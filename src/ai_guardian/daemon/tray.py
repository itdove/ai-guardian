"""
System tray integration using pystray (optional dependency).

Provides a system tray icon with status indicator, violation count, and
menu for pause/resume/quit. Gracefully degrades to no-op if pystray
is not installed.
"""

import logging
import os
import threading

logger = logging.getLogger(__name__)


def _get_tray_lock_path():
    """Get the tray lock file path."""
    from ai_guardian.config_utils import get_state_dir
    return get_state_dir() / "tray.lock"


def _is_tray_running():
    """Check if another tray process is already running."""
    lock_path = _get_tray_lock_path()
    if not lock_path.exists():
        return False
    try:
        pid = int(lock_path.read_text().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, ProcessLookupError, OSError):
        lock_path.unlink(missing_ok=True)
        return False


def _write_tray_lock():
    """Write tray lock file with current PID."""
    lock_path = _get_tray_lock_path()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)


def _remove_tray_lock():
    """Remove tray lock file."""
    try:
        lock_path = _get_tray_lock_path()
        if lock_path.exists():
            pid = int(lock_path.read_text().strip())
            if pid == os.getpid():
                lock_path.unlink(missing_ok=True)
    except (ValueError, OSError):
        pass

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

    def __init__(self, get_stats_callback, stop_callback, pause_callback,
                 discovery=None, multi_client=None, standalone=False):
        """Initialize tray icon.

        Args:
            get_stats_callback: Callable returning daemon stats dict
            stop_callback: Callable to stop the daemon
            pause_callback: Callable to toggle pause/resume
            discovery: Optional DaemonDiscovery for multi-daemon support
            multi_client: Optional MultiDaemonClient for action routing
            standalone: True when running as standalone tray (not embedded in daemon)
        """
        self._get_stats = get_stats_callback
        self._stop = stop_callback
        self._pause = pause_callback
        self._discovery = discovery
        self._multi_client = multi_client
        self._standalone = standalone
        self._icon = None
        self._thread = None
        self._pause_timer = None
        self._status = "running"
        self._current_mode = self._read_mode_from_config()
        self._proactive_level = self._read_proactive_level()
        self._targets = []
        self._active_target = None

    def start(self):
        """Start tray icon in a background thread."""
        if not HAS_PYSTRAY:
            logger.info("System tray not available (install pystray and Pillow)")
            return

        if _is_tray_running():
            logger.info("System tray already running (pid in tray.lock), skipping")
            return

        _write_tray_lock()

        if self._discovery:
            self._discovery.start_background_discovery(self._on_targets_updated)

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

        if _is_tray_running():
            logger.info("System tray already running (pid in tray.lock), skipping")
            return

        _write_tray_lock()

        if self._discovery:
            self._discovery.start_background_discovery(self._on_targets_updated)

        self._run()

    def stop(self):
        """Stop tray icon."""
        self._stats_refresh_running = False
        if self._discovery:
            self._discovery.stop()
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
        _remove_tray_lock()

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
            *self._build_daemon_menu_items_static(),
            pystray.MenuItem("Restart", self._on_restart_tray),
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

    @staticmethod
    def _launch_console(panel=None):
        """Launch the ai-guardian console in a new terminal window."""
        import os
        import shutil
        import sys
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        executable = shutil.which("ai-guardian")
        if executable:
            cmd_parts = [os.path.abspath(executable), "console"]
        else:
            cmd_parts = [sys.executable, "-m", "ai_guardian", "console"]
        if panel:
            cmd_parts.extend(["--panel", panel])
        _launch_in_terminal(cmd_parts)

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


    def _on_targets_updated(self, targets):
        """Callback from background discovery with updated target list."""
        self._targets = targets
        self._auto_select_target()
        logger.info(f"Discovery updated: {len(targets)} target(s) found")
        for t in targets:
            logger.info(f"  {t.name} ({t.runtime}) status={t.status} port={t.port}")

    def _auto_select_target(self):
        """Auto-select the best running daemon target.

        Prefers: current selection (if still running) > running local > first running.
        """
        if (self._active_target and self._active_target.status == "running"):
            for t in self._targets:
                if (t.name == self._active_target.name
                        and t.runtime == self._active_target.runtime):
                    self._active_target = t
                    return

        for t in self._targets:
            if t.runtime == "local" and t.status == "running":
                self._active_target = t
                return

        for t in self._targets:
            if t.status == "running":
                self._active_target = t
                return

        if self._targets:
            self._active_target = self._targets[0]
        else:
            self._active_target = None

    def _get_active_stats(self):
        """Get stats from the active target (local or remote).

        Also updates the target name from the REST API response if
        the daemon reports a configured name.
        """
        if (self._multi_client and self._active_target
                and self._active_target.runtime != "local"):
            result = self._multi_client.get_status(self._active_target)
            if result and result.get("name"):
                self._active_target.name = result["name"]
            return result or {}
        return self._get_stats()

    _MAX_DAEMON_SLOTS = 8

    def _build_daemon_menu_items_static(self):
        """Build fixed-slot menu items with per-daemon action submenus.

        Each daemon gets its own submenu with Console, Pause, Restart, etc.
        pystray on macOS requires items defined at build time, so we
        pre-allocate slots with dynamic text/visibility lambdas.
        """
        items = []
        for i in range(self._MAX_DAEMON_SLOTS):
            idx = i

            def make_label(_item, slot=idx):
                if slot >= len(self._targets):
                    return ""
                t = self._targets[slot]
                status_icon = {
                    "running": "●", "paused": "◐",
                    "error": "✗", "unknown": "○",
                }.get(t.status, "○")
                if t.runtime == "container" and t.container_engine:
                    runtime = f" ({t.container_engine})"
                elif t.runtime != "local":
                    runtime = f" ({t.runtime})"
                else:
                    runtime = ""
                return f"{status_icon} {t.name}{runtime}"

            def make_visible(_item, slot=idx):
                if slot == 0 and self._discovery:
                    self._discovery.request_refresh(wait=True, timeout=1.0)
                return slot < len(self._targets)

            def _mk_open_panel(panel=None, slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.open_console(t, panel)
                        else:
                            self._launch_console(panel)
                return action

            def _mk_pause(minutes, slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client and t.runtime != "local":
                            self._multi_client.send_pause(t, minutes)
                        else:
                            self._pause(minutes)
                return action

            def _mk_resume(slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client and t.runtime != "local":
                            self._multi_client.send_resume(t)
                        else:
                            self._pause(0)
                return action

            def _mk_stop(slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.send_stop(t)
                return action

            def _mk_restart(slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.send_restart(t)
                return action

            def _mk_stats(slot=idx):
                _cache = {"stats": {}, "time": 0}

                def _get(_item):
                    import time as time_mod
                    now = time_mod.monotonic()
                    if now - _cache["time"] < 2.0:
                        return _cache["stats"]
                    if slot >= len(self._targets):
                        return {}
                    target = self._targets[slot]
                    if self._multi_client and target.runtime != "local":
                        result = self._multi_client.get_status(target)
                        if result and result.get("name"):
                            target.name = result["name"]
                        _cache["stats"] = result or {}
                    else:
                        _cache["stats"] = self._get_stats()
                    _cache["time"] = now
                    return _cache["stats"]

                def requests(_item):
                    s = _get(_item)
                    return f"Requests: {s.get('request_count', 0):,}"

                def blocked(_item):
                    s = _get(_item)
                    b = s.get('blocked_count', 0)
                    t = s.get('request_count', 0)
                    if t > 0:
                        return f"Blocked: {b:,} ({b/t*100:.1f}%)"
                    return f"Blocked: {b:,}"

                def warned(_item):
                    s = _get(_item)
                    return f"Warned: {s.get('warning_count', 0):,}"

                def logged(_item):
                    s = _get(_item)
                    return f"Logged: {s.get('log_only_count', 0):,}"

                def violations(_item):
                    s = _get(_item)
                    return f"Violations: {s.get('violation_count', 0):,}"

                def critical(_item):
                    s = _get(_item)
                    return f"  Critical: {s.get('critical_count', 0):,}"

                def warning_sev(_item):
                    s = _get(_item)
                    return f"  Warning: {s.get('warning_severity_count', 0):,}"

                def last_block(_item):
                    s = _get(_item)
                    bt = s.get('last_block_type')
                    ba = s.get('last_block_seconds_ago')
                    if bt is None:
                        return "Last block: none"
                    return f"Last block: {bt} {self._format_time_ago(ba)}"

                def config_reload(_item):
                    s = _get(_item)
                    ago = s.get('last_config_reload_seconds_ago')
                    if ago is not None:
                        return f"Config reloaded: {self._format_time_ago(ago)}"
                    return "Config: loaded"

                return (requests, blocked, warned, logged,
                        violations, critical, warning_sev,
                        last_block, config_reload)

            stats_fns = _mk_stats()

            def _is_slot_running(_item, slot=idx):
                return (slot < len(self._targets)
                        and self._targets[slot].status == "running")

            items.append(
                pystray.MenuItem(
                    make_label,
                    pystray.Menu(
                        pystray.MenuItem("Console", _mk_open_panel()),
                        pystray.MenuItem("Violations", _mk_open_panel("panel-violations")),
                        pystray.MenuItem("Metrics", _mk_open_panel("panel-metrics")),
                        pystray.MenuItem(
                            "Statistics",
                            pystray.Menu(
                                pystray.MenuItem(stats_fns[0], None),
                                pystray.MenuItem(stats_fns[1], None),
                                pystray.MenuItem(stats_fns[2], None),
                                pystray.MenuItem(stats_fns[3], None),
                                pystray.Menu.SEPARATOR,
                                pystray.MenuItem(stats_fns[4], None),
                                pystray.MenuItem(stats_fns[5], None),
                                pystray.MenuItem(stats_fns[6], None),
                                pystray.Menu.SEPARATOR,
                                pystray.MenuItem(stats_fns[7], None),
                                pystray.Menu.SEPARATOR,
                                pystray.MenuItem(stats_fns[8], None),
                            ),
                            visible=_is_slot_running,
                        ),
                        pystray.Menu.SEPARATOR,
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
                            "Pause...",
                            pystray.Menu(
                                pystray.MenuItem("5 minutes", _mk_pause(5)),
                                pystray.MenuItem("15 minutes", _mk_pause(15)),
                                pystray.MenuItem("30 minutes", _mk_pause(30)),
                                pystray.MenuItem("1 hour", _mk_pause(60)),
                            ),
                            visible=_is_slot_running,
                        ),
                        pystray.MenuItem(
                            "Resume", _mk_resume(),
                            visible=_is_slot_running,
                        ),
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem(
                            "Start daemon", _mk_restart(),
                            visible=lambda _i, s=idx: (
                                s < len(self._targets)
                                and self._targets[s].status != "running"
                            ),
                        ),
                        pystray.MenuItem(
                            "Stop daemon", _mk_stop(),
                            visible=_is_slot_running,
                        ),
                        pystray.MenuItem(
                            "Restart daemon", _mk_restart(),
                            visible=_is_slot_running,
                        ),
                    ),
                    visible=make_visible,
                )
            )
        return items

    def _on_restart_tray(self, icon, item):
        """Restart the tray process."""
        import shutil
        import subprocess
        import sys

        executable = shutil.which("ai-guardian")
        cmd = (
            [executable, "tray", "start"]
            if executable
            else [sys.executable, "-m", "ai_guardian", "tray", "start"]
        )
        self.stop()
        self._stop()
        try:
            subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as e:
            logger.debug("Failed to restart tray: %s", e)

    def _on_quit(self, icon, item):
        self.stop()
        self._stop()
