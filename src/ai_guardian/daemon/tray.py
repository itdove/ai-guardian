"""
System tray integration using pystray (optional dependency).

Provides a system tray icon with status indicator, violation count, and
menu for pause/resume/quit. Gracefully degrades to no-op if pystray
is not installed.
"""

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)


def _get_tray_lock_path():
    """Get the tray lock file path."""
    from ai_guardian.config_utils import get_state_dir
    return get_state_dir() / "tray.lock"


def _is_tray_running():
    """Check if another tray process is already running.

    Returns the PID (int) of the running tray if found, otherwise False.
    """
    from ai_guardian.daemon import is_pid_alive

    lock_path = _get_tray_lock_path()
    if not lock_path.exists():
        return False
    try:
        pid = int(lock_path.read_text().strip())
        if is_pid_alive(pid):
            return pid
        lock_path.unlink(missing_ok=True)
        return False
    except ValueError:
        lock_path.unlink(missing_ok=True)
        return False


def _write_tray_lock():
    """Write tray lock file with current PID.

    Uses O_CREAT|O_EXCL for atomic creation to prevent concurrent tray
    starts from racing past the _is_tray_running() check.
    """
    from ai_guardian.daemon import is_pid_alive

    lock_path = _get_tray_lock_path()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
    except FileExistsError:
        try:
            old_pid = int(lock_path.read_text().strip())
            if is_pid_alive(old_pid):
                raise RuntimeError(f"Tray already starting (pid {old_pid})")
        except (ValueError, OSError):
            pass
        lock_path.unlink(missing_ok=True)
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
        self._proactive_level = self._read_proactive_level()
        self._mcp_installed = self._is_mcp_installed()
        self._targets = []
        self._active_target = None
        self._daemon_plugins = {}
        self._last_plugins_hash = {}
        self._config_error_notified = False
        self._discovery_animating = False
        self._discovery_anim_stop = threading.Event()
        self._discovery_timer = None
        self._discovery_frames = None
        self._is_initial_discovery = True
        self._discovery_in_progress = False
        self._refreshing_from_discovery = False

    def start(self):
        """Start tray icon in a background thread.

        Returns True if started, False if already running or unavailable.
        """
        if not HAS_PYSTRAY:
            logger.info("System tray not available (install pystray and Pillow)")
            return False

        if _is_tray_running():
            logger.info("System tray already running (pid in tray.lock), skipping")
            return False

        _write_tray_lock()

        self._thread = threading.Thread(
            target=self._run, daemon=True, name="tray-icon"
        )
        self._thread.start()
        return True

    def run_blocking(self):
        """Run tray icon on the current thread (blocks).

        Required on macOS where AppKit needs the main thread.
        Returns True if started, False if already running or unavailable.
        """
        if not HAS_PYSTRAY:
            logger.info("System tray not available")
            return False

        existing_pid = _is_tray_running()
        if existing_pid:
            logger.info("System tray already running (pid %s in tray.lock), skipping", existing_pid)
            return False

        _write_tray_lock()

        self._run()

    def stop(self):
        """Stop tray icon."""
        self._stop_discovery_animation()
        self._stats_refresh_running = False
        self._unregister_wake_handler()
        if self._discovery:
            self._discovery.stop()
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
        _remove_tray_lock()

    def update_status(self, status):
        """Update tray icon status and manage pause timer.

        Args:
            status: "running", "paused", or "error"
        """
        prev = self._status
        self._status = status
        self._invalidate_discovery_frames()
        if self._icon:
            self._icon.icon = self._create_icon()
        if status == "paused" and prev != "paused":
            self._start_pause_timer()
        elif status != "paused" and prev == "paused":
            self._stop_pause_timer()

    def flash_reload(self):
        """Record config reload (no visual change with monochrome icons)."""
        pass

    @staticmethod
    def _ensure_macos_activation_policy():
        """Set NSApplicationActivationPolicyAccessory on macOS.

        When launched from an .app bundle wrapper, the process may lose
        its Info.plist association after exec, so LSUIElement=True has no
        effect.  Setting the policy explicitly ensures the status bar
        icon appears regardless of launch method (issue #691).
        """
        import platform
        if platform.system() != "Darwin":
            return
        try:
            import AppKit
            app = AppKit.NSApplication.sharedApplication()
            app.setActivationPolicy_(
                AppKit.NSApplicationActivationPolicyAccessory
            )
        except Exception:
            pass

    def _run(self):
        """Run tray icon (blocking, called in thread)."""
        self._ensure_macos_activation_policy()
        menu = pystray.Menu(
            *self._build_single_daemon_menu_items(),
            *self._build_single_daemon_plugin_items(),
            *self._build_single_daemon_daemon_items(),
            *self._build_multi_daemon_menu_items(),
            pystray.Menu.SEPARATOR,
            *self._build_ide_setup_menu_items(),
            pystray.MenuItem("Restart", self._on_restart_tray),
            pystray.MenuItem("Quit", self._on_quit),
        )
        self._icon = pystray.Icon(
            "ai-guardian", self._create_icon(), "AI Guardian Tray", menu
        )
        if self._discovery:
            self._is_initial_discovery = True
            self._discovery_in_progress = True
            self._start_discovery_animation(delay=0)
            self._discovery.start_background_discovery(self._on_targets_updated)
        self._start_stats_refresh()
        self._register_wake_handler()
        import platform
        if platform.system() == "Linux":
            saved_fd = _suppress_gtk_stderr()
            threading.Timer(2.0, _restore_stderr, args=[saved_fd]).start()
            self._icon.run()
        else:
            self._icon.run()

    def _create_icon(self):
        """Create tray icon from monochrome shield template images."""
        icon_path = self._find_tray_icon_path()
        img = None
        if icon_path is not None:
            try:
                img = Image.open(icon_path).convert("RGBA")
            except Exception:
                pass
        if img is None:
            img = self._create_fallback_icon(22)
        if self._status == "paused":
            img = self._apply_paused_dimming(img)
        return img

    @staticmethod
    def _apply_paused_dimming(img):
        """Reduce alpha to ~50% to indicate paused state."""
        img = img.copy()
        alpha = img.split()[3]
        alpha = alpha.point(lambda a: a // 2)
        img.putalpha(alpha)
        return img

    @staticmethod
    def _get_tray_icon_size():
        """Return the preferred tray icon size for the current platform."""
        import platform
        system = platform.system()
        if system == "Darwin":
            return None  # macOS uses Template naming, not size suffix
        if system == "Windows":
            return 16
        return 22  # Linux (GNOME/KDE)

    @staticmethod
    def _find_tray_icon_path():
        """Find the monochrome tray icon for the current platform."""
        from pathlib import Path
        import platform
        import importlib.resources

        system = platform.system()

        if system == "Darwin":
            names = ["tray-iconTemplate@2x.png", "tray-iconTemplate.png"]
        elif system == "Windows":
            names = ["tray-icon-16.png"]
        else:
            names = ["tray-icon-22.png", "tray-icon-32.png"]

        for name in names:
            try:
                ref = (importlib.resources.files("ai_guardian")
                       / "images" / name)
                with importlib.resources.as_file(ref) as p:
                    if p.exists():
                        return str(p)
            except Exception:
                pass

        src_dir = Path(__file__).resolve().parent.parent
        candidates_dirs = [
            src_dir / "images",
            src_dir.parent.parent / "images",
        ]
        for d in candidates_dirs:
            for name in names:
                path = d / name
                if path.exists():
                    return str(path)

        return None

    @staticmethod
    def _create_fallback_icon(size):
        """Create a simple fallback icon if the tray icon files are not found."""
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse([4, 4, size - 4, size - 4], fill=(0, 160, 220, 255))
        try:
            draw.text((size // 4, size // 6), "G", fill=(255, 255, 255, 255))
        except Exception:
            pass
        return image

    def _generate_discovery_frames(self):
        """Generate alpha-pulsing icon frames for discovery animation."""
        if self._discovery_frames is not None:
            return self._discovery_frames
        base = self._create_icon()
        frames = []
        for alpha_pct in (100, 60, 30, 60):
            frame = base.copy()
            alpha = frame.split()[3]
            alpha = alpha.point(lambda a, pct=alpha_pct: a * pct // 100)
            frame.putalpha(alpha)
            frames.append(frame)
        self._discovery_frames = frames
        return frames

    def _invalidate_discovery_frames(self):
        """Clear cached animation frames."""
        self._discovery_frames = None

    def _start_discovery_animation(self, delay=0.5):
        """Schedule discovery animation after delay (0 for immediate)."""
        logger.info("Discovery animation: scheduling (delay=%.1fs)", delay)
        self._cancel_discovery_timer()
        self._discovery_anim_stop.clear()
        if delay <= 0:
            self._begin_discovery_animation()
        else:
            self._discovery_timer = threading.Timer(
                delay, self._begin_discovery_animation
            )
            self._discovery_timer.daemon = True
            self._discovery_timer.start()

    def _begin_discovery_animation(self):
        """Start the frame-cycling animation loop in a daemon thread."""
        if self._discovery_anim_stop.is_set():
            logger.info("Discovery animation: skipped (already stopped)")
            return
        logger.info("Discovery animation: starting loop")
        self._discovery_animating = True
        thread = threading.Thread(
            target=self._animate_discovery_loop,
            daemon=True, name="discovery-anim",
        )
        thread.start()

    def _animate_discovery_loop(self):
        """Cycle through alpha-pulsing icon frames until discovery completes."""
        frames = self._generate_discovery_frames()
        idx = 0
        while not self._discovery_anim_stop.is_set():
            if self._icon and not self._discovery_anim_stop.is_set():
                frame = frames[idx % len(frames)]
                self._dispatch_to_main(lambda f=frame: self._set_icon_frame(f))
            idx += 1
            self._discovery_anim_stop.wait(timeout=0.2)
        logger.info("Discovery animation: loop ended")
        self._discovery_animating = False

    def _set_icon_frame(self, frame):
        """Set the tray icon to a specific frame (main thread)."""
        if self._icon:
            self._icon.icon = frame

    def _stop_discovery_animation(self):
        """Stop discovery animation and restore normal icon."""
        logger.info("Discovery animation: stopping")
        self._cancel_discovery_timer()
        self._discovery_anim_stop.set()
        if self._icon:
            self._dispatch_to_main(self._refresh_icon_after_discovery)

    def _cancel_discovery_timer(self):
        """Cancel the pending discovery animation timer."""
        if self._discovery_timer is not None:
            self._discovery_timer.cancel()
            self._discovery_timer = None

    def _refresh_icon_after_discovery(self):
        """Restore normal icon after discovery animation (main thread)."""
        if self._icon:
            self._icon.icon = self._create_icon()

    def _request_discovery_refresh(self, **kwargs):
        """Request discovery refresh with animation support."""
        if self._discovery and not self._refreshing_from_discovery:
            self._discovery_in_progress = True
            self._start_discovery_animation(delay=0.5)
            self._discovery.request_refresh(**kwargs)

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
    def _is_mcp_installed():
        """Check if ai-guardian MCP server is configured in any supported IDE."""
        import json
        from pathlib import Path

        ide_mcp_configs = [
            ("~/.claude.json", "mcpServers"),
            ("~/.cursor/mcp.json", "mcpServers"),
            ("~/.windsurf/mcp.json", "mcpServers"),
            ("~/.gemini/settings.json", "mcpServers"),
            ("~/.cline/mcp_settings.json", "mcpServers"),
            ("~/.augment/settings.json", "mcpServers"),
            ("~/.kiro/settings.json", "mcpServers"),
            ("~/.junie/mcp.json", "mcpServers"),
            ("~/.aider-desk/settings.json", "mcpServers"),
            ("~/.openclaw/settings.json", "mcpServers"),
        ]
        for config_file, key in ide_mcp_configs:
            try:
                path = Path(config_file).expanduser()
                if path.exists():
                    config = json.loads(path.read_text(encoding="utf-8"))
                    if "ai-guardian" in config.get(key, {}):
                        return True
            except Exception:
                continue
        return False

    @staticmethod
    def _resolve_cli_cmd(*args):
        """Build command list for running ai-guardian with given arguments.

        Always uses the current process's Python interpreter to guarantee
        the same virtualenv as the running tray.
        """
        import sys

        return [sys.executable, "-m", "ai_guardian"] + list(args)

    @staticmethod
    def _launch_console(panel=None):
        """Launch the ai-guardian console in a new terminal window."""
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        cmd_parts = DaemonTray._resolve_cli_cmd("console")
        if panel:
            cmd_parts.extend(["--panel", panel])
        _launch_in_terminal(cmd_parts)

    @staticmethod
    def _launch_shell():
        """Launch the user's default shell in a new terminal window."""
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        import os
        shell = os.environ.get("SHELL", "/bin/sh")
        _launch_in_terminal([shell], keep_open=True)

    @staticmethod
    def _launch_doctor():
        """Launch ai-guardian doctor in a new terminal window."""
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        _launch_in_terminal(DaemonTray._resolve_cli_cmd("doctor"), keep_open=True)

    @staticmethod
    def _launch_ide_setup(ide_key):
        """Launch ai-guardian setup --ide <name> in a new terminal window."""
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        _launch_in_terminal(
            DaemonTray._resolve_cli_cmd("setup", "--ide", ide_key),
            keep_open=True,
        )

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
                still_paused = stats.get("paused", False)
                if remaining <= 0 and self._status == "paused" and not still_paused:
                    self._status = "running"
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

    def _refresh_menu(self):
        """Refresh the tray menu (must be called on main thread)."""
        if self._icon:
            try:
                self._icon.update_menu()
            except Exception:
                pass

    def _refresh_icon_running(self):
        """Refresh icon and menu to reflect resumed state (main thread)."""
        self._status = "running"
        if self._icon:
            self._icon.icon = self._create_icon()
        self._refresh_menu()

    def _rebuild_tray(self):
        """Rebuild tray icon and menu after system wake."""
        if not self._icon:
            return
        try:
            self._icon.icon = self._create_icon()
            self._icon.update_menu()
            logger.info("Tray icon rebuilt after system wake")
        except Exception as e:
            logger.debug("Failed to rebuild tray icon: %s", e)

    def _stop_pause_timer(self):
        """Stop the pause countdown timer."""
        self._pause_timer_running = False
        self._pause_timer = None

    def _sync_pause_state(self):
        """Sync tray status from daemon stats (handles external pause/resume)."""
        if self._is_multi_daemon():
            self._update_global_pause_status()
            return
        stats = self._get_stats()
        is_paused = stats.get("paused", False)
        if is_paused and self._status != "paused":
            self.update_status("paused")
        elif not is_paused and self._status == "paused":
            self.update_status("running")

    def _check_config_error_notification(self):
        """Show OS notification once when a config error is detected."""
        stats = self._get_stats()
        config_error = stats.get("config_error")
        if config_error and not self._config_error_notified:
            self._config_error_notified = True
            threading.Thread(
                target=self._send_config_error_notification,
                daemon=True,
                name="config-error-notify",
            ).start()
        elif not config_error and self._config_error_notified:
            self._config_error_notified = False

    @staticmethod
    def _send_config_error_notification():
        """Send config error OS notification (runs in background thread)."""
        try:
            from ai_guardian.daemon.tray_plugins import send_notification
            send_notification(
                "AI Guardian",
                "Config error detected — run Doctor from tray menu for details",
            )
        except Exception:
            pass

    def _update_global_pause_status(self):
        """Set tray icon to paused only when ALL daemons are paused."""
        if not self._targets:
            return
        all_paused = True
        for t in self._targets:
            if t.status not in ("running", "paused"):
                continue
            if self._multi_client:
                stats = self._multi_client.get_status(t) or {}
            else:
                stats = self._get_stats()
            if not stats.get("paused", False):
                all_paused = False
                break
        if all_paused:
            self.update_status("paused")
        else:
            self.update_status("running")

    _REFRESH_INTERVAL = 10
    _WAKE_GAP_THRESHOLD = 30

    def _register_wake_handler(self):
        """Register OS-level wake notification handler.

        On macOS, subscribes to NSWorkspaceDidWakeNotification for
        immediate wake detection.  Other platforms rely on timer gap
        detection in _start_stats_refresh().
        """
        import platform
        self._wake_observer = None
        if platform.system() != "Darwin":
            return
        try:
            from AppKit import NSWorkspace

            center = NSWorkspace.sharedWorkspace().notificationCenter()

            def _on_wake(notification):
                logger.info("macOS wake notification received")
                self._dispatch_to_main(self._rebuild_tray)

            token = center.addObserverForName_object_queue_usingBlock_(
                "NSWorkspaceDidWakeNotification", None, None, _on_wake,
            )
            self._wake_observer = (center, token)
            logger.debug("Registered macOS wake notification handler")
        except Exception:
            logger.debug("macOS wake handler unavailable, using timer fallback")

    def _unregister_wake_handler(self):
        """Remove OS-level wake notification observer."""
        if getattr(self, "_wake_observer", None) is None:
            return
        try:
            center, token = self._wake_observer
            center.removeObserver_(token)
        except Exception:
            pass
        self._wake_observer = None

    def _start_stats_refresh(self):
        """Start a background thread that refreshes menu counters periodically."""
        self._stats_refresh_running = True
        self._last_refresh_wallclock = time.time()

        def _refresh():
            while self._stats_refresh_running:
                time.sleep(self._REFRESH_INTERVAL)
                now = time.time()
                elapsed = now - self._last_refresh_wallclock
                self._last_refresh_wallclock = now

                if elapsed > self._WAKE_GAP_THRESHOLD:
                    logger.info(
                        "System wake detected (%.1fs gap), rebuilding tray",
                        elapsed,
                    )
                    self._dispatch_to_main(self._rebuild_tray)

                if self._stats_refresh_running and self._icon:
                    self._dispatch_to_main(self._sync_pause_state)
                    self._check_config_error_notification()
                    self._poll_plugins()
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
        self._discovery_in_progress = False
        self._stop_discovery_animation()
        self._is_initial_discovery = False
        self._targets = targets
        self._auto_select_target()
        self._refreshing_from_discovery = True
        self._dispatch_to_main(self._refresh_menu)
        self._refreshing_from_discovery = False
        logger.info(f"Discovery updated: {len(targets)} target(s) found")
        for t in targets:
            logger.info(f"  {t.name} ({t.runtime}) status={t.status} port={t.port}")

    def _auto_select_target(self):
        """Auto-select the best running daemon target.

        Prefers: current selection (if still running) > running local > first running.
        """
        if (self._active_target
                and self._active_target.status in ("running", "paused")):
            for t in self._targets:
                if (t.name == self._active_target.name
                        and t.runtime == self._active_target.runtime):
                    self._active_target = t
                    return

        for t in self._targets:
            if t.runtime == "local" and t.status in ("running", "paused"):
                self._active_target = t
                return

        for t in self._targets:
            if t.status in ("running", "paused"):
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
    _MAX_PLUGIN_SLOTS = 8
    _MAX_ITEMS_PER_PLUGIN = 12

    def _is_multi_daemon(self):
        """True when multiple daemons are discovered (nested submenu layout)."""
        return len(self._targets) != 1

    def _is_single_daemon(self):
        """True when exactly one daemon is discovered (flat layout)."""
        return len(self._targets) == 1

    @staticmethod
    def _daemon_status_label(target):
        """Format a daemon target into a status header label."""
        status_icon = {
            "running": "●", "paused": "◐", "stopped": "⚠",
            "error": "✗", "unknown": "○",
        }.get(target.status, "○")
        if target.runtime == "container" and target.container_engine:
            runtime = f" ({target.container_engine})"
        elif target.runtime != "local":
            runtime = f" ({target.runtime})"
        else:
            runtime = ""
        label = f"{status_icon} {target.name}{runtime}"
        if target.status == "stopped":
            label += " — daemon not running"
        return label

    def _build_single_daemon_menu_items(self):
        """Build flat menu items for single-daemon mode.

        When exactly one daemon is discovered, all submenu items are
        promoted to the top level. Visible only when len(targets) == 1.
        """
        def _single_vis(_item):
            return self._is_single_daemon()

        def _single_vis_refresh(_item):
            self._request_discovery_refresh(wait=False)
            return self._is_single_daemon()

        def _single_running(_item):
            return (self._is_single_daemon()
                    and self._targets[0].status in ("running", "paused"))

        def _single_not_running(_item):
            return (self._is_single_daemon()
                    and self._targets[0].status not in ("running", "paused"))

        def _header_label(_item):
            if not self._targets:
                return ""
            return self._daemon_status_label(self._targets[0])

        def _open_panel(panel=None):
            def action(_, __):
                if self._targets:
                    t = self._targets[0]
                    if self._multi_client:
                        self._multi_client.open_console(t, panel)
                    else:
                        self._launch_console(panel)
            return action

        def _open_shell():
            def action(_, __):
                if self._targets:
                    t = self._targets[0]
                    if self._multi_client:
                        self._multi_client.open_shell(t)
                    else:
                        self._launch_shell()
            return action

        def _open_doctor():
            def action(_, __):
                if self._targets:
                    t = self._targets[0]
                    if self._multi_client:
                        self._multi_client.open_doctor(t)
                    else:
                        self._launch_doctor()
            return action

        def _pause_action(minutes):
            def action(_, __):
                if self._targets:
                    t = self._targets[0]
                    if self._multi_client:
                        self._multi_client.send_pause(t, minutes)
                    else:
                        self._pause(minutes)
                    self.update_status("paused")
            return action

        def _resume_action(_, __):
            if self._targets:
                t = self._targets[0]
                if self._multi_client:
                    self._multi_client.send_resume(t)
                else:
                    self._pause(0)
                self.update_status("running")

        def _stop_action(_, __):
            if self._targets and self._multi_client:
                self._multi_client.send_stop(self._targets[0])

        def _restart_action(_, __):
            if self._targets and self._multi_client:
                self._multi_client.send_restart(self._targets[0])

        _cache = {"stats": {}, "time": 0}

        def _get_stats(_item):
            import time as time_mod
            now = time_mod.monotonic()
            if now - _cache["time"] < 2.0:
                return _cache["stats"]
            if not self._targets:
                return {}
            target = self._targets[0]
            if self._multi_client and target.runtime != "local":
                result = self._multi_client.get_status(target)
                if result and result.get("name"):
                    target.name = result["name"]
                _cache["stats"] = result or {}
            else:
                _cache["stats"] = self._get_stats()
            _cache["time"] = now
            return _cache["stats"]

        def _s_requests(_item):
            s = _get_stats(_item)
            return f"Requests: {s.get('request_count', 0):,}"

        def _s_blocked(_item):
            s = _get_stats(_item)
            b = s.get('blocked_count', 0)
            t = s.get('request_count', 0)
            if t > 0:
                return f"Blocked: {b:,} ({b/t*100:.1f}%)"
            return f"Blocked: {b:,}"

        def _s_warned(_item):
            s = _get_stats(_item)
            return f"Warned: {s.get('warning_count', 0):,}"

        def _s_logged(_item):
            s = _get_stats(_item)
            return f"Logged: {s.get('log_only_count', 0):,}"

        def _s_violations(_item):
            s = _get_stats(_item)
            return f"Violations: {s.get('violation_count', 0):,}"

        def _s_critical(_item):
            s = _get_stats(_item)
            return f"  Critical: {s.get('critical_count', 0):,}"

        def _s_warning_sev(_item):
            s = _get_stats(_item)
            return f"  Warning: {s.get('warning_severity_count', 0):,}"

        def _s_last_block(_item):
            s = _get_stats(_item)
            bt = s.get('last_block_type')
            ba = s.get('last_block_seconds_ago')
            if bt is None:
                return "Last block: none"
            return f"Last block: {bt} {self._format_time_ago(ba)}"

        def _s_config_reload(_item):
            s = _get_stats(_item)
            ago = s.get('last_config_reload_seconds_ago')
            if ago is not None:
                return f"Config reloaded: {self._format_time_ago(ago)}"
            return "Config: loaded"

        self._single_daemon_closures = {
            "pause_action": _pause_action,
            "resume_action": _resume_action,
            "stop_action": _stop_action,
            "restart_action": _restart_action,
            "single_running": _single_running,
            "single_not_running": _single_not_running,
            "get_stats": _get_stats,
        }

        return [
            pystray.MenuItem(_header_label, None, visible=_single_vis_refresh),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Console", _open_panel(), visible=_single_vis),
            pystray.MenuItem("Violations", _open_panel("panel-violations"),
                             visible=_single_vis),
            pystray.MenuItem("Metrics", _open_panel("panel-metrics"),
                             visible=_single_vis),
            pystray.MenuItem(
                "Statistics",
                pystray.Menu(
                    pystray.MenuItem(_s_requests, None),
                    pystray.MenuItem(_s_blocked, None),
                    pystray.MenuItem(_s_warned, None),
                    pystray.MenuItem(_s_logged, None),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem(_s_violations, None),
                    pystray.MenuItem(_s_critical, None),
                    pystray.MenuItem(_s_warning_sev, None),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem(_s_last_block, None),
                    pystray.Menu.SEPARATOR,
                    pystray.MenuItem(_s_config_reload, None),
                ),
                visible=_single_running,
            ),
            pystray.Menu.SEPARATOR,
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
                visible=lambda _: _single_vis(_) and self._mcp_installed,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Shell", _open_shell(), visible=_single_vis),
            pystray.MenuItem("Doctor", _open_doctor(), visible=_single_vis),
        ]

    def _build_single_daemon_daemon_items(self):
        """Build daemon operation items for single-daemon mode.

        Pause/Resume and Start/Stop/Restart grouped together without
        internal separators. Separated from preceding items by a
        separator. Must be called after _build_single_daemon_menu_items().
        """
        c = self._single_daemon_closures
        _pause_action = c["pause_action"]
        _resume_action = c["resume_action"]
        _stop_action = c["stop_action"]
        _restart_action = c["restart_action"]
        _single_running = c["single_running"]
        _single_not_running = c["single_not_running"]
        _get_stats = c["get_stats"]

        return [
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Pause...",
                pystray.Menu(
                    pystray.MenuItem("5 minutes", _pause_action(5)),
                    pystray.MenuItem("15 minutes", _pause_action(15)),
                    pystray.MenuItem("30 minutes", _pause_action(30)),
                    pystray.MenuItem("1 hour", _pause_action(60)),
                    pystray.MenuItem("Until resume", _pause_action(0)),
                ),
                visible=lambda _: (
                    _single_running(_)
                    and not _get_stats(_).get("paused")
                ),
            ),
            pystray.MenuItem(
                lambda _: self._resume_menu_label(),
                _resume_action,
                visible=lambda _: (
                    _single_running(_)
                    and _get_stats(_).get("paused")
                ),
            ),
            pystray.MenuItem("Start daemon", _restart_action,
                             visible=_single_not_running),
            pystray.MenuItem("Stop daemon", _stop_action,
                             visible=_single_running),
            pystray.MenuItem("Restart daemon", _restart_action,
                             visible=_single_running),
        ]

    def _build_multi_daemon_menu_items(self):
        """Build fixed-slot menu items with per-daemon action submenus.

        Each daemon gets its own submenu with Console, Pause, Restart, etc.
        pystray on macOS requires items defined at build time, so we
        pre-allocate slots with dynamic text/visibility lambdas.

        Only visible when 2+ daemons are discovered.
        """
        items = []
        for i in range(self._MAX_DAEMON_SLOTS):
            idx = i

            def make_label(_item, slot=idx):
                if slot >= len(self._targets):
                    return ""
                return self._daemon_status_label(self._targets[slot])

            def make_visible(_item, slot=idx):
                if slot == 0:
                    self._request_discovery_refresh(wait=False)
                return self._is_multi_daemon() and slot < len(self._targets)

            def _mk_open_panel(panel=None, slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.open_console(t, panel)
                        else:
                            self._launch_console(panel)
                return action

            def _mk_open_shell(slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.open_shell(t)
                        else:
                            self._launch_shell()
                return action

            def _mk_doctor(slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.open_doctor(t)
                        else:
                            self._launch_doctor()
                return action

            def _mk_pause(minutes, slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.send_pause(t, minutes)
                        else:
                            self._pause(minutes)
                        self._update_global_pause_status()
                return action

            def _mk_resume(slot=idx):
                def action(_, __):
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.send_resume(t)
                        else:
                            self._pause(0)
                        self._update_global_pause_status()
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

                def is_paused(_item):
                    return _get(_item).get("paused", False)

                def resume_label(_item):
                    s = _get(_item)
                    remaining = s.get("pause_remaining_seconds", 0)
                    if remaining > 0:
                        mins = int(remaining // 60)
                        secs = int(remaining % 60)
                        return f"Resume ({mins}m {secs}s left)"
                    return "Resume (paused)"

                return (requests, blocked, warned, logged,
                        violations, critical, warning_sev,
                        last_block, config_reload,
                        is_paused, resume_label)

            stats_fns = _mk_stats()

            def _is_slot_running(_item, slot=idx):
                return (slot < len(self._targets)
                        and self._targets[slot].status in ("running", "paused"))

            multi_plugin_items = self._build_multi_daemon_plugin_slots(idx)

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
                            visible=lambda _i, s=idx: _is_slot_running(_i, s) and self._mcp_installed,
                        ),
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem("Shell", _mk_open_shell()),
                        pystray.MenuItem("Doctor", _mk_doctor()),
                        pystray.Menu.SEPARATOR,
                        *multi_plugin_items,
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem(
                            "Pause...",
                            pystray.Menu(
                                pystray.MenuItem("5 minutes", _mk_pause(5)),
                                pystray.MenuItem("15 minutes", _mk_pause(15)),
                                pystray.MenuItem("30 minutes", _mk_pause(30)),
                                pystray.MenuItem("1 hour", _mk_pause(60)),
                                pystray.MenuItem("Until resume", _mk_pause(0)),
                            ),
                            visible=lambda _i, s=idx, _sf=stats_fns: (
                                _is_slot_running(_i, s)
                                and not _sf[9](_i)
                            ),
                        ),
                        pystray.MenuItem(
                            stats_fns[10], _mk_resume(),
                            visible=lambda _i, s=idx, _sf=stats_fns: (
                                _is_slot_running(_i, s)
                                and _sf[9](_i)
                            ),
                        ),
                        pystray.MenuItem(
                            "Start daemon", _mk_restart(),
                            visible=lambda _i, s=idx: (
                                s < len(self._targets)
                                and self._targets[s].status not in (
                                    "running", "paused"
                                )
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

    def _poll_plugins(self):
        """Fetch plugin definitions from each discovered daemon."""
        import json as json_mod
        for i, target in enumerate(self._targets):
            is_reachable = target.status in ("running", "paused")
            if not is_reachable and target.runtime != "local":
                continue
            try:
                if self._multi_client:
                    if target.runtime == "local":
                        data = self._multi_client._local_plugins()
                    elif is_reachable:
                        data = self._multi_client.get_plugins(target)
                    else:
                        continue
                else:
                    from ai_guardian.daemon.tray_plugins import load_plugins, plugins_to_dict
                    data = plugins_to_dict(load_plugins())
                if data:
                    data_hash = json_mod.dumps(data, sort_keys=True)
                    if self._last_plugins_hash.get(i) != data_hash:
                        from ai_guardian.daemon.tray_plugins import dict_to_plugins
                        self._daemon_plugins[i] = dict_to_plugins(data)
                        self._last_plugins_hash[i] = data_hash
            except Exception:
                pass

    def _get_daemon_plugins(self, slot):
        """Get plugin list for a daemon slot index."""
        return self._daemon_plugins.get(slot, [])

    @staticmethod
    def _execute_plugin_command(command_str, item_type):
        """Execute a plugin command with no params."""
        import shlex
        import subprocess
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        try:
            cmd_parts = shlex.split(command_str)
        except ValueError:
            logger.warning("Malformed plugin command: %s", command_str)
            return

        try:
            if item_type == "terminal":
                _launch_in_terminal(cmd_parts, keep_open=True)
            elif item_type == "notification":
                result = subprocess.run(
                    cmd_parts, capture_output=True, text=True, timeout=60,
                )
                from ai_guardian.daemon.tray_plugins import send_notification
                send_notification("AI Guardian", result.stdout.strip() or "(no output)")
            elif item_type == "clipboard":
                result = subprocess.run(
                    cmd_parts, capture_output=True, text=True, timeout=60,
                )
                from ai_guardian.daemon.tray_plugins import copy_to_clipboard
                copy_to_clipboard(result.stdout.strip())
            else:
                subprocess.run(cmd_parts, timeout=60)
        except Exception:
            pass

    def _execute_plugin_command_with_params(self, plugin_item_dict):
        """Launch tray-prompt for parameter collection, then execute."""
        import json as json_mod
        import shlex
        from ai_guardian.daemon.tray_plugins import resolve_command
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        resolved_cmd = resolve_command(plugin_item_dict["command"])
        if resolved_cmd is None:
            return

        params_json = json_mod.dumps(plugin_item_dict.get("params", []))
        prompt_cmd = self._resolve_cli_cmd(
            "tray-prompt",
            "--params", params_json,
            "--template", resolved_cmd,
            "--type", plugin_item_dict.get("type", "terminal"),
        )
        _launch_in_terminal(prompt_cmd, keep_open=True, clear=True)

    def _build_single_daemon_plugin_items(self):
        """Build plugin menu items for single-daemon mode.

        Each plugin becomes a top-level submenu. Pre-allocates slots
        for pystray macOS compatibility. Only visible when exactly one
        daemon is discovered and that daemon has plugins.
        """
        items = []

        def _has_plugins(_item):
            return self._is_single_daemon() and len(self._get_daemon_plugins(0)) > 0

        items.append(pystray.MenuItem("", None, visible=lambda _: (
            _has_plugins(_) and False
        )))

        for p_idx in range(self._MAX_PLUGIN_SLOTS):
            p_slot = p_idx

            def _plugin_name(_item, ps=p_slot):
                plugins = self._get_daemon_plugins(0)
                if ps < len(plugins):
                    return plugins[ps].name
                return ""

            def _plugin_visible(_item, ps=p_slot):
                if not self._is_single_daemon():
                    return False
                plugins = self._get_daemon_plugins(0)
                return ps < len(plugins)

            sub_items = []
            for i_idx in range(self._MAX_ITEMS_PER_PLUGIN):
                i_slot = i_idx

                def _item_label(_item, ps=p_slot, ix=i_slot):
                    plugins = self._get_daemon_plugins(0)
                    if ps < len(plugins) and ix < len(plugins[ps].items):
                        return plugins[ps].items[ix].label
                    return ""

                def _item_visible(_item, ps=p_slot, ix=i_slot):
                    plugins = self._get_daemon_plugins(0)
                    if ps >= len(plugins) or ix >= len(plugins[ps].items):
                        return False
                    from ai_guardian.daemon.tray_plugins import resolve_command
                    return resolve_command(plugins[ps].items[ix].command) is not None

                def _item_action(ps=p_slot, ix=i_slot):
                    def action(_, __):
                        plugins = self._get_daemon_plugins(0)
                        if ps >= len(plugins) or ix >= len(plugins[ps].items):
                            return
                        item = plugins[ps].items[ix]
                        if item.params:
                            from ai_guardian.daemon.tray_plugins import _item_to_dict
                            self._execute_plugin_command_with_params(
                                _item_to_dict(item)
                            )
                        else:
                            from ai_guardian.daemon.tray_plugins import resolve_command
                            cmd = resolve_command(item.command)
                            if cmd:
                                self._execute_plugin_command(cmd, item.type)
                    return action

                sub_items.append(
                    pystray.MenuItem(_item_label, _item_action(), visible=_item_visible)
                )

            items.append(
                pystray.MenuItem(_plugin_name, pystray.Menu(*sub_items),
                                 visible=_plugin_visible)
            )

        return items

    def _build_multi_daemon_plugin_slots(self, daemon_slot):
        """Build pre-allocated plugin slots for a multi-daemon submenu."""
        items = []
        d_slot = daemon_slot

        for p_idx in range(self._MAX_PLUGIN_SLOTS):
            p_slot = p_idx

            def _plugin_name(_item, ds=d_slot, ps=p_slot):
                plugins = self._get_daemon_plugins(ds)
                if ps < len(plugins):
                    return plugins[ps].name
                return ""

            def _plugin_visible(_item, ds=d_slot, ps=p_slot):
                plugins = self._get_daemon_plugins(ds)
                return ps < len(plugins)

            sub_items = []
            for i_idx in range(self._MAX_ITEMS_PER_PLUGIN):
                i_slot = i_idx

                def _item_label(_item, ds=d_slot, ps=p_slot, ix=i_slot):
                    plugins = self._get_daemon_plugins(ds)
                    if ps < len(plugins) and ix < len(plugins[ps].items):
                        return plugins[ps].items[ix].label
                    return ""

                def _item_visible(_item, ds=d_slot, ps=p_slot, ix=i_slot):
                    plugins = self._get_daemon_plugins(ds)
                    if ps >= len(plugins) or ix >= len(plugins[ps].items):
                        return False
                    from ai_guardian.daemon.tray_plugins import resolve_command
                    return resolve_command(plugins[ps].items[ix].command) is not None

                def _item_action(ds=d_slot, ps=p_slot, ix=i_slot):
                    def action(_, __):
                        plugins = self._get_daemon_plugins(ds)
                        if ps >= len(plugins) or ix >= len(plugins[ps].items):
                            return
                        item = plugins[ps].items[ix]
                        if item.params:
                            from ai_guardian.daemon.tray_plugins import _item_to_dict
                            self._execute_plugin_command_with_params(
                                _item_to_dict(item)
                            )
                        else:
                            from ai_guardian.daemon.tray_plugins import resolve_command
                            cmd = resolve_command(item.command)
                            if cmd:
                                self._execute_plugin_command(cmd, item.type)
                    return action

                sub_items.append(
                    pystray.MenuItem(_item_label, _item_action(), visible=_item_visible)
                )

            items.append(
                pystray.MenuItem(_plugin_name, pystray.Menu(*sub_items),
                                 visible=_plugin_visible)
            )

        return items

    @staticmethod
    def _launch_create_config():
        """Launch ai-guardian setup --create-config in a new terminal."""
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        _launch_in_terminal(
            DaemonTray._resolve_cli_cmd("setup", "--create-config"),
            keep_open=True,
        )

    def _build_ide_setup_menu_items(self):
        """Build the top-level 'Local Setup...' submenu.

        Always visible regardless of daemon count. Contains config
        creation and per-IDE hook setup entries.
        """
        from ai_guardian.setup import IDESetup

        def _mk_ide_action(k):
            def action(_, __):
                self._launch_ide_setup(k)
            return action

        ide_items = [
            pystray.MenuItem("IDE Hooks (required)", None),
        ]
        for ide_key, ide_cfg in IDESetup.IDE_CONFIGS.items():
            ide_items.append(
                pystray.MenuItem(f"  {ide_cfg['name']}", _mk_ide_action(ide_key))
            )
        ide_items.extend([
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Configuration", None),
            pystray.MenuItem(
                "  Create Config...",
                lambda _, __: self._launch_create_config(),
            ),
        ])

        return [
            pystray.MenuItem(
                "Local Setup...",
                pystray.Menu(*ide_items),
            ),
        ]

    def _on_restart_tray(self, icon, item):
        """Restart the tray process."""
        import subprocess
        import sys

        cmd = [sys.executable, "-m", "ai_guardian", "tray", "start"]
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
