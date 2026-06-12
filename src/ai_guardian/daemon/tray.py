"""
System tray integration using pystray (optional dependency).

Provides a system tray icon with status indicator, violation count, and
menu for pause/resume/quit. Gracefully degrades to no-op if pystray
is not installed.
"""

import logging
import os
import subprocess
import sys
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
        try:
            fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
        except FileExistsError:
            raise RuntimeError("Tray already starting (concurrent lock)")


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

def _ensure_system_gi():
    """Make system GObject Introspection visible in isolated environments.

    uv tool install creates an isolated Python env that can't see system
    site-packages. Detect system gi location via the system Python and
    add its parent directory to sys.path so pystray can use AppIndicator.
    """
    import platform
    if platform.system() != "Linux":
        return
    try:
        import gi  # noqa: F401
        return
    except ImportError:
        pass
    for python in ("/usr/bin/python3", "/usr/bin/python", "python3", "python"):
        try:
            result = subprocess.run(
                [python, "-c",
                 "import gi; import os; print(os.path.dirname(gi.__path__[0]))"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                site_dir = result.stdout.strip()
                if site_dir not in sys.path:
                    sys.path.insert(0, site_dir)
                    try:
                        import gi  # noqa: F401
                        logger.info("System gi found at %s", site_dir)
                        return
                    except ImportError:
                        sys.path.remove(site_dir)
        except (OSError, subprocess.TimeoutExpired):
            continue


_ensure_system_gi()

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


def _check_gi_available():
    """Check if GObject Introspection is available (required for tray on Linux).

    Without gi, pystray falls back from AppIndicator3 to the Xorg backend
    which crashes on Wayland sessions.
    """
    try:
        import gi  # noqa: F401
        return True
    except ImportError:
        return False


def is_tray_available():
    """Check if system tray can be displayed (dependencies + display)."""
    if not HAS_PYSTRAY:
        return False
    import os
    import platform
    if os.environ.get("DISPLAY") is None and os.environ.get("WAYLAND_DISPLAY") is None:
        if platform.system() == "Linux":
            return False
    if platform.system() == "Linux":
        if not _check_gi_available():
            logger.warning(
                "GObject Introspection (gi) not available — tray requires it on Linux. "
                "This often happens with 'uv tool install' (isolated environment). "
                "Fix: reinstall with --venv flag: install.sh --venv"
            )
            return False
        if not _check_gnome_appindicator():
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

    _has_web_console = sys.version_info >= (3, 10)

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
        self._mcp_installed_local = self._is_mcp_installed()
        self._mcp_installed = self._mcp_installed_local
        self._mcp_installed_per_daemon = {}
        self._targets = []
        self._active_target = None
        self._daemon_plugins = {}
        self._last_plugins_hash = {}
        self._global_plugins = []
        self._daemon_global_plugins = {}
        self._config_error_notified = False
        self._version_mismatch_notified = set()
        self._daemon_versions = {}
        self._daemon_about_cache = {}
        self._pip_available = {}
        self._pypi_latest = None
        self._pypi_last_check = 0.0
        self._upgrade_in_progress = set()
        self._discovery_animating = False
        self._discovery_anim_stop = threading.Event()
        self._discovery_timer = None
        self._discovery_frames = None
        self._is_initial_discovery = True
        self._discovery_in_progress = False
        self._refreshing_from_discovery = False
        self._last_discovery_refresh = 0.0
        self._refresh_event = threading.Event()
        self._web_proc = None
        self._last_autostart_attempt = 0.0
        self._last_stats_snapshot = None

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
        self._stop_web_console()
        if self._discovery:
            self._discovery.stop()
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
        _remove_tray_lock()

    def _stop_web_console(self):
        """Stop the web console subprocess if we started it."""
        proc = getattr(self, '_web_proc', None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        from ai_guardian.config_utils import get_state_dir
        port_file = get_state_dir() / "web-console.port"
        try:
            port_file.unlink(missing_ok=True)
        except OSError:
            pass

    _AUTOSTART_COOLDOWN = 5.0

    def _can_autostart_daemon(self):
        """Check if daemon auto-restart is possible.

        Returns True when the tray is standalone and no stop-requested
        marker exists (user explicitly stopped the daemon).
        """
        if not self._standalone:
            return False
        try:
            from ai_guardian.config_utils import get_state_dir
            marker = get_state_dir() / "daemon.stop-requested"
            return not marker.exists()
        except Exception:
            return False

    def _check_and_autostart_daemon(self):
        """Auto-start local daemon if stopped (idle timeout or crash).

        Only runs in standalone tray mode. Respects stop-requested
        marker and cooldown. A paused daemon is still running and
        is not restarted.

        Returns True if daemon is running after this call.
        """
        if not self._standalone:
            return True
        try:
            from ai_guardian.daemon.client import is_daemon_running
            if is_daemon_running():
                return True
        except Exception:
            return False
        now = time.monotonic()
        if now - self._last_autostart_attempt < self._AUTOSTART_COOLDOWN:
            return False
        self._last_autostart_attempt = now
        try:
            from ai_guardian.daemon.client import start_daemon_background
            if start_daemon_background():
                logger.info("Auto-started daemon from tray interaction")
                self._request_discovery_refresh(wait=False)
                return True
        except Exception:
            pass
        return False

    def update_status(self, status):
        """Update tray icon status and manage pause timer.

        Args:
            status: "running", "paused", or "error"
        """
        prev = self._status
        self._status = status
        self._invalidate_discovery_frames()
        if self._icon:
            self._dispatch_to_main(
                lambda: setattr(self._icon, 'icon', self._create_icon())
            )
        if status == "paused" and prev != "paused":
            self._start_pause_timer()
        elif status != "paused" and prev == "paused":
            self._stop_pause_timer()

    def flash_reload(self):
        """Record config reload (no visual change with monochrome icons)."""
        pass

    @staticmethod
    def _ensure_macos_activation_policy():
        """Set NSApplicationActivationPolicyAccessory and bundle identity on macOS.

        When launched from an .app bundle wrapper, the process may lose
        its Info.plist association after exec, so LSUIElement=True has no
        effect.  Setting the policy explicitly ensures the status bar
        icon appears regardless of launch method (issue #691).

        Also sets the process bundle identifier to match the installed
        .app so macOS notification center displays the AI Guardian icon
        instead of the generic Python icon (issue #769).
        """
        import platform
        if platform.system() != "Darwin":
            return
        try:
            import AppKit
            import Foundation
            info = Foundation.NSBundle.mainBundle().infoDictionary()
            if info.get("CFBundleIdentifier") is None:
                info["CFBundleIdentifier"] = "com.itdove.ai-guardian.tray"
                info["CFBundleName"] = "AI Guardian Tray"
            app = AppKit.NSApplication.sharedApplication()
            app.setActivationPolicy_(
                AppKit.NSApplicationActivationPolicyAccessory
            )
            try:
                from ai_guardian.daemon.tray_plugins import _find_icon
                icns_path = _find_icon("ai-guardian.icns")
                if icns_path:
                    icon_image = AppKit.NSImage.alloc().initWithContentsOfFile_(icns_path)
                    if icon_image:
                        app.setApplicationIconImage_(icon_image)
            except Exception:
                pass
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
            *self._build_global_plugin_items(),
            *self._build_ide_setup_menu_items(),
            pystray.MenuItem("Restart", self._on_restart_tray),
            pystray.MenuItem("Quit", self._on_quit),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(self._about_label, self._on_about,
                             enabled=lambda _: (
                                 any(
                                     t.status in ("running", "paused")
                                     for t in self._targets
                                 )
                                 or self._can_autostart_daemon()
                             )),
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
        self._start_web_console()
        self._register_wake_handler()
        import platform
        if platform.system() == "Linux":
            saved_fd = _suppress_gtk_stderr()
            threading.Timer(0.5, _restore_stderr, args=[saved_fd]).start()
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
        if self._needs_dark_icon():
            img = self._invert_icon(img)
        if self._status == "paused":
            img = self._apply_paused_dimming(img)
        return img

    @staticmethod
    def _needs_dark_icon():
        """Check if the panel has a light background requiring a dark icon.

        GNOME with a light GTK theme renders the panel light, making
        the default white icon invisible.
        """
        import platform
        if platform.system() != "Linux":
            return False
        import os
        desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
        if "GNOME" not in desktop.upper():
            return False
        try:
            import subprocess
            result = subprocess.run(
                ["gsettings", "get", "org.gnome.desktop.interface",
                 "color-scheme"],
                capture_output=True, text=True, timeout=3,
            )
            scheme = result.stdout.strip().strip("'\"")
            return scheme != "prefer-dark"
        except Exception:
            return False

    @staticmethod
    def _invert_icon(img):
        """Invert a white monochrome icon to dark, preserving alpha."""
        img = img.copy()
        r, g, b, a = img.split()
        from PIL import ImageOps
        r = ImageOps.invert(r)
        g = ImageOps.invert(g)
        b = ImageOps.invert(b)
        return Image.merge("RGBA", (r, g, b, a))

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
        """Find the monochrome tray icon for the current platform.

        Uses three strategies to ensure the returned path remains valid
        after this method returns (important for AppIndicator on GNOME/KDE
        which reads the icon asynchronously).
        """
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

        # Strategy 1: If importlib.resources returns a real filesystem Path
        # (editable install or unpacked wheel), use it directly.
        for name in names:
            try:
                ref = (importlib.resources.files("ai_guardian")
                       / "images" / name)
                if isinstance(ref, Path) and ref.exists():
                    return str(ref)
            except Exception:
                pass

        # Strategy 2: For zipped wheels, extract via as_file() and copy to
        # a persistent temp directory so the path survives context exit.
        for name in names:
            try:
                ref = (importlib.resources.files("ai_guardian")
                       / "images" / name)
                with importlib.resources.as_file(ref) as p:
                    if p.exists():
                        import shutil
                        import tempfile
                        persistent_dir = (
                            Path(tempfile.gettempdir()) / "ai-guardian-icons"
                        )
                        persistent_dir.mkdir(parents=True, exist_ok=True)
                        dest = persistent_dir / name
                        if not dest.exists():
                            shutil.copy2(str(p), str(dest))
                        return str(dest)
            except Exception:
                pass

        # Strategy 3: Filesystem fallback (development layout).
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
        """Request discovery refresh.

        Debounces calls to prevent overlapping refreshes.  Skips animation
        for periodic background refreshes — animation only runs on the
        initial discovery at startup.
        """
        import time
        now = time.monotonic()
        if now - self._last_discovery_refresh < 15.0:
            return
        if self._discovery and not self._refreshing_from_discovery:
            self._last_discovery_refresh = now
            self._discovery_in_progress = True
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
        from ai_guardian.daemon import is_mcp_installed
        return is_mcp_installed()

    def _is_mcp_for_current_target(self):
        """Check MCP installed status for the current single-daemon target."""
        if not self._targets:
            return self._mcp_installed_local
        target = self._targets[0]
        key = (target.name, target.runtime)
        return self._mcp_installed_per_daemon.get(key, self._mcp_installed_local)

    def _is_mcp_for_slot(self, idx):
        """Check MCP installed status for a multi-daemon slot."""
        if idx >= len(self._targets):
            return self._mcp_installed_local
        target = self._targets[idx]
        key = (target.name, target.runtime)
        return self._mcp_installed_per_daemon.get(key, self._mcp_installed_local)

    @staticmethod
    def _get_python_executable():
        """Get the best available Python executable path.

        Returns:
            str: Path to Python executable
        """
        import shutil
        import sys

        # Try to find python in PATH
        python_exe = shutil.which("python")
        if python_exe:
            return python_exe

        # Try python3 as fallback
        python_exe = shutil.which("python3")
        if python_exe:
            return python_exe

        # Use sys.executable as last resort
        return sys.executable

    @staticmethod
    def _resolve_cli_cmd(*args):
        """Build command list for running ai-guardian with given arguments.

        Uses absolute path to python to ensure it works in subprocesses that
        may not have the same PATH (e.g., Terminal.app on macOS).
        """
        import shutil

        # Try multiple strategies to find a working Python
        # 1. Check if ai-guardian executable exists (best option)
        ag_path = shutil.which("ai-guardian")
        if ag_path:
            return [ag_path] + list(args)

        # 2. Use resolved Python executable
        python_exe = DaemonTray._get_python_executable()
        return [python_exe, "-m", "ai_guardian"] + list(args)

    @staticmethod
    def _resolve_plugin_ai_guardian(command_str, run_on_target, target):
        """Replace bare ``ai-guardian`` with absolute python path.

        Skipped for remote targets (container / kubernetes) where the
        command must resolve via PATH on the remote host.
        """
        import shlex

        is_remote = (
            run_on_target and target
            and getattr(target, "runtime", "local")
            in ("container", "kubernetes")
        )
        if is_remote:
            return command_str

        stripped = command_str.lstrip()
        if stripped == "ai-guardian" or stripped.startswith("ai-guardian "):
            python_exe = DaemonTray._get_python_executable()
            resolved = shlex.quote(python_exe) + " -m ai_guardian"
            return resolved + stripped[len("ai-guardian"):]
        return command_str

    @staticmethod
    def _launch_console(panel=None):
        """Launch the ai-guardian console in a new terminal window."""
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        cmd_parts = DaemonTray._resolve_cli_cmd("console")
        if panel:
            cmd_parts.extend(["--panel", panel])
        _launch_in_terminal(cmd_parts)

    def _start_web_console(self):
        """Start the web console server as a subprocess."""
        from ai_guardian.config_utils import get_state_dir
        port_file = get_state_dir() / "web-console.port"
        if port_file.exists():
            if self._is_web_console_alive(port_file):
                logger.debug("Web console already running, reusing")
                return
            try:
                port_file.unlink()
            except OSError:
                pass
        try:
            cmd = DaemonTray._resolve_cli_cmd("console") + ["--web", "--no-open"]
            logger.debug("Starting web console with command: %s", cmd)
            self._web_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info("Web console started (pid %d, cmd: %s)", self._web_proc.pid, cmd[0])
            threading.Thread(
                target=self._notify_web_console_ready,
                daemon=True,
                name="web-console-notify",
            ).start()
        except Exception as e:
            logger.error("Web console failed to start: %s (cmd: %s)", e, cmd if 'cmd' in locals() else 'N/A')

    def _notify_web_console_ready(self):
        """Wait for web console to be ready, update menu, then notify."""
        from ai_guardian.config_utils import get_state_dir
        port_file = get_state_dir() / "web-console.port"
        for _ in range(30):
            if port_file.exists() and self._is_web_console_alive(port_file):
                if self._icon:
                    self._icon.update_menu()
                try:
                    port = int(port_file.read_text().strip())
                    self._show_notification(
                        "Web Console Ready",
                        f"http://127.0.0.1:{port}",
                    )
                except (ValueError, OSError):
                    pass
                return
            time.sleep(1)

    @staticmethod
    def _show_notification(title, message):
        """Show a desktop notification."""
        import platform
        system = platform.system()
        try:
            if system == "Darwin":
                safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
                safe_msg = message.replace("\\", "\\\\").replace('"', '\\"')
                subprocess.Popen([
                    "osascript", "-e",
                    f'display notification "{safe_msg}" with title "{safe_title}"',
                ])
            elif system == "Linux":
                subprocess.Popen(["notify-send", title, message])
            elif system == "Windows":
                safe_title = title.replace("'", "''").replace("`", "``").replace("$", "`$")
                safe_msg = message.replace("'", "''").replace("`", "``").replace("$", "`$")
                ps = (
                    "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; "
                    "[System.Reflection.Assembly]::LoadWithPartialName('System.Drawing') | Out-Null; "
                    "$n = New-Object System.Windows.Forms.NotifyIcon; "
                    "$n.Icon = [System.Drawing.SystemIcons]::Information; "
                    "$n.Visible = $true; "
                    f"$n.ShowBalloonTip(5000, '{safe_title}', '{safe_msg}', 'Info')"
                )
                subprocess.Popen(["powershell", "-NoProfile", "-Command", ps])
        except OSError:
            pass

    @staticmethod
    def _is_web_console_alive(port_file):
        """Check if the web console at the port file is reachable."""
        import socket
        try:
            port = int(port_file.read_text().strip())
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect(("127.0.0.1", port))
            sock.close()
            return True
        except (ValueError, OSError):
            return False

    @staticmethod
    def _is_web_console_ready():
        """Check if web console is running and reachable."""
        from ai_guardian.config_utils import get_state_dir
        port_file = get_state_dir() / "web-console.port"
        if not port_file.exists():
            return False
        return DaemonTray._is_web_console_alive(port_file)

    _PANEL_TO_WEB_PATH = {
        "panel-violations": "violations",
        "panel-metrics": "metrics",
        "panel-health-check": "health-check",
    }

    @staticmethod
    def _open_web_console(daemon_name: str = "", page: str = ""):
        """Open the web console for a specific daemon and optional page."""
        from ai_guardian.config_utils import get_state_dir
        from ai_guardian.desktop_utils import open_url
        port_file = get_state_dir() / "web-console.port"
        try:
            port = int(port_file.read_text().strip())
            path = f"/{daemon_name}" if daemon_name else ""
            if page:
                path = f"{path}/{page}"
            open_url(f"http://127.0.0.1:{port}{path}")
        except (ValueError, OSError):
            pass

    @staticmethod
    def _launch_shell(cwd=None):
        """Launch the user's default shell in a new terminal window."""
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        import os
        import platform as _plat
        if _plat.system() == "Windows":
            shell = os.environ.get("COMSPEC", "cmd.exe")
        else:
            shell = os.environ.get("SHELL", "/bin/sh")
        _launch_in_terminal([shell], keep_open=True, cwd=cwd)

    @staticmethod
    def _launch_doctor():
        """Launch ai-guardian doctor in a new terminal window."""
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        _launch_in_terminal(DaemonTray._resolve_cli_cmd("doctor"), keep_open=True)

    @staticmethod
    def _about_label(_item=None):
        """Build About menu label with tray version."""
        try:
            from ai_guardian import __version__
            return f"About — v{__version__}"
        except ImportError:
            return "About"

    @staticmethod
    def _build_about_text():
        """Build the About dialog text with tray process info."""
        from ai_guardian.daemon.about import get_about_info, format_about_text
        return format_about_text(get_about_info())

    def _on_about(self, icon, item):
        """Show About info via OS dialog."""
        def _show():
            try:
                from ai_guardian.daemon.tray_plugins import show_dialog
                text = self._build_about_text()
                if self._is_multi_daemon():
                    text += self._format_daemon_list()
                show_dialog("About AI Guardian", text)
            except Exception:
                pass
        threading.Thread(target=_show, daemon=True, name="about-dialog").start()

    def _daemon_about_label(self, slot):
        """Build About menu label with daemon version for a specific slot."""
        def _label(_item=None):
            if slot >= len(self._targets):
                return "About"
            target = self._targets[slot]
            key = (target.name, target.runtime)
            version = self._daemon_versions.get(key, "")
            if version:
                return f"About — v{version}"
            return "About"
        return _label

    def _on_daemon_about(self, slot):
        """Show About info for a specific daemon via OS dialog."""
        def action(_, __):
            if slot >= len(self._targets):
                return
            target = self._targets[slot]
            def _show():
                try:
                    from ai_guardian.daemon.tray_plugins import show_dialog
                    info = self._daemon_about_cache.get(slot)
                    if info is None and self._multi_client:
                        info = self._multi_client.get_about(target)
                        if info:
                            self._daemon_about_cache[slot] = info
                    if info:
                        from ai_guardian.daemon.about import format_about_text
                        text = format_about_text(info)
                    else:
                        text = self._build_about_text()
                    show_dialog(f"About {target.name}", text)
                except Exception:
                    pass
            threading.Thread(target=_show, daemon=True, name="daemon-about-dialog").start()
        return action

    def _format_daemon_list(self):
        """Format connected daemons list for multi-daemon About."""
        if not self._targets:
            return ""
        lines = [f"\nDaemons: {len(self._targets)} connected"]
        for target in self._targets:
            key = (target.name, target.runtime)
            ver = self._daemon_versions.get(key, "?")
            icon = {"running": "●", "paused": "☾", "stopped": "⚠"}.get(
                target.status, "○"
            )
            suffix = ""
            if key in self._version_mismatch_notified:
                suffix = " ⟳"
            lines.append(f"  {icon} {target.name} v{ver}{suffix}")
        return "\n".join(lines)

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
        """Dispatch a callable to the GUI main loop.

        macOS: uses PyObjCTools.AppHelper.callAfter.
        Linux: uses GLib.idle_add to schedule on the GTK main loop,
               avoiding thread-safety issues that cause blank menu text.
        Other: calls directly.
        """
        try:
            from PyObjCTools.AppHelper import callAfter
            callAfter(func)
            return
        except ImportError:
            pass
        try:
            import platform
            if platform.system() == "Linux":
                from gi.repository import GLib
                GLib.idle_add(func)
                return
        except (ImportError, ValueError):
            pass
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

    def _refresh_menu_if_changed(self):
        """Refresh the tray menu only if stats changed.

        GNOME's AppIndicator rebuilds the entire DBus menu tree on
        update_menu(), causing a visible blank flash.  Skip the call
        when nothing has changed.
        """
        snapshot = self._build_stats_snapshot()
        if snapshot == self._last_stats_snapshot:
            return
        self._last_stats_snapshot = snapshot
        self._refresh_menu()

    def _build_stats_snapshot(self):
        """Build a hashable snapshot of menu-relevant state."""
        try:
            stats = self._get_stats()
            return (
                stats.get("request_count"),
                stats.get("blocked_count"),
                stats.get("warning_count"),
                stats.get("violation_count"),
                stats.get("paused"),
                stats.get("pause_remaining_seconds", 0) // 5,
                stats.get("config_error"),
                self._status,
                len(self._targets),
                tuple(
                    (t.name, t.status) for t in self._targets
                ),
            )
        except Exception:
            return None

    def _refresh_menu_and_clear_discovery_flag(self):
        """Refresh menu and clear the discovery refresh guard (main thread)."""
        self._refresh_menu()
        self._refreshing_from_discovery = False

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

    @staticmethod
    def _parse_version_tuple(version_str):
        """Parse version string into (major, minor, patch) tuple.

        Handles formats like '1.9.0', 'v1.9.0', '1.9.0-dev'.
        Returns None if parsing fails.
        """
        import re
        if not version_str or version_str == "unknown":
            return None
        match = re.match(r'v?(\d+)\.(\d+)\.(\d+)', version_str)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return None

    def _check_version_mismatch(self):
        """Check each daemon's version against the tray version and warn on mismatch."""
        try:
            from ai_guardian import __version__ as tray_version
        except ImportError:
            return

        tray_tuple = self._parse_version_tuple(tray_version)
        if tray_tuple is None:
            return

        for target in self._targets:
            if target.status not in ("running", "paused"):
                continue
            key = (target.name, target.runtime)
            daemon_version = self._daemon_versions.get(key)
            if daemon_version is None:
                continue

            daemon_tuple = self._parse_version_tuple(daemon_version)
            if daemon_tuple is None:
                continue

            if daemon_tuple < tray_tuple:
                if key not in self._version_mismatch_notified:
                    self._version_mismatch_notified.add(key)
                    name = target.name
                    threading.Thread(
                        target=self._send_version_mismatch_notification,
                        args=(name, daemon_version, tray_version),
                        daemon=True,
                        name="version-mismatch-notify",
                    ).start()
                if key not in self._pip_available:
                    threading.Thread(
                        target=self._check_pip_available_for_target,
                        args=(target,),
                        daemon=True,
                        name="pip-check",
                    ).start()
            elif key in self._version_mismatch_notified:
                self._version_mismatch_notified.discard(key)

    @staticmethod
    def _send_version_mismatch_notification(daemon_name, daemon_version, tray_version):
        """Send version mismatch OS notification (runs in background thread)."""
        try:
            from ai_guardian.daemon.tray_plugins import send_notification
            send_notification(
                "AI Guardian",
                f"Daemon '{daemon_name}' is running v{daemon_version} — "
                f"upgrade to v{tray_version} recommended",
            )
        except Exception:
            pass

    def _check_pypi_version(self):
        """Fetch latest version from PyPI (throttled to every 300s)."""
        import time as _time
        now = _time.monotonic()
        if now - self._pypi_last_check < 300:
            return
        self._pypi_last_check = now
        try:
            from ai_guardian.daemon.multi_client import MultiDaemonClient
            version = MultiDaemonClient.check_pypi_version()
            if version:
                self._pypi_latest = version
        except (OSError, ValueError, KeyError):
            pass

    def _check_pip_available_for_target(self, target):
        """Check pip availability on a target (runs in background thread)."""
        key = (target.name, target.runtime)
        try:
            if self._multi_client:
                available = self._multi_client.check_pip_available(target)
            else:
                import subprocess as _sp
                python_exe = DaemonTray._get_python_executable()
                result = _sp.run(
                    [python_exe, "-m", "pip", "--version"],
                    capture_output=True, text=True, timeout=10,
                )
                available = result.returncode == 0
            self._pip_available[key] = available
        except Exception:
            self._pip_available[key] = False

    def _is_upgrade_available(self, target):
        """Return True if target has a version mismatch and pip is available.

        Only offers upgrade if tray version is installable (not a dev version).
        """
        if not target:
            return False
        key = (target.name, target.runtime)
        # Don't offer upgrade if tray is running a dev version (not on PyPI)
        try:
            from ai_guardian import __version__ as tray_version
            if "-dev" in tray_version or "dev" in tray_version.lower():
                return False
        except ImportError:
            return False
        return (
            key in self._version_mismatch_notified
            and self._pip_available.get(key, False)
            and key not in self._upgrade_in_progress
        )

    def _upgrade_label(self, target):
        """Dynamic label for the sync-to-tray-version menu item."""
        if target:
            key = (target.name, target.runtime)
            if key in self._upgrade_in_progress:
                return "Syncing…"
        try:
            from ai_guardian import __version__ as tray_version
            return f"Match Tray v{tray_version}"
        except ImportError:
            return "Match Tray Version"

    def _do_upgrade_daemon(self, target):
        """Sync daemon version to match tray version (runs in background thread)."""
        key = (target.name, target.runtime)
        self._upgrade_in_progress.add(key)
        self._dispatch_to_main(self._refresh_menu)

        # Get tray version to sync to
        try:
            from ai_guardian import __version__ as tray_version
        except ImportError:
            tray_version = None

        try:
            from ai_guardian.daemon.tray_plugins import send_notification
            send_notification(
                "AI Guardian",
                f"Syncing ai-guardian on '{target.name}' to v{tray_version}…" if tray_version
                else f"Syncing ai-guardian on '{target.name}'…",
            )
        except Exception:
            pass

        success = False
        output = ""
        try:
            if self._multi_client:
                success, output = self._multi_client.run_pip_upgrade(target, tray_version)
            else:
                import subprocess as _sp
                python_exe = DaemonTray._get_python_executable()
                # Install specific version to match tray
                if tray_version:
                    cmd = [python_exe, "-m", "pip", "install", f"ai-guardian=={tray_version}"]
                else:
                    cmd = [python_exe, "-m", "pip", "install", "--upgrade", "ai-guardian"]
                result = _sp.run(cmd, capture_output=True, text=True, timeout=120)
                success = result.returncode == 0
                output = result.stdout + result.stderr
        except Exception as exc:
            output = str(exc)

        try:
            from ai_guardian.daemon.tray_plugins import send_notification
            if success:
                send_notification(
                    "AI Guardian",
                    f"Version sync complete on '{target.name}'. Restarting daemon…",
                )
                if self._multi_client:
                    self._multi_client.send_restart(target)
                self._version_mismatch_notified.discard(key)
                self._daemon_versions.pop(key, None)
                self._pip_available.pop(key, None)
            else:
                first_line = output.strip().split("\n")[-1][:120] if output else "unknown error"
                send_notification(
                    "AI Guardian",
                    f"Version sync failed on '{target.name}': {first_line}",
                )
        except Exception:
            pass
        finally:
            self._upgrade_in_progress.discard(key)
            self._dispatch_to_main(self._refresh_menu)

    def _on_upgrade_single(self, _icon, _item):
        """Click handler for single-daemon Upgrade menu item."""
        if self._targets:
            target = self._targets[0]
            threading.Thread(
                target=self._do_upgrade_daemon,
                args=(target,),
                daemon=True,
                name="daemon-upgrade",
            ).start()

    def _mk_upgrade(self, slot):
        """Factory returning a click handler for multi-daemon Upgrade item."""
        def action(_, __):
            if slot < len(self._targets):
                target = self._targets[slot]
                threading.Thread(
                    target=self._do_upgrade_daemon,
                    args=(target,),
                    daemon=True,
                    name=f"daemon-upgrade-{slot}",
                ).start()
        return action

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
                self._refresh_event.wait(timeout=self._REFRESH_INTERVAL)
                self._refresh_event.clear()
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
                    self._check_version_mismatch()
                    self._check_pypi_version()
                    self._poll_plugins()
                    self._request_discovery_refresh(wait=False)
                    self._dispatch_to_main(self._refresh_menu_if_changed)

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


    def _get_merged_dir_list(self, stats):
        """Merge active project dirs and paused dirs into a sorted list."""
        active = set(stats.get("active_project_dirs") or [])
        paused = set(stats.get("paused_dirs") or {})
        return sorted(active | paused)

    def _multi_global_pause_label(self, stats_fns, _item):
        """Format global pause label with status circle for multi-daemon."""
        is_paused = stats_fns[9](_item)
        if is_paused:
            stats = stats_fns[11](_item)
            remaining = stats.get("pause_remaining_seconds", 0)
            if remaining > 0:
                mins = int(remaining // 60)
                secs = int(remaining % 60)
                return f"☾ Daemon (global) ({mins}m {secs}s)"
            return "☾ Daemon (global)"
        return "● Daemon (global)"

    def _mk_multi_pause_dir(self, slot):
        """Create a pause_dir callback for a multi-daemon slot."""
        def pause_dir_fn(directory, minutes):
            if slot < len(self._targets) and self._multi_client:
                self._multi_client.send_pause_dir(
                    self._targets[slot], directory, minutes,
                )
        return pause_dir_fn

    def _mk_multi_resume_dir(self, slot):
        """Create a resume_dir callback for a multi-daemon slot."""
        def resume_dir_fn(directory):
            if slot < len(self._targets) and self._multi_client:
                self._multi_client.send_resume_dir(
                    self._targets[slot], directory,
                )
        return resume_dir_fn

    def _build_dir_pause_items(self, get_stats_fn, pause_dir_fn, resume_dir_fn):
        """Build pre-allocated per-directory pause/resume menu items.

        Returns a list of pystray.MenuItem, one per slot, each with a
        submenu for duration options or resume. Uses visibility lambdas
        to show only slots with actual directories.
        """
        from ai_guardian.daemon.working_dir import shorten_path

        items = []
        for i in range(self._MAX_DIR_PAUSE_SLOTS):
            slot = i

            def _dir_at(s, stats, slot=slot):
                dirs = self._get_merged_dir_list(stats)
                if slot < len(dirs):
                    return dirs[slot]
                return None

            def _is_visible(_item, slot=slot):
                stats = get_stats_fn(_item)
                return _dir_at(None, stats, slot) is not None

            def _label(_item, slot=slot):
                stats = get_stats_fn(_item)
                d = _dir_at(None, stats, slot)
                if d is None:
                    return ""
                paused_dirs = stats.get("paused_dirs") or {}
                short = shorten_path(d)
                if len(short) > 40:
                    short = "..." + short[-37:]
                if d in paused_dirs:
                    remaining = paused_dirs[d]
                    if remaining > 0:
                        mins = int(remaining // 60)
                        secs = int(remaining % 60)
                        return f"☾ {short} ({mins}m {secs}s)"
                    return f"☾ {short}"
                return f"● {short}"

            def _is_paused(_item, slot=slot):
                stats = get_stats_fn(_item)
                d = _dir_at(None, stats, slot)
                if d is None:
                    return False
                return d in (stats.get("paused_dirs") or {})

            def _is_active(_item, slot=slot):
                stats = get_stats_fn(_item)
                d = _dir_at(None, stats, slot)
                if d is None:
                    return False
                return d not in (stats.get("paused_dirs") or {})

            def _mk_dir_pause(minutes, slot=slot):
                def action(_, __):
                    stats = get_stats_fn(None)
                    d = _dir_at(None, stats, slot)
                    if d:
                        pause_dir_fn(d, minutes)
                return action

            def _mk_dir_resume(slot=slot):
                def action(_, __):
                    stats = get_stats_fn(None)
                    d = _dir_at(None, stats, slot)
                    if d:
                        resume_dir_fn(d)
                return action

            def _full_path_label(_item, slot=slot):
                stats = get_stats_fn(_item)
                d = _dir_at(None, stats, slot)
                return shorten_path(d) if d else ""

            items.append(
                pystray.MenuItem(
                    _label,
                    pystray.Menu(
                        pystray.MenuItem(
                            _full_path_label, None, enabled=False,
                        ),
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem(
                            "5 minutes", _mk_dir_pause(5),
                            visible=_is_active,
                        ),
                        pystray.MenuItem(
                            "15 minutes", _mk_dir_pause(15),
                            visible=_is_active,
                        ),
                        pystray.MenuItem(
                            "30 minutes", _mk_dir_pause(30),
                            visible=_is_active,
                        ),
                        pystray.MenuItem(
                            "1 hour", _mk_dir_pause(60),
                            visible=_is_active,
                        ),
                        pystray.MenuItem(
                            "Until resume", _mk_dir_pause(0),
                            visible=_is_active,
                        ),
                        pystray.MenuItem(
                            "Resume", _mk_dir_resume(),
                            visible=_is_paused,
                        ),
                    ),
                    visible=_is_visible,
                )
            )
        return items

    def _on_targets_updated(self, targets):
        """Callback from background discovery with updated target list."""
        self._discovery_in_progress = False
        self._stop_discovery_animation()
        self._is_initial_discovery = False
        self._targets = targets
        self._apply_working_dirs()
        self._auto_select_target()
        self._poll_plugins()
        self._refreshing_from_discovery = True
        self._dispatch_to_main(self._refresh_menu_and_clear_discovery_flag)
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
    _MAX_DIR_PAUSE_SLOTS = 16
    _MAX_PLUGIN_SLOTS = 8
    _MAX_ITEMS_PER_PLUGIN = 12
    _MAX_SUBMENU_ITEMS = 8
    _MAX_SUBMENU_DEPTH = 2

    def _is_multi_daemon(self):
        """True when multiple daemons are discovered (nested submenu layout)."""
        return len(self._targets) != 1

    def _is_single_daemon(self):
        """True when exactly one daemon is discovered (flat layout)."""
        return len(self._targets) == 1

    @staticmethod
    def _daemon_status_label(target):
        """Format a daemon target into a status header label."""
        from ai_guardian.daemon.working_dir import shorten_path

        status_icon = {
            "running": "●", "paused": "☾", "starting": "◌",
            "stopped": "⚠", "error": "✗", "unknown": "○",
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
        elif target.status == "starting":
            label += " — starting..."
        elif getattr(target, "working_dir", None):
            short = shorten_path(target.working_dir)
            if len(short) > 40:
                short = short[:37] + "..."
            label += f" — {short}"
        return label

    def _version_annotated_label(self, target):
        """Format daemon label with version mismatch indicator if needed."""
        label = self._daemon_status_label(target)
        key = (target.name, target.runtime)
        if key in self._version_mismatch_notified:
            daemon_ver = self._daemon_versions.get(key, "")
            if daemon_ver:
                label += f" — v{daemon_ver} ⟳"
        return label

    def _working_dir_menu_label(self, slot):
        """Format the Working Dir menu item label for a daemon slot."""
        from ai_guardian.daemon.working_dir import shorten_path
        if slot < len(self._targets):
            wd = getattr(self._targets[slot], "working_dir", None)
            if wd:
                short = shorten_path(wd)
                if len(short) > 50:
                    short = short[:47] + "..."
                return f"Working Dir: {short}"
        return "Working Dir: ~"

    def _mk_change_working_dir(self, slot):
        """Create a click handler that opens a directory picker for a slot."""
        def action(_, __):
            if slot >= len(self._targets):
                return
            t = self._targets[slot]
            current = getattr(t, "working_dir", None)
            threading.Thread(
                target=self._pick_working_dir,
                args=(t, current),
                daemon=True,
                name="working-dir-picker",
            ).start()
        return action

    def _pick_working_dir(self, target, current):
        """Run directory picker in background thread and persist result."""
        from ai_guardian.daemon.working_dir import choose_directory, set_working_dir
        chosen = choose_directory(current)
        if chosen:
            target.working_dir = chosen
            set_working_dir(target.name, chosen)
            self._refresh_event.set()

    def _apply_working_dirs(self):
        """Populate target.working_dir from persisted state after discovery."""
        from ai_guardian.daemon.working_dir import get_working_dir
        for t in self._targets:
            if not getattr(t, "working_dir", None):
                t.working_dir = get_working_dir(t.name)

    def _build_single_daemon_menu_items(self):
        """Build flat menu items for single-daemon mode.

        When exactly one daemon is discovered, all submenu items are
        promoted to the top level. Visible only when len(targets) == 1.
        """
        def _single_vis(_item):
            return self._is_single_daemon()

        def _single_vis_refresh(_item):
            return self._is_single_daemon()

        def _single_running(_item):
            if not self._is_single_daemon():
                return False
            if self._targets[0].status in ("running", "paused"):
                return True
            return self._can_autostart_daemon()

        def _single_not_running(_item):
            return (self._is_single_daemon()
                    and self._targets[0].status not in ("running", "paused"))

        def _header_label(_item):
            if not self._targets:
                return ""
            return self._version_annotated_label(self._targets[0])

        def _open_panel(panel=None):
            def action(_, __):
                self._check_and_autostart_daemon()
                # Try to open web console if available (for any panel including main console)
                if self._has_web_console and self._is_web_console_ready():
                    web_page = self._PANEL_TO_WEB_PATH.get(panel, "") if panel else ""
                    daemon_name = self._targets[0].name if self._targets else ""
                    self._open_web_console(daemon_name, web_page)
                    return
                # Fall back to TUI console
                if self._targets:
                    t = self._targets[0]
                    if self._multi_client:
                        self._multi_client.open_console(t, panel)
                    else:
                        self._launch_console(panel)
            return action

        def _open_shell():
            def action(_, __):
                self._check_and_autostart_daemon()
                if self._targets:
                    t = self._targets[0]
                    if self._multi_client:
                        self._multi_client.open_shell(t)
                    else:
                        self._launch_shell(
                            cwd=getattr(t, "working_dir", None),
                        )
            return action

        def _open_doctor():
            def action(_, __):
                self._check_and_autostart_daemon()
                if self._targets:
                    t = self._targets[0]
                    if self._multi_client:
                        self._multi_client.open_doctor(t)
                    else:
                        self._launch_doctor()
            return action

        def _pause_action(minutes):
            def action(_, __):
                self._check_and_autostart_daemon()
                if self._targets:
                    t = self._targets[0]
                    if self._multi_client:
                        self._multi_client.send_pause(t, minutes)
                    else:
                        self._pause(minutes)
                    self.update_status("paused")
            return action

        def _resume_action(_, __):
            self._check_and_autostart_daemon()
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
            stats = _cache["stats"]
            if stats:
                key = (target.name, target.runtime)
                if "mcp_installed" in stats:
                    self._mcp_installed_per_daemon[key] = stats["mcp_installed"]
                if "version" in stats:
                    self._daemon_versions[key] = stats["version"]
            _cache["time"] = now
            return stats

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
            pystray.MenuItem("Console",
                             _open_panel(None),  # None means main console page
                             visible=_single_vis, enabled=_single_running),
            pystray.MenuItem("Violations", _open_panel("panel-violations"),
                             visible=_single_vis, enabled=_single_running),
            pystray.MenuItem("Metrics & Audit", _open_panel("panel-metrics"),
                             visible=_single_vis, enabled=_single_running),
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
                visible=_single_vis,
                enabled=_single_running,
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
                visible=lambda _: _single_vis(_) and self._is_mcp_for_current_target(),
                enabled=_single_running,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                lambda _: self._working_dir_menu_label(0),
                self._mk_change_working_dir(0),
                visible=_single_vis,
            ),
            pystray.MenuItem("Terminal", _open_shell(), visible=_single_vis),
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

        def _global_pause_label(_item):
            stats = _get_stats(_item)
            if stats.get("paused"):
                remaining = stats.get("pause_remaining_seconds", 0)
                if remaining > 0:
                    mins = int(remaining // 60)
                    secs = int(remaining % 60)
                    return f"☾ Daemon (global) ({mins}m {secs}s)"
                return "☾ Daemon (global)"
            return "● Daemon (global)"

        def _global_is_paused(_item):
            return _get_stats(_item).get("paused", False)

        def _global_is_active(_item):
            return not _get_stats(_item).get("paused", False)

        def _pause_dir_action(directory, minutes):
            if self._targets and self._multi_client:
                self._multi_client.send_pause_dir(
                    self._targets[0], directory, minutes,
                )

        def _resume_dir_action(directory):
            if self._targets and self._multi_client:
                self._multi_client.send_resume_dir(
                    self._targets[0], directory,
                )

        dir_pause_items = self._build_dir_pause_items(
            _get_stats, _pause_dir_action, _resume_dir_action,
        )

        def _has_dirs(_item):
            stats = _get_stats(_item)
            return bool(self._get_merged_dir_list(stats))

        return [
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Pause...",
                pystray.Menu(
                    pystray.MenuItem(
                        _global_pause_label,
                        pystray.Menu(
                            pystray.MenuItem(
                                "5 minutes", _pause_action(5),
                                visible=_global_is_active,
                            ),
                            pystray.MenuItem(
                                "15 minutes", _pause_action(15),
                                visible=_global_is_active,
                            ),
                            pystray.MenuItem(
                                "30 minutes", _pause_action(30),
                                visible=_global_is_active,
                            ),
                            pystray.MenuItem(
                                "1 hour", _pause_action(60),
                                visible=_global_is_active,
                            ),
                            pystray.MenuItem(
                                "Until resume", _pause_action(0),
                                visible=_global_is_active,
                            ),
                            pystray.MenuItem(
                                "Resume", _resume_action,
                                visible=_global_is_paused,
                            ),
                        ),
                    ),
                    pystray.Menu.SEPARATOR,
                    *dir_pause_items,
                ),
                visible=_single_running,
            ),
            pystray.MenuItem("Start daemon", _restart_action,
                             visible=_single_not_running),
            pystray.MenuItem(
                "Maintenance",
                pystray.Menu(
                    pystray.MenuItem("Stop daemon", _stop_action),
                    pystray.MenuItem("Restart daemon", _restart_action),
                    pystray.MenuItem(
                        lambda _: self._upgrade_label(
                            self._targets[0] if self._targets else None,
                        ),
                        self._on_upgrade_single,
                        visible=lambda _: (
                            self._targets
                            and self._is_upgrade_available(self._targets[0])
                        ),
                    ),
                ),
                visible=lambda _: self._is_single_daemon(),
            ),
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
                return self._version_annotated_label(self._targets[slot])

            def make_visible(_item, slot=idx):
                return self._is_multi_daemon() and slot < len(self._targets)

            def _mk_open_panel(panel=None, slot=idx):
                def action(_, __):
                    self._check_and_autostart_daemon()
                    if panel and self._has_web_console and self._is_web_console_ready():
                        web_page = self._PANEL_TO_WEB_PATH.get(panel, "")
                        daemon_name = self._targets[slot].name if slot < len(self._targets) else ""
                        self._open_web_console(daemon_name, web_page)
                        return
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.open_console(t, panel)
                        else:
                            self._launch_console(panel)
                return action

            def _mk_web_console_action(slot=idx):
                def action(_, __):
                    self._check_and_autostart_daemon()
                    if slot < len(self._targets):
                        self._open_web_console(self._targets[slot].name)
                return action

            def _mk_web_console_visible(slot=idx):
                def check(_):
                    return (self._has_web_console
                            and slot < len(self._targets)
                            and self._is_web_console_ready())
                return check

            def _mk_open_shell(slot=idx):
                def action(_, __):
                    self._check_and_autostart_daemon()
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.open_shell(t)
                        else:
                            self._launch_shell(
                                cwd=getattr(t, "working_dir", None),
                            )
                return action

            def _mk_doctor(slot=idx):
                def action(_, __):
                    self._check_and_autostart_daemon()
                    if slot < len(self._targets):
                        t = self._targets[slot]
                        if self._multi_client:
                            self._multi_client.open_doctor(t)
                        else:
                            self._launch_doctor()
                return action

            def _mk_pause(minutes, slot=idx):
                def action(_, __):
                    self._check_and_autostart_daemon()
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
                    self._check_and_autostart_daemon()
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
                    stats = _cache["stats"]
                    if stats:
                        key = (target.name, target.runtime)
                        if "mcp_installed" in stats:
                            self._mcp_installed_per_daemon[key] = stats["mcp_installed"]
                        if "version" in stats:
                            self._daemon_versions[key] = stats["version"]
                    _cache["time"] = now
                    return stats

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
                        is_paused, resume_label, _get)

            stats_fns = _mk_stats()

            def _is_slot_running(_item, slot=idx):
                if slot >= len(self._targets):
                    return False
                if self._targets[slot].status in ("running", "paused"):
                    return True
                return self._can_autostart_daemon()

            multi_plugin_items = self._build_multi_daemon_plugin_slots(idx)

            items.append(
                pystray.MenuItem(
                    make_label,
                    pystray.Menu(
                        pystray.MenuItem("Console",
                                         _mk_web_console_action(idx),
                                         visible=_mk_web_console_visible(idx),
                                         enabled=_is_slot_running),
                        pystray.MenuItem("Violations",
                                         _mk_open_panel("panel-violations"),
                                         enabled=_is_slot_running),
                        pystray.MenuItem("Metrics & Audit",
                                         _mk_open_panel("panel-metrics"),
                                         enabled=_is_slot_running),
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
                            enabled=_is_slot_running,
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
                            visible=lambda _i, s=idx: self._is_mcp_for_slot(s),
                            enabled=_is_slot_running,
                        ),
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem(
                            lambda _i, s=idx: self._working_dir_menu_label(s),
                            self._mk_change_working_dir(idx),
                        ),
                        pystray.MenuItem("Terminal", _mk_open_shell()),
                        pystray.Menu.SEPARATOR,
                        *multi_plugin_items,
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem(
                            "Pause...",
                            pystray.Menu(
                                pystray.MenuItem(
                                    lambda _i, _sf=stats_fns: (
                                        self._multi_global_pause_label(_sf, _i)
                                    ),
                                    pystray.Menu(
                                        pystray.MenuItem(
                                            "5 minutes", _mk_pause(5),
                                            visible=lambda _i, _sf=stats_fns: (
                                                not _sf[9](_i)
                                            ),
                                        ),
                                        pystray.MenuItem(
                                            "15 minutes", _mk_pause(15),
                                            visible=lambda _i, _sf=stats_fns: (
                                                not _sf[9](_i)
                                            ),
                                        ),
                                        pystray.MenuItem(
                                            "30 minutes", _mk_pause(30),
                                            visible=lambda _i, _sf=stats_fns: (
                                                not _sf[9](_i)
                                            ),
                                        ),
                                        pystray.MenuItem(
                                            "1 hour", _mk_pause(60),
                                            visible=lambda _i, _sf=stats_fns: (
                                                not _sf[9](_i)
                                            ),
                                        ),
                                        pystray.MenuItem(
                                            "Until resume", _mk_pause(0),
                                            visible=lambda _i, _sf=stats_fns: (
                                                not _sf[9](_i)
                                            ),
                                        ),
                                        pystray.MenuItem(
                                            "Resume", _mk_resume(),
                                            visible=lambda _i, _sf=stats_fns: (
                                                _sf[9](_i)
                                            ),
                                        ),
                                    ),
                                ),
                                pystray.Menu.SEPARATOR,
                                *self._build_dir_pause_items(
                                    stats_fns[11],
                                    self._mk_multi_pause_dir(idx),
                                    self._mk_multi_resume_dir(idx),
                                ),
                            ),
                            visible=_is_slot_running,
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
                            "Maintenance",
                            pystray.Menu(
                                pystray.MenuItem(
                                    "Stop daemon", _mk_stop(),
                                ),
                                pystray.MenuItem(
                                    "Restart daemon", _mk_restart(),
                                ),
                                pystray.MenuItem(
                                    lambda _i, s=idx: self._upgrade_label(
                                        self._targets[s]
                                        if s < len(self._targets) else None,
                                    ),
                                    self._mk_upgrade(idx),
                                    visible=lambda _i, s=idx: (
                                        s < len(self._targets)
                                        and self._is_upgrade_available(
                                            self._targets[s]
                                        )
                                    ),
                                ),
                            ),
                        ),
                        pystray.Menu.SEPARATOR,
                        pystray.MenuItem(self._daemon_about_label(idx), self._on_daemon_about(idx),
                                         enabled=_is_slot_running),
                    ),
                    visible=make_visible,
                )
            )
        return items

    def _poll_plugins(self):
        """Fetch plugin definitions from each discovered daemon.

        Global-scope plugins are collected from all reachable daemons
        and stored in ``_global_plugins`` for top-level rendering.
        They follow the daemon lifecycle: when a daemon stops, its
        global plugins disappear.
        """
        import json as json_mod
        collected_globals = []
        seen_global_names = set()
        reachable_slots = set()
        for i, target in enumerate(self._targets):
            is_reachable = target.status in ("running", "paused")
            if not is_reachable and target.runtime != "local":
                continue
            reachable_slots.add(i)
            try:
                wd = getattr(target, "working_dir", None)
                if self._multi_client:
                    if target.runtime == "local":
                        data = self._multi_client._local_plugins(working_dir=wd)
                    elif is_reachable:
                        data = self._multi_client.get_plugins(target)
                    else:
                        continue
                else:
                    from ai_guardian.daemon.tray_plugins import load_merged_plugins, plugins_to_dict
                    data = plugins_to_dict(load_merged_plugins(wd))
                if data:
                    data_hash = json_mod.dumps(data, sort_keys=True)
                    daemon_tags = self._get_daemon_menu_tags(target)
                    tag_hash = json_mod.dumps(daemon_tags, sort_keys=True)
                    combined_hash = data_hash + tag_hash
                    if self._last_plugins_hash.get(i) != combined_hash:
                        from ai_guardian.daemon.tray_plugins import (
                            dict_to_plugins, filter_plugins_by_tags,
                        )
                        plugins = dict_to_plugins(data)
                        daemon_only = [p for p in plugins if p.scope != "global"]
                        self._daemon_plugins[i] = filter_plugins_by_tags(
                            daemon_only, daemon_tags,
                        )
                        self._last_plugins_hash[i] = combined_hash
                        self._daemon_global_plugins[i] = [
                            p for p in plugins if p.scope == "global"
                        ]
            except Exception:
                pass
        for i in reachable_slots:
            for p in self._daemon_global_plugins.get(i, []):
                if p.name not in seen_global_names:
                    collected_globals.append(p)
                    seen_global_names.add(p.name)
        stale = set(self._daemon_global_plugins) - reachable_slots
        for i in stale:
            del self._daemon_global_plugins[i]
        if collected_globals != self._global_plugins:
            self._global_plugins = collected_globals

    def _get_daemon_menu_tags(self, target):
        """Get menu_tags for a daemon target."""
        if target.runtime == "local":
            from ai_guardian.daemon import get_local_menu_tags
            return get_local_menu_tags()
        if self._multi_client:
            status = self._multi_client.get_status(target)
            if status:
                return status.get("menu_tags", [])
        return []

    def _get_daemon_plugins(self, slot):
        """Get plugin list for a daemon slot index."""
        return self._daemon_plugins.get(slot, [])

    @staticmethod
    def _poll_output_file(output_path, tmpdir, timeout=300, interval=0.5):
        """Poll for an output file, read its content, and clean up.

        Returns the stripped file content, or ``None`` if the file was not
        created before *timeout* seconds elapsed.
        """
        import shutil
        import time
        elapsed = 0.0
        while elapsed < timeout:
            if os.path.exists(output_path):
                try:
                    with open(output_path) as f:
                        content = f.read().strip()
                except OSError:
                    content = ""
                shutil.rmtree(tmpdir, ignore_errors=True)
                return content
            time.sleep(interval)
            elapsed += interval
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None

    @staticmethod
    def _execute_plugin_command(
        command_str, item_type, target=None, run_on_target=False,
        label=None,
    ):
        """Execute a plugin command with optional target context."""
        import os
        import shlex
        import subprocess
        from ai_guardian.daemon.multi_client import _launch_in_terminal
        from ai_guardian.daemon.tray_plugins import (
            _needs_shell,
            substitute_params,
            substitute_target_vars,
            wrap_for_target,
        )

        command_str = substitute_target_vars(command_str, target)
        if target and getattr(target, "working_dir", None):
            command_str = substitute_params(
                command_str, {"working_dir": target.working_dir},
            )

        command_str = DaemonTray._resolve_plugin_ai_guardian(
            command_str, run_on_target, target,
        )

        if _needs_shell(command_str):
            cmd_parts = ["sh", "-c", command_str]
        else:
            try:
                cmd_parts = shlex.split(command_str)
            except ValueError:
                logger.warning("Malformed plugin command: %s", command_str)
                return

        if run_on_target and target:
            cmd_parts = wrap_for_target(
                cmd_parts, target, interactive=(item_type == "terminal"),
            )

        is_remote = (
            run_on_target and target
            and getattr(target, "runtime", "local")
            in ("container", "kubernetes")
        )
        if item_type != "terminal" and not is_remote:
            shell = os.environ.get("SHELL", "/bin/bash")
            cmd_parts = [shell, "-lc", command_str]

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
            elif item_type == "modal":
                result = subprocess.run(
                    cmd_parts, capture_output=True, text=True, timeout=60,
                )
                output = result.stdout.strip()
                err = result.stderr.strip()
                if err:
                    if result.returncode != 0:
                        output = err if not output else (
                            output + "\n\n--- stderr ---\n" + err
                        )
                    else:
                        output = (output + "\n" + err).strip() if output else err
                from ai_guardian.daemon.tray_plugins import show_dialog
                show_dialog(label or "AI Guardian", output or "(no output)")
            else:
                subprocess.run(cmd_parts, timeout=60)
        except Exception:
            pass

    def _execute_plugin_command_with_params(self, plugin_item_dict, target=None):
        """Launch tray-prompt for parameter collection, then execute.

        Uses tkinter popup (no terminal) when available, otherwise falls
        back to Textual TUI in a terminal window.
        """
        import json as json_mod
        import os
        import subprocess
        import tempfile
        import threading
        from ai_guardian.daemon.tray_plugins import resolve_command, substitute_target_vars

        resolved_cmd = resolve_command(plugin_item_dict["command"])
        if resolved_cmd is None:
            return

        resolved_cmd = substitute_target_vars(resolved_cmd, target)

        tmpdir = tempfile.mkdtemp(prefix="ai-guardian-prompt-")
        output_path = os.path.join(tmpdir, "command")

        extra_vars = {}
        if target and getattr(target, "working_dir", None):
            extra_vars["working_dir"] = target.working_dir

        params_json = json_mod.dumps(plugin_item_dict.get("params", []))
        prompt_cmd = self._resolve_cli_cmd(
            "tray-prompt",
            "--params", params_json,
            "--template", resolved_cmd,
            "--type", plugin_item_dict.get("type", "terminal"),
            "--output-file", output_path,
        )
        label = plugin_item_dict.get("label")
        if extra_vars:
            prompt_cmd += ["--extra-vars", json_mod.dumps(extra_vars)]
        if label:
            prompt_cmd += ["--title", label]

        from ai_guardian.tui.tray_prompt import (
            _nicegui_available, _tkinter_available,
        )
        if _tkinter_available() or _nicegui_available():
            subprocess.Popen(prompt_cmd)
        else:
            from ai_guardian.daemon.multi_client import _launch_in_terminal
            _launch_in_terminal(prompt_cmd, keep_open=False, clear=True)

        item_type = plugin_item_dict.get("type", "terminal")
        run_on_target = plugin_item_dict.get("run_on_target", False)

        def _watch_and_dispatch():
            command = DaemonTray._poll_output_file(output_path, tmpdir)
            if command:
                DaemonTray._execute_plugin_command(
                    command, item_type, target=target,
                    run_on_target=run_on_target, label=label,
                )

        watcher = threading.Thread(target=_watch_and_dispatch, daemon=True)
        watcher.start()

    def _resolve_target_list(self, target_mode):
        """Resolve a target mode to a list of DaemonTarget instances."""
        if target_mode == "all":
            return list(self._targets)
        if target_mode == "containers":
            return [t for t in self._targets if t.runtime == "container"]
        return []

    def _execute_multi_target_command(
        self, targets, command_str, item_type, run_on_target=False, label=None,
    ):
        """Execute the same command on multiple targets sequentially."""
        for target in targets:
            self._execute_plugin_command(
                command_str, item_type, target=target,
                run_on_target=run_on_target, label=label,
            )

    def _serialize_targets_for_selector(self):
        """Serialize discovered targets to JSON dicts for the selector TUI."""
        return [
            {
                "name": t.name,
                "runtime": t.runtime,
                "container_name": getattr(t, "container_name", None),
                "container_engine": t.container_engine,
                "container_id": t.container_id,
                "pod_name": t.pod_name,
                "namespace": t.namespace,
                "status": t.status,
            }
            for t in self._targets
        ]

    def _execute_multi_target_with_params(self, plugin_item, targets):
        """Collect params once via tray-prompt, then execute on all targets.

        Uses tkinter popup when available, Textual terminal fallback otherwise.
        """
        import json as json_mod
        import os
        import subprocess
        import tempfile
        import threading
        from ai_guardian.daemon.tray_plugins import (
            _item_to_dict, resolve_command, substitute_target_vars,
        )

        item_dict = _item_to_dict(plugin_item)
        resolved_cmd = resolve_command(plugin_item.command)
        if resolved_cmd is None:
            return

        tmpdir = tempfile.mkdtemp(prefix="ai-guardian-prompt-")
        output_path = os.path.join(tmpdir, "command")

        params_json = json_mod.dumps(item_dict.get("params", []))
        prompt_cmd = self._resolve_cli_cmd(
            "tray-prompt",
            "--params", params_json,
            "--template", resolved_cmd,
            "--type", plugin_item.type,
            "--output-file", output_path,
        )
        label = plugin_item.label
        if label:
            prompt_cmd += ["--title", label]

        from ai_guardian.tui.tray_prompt import (
            _nicegui_available, _tkinter_available,
        )
        if _tkinter_available() or _nicegui_available():
            subprocess.Popen(prompt_cmd)
        else:
            from ai_guardian.daemon.multi_client import _launch_in_terminal
            _launch_in_terminal(prompt_cmd, keep_open=False, clear=True)

        item_type = plugin_item.type
        run_on_target = plugin_item.run_on_target

        def _watch_and_dispatch():
            command = DaemonTray._poll_output_file(output_path, tmpdir)
            if command:
                self._execute_multi_target_command(
                    targets, command, item_type,
                    run_on_target=run_on_target, label=label,
                )

        watcher = threading.Thread(target=_watch_and_dispatch, daemon=True)
        watcher.start()

    def _execute_plugin_with_target_select(self, plugin_item):
        """Launch target selector, then execute on selected targets."""
        import json as json_mod
        import os
        import tempfile
        import threading
        from ai_guardian.daemon.tray_plugins import (
            _item_to_dict, resolve_command,
        )
        from ai_guardian.daemon.multi_client import _launch_in_terminal

        targets_json = json_mod.dumps(self._serialize_targets_for_selector())
        tmpdir = tempfile.mkdtemp(prefix="ai-guardian-target-")
        output_path = os.path.join(tmpdir, "selected")

        select_cmd = self._resolve_cli_cmd(
            "tray-target-select",
            "--targets", targets_json,
            "--output-file", output_path,
        )
        _launch_in_terminal(select_cmd, keep_open=False, clear=True)

        def _watch_and_dispatch():
            raw = DaemonTray._poll_output_file(output_path, tmpdir)
            if not raw:
                return
            try:
                indices = json_mod.loads(raw)
            except (json_mod.JSONDecodeError, TypeError):
                return
            if not isinstance(indices, list):
                return
            selected = [
                self._targets[i]
                for i in indices
                if isinstance(i, int) and 0 <= i < len(self._targets)
            ]
            if not selected:
                return

            if plugin_item.params:
                self._execute_multi_target_with_params(
                    plugin_item, selected,
                )
            else:
                cmd = resolve_command(plugin_item.command)
                if cmd:
                    self._execute_multi_target_command(
                        selected, cmd, plugin_item.type,
                        run_on_target=plugin_item.run_on_target,
                        label=plugin_item.label,
                    )

        watcher = threading.Thread(target=_watch_and_dispatch, daemon=True)
        watcher.start()

    def _build_plugin_slots_for_daemon(self, daemon_slot, visibility_guard=None):
        """Build pre-allocated plugin menu item slots for a daemon.

        Args:
            daemon_slot: Index into self._targets for this daemon.
            visibility_guard: Optional callable(_item) -> bool wrapping
                each plugin's visibility. When None, plugins are always
                visible if they exist.
        """
        get_plugins = lambda: self._get_daemon_plugins(daemon_slot)
        get_target = lambda: (
            self._targets[daemon_slot]
            if daemon_slot < len(self._targets)
            else None
        )
        return self._build_plugin_slots(
            get_plugins, get_target,
            max_plugins=self._MAX_PLUGIN_SLOTS,
            max_items=self._MAX_ITEMS_PER_PLUGIN,
            visibility_guard=visibility_guard,
        )

    def _build_plugin_slots(
        self, get_plugins_fn, get_target_fn,
        max_plugins, max_items, visibility_guard=None,
    ):
        """Build pre-allocated plugin menu item slots.

        Args:
            get_plugins_fn: Callable returning the plugin list.
            get_target_fn: Callable returning the target for execution.
            max_plugins: Number of plugin slots to pre-allocate.
            max_items: Number of item slots per plugin.
            visibility_guard: Optional callable(_item) -> bool.
        """
        items = []

        for p_idx in range(max_plugins):
            p_slot = p_idx

            def _plugin_name(_item, ps=p_slot):
                plugins = get_plugins_fn()
                if ps < len(plugins):
                    return plugins[ps].name
                return ""

            def _plugin_visible(_item, ps=p_slot):
                if visibility_guard is not None and not visibility_guard(_item):
                    return False
                plugins = get_plugins_fn()
                return ps < len(plugins)

            def _get_item_list(ps=p_slot):
                plugins = get_plugins_fn()
                if ps < len(plugins):
                    return plugins[ps].items
                return []

            sub_items = self._build_nested_item_slots(
                _get_item_list, get_target_fn, max_items, depth=0,
            )

            items.append(
                pystray.MenuItem(_plugin_name, pystray.Menu(*sub_items),
                                 visible=_plugin_visible)
            )

        return items

    def _build_nested_item_slots(
        self, get_items_fn, get_target_fn, max_items, depth,
    ):
        """Build pre-allocated slots for items that may contain submenus.

        For each slot position, two pystray MenuItems are created:
        one for command items (clickable) and one for submenu items
        (expandable). Only one is visible at a time.

        Args:
            get_items_fn: Callable returning the item list.
            get_target_fn: Callable returning the execution target.
            max_items: Number of item slots to pre-allocate.
            depth: Current nesting depth (0 = direct plugin children).
        """
        slots = []

        for i_idx in range(max_items):
            i_slot = i_idx

            def _cmd_label(_item, ix=i_slot):
                items_list = get_items_fn()
                if ix < len(items_list):
                    return items_list[ix].label
                return ""

            def _cmd_visible(_item, ix=i_slot):
                items_list = get_items_fn()
                if ix >= len(items_list):
                    return False
                item = items_list[ix]
                if item.items:
                    return False
                from ai_guardian.daemon.tray_plugins import resolve_command
                return resolve_command(item.command) is not None

            def _cmd_action(ix=i_slot):
                def action(_, __):
                    items_list = get_items_fn()
                    if ix >= len(items_list):
                        return
                    item = items_list[ix]
                    if item.items:
                        return
                    target = get_target_fn()

                    if item.target in ("all", "containers"):
                        from ai_guardian.daemon.tray_plugins import resolve_command
                        targets = self._resolve_target_list(item.target)
                        if not targets:
                            return
                        if item.params:
                            self._execute_multi_target_with_params(
                                item, targets,
                            )
                        else:
                            cmd = resolve_command(item.command)
                            if cmd:
                                self._execute_multi_target_command(
                                    targets, cmd, item.type,
                                    run_on_target=item.run_on_target,
                                    label=item.label,
                                )
                    elif item.target == "select":
                        self._execute_plugin_with_target_select(item)
                    elif item.params:
                        from ai_guardian.daemon.tray_plugins import _item_to_dict
                        self._execute_plugin_command_with_params(
                            _item_to_dict(item), target=target,
                        )
                    else:
                        from ai_guardian.daemon.tray_plugins import resolve_command
                        cmd = resolve_command(item.command)
                        if cmd:
                            self._execute_plugin_command(
                                cmd, item.type,
                                target=target,
                                run_on_target=item.run_on_target,
                                label=item.label,
                            )
                return action

            def _cmd_enabled(_item, ix=i_slot):
                items_list = get_items_fn()
                if ix >= len(items_list):
                    return True
                item = items_list[ix]
                if not item.run_on_target:
                    return True
                target = get_target_fn()
                if target is None:
                    return False
                return target.status in ("running", "paused")

            slots.append(
                pystray.MenuItem(_cmd_label, _cmd_action(),
                                 visible=_cmd_visible, enabled=_cmd_enabled)
            )

            if depth < self._MAX_SUBMENU_DEPTH:
                def _sub_label(_item, ix=i_slot):
                    items_list = get_items_fn()
                    if ix < len(items_list):
                        return items_list[ix].label
                    return ""

                def _sub_visible(_item, ix=i_slot):
                    items_list = get_items_fn()
                    if ix >= len(items_list):
                        return False
                    return bool(items_list[ix].items)

                def _get_children(ix=i_slot):
                    items_list = get_items_fn()
                    if ix < len(items_list) and items_list[ix].items:
                        return items_list[ix].items
                    return []

                child_slots = self._build_nested_item_slots(
                    _get_children, get_target_fn,
                    self._MAX_SUBMENU_ITEMS, depth + 1,
                )

                slots.append(
                    pystray.MenuItem(
                        _sub_label, pystray.Menu(*child_slots),
                        visible=_sub_visible,
                    )
                )

        return slots

    def _build_single_daemon_plugin_items(self):
        """Build plugin menu items for single-daemon mode.

        Each plugin becomes a top-level submenu. Pre-allocates slots
        for pystray macOS compatibility. Only visible when exactly one
        daemon is discovered and that daemon has plugins.
        """
        def _has_plugins(_item):
            return self._is_single_daemon() and len(self._get_daemon_plugins(0)) > 0

        guard = lambda _item: self._is_single_daemon()
        items = [pystray.MenuItem("", None, visible=lambda _: (
            _has_plugins(_) and False
        ))]
        items.extend(self._build_plugin_slots_for_daemon(0, visibility_guard=guard))
        return items

    def _build_multi_daemon_plugin_slots(self, daemon_slot):
        """Build pre-allocated plugin slots for a multi-daemon submenu."""
        return self._build_plugin_slots_for_daemon(daemon_slot)

    _MAX_GLOBAL_PLUGIN_SLOTS = 4
    _MAX_GLOBAL_ITEMS_PER_PLUGIN = 12

    def _build_global_plugin_items(self):
        """Build top-level menu items for global-scope plugins.

        Global plugins appear at the tray top level, not inside any
        daemon submenu. Pre-allocates slots for pystray macOS
        compatibility.
        """
        items = self._build_plugin_slots(
            get_plugins_fn=lambda: self._global_plugins,
            get_target_fn=lambda: self._active_target,
            max_plugins=self._MAX_GLOBAL_PLUGIN_SLOTS,
            max_items=self._MAX_GLOBAL_ITEMS_PER_PLUGIN,
        )
        items.append(pystray.Menu.SEPARATOR)
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

        cmd = DaemonTray._resolve_cli_cmd("tray", "start")
        logger.debug("Restarting tray with command: %s", cmd)
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
            logger.error("Failed to restart tray: %s (cmd: %s)", e, cmd)

    def _on_quit(self, icon, item):
        self.stop()
        self._stop()
