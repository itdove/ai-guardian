"""
Discovery animation manager for the system tray.

Split from tray.py (Issue #1542) to separate animation state and frame
cycling from tray lifecycle and menu construction.

TrayIconManager holds all discovery animation state and methods.
It receives a back-reference to DaemonTray for accessing the icon,
dispatch_to_main, create_icon, discovery, and refresh_menu.
"""

import logging
import threading

logger = logging.getLogger(__name__)


class TrayIconManager:
    """Manages discovery animation frames and cycling for the tray icon."""

    def __init__(self, tray):
        self._tray = tray
        self._discovery_animating = False
        self._discovery_anim_stop = threading.Event()
        self._discovery_timer = None
        self._discovery_frames = None
        self._is_initial_discovery = True
        self._discovery_in_progress = False
        self._refreshing_from_discovery = False
        self._last_discovery_refresh = 0.0

    def _generate_discovery_frames(self):
        """Generate alpha-pulsing icon frames for discovery animation."""
        if self._discovery_frames is not None:
            return self._discovery_frames
        base = self._tray._create_icon()
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
            daemon=True,
            name="discovery-anim",
        )
        thread.start()

    def _animate_discovery_loop(self):
        """Cycle through alpha-pulsing icon frames until discovery completes."""
        frames = self._generate_discovery_frames()
        idx = 0
        while not self._discovery_anim_stop.is_set():
            if self._tray._icon and not self._discovery_anim_stop.is_set():
                frame = frames[idx % len(frames)]
                self._tray._dispatch_to_main(lambda f=frame: self._set_icon_frame(f))
            idx += 1
            self._discovery_anim_stop.wait(timeout=0.2)
        logger.info("Discovery animation: loop ended")
        self._discovery_animating = False

    def _set_icon_frame(self, frame):
        """Set the tray icon to a specific frame (main thread)."""
        if self._tray._icon:
            self._tray._icon.icon = frame

    def _stop_discovery_animation(self):
        """Stop discovery animation and restore normal icon."""
        logger.info("Discovery animation: stopping")
        self._cancel_discovery_timer()
        self._discovery_anim_stop.set()
        if self._tray._icon:
            self._tray._dispatch_to_main(self._refresh_icon_after_discovery)

    def _cancel_discovery_timer(self):
        """Cancel the pending discovery animation timer."""
        if self._discovery_timer is not None:
            self._discovery_timer.cancel()
            self._discovery_timer = None

    def _refresh_icon_after_discovery(self):
        """Restore normal icon after discovery animation (main thread)."""
        if self._tray._icon:
            self._tray._icon.icon = self._tray._create_icon()

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
        if self._tray._discovery and not self._refreshing_from_discovery:
            self._last_discovery_refresh = now
            self._discovery_in_progress = True
            self._tray._discovery.request_refresh(**kwargs)

    def _refresh_menu_and_clear_discovery_flag(self):
        """Refresh menu and clear the discovery refresh guard (main thread)."""
        self._tray._refresh_menu()
        self._refreshing_from_discovery = False
