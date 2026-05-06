"""
Thread-safe in-memory state for the daemon process.

Manages cross-hook correlation contexts, config caching with auto-reload,
compiled regex pattern caching, and activity tracking for idle timeout.
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from pathlib import Path

from ai_guardian.config_utils import get_config_dir

logger = logging.getLogger(__name__)

DEFAULT_CONTEXT_TTL = 300.0  # 5 minutes
DEFAULT_IDLE_TIMEOUT = 1800.0  # 30 minutes
CONFIG_CHECKSUM_INTERVAL = 60.0  # check checksum every 60s


class DaemonState:
    """Thread-safe in-memory state for the daemon process."""

    def __init__(self, config_path=None, idle_timeout=DEFAULT_IDLE_TIMEOUT,
                 context_ttl=DEFAULT_CONTEXT_TTL):
        self._lock = threading.Lock()

        # Cross-hook correlation: "session_id:tool_use_id" -> PreToolUse data
        self._hook_contexts = {}
        self._context_ttl = context_ttl

        # Compiled regex cache: pattern_string -> re.Pattern
        self._compiled_patterns = {}

        # Config caching
        self._config = None
        self._config_path = config_path or self._default_config_path()
        self._config_mtime = 0.0
        self._config_checksum = ""
        self._last_checksum_check = 0.0

        # Activity tracking
        self._last_activity = time.monotonic()
        self._idle_timeout = idle_timeout

        # Stats
        self._request_count = 0
        self._blocked_count = 0
        self._warning_count = 0
        self._log_only_count = 0
        self._started_at = time.time()

        # Proxy stats
        self._proxy_request_count = 0
        self._proxy_violations_count = 0
        self._proxy_blocked_count = 0
        self._proxy_port = 0

        # Paused state (for tray Pause/Resume)
        self._paused = False
        self._paused_until = 0.0  # monotonic timestamp, 0 = not time-limited

        # Initial config load
        self._reload_config()

    @staticmethod
    def _default_config_path():
        return get_config_dir() / "ai-guardian.json"

    # --- Cross-hook correlation ---

    def store_pretooluse_context(self, session_id, tool_use_id, context):
        """Store PreToolUse context for later PostToolUse correlation.

        Args:
            session_id: IDE session identifier
            tool_use_id: Tool use identifier
            context: Dict with PreToolUse scan results and metadata
        """
        if not session_id or not tool_use_id:
            return
        key = f"{session_id}:{tool_use_id}"
        with self._lock:
            self._hook_contexts[key] = {
                "context": context,
                "timestamp": time.monotonic(),
            }

    def get_pretooluse_context(self, session_id, tool_use_id):
        """Retrieve PreToolUse context for PostToolUse correlation.

        Args:
            session_id: IDE session identifier
            tool_use_id: Tool use identifier

        Returns:
            dict or None: PreToolUse context if found and not expired
        """
        if not session_id or not tool_use_id:
            return None
        key = f"{session_id}:{tool_use_id}"
        with self._lock:
            entry = self._hook_contexts.get(key)
            if entry is None:
                return None
            age = time.monotonic() - entry["timestamp"]
            if age > self._context_ttl:
                del self._hook_contexts[key]
                return None
            return entry["context"]

    def cleanup_expired_contexts(self):
        """Remove expired cross-hook correlation entries."""
        now = time.monotonic()
        with self._lock:
            expired = [
                k for k, v in self._hook_contexts.items()
                if now - v["timestamp"] > self._context_ttl
            ]
            for key in expired:
                del self._hook_contexts[key]
            if expired:
                logger.debug(f"Cleaned up {len(expired)} expired hook contexts")

    # --- Config caching with auto-reload ---

    def get_config(self):
        """Get cached config, reloading if file changed.

        Uses mtime check on every call (fast) and periodic checksum
        verification for edge cases.

        Returns:
            dict or None: Parsed config, or None if no config file
        """
        with self._lock:
            if self._check_config_reload():
                self._reload_config()
            return self._config

    def force_reload_config(self):
        """Force config reload regardless of mtime/checksum."""
        with self._lock:
            self._reload_config()
            logger.info("Config force-reloaded")

    def _check_config_reload(self):
        """Check if config file has changed (must be called with lock held).

        Returns:
            bool: True if config should be reloaded
        """
        try:
            if not self._config_path.exists():
                if self._config is not None:
                    logger.info("Config file removed, clearing cached config")
                    return True
                return False

            stat = os.stat(self._config_path)
            current_mtime = stat.st_mtime

            # Fast path: mtime changed
            if current_mtime != self._config_mtime:
                logger.info("Config file mtime changed, reloading")
                return True

            # Periodic checksum verification
            now = time.monotonic()
            if now - self._last_checksum_check > CONFIG_CHECKSUM_INTERVAL:
                self._last_checksum_check = now
                current_checksum = self._compute_config_checksum()
                if current_checksum != self._config_checksum:
                    logger.info("Config file checksum changed, reloading")
                    return True

            return False
        except OSError:
            return False

    def _reload_config(self):
        """Reload config from disk (must be called with lock held)."""
        try:
            if not self._config_path.exists():
                self._config = None
                self._config_mtime = 0.0
                self._config_checksum = ""
                return

            content = self._config_path.read_text(encoding="utf-8")
            self._config = json.loads(content)
            stat = os.stat(self._config_path)
            self._config_mtime = stat.st_mtime
            self._config_checksum = hashlib.sha256(
                content.encode("utf-8")
            ).hexdigest()
            self._last_checksum_check = time.monotonic()

            # Invalidate compiled pattern cache on config change
            self._compiled_patterns.clear()

            logger.info(f"Config loaded from {self._config_path}")
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to reload config: {e}")

    def _compute_config_checksum(self):
        """Compute SHA256 of config file content."""
        try:
            content = self._config_path.read_bytes()
            return hashlib.sha256(content).hexdigest()
        except OSError:
            return ""

    # --- Compiled regex pattern cache ---

    def get_compiled_pattern(self, pattern):
        """Get a compiled regex pattern, using cache.

        Args:
            pattern: Regex pattern string

        Returns:
            re.Pattern or None: Compiled pattern, or None on invalid regex
        """
        with self._lock:
            if pattern in self._compiled_patterns:
                return self._compiled_patterns[pattern]
            try:
                compiled = re.compile(pattern)
                self._compiled_patterns[pattern] = compiled
                return compiled
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {e}")
                return None

    # --- Activity tracking ---

    def record_activity(self):
        """Record that a request was processed (resets idle timer)."""
        with self._lock:
            self._last_activity = time.monotonic()
            self._request_count += 1

    def record_blocked(self):
        """Record that a request was blocked (operation denied)."""
        with self._lock:
            self._blocked_count += 1

    def record_warning(self):
        """Record that a warning was shown to the user (threat detected, allowed)."""
        with self._lock:
            self._warning_count += 1

    def record_log_only(self):
        """Record a silently logged violation (no user-visible message)."""
        with self._lock:
            self._log_only_count += 1

    # --- Proxy stats ---

    def set_proxy_port(self, port):
        """Set the proxy listen port for stats reporting."""
        with self._lock:
            self._proxy_port = port

    def record_proxy_request(self):
        """Record a proxied HTTP request."""
        with self._lock:
            self._proxy_request_count += 1
            self._last_activity = time.monotonic()

    def record_proxy_violation(self):
        """Record a violation detected in proxied traffic."""
        with self._lock:
            self._proxy_violations_count += 1

    def record_proxy_blocked(self):
        """Record a proxied request that was blocked due to violations."""
        with self._lock:
            self._proxy_blocked_count += 1

    def is_idle_timeout_expired(self):
        """Check if daemon has been idle longer than the timeout.

        Returns:
            bool: True if idle timeout has expired
        """
        if self._idle_timeout <= 0:
            return False  # Disabled
        with self._lock:
            elapsed = time.monotonic() - self._last_activity
            return elapsed > self._idle_timeout

    # --- Pause/resume ---

    @property
    def paused(self):
        with self._lock:
            if not self._paused:
                return False
            # Check if time-limited pause has expired
            if self._paused_until > 0 and time.monotonic() >= self._paused_until:
                self._paused = False
                self._paused_until = 0.0
                logger.info("Pause expired, resuming")
                return False
            return True

    def pause(self, duration_minutes=0):
        """Pause all hook scanning.

        Args:
            duration_minutes: Pause duration in minutes. 0 = indefinite.
        """
        with self._lock:
            self._paused = True
            if duration_minutes > 0:
                self._paused_until = time.monotonic() + duration_minutes * 60
                logger.info(f"Daemon paused for {duration_minutes} minutes")
            else:
                self._paused_until = 0.0
                logger.info("Daemon paused indefinitely")

    def resume(self):
        """Resume hook scanning."""
        with self._lock:
            self._paused = False
            self._paused_until = 0.0
            logger.info("Daemon resumed")

    def pause_remaining_seconds(self):
        """Get remaining seconds of a time-limited pause.

        Returns:
            float: Seconds remaining, 0 if not paused or indefinite pause
        """
        with self._lock:
            if not self._paused or self._paused_until <= 0:
                return 0.0
            remaining = self._paused_until - time.monotonic()
            return max(0.0, remaining)

    # --- Stats ---

    def get_stats(self):
        """Get daemon statistics.

        Returns:
            dict: Stats including uptime, request count, violation count
        """
        with self._lock:
            uptime = time.time() - self._started_at
            violations = (self._blocked_count + self._warning_count
                         + self._log_only_count)
            return {
                "uptime_seconds": uptime,
                "request_count": self._request_count,
                "blocked_count": self._blocked_count,
                "warning_count": self._warning_count,
                "log_only_count": self._log_only_count,
                "violation_count": violations,
                "active_contexts": len(self._hook_contexts),
                "cached_patterns": len(self._compiled_patterns),
                "config_loaded": self._config is not None,
                "paused": self._paused,
                "pause_remaining_seconds": self._pause_remaining_locked(),
                "started_at": self._started_at,
                "proxy_port": self._proxy_port,
                "proxy_request_count": self._proxy_request_count,
                "proxy_violations_count": self._proxy_violations_count,
                "proxy_blocked_count": self._proxy_blocked_count,
            }

    def _pause_remaining_locked(self):
        """Get remaining pause seconds (must be called with lock held)."""
        if not self._paused or self._paused_until <= 0:
            return 0.0
        remaining = self._paused_until - time.monotonic()
        return max(0.0, remaining)
