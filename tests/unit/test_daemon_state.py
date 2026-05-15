"""Tests for daemon in-memory state management."""

import json
import os
import re
import time
import threading

import pytest

from ai_guardian.daemon.state import DaemonState


class TestCrossHookCorrelation:
    def test_store_and_retrieve_context(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        ctx = {"file_path": "/tmp/test.py", "findings": []}
        state.store_pretooluse_context("session1", "tool1", ctx)
        result = state.get_pretooluse_context("session1", "tool1")
        assert result == ctx

    def test_retrieve_nonexistent_context(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        result = state.get_pretooluse_context("session1", "tool1")
        assert result is None

    def test_context_expiry(self, tmp_path):
        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            context_ttl=0.1,  # 100ms TTL
        )
        state.store_pretooluse_context("s1", "t1", {"data": "test"})
        time.sleep(0.15)
        result = state.get_pretooluse_context("s1", "t1")
        assert result is None

    def test_cleanup_expired_contexts(self, tmp_path):
        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            context_ttl=0.1,
        )
        state.store_pretooluse_context("s1", "t1", {"data": "old"})
        state.store_pretooluse_context("s2", "t2", {"data": "old2"})
        time.sleep(0.15)
        state.store_pretooluse_context("s3", "t3", {"data": "new"})
        state.cleanup_expired_contexts()

        assert state.get_pretooluse_context("s1", "t1") is None
        assert state.get_pretooluse_context("s2", "t2") is None
        assert state.get_pretooluse_context("s3", "t3") == {"data": "new"}

    def test_none_session_id_ignored(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.store_pretooluse_context(None, "t1", {"data": "test"})
        assert state.get_pretooluse_context(None, "t1") is None

    def test_none_tool_use_id_ignored(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.store_pretooluse_context("s1", None, {"data": "test"})
        assert state.get_pretooluse_context("s1", None) is None


class TestConfigCaching:
    def test_load_config_on_init(self, tmp_path):
        config = {"secret_scanning": {"enabled": True}}
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps(config))

        state = DaemonState(config_path=config_path)
        assert state.get_config() == config

    def test_no_config_file(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        assert state.get_config() is None

    def test_config_reload_on_mtime_change(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"version": 1}))

        state = DaemonState(config_path=config_path)
        assert state.get_config()["version"] == 1

        # Modify config (ensure mtime changes)
        time.sleep(0.05)
        config_path.write_text(json.dumps({"version": 2}))

        result = state.get_config()
        assert result["version"] == 2

    def test_config_reload_clears_pattern_cache(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))

        state = DaemonState(config_path=config_path)
        state.get_compiled_pattern(r"\d+")
        assert state.get_stats()["cached_patterns"] > 0

        time.sleep(0.05)
        config_path.write_text(json.dumps({"v": 2}))
        state.get_config()  # triggers reload

        # Pattern cache should be cleared
        assert len(state._compiled_patterns) == 0

    def test_force_reload_config(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))

        state = DaemonState(config_path=config_path)

        # Modify without waiting for mtime to differ
        config_path.write_text(json.dumps({"v": 2}))
        state.force_reload_config()

        assert state.get_config()["v"] == 2

    def test_config_file_removed(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))

        state = DaemonState(config_path=config_path)
        assert state.get_config() is not None

        config_path.unlink()
        state.force_reload_config()
        assert state.get_config() is None

    def test_invalid_json_config(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text("valid json")
        config_path.write_text(json.dumps({"v": 1}))

        state = DaemonState(config_path=config_path)
        assert state.get_config()["v"] == 1

        # Write invalid JSON
        time.sleep(0.05)
        config_path.write_text("{invalid")
        state.get_config()  # Should log error but not crash
        # Config should still be old value since reload failed
        assert state._config["v"] == 1


class TestCompiledPatternCache:
    def test_cache_compiled_pattern(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        pattern = state.get_compiled_pattern(r"\d{3}-\d{4}")
        assert isinstance(pattern, re.Pattern)

        # Same pattern returns cached instance
        pattern2 = state.get_compiled_pattern(r"\d{3}-\d{4}")
        assert pattern is pattern2

    def test_invalid_regex_returns_none(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        result = state.get_compiled_pattern(r"[invalid")
        assert result is None


class TestActivityTracking:
    def test_record_activity_resets_idle(self, tmp_path):
        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            idle_timeout=0.2,
        )
        time.sleep(0.1)
        state.record_activity()
        assert not state.is_idle_timeout_expired()

    def test_idle_timeout_expires(self, tmp_path):
        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            idle_timeout=0.1,
        )
        time.sleep(0.15)
        assert state.is_idle_timeout_expired()

    def test_idle_timeout_disabled(self, tmp_path):
        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            idle_timeout=0,
        )
        time.sleep(0.05)
        assert not state.is_idle_timeout_expired()


class TestPauseResume:
    def test_default_not_paused(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        assert not state.paused

    def test_pause_indefinite(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.pause()
        assert state.paused
        assert state.pause_remaining_seconds() == 0.0  # indefinite

    def test_pause_with_duration(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.pause(duration_minutes=5)
        assert state.paused
        remaining = state.pause_remaining_seconds()
        assert 290 < remaining <= 300  # ~5 minutes

    def test_pause_auto_expires(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        # Pause for a very short duration
        state.pause(duration_minutes=0.002)  # ~0.12 seconds
        assert state.paused
        time.sleep(0.15)
        assert not state.paused  # auto-expired

    def test_resume(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.pause(duration_minutes=30)
        assert state.paused
        state.resume()
        assert not state.paused
        assert state.pause_remaining_seconds() == 0.0


class TestStats:
    def test_initial_stats(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        stats = state.get_stats()
        assert stats["request_count"] == 0
        assert stats["blocked_count"] == 0
        assert stats["warning_count"] == 0
        assert stats["log_only_count"] == 0
        assert stats["violation_count"] == 0
        assert stats["critical_count"] == 0
        assert stats["warning_severity_count"] == 0
        assert stats["last_block_type"] is None
        assert stats["last_block_seconds_ago"] is None
        assert stats["active_contexts"] == 0
        assert stats["paused"] is False
        assert "uptime_seconds" in stats
        assert "started_at" in stats

    def test_stats_accumulate(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.record_activity()
        state.record_activity()
        state.record_blocked()
        state.record_warning()
        state.record_warning()
        state.record_log_only()

        stats = state.get_stats()
        assert stats["request_count"] == 2
        assert stats["blocked_count"] == 1
        assert stats["warning_count"] == 2
        assert stats["log_only_count"] == 1
        assert stats["violation_count"] == 4  # 1 + 2 + 1

    def test_severity_counts(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.record_blocked()
        state.record_blocked()
        state.record_warning()

        stats = state.get_stats()
        assert stats["critical_count"] == 2
        assert stats["warning_severity_count"] == 1

    def test_last_block_tracking(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.record_blocked(violation_type="secret_detected")

        stats = state.get_stats()
        assert stats["last_block_type"] == "secret_detected"
        assert stats["last_block_seconds_ago"] is not None
        assert stats["last_block_seconds_ago"] < 2.0

    def test_last_block_updated_on_new_block(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.record_blocked(violation_type="secret_detected")
        state.record_blocked(violation_type="prompt_injection")

        stats = state.get_stats()
        assert stats["last_block_type"] == "prompt_injection"

    def test_blocked_without_violation_type(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.record_blocked()

        stats = state.get_stats()
        assert stats["last_block_type"] is None
        assert stats["last_block_seconds_ago"] is not None
        assert stats["critical_count"] == 1


class TestConfigReloadTracking:
    def test_last_reload_set_on_init(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))
        state = DaemonState(config_path=config_path)
        stats = state.get_stats()
        assert stats["last_config_reload_at"] is not None
        assert stats["last_config_reload_seconds_ago"] is not None
        assert stats["last_config_reload_seconds_ago"] < 2.0

    def test_last_reload_none_without_config(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        stats = state.get_stats()
        assert stats["last_config_reload_at"] is None
        assert stats["last_config_reload_seconds_ago"] is None

    def test_last_reload_updates_on_change(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))
        state = DaemonState(config_path=config_path)
        first_reload = state.get_stats()["last_config_reload_at"]

        time.sleep(0.05)
        config_path.write_text(json.dumps({"v": 2}))
        state.get_config()

        second_reload = state.get_stats()["last_config_reload_at"]
        assert second_reload > first_reload

    def test_callback_fires_on_reload(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))
        fired = []
        state = DaemonState(config_path=config_path)
        state._on_config_reloaded = lambda: fired.append(True)

        time.sleep(0.05)
        config_path.write_text(json.dumps({"v": 2}))
        state.get_config()

        assert fired == [True]

    def test_callback_fires_on_force_reload(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))
        fired = []
        state = DaemonState(config_path=config_path)
        state._on_config_reloaded = lambda: fired.append(True)

        state.force_reload_config()
        assert fired == [True]

    def test_callback_not_fired_without_change(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))
        fired = []
        state = DaemonState(config_path=config_path)
        state._on_config_reloaded = lambda: fired.append(True)

        state.get_config()  # no change, no callback
        assert fired == []

    def test_callback_error_does_not_propagate(self, tmp_path):
        config_path = tmp_path / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))
        state = DaemonState(config_path=config_path)
        state._on_config_reloaded = lambda: (_ for _ in ()).throw(RuntimeError("boom"))

        time.sleep(0.05)
        config_path.write_text(json.dumps({"v": 2}))
        state.get_config()  # should not raise


class TestProjectConfigTracking:
    def test_check_project_config_new_dir(self, tmp_path):
        """First time seeing a project dir — records mtime, no callback."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        config_dir = project_dir / ".ai-guardian"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text(json.dumps({"v": 1}))

        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        fired = []
        state._on_config_reloaded = lambda: fired.append(True)

        state.check_project_config(str(project_dir))

        assert fired == []
        stats = state.get_stats()
        assert stats["project_configs_tracked"] == 1

    def test_check_project_config_changed(self, tmp_path):
        """Mtime change triggers callback and updates reload timestamp."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        config_dir = project_dir / ".ai-guardian"
        config_dir.mkdir()
        config_path = config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))

        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        fired = []
        state._on_config_reloaded = lambda: fired.append(True)

        state.check_project_config(str(project_dir))
        assert fired == []

        time.sleep(0.05)
        config_path.write_text(json.dumps({"v": 2}))

        state.check_project_config(str(project_dir))
        assert fired == [True]
        stats = state.get_stats()
        assert stats["last_project_config_reload_at"] is not None
        assert stats["last_project_config_reload_seconds_ago"] < 2.0

    def test_check_project_config_no_file(self, tmp_path):
        """Dir without config file — no crash, no tracking."""
        project_dir = tmp_path / "empty_project"
        project_dir.mkdir()

        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.check_project_config(str(project_dir))

        stats = state.get_stats()
        assert stats["project_configs_tracked"] == 0

    def test_check_project_config_none_dir(self, tmp_path):
        """None dir — no crash."""
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.check_project_config(None)

        stats = state.get_stats()
        assert stats["project_configs_tracked"] == 0

    def test_stats_include_project_fields(self, tmp_path):
        """Stats include project config tracking fields."""
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        stats = state.get_stats()
        assert "last_project_config_reload_at" in stats
        assert "last_project_config_reload_seconds_ago" in stats
        assert "project_configs_tracked" in stats
        assert stats["last_project_config_reload_at"] is None
        assert stats["last_project_config_reload_seconds_ago"] is None
        assert stats["project_configs_tracked"] == 0

    def test_multiple_project_dirs_tracked(self, tmp_path):
        """Multiple project directories tracked independently."""
        state = DaemonState(config_path=tmp_path / "nonexistent.json")

        for i in range(3):
            project_dir = tmp_path / f"project{i}"
            project_dir.mkdir()
            config_dir = project_dir / ".ai-guardian"
            config_dir.mkdir()
            (config_dir / "ai-guardian.json").write_text(
                json.dumps({"project": i})
            )
            state.check_project_config(str(project_dir))

        stats = state.get_stats()
        assert stats["project_configs_tracked"] == 3

    def test_project_config_legacy_location(self, tmp_path):
        """Legacy ai-guardian.json at project root is detected."""
        project_dir = tmp_path / "legacy_project"
        project_dir.mkdir()
        (project_dir / "ai-guardian.json").write_text(json.dumps({"v": 1}))

        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state.check_project_config(str(project_dir))

        assert state.get_stats()["project_configs_tracked"] == 1

    def test_callback_error_does_not_propagate(self, tmp_path):
        """Callback error in check_project_config is swallowed."""
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        config_dir = project_dir / ".ai-guardian"
        config_dir.mkdir()
        config_path = config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({"v": 1}))

        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        state._on_config_reloaded = lambda: (_ for _ in ()).throw(
            RuntimeError("boom")
        )

        state.check_project_config(str(project_dir))
        time.sleep(0.05)
        config_path.write_text(json.dumps({"v": 2}))
        state.check_project_config(str(project_dir))  # should not raise


class TestThreadSafety:
    def test_concurrent_context_access(self, tmp_path):
        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        errors = []

        def writer(thread_id):
            try:
                for i in range(50):
                    state.store_pretooluse_context(
                        f"s{thread_id}", f"t{i}", {"data": f"thread{thread_id}"}
                    )
            except Exception as e:
                errors.append(e)

        def reader(thread_id):
            try:
                for i in range(50):
                    state.get_pretooluse_context(f"s{thread_id}", f"t{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(5):
            threads.append(threading.Thread(target=writer, args=(i,)))
            threads.append(threading.Thread(target=reader, args=(i,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Thread safety errors: {errors}"


class TestSessionPersistence:
    def _make_state(self, tmp_path):
        sessions_file = tmp_path / "daemon_sessions.json"
        return DaemonState(
            config_path=tmp_path / "nonexistent.json",
            sessions_file=sessions_file,
        )

    def test_sessions_persisted_to_file(self, tmp_path):
        state = self._make_state(tmp_path)
        state.mark_security_injected("sess-1")
        state.flush_sessions()

        sessions_file = tmp_path / "daemon_sessions.json"
        assert sessions_file.exists()
        data = json.loads(sessions_file.read_text())
        assert data["version"] == 1
        assert "sess-1" in data["sessions"]
        assert data["sessions"]["sess-1"]["security_injected"] is True
        assert data["sessions"]["sess-1"]["security_reinject"] is False

    def test_sessions_restored_on_init(self, tmp_path):
        sessions_file = tmp_path / "daemon_sessions.json"
        sessions_file.write_text(json.dumps({
            "sessions": {
                "sess-a": {
                    "security_injected": True,
                    "security_reinject": False,
                    "last_activity": time.time(),
                }
            },
            "version": 1,
        }))

        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            sessions_file=sessions_file,
        )
        assert not state.should_inject_security("sess-a")

    def test_sessions_pruned_on_load(self, tmp_path):
        sessions_file = tmp_path / "daemon_sessions.json"
        sessions_file.write_text(json.dumps({
            "sessions": {
                "old-sess": {
                    "security_injected": True,
                    "security_reinject": False,
                    "last_activity": time.time() - 90000,  # >24h ago
                },
                "recent-sess": {
                    "security_injected": True,
                    "security_reinject": False,
                    "last_activity": time.time(),
                },
            },
            "version": 1,
        }))

        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            sessions_file=sessions_file,
        )
        assert state.should_inject_security("old-sess")  # pruned, so True
        assert not state.should_inject_security("recent-sess")  # loaded

    def test_sessions_pruned_on_persist(self, tmp_path):
        state = self._make_state(tmp_path)
        state.mark_security_injected("recent-sess")
        # Manually insert an old entry
        with state._lock:
            state._security_injected_sessions.add("old-sess")
            state._session_last_activity["old-sess"] = time.time() - 90000

        state._sessions_dirty = True
        state.flush_sessions()

        sessions_file = tmp_path / "daemon_sessions.json"
        data = json.loads(sessions_file.read_text())
        assert "recent-sess" in data["sessions"]
        assert "old-sess" not in data["sessions"]

    def test_persist_not_called_immediately(self, tmp_path):
        state = self._make_state(tmp_path)
        state.mark_security_injected("sess-1")
        sessions_file = tmp_path / "daemon_sessions.json"
        assert not sessions_file.exists()  # debounce hasn't fired yet

    def test_flush_forces_write(self, tmp_path):
        state = self._make_state(tmp_path)
        state.mark_security_injected("sess-1")
        state.flush_sessions()

        sessions_file = tmp_path / "daemon_sessions.json"
        assert sessions_file.exists()

    def test_reinject_flag_persisted(self, tmp_path):
        sessions_file = tmp_path / "daemon_sessions.json"
        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            sessions_file=sessions_file,
        )
        state.mark_security_injected("sess-r")
        state.mark_security_reinject("sess-r")
        state.flush_sessions()

        state2 = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            sessions_file=sessions_file,
        )
        assert state2.should_inject_security("sess-r")  # reinject flag

    def test_corrupt_file_handled_gracefully(self, tmp_path):
        sessions_file = tmp_path / "daemon_sessions.json"
        sessions_file.write_text("{invalid json")

        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            sessions_file=sessions_file,
        )
        assert state.should_inject_security("any-session")

    def test_missing_file_handled(self, tmp_path):
        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            sessions_file=tmp_path / "nonexistent_sessions.json",
        )
        assert state.should_inject_security("any-session")

    def test_atomic_write_permissions(self, tmp_path):
        state = self._make_state(tmp_path)
        state.mark_security_injected("sess-perm")
        state.flush_sessions()

        sessions_file = tmp_path / "daemon_sessions.json"
        file_stat = os.stat(sessions_file)
        mode = file_stat.st_mode & 0o777
        assert mode == 0o600
