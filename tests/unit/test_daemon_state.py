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
