"""Tests for HookContextManager (cross-hook context passing)."""

import json
import os
import stat
import time
import threading

import pytest

from ai_guardian.hook_context import HookContextManager


class TestTempFileMode:
    """Test HookContextManager with temp file storage (local mode)."""

    def test_save_and_load_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ai_guardian.hook_context.HookContextManager._sanitize_session_id",
            staticmethod(lambda sid: sid),
        )
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "ai-guardian-test.json"

        ctx = {
            "file_path": "/tmp/test.py",
            "tool_name": "Read",
            "scan_results": {"secrets_scanned": True, "secrets_found": False},
        }
        assert mgr.save_pretool_context("toolu_01abc", ctx)
        result = mgr.get_pretool_context("toolu_01abc")
        assert result == ctx

    def test_load_nonexistent_context(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "nonexistent.json"
        assert mgr.get_pretool_context("toolu_missing") is None

    def test_multiple_entries(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "ai-guardian-test.json"

        mgr.save_pretool_context("tool1", {"file_path": "/a.py"})
        mgr.save_pretool_context("tool2", {"file_path": "/b.py"})

        assert mgr.get_pretool_context("tool1")["file_path"] == "/a.py"
        assert mgr.get_pretool_context("tool2")["file_path"] == "/b.py"

    def test_expired_entry_not_returned(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "ai-guardian-test.json"

        # Write an entry with old timestamp
        data = {
            "toolu_old": {
                "context": {"file_path": "/old.py"},
                "timestamp": time.time() - 400,  # older than 5 min TTL
            }
        }
        (tmp_path / "ai-guardian-test.json").write_text(json.dumps(data))

        assert mgr.get_pretool_context("toolu_old") is None

    def test_cleanup_removes_expired(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "ai-guardian-test.json"

        now = time.time()
        data = {
            "old_entry": {"context": {"x": 1}, "timestamp": now - 400},
            "new_entry": {"context": {"x": 2}, "timestamp": now},
        }
        (tmp_path / "ai-guardian-test.json").write_text(json.dumps(data))

        mgr.cleanup(max_age_seconds=300)

        result = json.loads((tmp_path / "ai-guardian-test.json").read_text())
        assert "old_entry" not in result
        assert "new_entry" in result

    def test_cleanup_no_file(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "nonexistent.json"
        mgr.cleanup()  # should not raise

    def test_corrupt_file_handled_gracefully(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "ai-guardian-test.json"
        (tmp_path / "ai-guardian-test.json").write_text("{invalid json")

        assert mgr.get_pretool_context("toolu_01abc") is None
        # Save should overwrite corrupt file
        assert mgr.save_pretool_context("toolu_new", {"data": "ok"})
        assert mgr.get_pretool_context("toolu_new") == {"data": "ok"}

    def test_empty_file_handled(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "ai-guardian-test.json"
        (tmp_path / "ai-guardian-test.json").write_text("")

        assert mgr.get_pretool_context("toolu_01abc") is None

    def test_secure_file_permissions(self, tmp_path):
        # Create a context file in /tmp to test actual permissions
        mgr = HookContextManager(session_id="perm-test-12345")
        # Override to use tmp_path subdir for test isolation
        test_file = tmp_path / "perm-test.json"
        mgr._context_file = test_file

        mgr.save_pretool_context("toolu_01", {"data": "test"})

        file_stat = os.stat(test_file)
        mode = stat.S_IMODE(file_stat.st_mode)
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    def test_overwrite_existing_entry(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "ai-guardian-test.json"

        mgr.save_pretool_context("toolu_01", {"version": 1})
        mgr.save_pretool_context("toolu_01", {"version": 2})

        result = mgr.get_pretool_context("toolu_01")
        assert result["version"] == 2


class TestDaemonMode:
    """Test HookContextManager with DaemonState (daemon mode)."""

    def test_daemon_save_and_load(self, tmp_path):
        from ai_guardian.daemon.state import DaemonState

        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        mgr = HookContextManager(session_id="s1", daemon_state=state)

        ctx = {"file_path": "/test.py", "tool_name": "Read"}
        assert mgr.save_pretool_context("t1", ctx)

        result = mgr.get_pretool_context("t1")
        assert result == ctx

    def test_daemon_nonexistent_context(self, tmp_path):
        from ai_guardian.daemon.state import DaemonState

        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        mgr = HookContextManager(session_id="s1", daemon_state=state)

        assert mgr.get_pretool_context("missing") is None

    def test_daemon_cleanup_delegates(self, tmp_path):
        from ai_guardian.daemon.state import DaemonState

        state = DaemonState(
            config_path=tmp_path / "nonexistent.json",
            context_ttl=0.05,
        )
        mgr = HookContextManager(session_id="s1", daemon_state=state)

        mgr.save_pretool_context("t1", {"data": "old"})
        time.sleep(0.1)
        mgr.save_pretool_context("t2", {"data": "new"})

        mgr.cleanup()

        assert mgr.get_pretool_context("t1") is None
        assert mgr.get_pretool_context("t2") == {"data": "new"}

    def test_no_temp_file_created_in_daemon_mode(self, tmp_path):
        from ai_guardian.daemon.state import DaemonState

        state = DaemonState(config_path=tmp_path / "nonexistent.json")
        mgr = HookContextManager(session_id="s1", daemon_state=state)

        assert mgr._context_file is None
        mgr.save_pretool_context("t1", {"data": "test"})
        # No temp files should exist
        import glob
        assert not glob.glob("/tmp/ai-guardian-s1.json")


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_none_tool_use_id_save(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "test.json"
        assert not mgr.save_pretool_context(None, {"data": "test"})

    def test_none_tool_use_id_load(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "test.json"
        assert mgr.get_pretool_context(None) is None

    def test_empty_string_tool_use_id(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "test.json"
        assert not mgr.save_pretool_context("", {"data": "test"})
        assert mgr.get_pretool_context("") is None

    def test_no_session_id_no_daemon(self):
        mgr = HookContextManager(session_id=None, daemon_state=None)
        assert mgr._context_file is None
        assert not mgr.save_pretool_context("t1", {"data": "test"})
        assert mgr.get_pretool_context("t1") is None

    def test_empty_context_dict(self, tmp_path):
        mgr = HookContextManager(session_id="test-session")
        mgr._context_file = tmp_path / "test.json"
        assert mgr.save_pretool_context("t1", {})
        assert mgr.get_pretool_context("t1") == {}

    def test_sanitize_session_id(self):
        result = HookContextManager._sanitize_session_id("abc-123_def")
        assert result == "abc-123_def"

        result = HookContextManager._sanitize_session_id("../../../etc/passwd")
        assert result == "etcpasswd"

        result = HookContextManager._sanitize_session_id("id with spaces & special!")
        assert result == "idwithspacesspecial"

    def test_concurrent_file_access(self, tmp_path):
        """Test that concurrent save/load doesn't corrupt data."""
        errors = []

        def writer(mgr, thread_id):
            try:
                for i in range(20):
                    mgr.save_pretool_context(
                        f"tool_{thread_id}_{i}",
                        {"thread": thread_id, "index": i},
                    )
            except Exception as e:
                errors.append(e)

        mgr = HookContextManager(session_id="concurrent-test")
        mgr._context_file = tmp_path / "concurrent.json"

        threads = [threading.Thread(target=writer, args=(mgr, i)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Concurrent access errors: {errors}"

        # Verify file is still valid JSON
        data = json.loads((tmp_path / "concurrent.json").read_text())
        assert isinstance(data, dict)
