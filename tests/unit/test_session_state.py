"""
Tests for SessionStateManager — session-scoped security injection tracking.

Issue #584: Inject security rules on first prompt + after blocks only.
"""

import json
import os
import tempfile
import time
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

from ai_guardian.session_state import (
    SESSION_TTL,
    STATE_FILENAME,
    SessionStateManager,
    derive_session_key,
)


class TestDeriveSessionKey(TestCase):
    """Test session key derivation from hook data."""

    def test_prefers_session_id(self):
        hook_data = {
            "session_id": "sess-123",
            "transcript_path": "/path/to/transcript",
        }
        self.assertEqual(derive_session_key(hook_data), "sess-123")

    def test_falls_back_to_transcript_path(self):
        hook_data = {"transcript_path": "/path/to/transcript"}
        self.assertEqual(derive_session_key(hook_data), "/path/to/transcript")

    def test_falls_back_to_cwd_time_bucket(self):
        hook_data = {}
        key = derive_session_key(hook_data)
        self.assertIn(os.getcwd(), key)
        self.assertIn(":", key)

    def test_empty_session_id_uses_fallback(self):
        hook_data = {"session_id": "", "transcript_path": "/path"}
        self.assertEqual(derive_session_key(hook_data), "/path")


class TestSessionStateManagerLocal(TestCase):
    """Test SessionStateManager in local (file-based) mode."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.patcher = patch(
            "ai_guardian.session_state.get_state_dir",
            return_value=Path(self.tmpdir),
        )
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_prompt_should_inject(self):
        mgr = SessionStateManager()
        self.assertTrue(mgr.should_inject_security("session-1"))

    def test_second_prompt_should_not_inject(self):
        mgr = SessionStateManager()
        self.assertTrue(mgr.should_inject_security("session-1"))
        mgr.mark_security_injected("session-1")
        self.assertFalse(mgr.should_inject_security("session-1"))

    def test_reinject_after_block(self):
        mgr = SessionStateManager()
        mgr.mark_security_injected("session-1")
        self.assertFalse(mgr.should_inject_security("session-1"))

        mgr.mark_security_reinject("session-1")
        self.assertTrue(mgr.should_inject_security("session-1"))

    def test_reinject_cleared_after_injection(self):
        mgr = SessionStateManager()
        mgr.mark_security_injected("session-1")
        mgr.mark_security_reinject("session-1")
        self.assertTrue(mgr.should_inject_security("session-1"))

        mgr.mark_security_injected("session-1")
        self.assertFalse(mgr.should_inject_security("session-1"))

    def test_independent_sessions(self):
        mgr = SessionStateManager()
        mgr.mark_security_injected("session-1")
        self.assertFalse(mgr.should_inject_security("session-1"))
        self.assertTrue(mgr.should_inject_security("session-2"))

    def test_file_persistence_across_instances(self):
        mgr1 = SessionStateManager()
        mgr1.mark_security_injected("session-1")

        mgr2 = SessionStateManager()
        self.assertFalse(mgr2.should_inject_security("session-1"))

    def test_auto_prune_old_sessions(self):
        mgr = SessionStateManager()
        state_file = Path(self.tmpdir) / STATE_FILENAME

        old_data = {
            "sessions": {
                "old-session": {
                    "security_injected": True,
                    "security_reinject": False,
                    "last_activity": time.time() - SESSION_TTL - 100,
                },
                "fresh-session": {
                    "security_injected": True,
                    "security_reinject": False,
                    "last_activity": time.time(),
                },
            }
        }
        state_file.write_text(json.dumps(old_data))

        mgr.mark_security_injected("new-session")

        data = json.loads(state_file.read_text())
        sessions = data["sessions"]
        self.assertNotIn("old-session", sessions)
        self.assertIn("fresh-session", sessions)
        self.assertIn("new-session", sessions)

    def test_empty_session_key_always_injects(self):
        mgr = SessionStateManager()
        self.assertTrue(mgr.should_inject_security(""))

    def test_state_file_created_with_correct_format(self):
        mgr = SessionStateManager()
        mgr.mark_security_injected("test-session")

        state_file = Path(self.tmpdir) / STATE_FILENAME
        data = json.loads(state_file.read_text())
        self.assertIn("sessions", data)
        entry = data["sessions"]["test-session"]
        self.assertTrue(entry["security_injected"])
        self.assertFalse(entry["security_reinject"])
        self.assertIsInstance(entry["last_activity"], float)

    def test_corrupt_file_treated_as_empty(self):
        state_file = Path(self.tmpdir) / STATE_FILENAME
        state_file.write_text("not valid json!!!")

        mgr = SessionStateManager()
        self.assertTrue(mgr.should_inject_security("session-1"))


class TestSessionStateManagerDaemon(TestCase):
    """Test SessionStateManager in daemon (in-memory) mode."""

    def _make_daemon_state(self):
        mock = MagicMock()
        mock.should_inject_security = MagicMock(return_value=True)
        mock.mark_security_injected = MagicMock()
        mock.mark_security_reinject = MagicMock()
        return mock

    def test_delegates_should_inject_to_daemon(self):
        ds = self._make_daemon_state()
        mgr = SessionStateManager(daemon_state=ds)
        mgr.should_inject_security("session-1")
        ds.should_inject_security.assert_called_once_with("session-1")

    def test_delegates_mark_injected_to_daemon(self):
        ds = self._make_daemon_state()
        mgr = SessionStateManager(daemon_state=ds)
        mgr.mark_security_injected("session-1")
        ds.mark_security_injected.assert_called_once_with("session-1")

    def test_delegates_mark_reinject_to_daemon(self):
        ds = self._make_daemon_state()
        mgr = SessionStateManager(daemon_state=ds)
        mgr.mark_security_reinject("session-1")
        ds.mark_security_reinject.assert_called_once_with("session-1")

    def test_no_file_created_in_daemon_mode(self):
        ds = self._make_daemon_state()
        mgr = SessionStateManager(daemon_state=ds)
        self.assertIsNone(mgr._state_file)


class TestDaemonStateSecurityInjection(TestCase):
    """Test DaemonState security injection tracking methods."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        config_path = Path(self.tmpdir) / "ai-guardian.json"
        config_path.write_text("{}")

        from ai_guardian.daemon.state import DaemonState

        self.state = DaemonState(config_path=config_path)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_call_returns_true(self):
        self.assertTrue(self.state.should_inject_security("sess-1"))

    def test_after_mark_injected_returns_false(self):
        self.state.mark_security_injected("sess-1")
        self.assertFalse(self.state.should_inject_security("sess-1"))

    def test_reinject_after_block(self):
        self.state.mark_security_injected("sess-1")
        self.state.mark_security_reinject("sess-1")
        self.assertTrue(self.state.should_inject_security("sess-1"))

    def test_reinject_cleared_by_mark_injected(self):
        self.state.mark_security_injected("sess-1")
        self.state.mark_security_reinject("sess-1")
        self.state.mark_security_injected("sess-1")
        self.assertFalse(self.state.should_inject_security("sess-1"))

    def test_independent_sessions(self):
        self.state.mark_security_injected("sess-1")
        self.assertFalse(self.state.should_inject_security("sess-1"))
        self.assertTrue(self.state.should_inject_security("sess-2"))

    def test_empty_key_always_injects(self):
        self.assertTrue(self.state.should_inject_security(""))
        self.state.mark_security_injected("")
        self.assertTrue(self.state.should_inject_security(""))
