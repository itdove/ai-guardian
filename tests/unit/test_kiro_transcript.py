"""
Unit tests for Kiro transcript scanning via JSONL session files (Issue #939).

Tests reading conversation data from Kiro's per-session
JSONL files and feeding it into the transcript scanning pipeline.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from ai_guardian.scanners.transcript.kiro import (
    KiroTranscriptAdapter,
    _extract_text_from_kiro_entry,
    get_kiro_sessions_dir,
    get_most_recent_session_file,
    read_kiro_transcript,
    scan_kiro_transcript_incremental,
)


def _write_jsonl(path, entries):
    """Write a list of entry dicts as a JSONL file."""
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


SESSION_ID = "f2946a26-3735-4b08-8d05-c928010302d5"


class TestGetKiroSessionsDir(unittest.TestCase):
    """Test Kiro sessions directory discovery."""

    def test_env_var_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, {"KIRO_SESSIONS_DIR": tmpdir}):
                result = get_kiro_sessions_dir()
                self.assertEqual(result, tmpdir)

    def test_env_var_missing_dir(self):
        with mock.patch.dict(os.environ, {"KIRO_SESSIONS_DIR": "/nonexistent/path"}):
            result = get_kiro_sessions_dir()
            self.assertIsNone(result)

    def test_no_env_uses_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            default_path = os.path.join(tmpdir, ".kiro", "sessions", "cli")
            os.makedirs(default_path)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("KIRO_SESSIONS_DIR", None)
                with mock.patch(
                    "ai_guardian.scanners.transcript.kiro.os.path.expanduser",
                    return_value=default_path,
                ):
                    result = get_kiro_sessions_dir()
                    self.assertEqual(result, default_path)

    def test_no_env_no_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KIRO_SESSIONS_DIR", None)
            with mock.patch(
                "ai_guardian.scanners.transcript.kiro.os.path.isdir",
                return_value=False,
            ):
                result = get_kiro_sessions_dir()
                self.assertIsNone(result)


class TestExtractTextFromKiroEntry(unittest.TestCase):
    """Test text extraction from Kiro JSONL entry objects."""

    def test_user_message(self):
        entry = {
            "type": "user_message",
            "session_id": "abc-123",
            "timestamp": "2025-07-01T10:00:00Z",
            "content": "create a hello world file",
        }
        self.assertEqual(
            _extract_text_from_kiro_entry(entry), "create a hello world file"
        )

    def test_agent_message_chunk(self):
        entry = {
            "type": "agent_message_chunk",
            "chunk_index": 0,
            "content": "I'll create that file for you.",
            "message_id": "msg_01",
        }
        self.assertEqual(
            _extract_text_from_kiro_entry(entry),
            "I'll create that file for you.",
        )

    def test_tool_call_with_dict_arguments(self):
        entry = {
            "type": "tool_call",
            "tool_name": "read_file",
            "arguments": {"path": "src/index.ts", "content": "hello world"},
            "tool_call_id": "tc_001",
        }
        result = _extract_text_from_kiro_entry(entry)
        self.assertIn("hello world", result)
        self.assertIn("src/index.ts", result)

    def test_tool_call_with_command_arg(self):
        entry = {
            "type": "tool_call",
            "tool_name": "run_command",
            "arguments": {"command": "ls -la"},
            "tool_call_id": "tc_002",
        }
        self.assertEqual(_extract_text_from_kiro_entry(entry), "ls -la")

    def test_tool_call_with_string_arguments(self):
        entry = {
            "type": "tool_call",
            "tool_name": "bash",
            "arguments": "echo hello",
            "tool_call_id": "tc_003",
        }
        self.assertEqual(_extract_text_from_kiro_entry(entry), "echo hello")

    def test_tool_call_no_arguments(self):
        entry = {
            "type": "tool_call",
            "tool_name": "list_files",
            "tool_call_id": "tc_004",
        }
        self.assertEqual(_extract_text_from_kiro_entry(entry), "")

    def test_tool_result_with_content(self):
        entry = {
            "type": "tool_result",
            "tool_call_id": "tc_001",
            "content": "file contents here",
        }
        self.assertEqual(_extract_text_from_kiro_entry(entry), "file contents here")

    def test_tool_result_with_output(self):
        entry = {
            "type": "tool_result",
            "tool_call_id": "tc_002",
            "output": "total 42\ndrwxr-xr-x ...",
        }
        self.assertEqual(
            _extract_text_from_kiro_entry(entry), "total 42\ndrwxr-xr-x ..."
        )

    def test_tool_result_content_preferred_over_output(self):
        entry = {
            "type": "tool_result",
            "tool_call_id": "tc_001",
            "content": "primary",
            "output": "secondary",
        }
        self.assertEqual(_extract_text_from_kiro_entry(entry), "primary")

    def test_tool_result_empty(self):
        entry = {"type": "tool_result", "tool_call_id": "tc_005"}
        self.assertEqual(_extract_text_from_kiro_entry(entry), "")

    def test_unknown_type_with_content(self):
        entry = {"type": "system_event", "content": "session started"}
        self.assertEqual(_extract_text_from_kiro_entry(entry), "session started")

    def test_unknown_type_no_content(self):
        entry = {"type": "system_event", "data": {"key": "value"}}
        self.assertEqual(_extract_text_from_kiro_entry(entry), "")

    def test_missing_type(self):
        entry = {"content": "no type field"}
        self.assertEqual(_extract_text_from_kiro_entry(entry), "")

    def test_non_string_type(self):
        entry = {"type": 42}
        self.assertEqual(_extract_text_from_kiro_entry(entry), "")

    def test_non_string_content(self):
        entry = {"type": "user_message", "content": 42}
        self.assertEqual(_extract_text_from_kiro_entry(entry), "")


class TestGetMostRecentSessionFile(unittest.TestCase):
    """Test finding the most recently modified session file."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_finds_most_recent(self):
        old_path = os.path.join(self.tmpdir, "old-session.jsonl")
        new_path = os.path.join(self.tmpdir, "new-session.jsonl")
        _write_jsonl(old_path, [{"type": "user_message", "content": "old"}])
        import time

        time.sleep(0.05)
        _write_jsonl(new_path, [{"type": "user_message", "content": "new"}])

        result = get_most_recent_session_file(self.tmpdir)
        self.assertEqual(result, new_path)

    def test_ignores_non_jsonl_files(self):
        json_path = os.path.join(self.tmpdir, "session.json")
        with open(json_path, "w") as f:
            f.write("{}")

        result = get_most_recent_session_file(self.tmpdir)
        self.assertIsNone(result)

    def test_empty_directory(self):
        result = get_most_recent_session_file(self.tmpdir)
        self.assertIsNone(result)

    def test_nonexistent_directory(self):
        result = get_most_recent_session_file("/nonexistent/dir")
        self.assertIsNone(result)


class TestReadKiroTranscript(unittest.TestCase):
    """Test reading conversation from Kiro JSONL files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_all_lines(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [
            {"type": "user_message", "content": "Hello"},
            {"type": "agent_message_chunk", "content": "World"},
        ]
        _write_jsonl(path, entries)

        text, count = read_kiro_transcript(path)
        self.assertIn("Hello", text)
        self.assertIn("World", text)
        self.assertEqual(count, 2)

    def test_incremental_read_skips_seen(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [
            {"type": "user_message", "content": "Old"},
            {"type": "user_message", "content": "New"},
        ]
        _write_jsonl(path, entries)

        text, count = read_kiro_transcript(path, seen_count=1)
        self.assertNotIn("Old", text)
        self.assertIn("New", text)
        self.assertEqual(count, 2)

    def test_empty_file(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        with open(path, "w") as f:
            f.write("")

        text, count = read_kiro_transcript(path)
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_file_not_found(self):
        text, count = read_kiro_transcript("/nonexistent/session.jsonl")
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_malformed_json_lines_skipped(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        with open(path, "w") as f:
            f.write("not valid json\n")
            f.write(json.dumps({"type": "user_message", "content": "Valid"}) + "\n")

        text, count = read_kiro_transcript(path)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)

    def test_truncated_file_resets(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [{"type": "user_message", "content": "Only"}]
        _write_jsonl(path, entries)

        text, count = read_kiro_transcript(path, seen_count=5)
        self.assertIn("Only", text)
        self.assertEqual(count, 1)

    def test_nothing_new(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [{"type": "user_message", "content": "Done"}]
        _write_jsonl(path, entries)

        text, count = read_kiro_transcript(path, seen_count=1)
        self.assertEqual(text, "")
        self.assertEqual(count, 1)

    def test_non_dict_lines_skipped(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        with open(path, "w") as f:
            f.write('"just a string"\n')
            f.write(json.dumps({"type": "user_message", "content": "Valid"}) + "\n")

        text, count = read_kiro_transcript(path)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)


class TestScanKiroTranscriptIncremental(unittest.TestCase):
    """Test incremental scanning of Kiro transcripts."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_dir = os.path.join(self.tmpdir, "state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.env_patches = {
            "AI_GUARDIAN_STATE_DIR": self.state_dir,
            "AI_GUARDIAN_CONFIG_DIR": self.state_dir,
        }

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_scan_skips_existing(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [{"type": "user_message", "content": "Old content"}]
        _write_jsonl(path, entries)

        with mock.patch.dict(os.environ, self.env_patches):
            warnings = scan_kiro_transcript_incremental(path, SESSION_ID)
            self.assertEqual(warnings, [])

    def test_second_scan_reads_new_lines(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [{"type": "user_message", "content": "Hello"}]
        _write_jsonl(path, entries)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_kiro_transcript_incremental(path, SESSION_ID)

            entries.append({"type": "agent_message_chunk", "content": "New content"})
            _write_jsonl(path, entries)

            with mock.patch(
                "ai_guardian.scanners.transcript.kiro._scan_transcript_text",
                return_value=["WARNING: test"],
            ) as mock_scan:
                warnings = scan_kiro_transcript_incremental(path, SESSION_ID)
                self.assertEqual(warnings, ["WARNING: test"])
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertIn("New content", call_args[0][0])

    def test_nothing_new_returns_empty(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [{"type": "user_message", "content": "Done"}]
        _write_jsonl(path, entries)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_kiro_transcript_incremental(path, SESSION_ID)
            warnings = scan_kiro_transcript_incremental(path, SESSION_ID)
            self.assertEqual(warnings, [])


class TestKiroTranscriptAdapter(unittest.TestCase):
    """Test KiroTranscriptAdapter.can_scan() and scan_incremental()."""

    def setUp(self):
        self.adapter = KiroTranscriptAdapter()

    def test_can_scan_kiro_adapter(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Kiro"
        result = self.adapter.can_scan({}, mock_hook_adapter)
        self.assertTrue(result)

    def test_cannot_scan_with_transcript_path(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Kiro"
        result = self.adapter.can_scan(
            {"transcript_path": "/some/file.jsonl"}, mock_hook_adapter
        )
        self.assertFalse(result)

    def test_cannot_scan_other_adapter(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Claude Code"
        result = self.adapter.can_scan({}, mock_hook_adapter)
        self.assertFalse(result)

    def test_cannot_scan_no_adapter(self):
        result = self.adapter.can_scan({}, None)
        self.assertFalse(result)

    def test_name(self):
        self.assertEqual(self.adapter.name, "Kiro")

    def test_scan_incremental_no_dir(self):
        with mock.patch(
            "ai_guardian.scanners.transcript.kiro.get_kiro_sessions_dir",
            return_value=None,
        ):
            result = self.adapter.scan_incremental({})
            self.assertEqual(result, [])

    def test_scan_incremental_no_session_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch(
                "ai_guardian.scanners.transcript.kiro.get_kiro_sessions_dir",
                return_value=tmpdir,
            ):
                result = self.adapter.scan_incremental({})
                self.assertEqual(result, [])

    def test_scan_incremental_uses_session_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, f"{SESSION_ID}.jsonl")
            _write_jsonl(path, [{"type": "user_message", "content": "test"}])

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.kiro.get_kiro_sessions_dir",
                    return_value=tmpdir,
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.kiro.scan_kiro_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({"session_id": SESSION_ID})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][0], path)
                self.assertEqual(mock_scan.call_args[0][1], SESSION_ID)

    def test_scan_incremental_falls_back_to_most_recent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "some-session.jsonl")
            _write_jsonl(path, [{"type": "user_message", "content": "test"}])

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.kiro.get_kiro_sessions_dir",
                    return_value=tmpdir,
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.kiro.scan_kiro_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][0], path)
                self.assertEqual(mock_scan.call_args[0][1], "some-session")

    def test_scan_incremental_session_id_file_not_found_falls_back(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fallback_path = os.path.join(tmpdir, "fallback.jsonl")
            _write_jsonl(fallback_path, [{"type": "user_message", "content": "test"}])

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.kiro.get_kiro_sessions_dir",
                    return_value=tmpdir,
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.kiro.scan_kiro_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({"session_id": "nonexistent-id"})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][0], fallback_path)


if __name__ == "__main__":
    unittest.main()
