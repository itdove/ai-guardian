"""
Unit tests for Cursor IDE transcript scanning via SQLite (Issue #936).

Tests reading conversation data from Cursor's state.vscdb database
and feeding it into the transcript scanning pipeline.
"""

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from ai_guardian.scanners.transcript.cursor import (
    CursorTranscriptAdapter,
    _extract_text_from_bubble,
    get_cursor_bubble_ids,
    get_cursor_db_path,
    read_cursor_transcript,
    scan_cursor_transcript_incremental,
)


def _create_test_db(db_path):
    """Create a Cursor-schema SQLite DB for testing."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE cursorDiskKV ("
        "  key TEXT UNIQUE ON CONFLICT REPLACE,"
        "  value BLOB"
        ")"
    )
    conn.execute(
        "CREATE TABLE composerHeaders ("
        "  composerId TEXT PRIMARY KEY,"
        "  workspaceId TEXT,"
        "  createdAt INTEGER,"
        "  lastUpdatedAt INTEGER,"
        "  isArchived INTEGER,"
        "  isSubagent INTEGER,"
        "  recency INTEGER,"
        "  checkpointAt INTEGER,"
        "  value TEXT"
        ")"
    )
    conn.commit()
    return conn


def _insert_bubble(conn, composer_id, bubble_id, bubble_data):
    key = f"bubbleId:{composer_id}:{bubble_id}"
    conn.execute(
        "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
        (key, json.dumps(bubble_data)),
    )
    conn.commit()


COMPOSER_ID = "test-comp-001"


class TestGetCursorDbPath(unittest.TestCase):
    """Test Cursor DB path discovery."""

    def test_env_var_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "state.vscdb")
            sqlite3.connect(db_path).close()
            with mock.patch.dict(os.environ, {"CURSOR_DATA_DIR": tmpdir}):
                result = get_cursor_db_path()
                self.assertEqual(result, db_path)

    def test_env_var_missing_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, {"CURSOR_DATA_DIR": tmpdir}):
                with mock.patch(
                    "ai_guardian.scanners.transcript.cursor.os.path.exists",
                    return_value=False,
                ):
                    result = get_cursor_db_path()
                    self.assertIsNone(result)

    def test_no_env_no_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CURSOR_DATA_DIR", None)
            with mock.patch("os.path.exists", return_value=False):
                result = get_cursor_db_path()
                self.assertIsNone(result)


class TestExtractTextFromBubble(unittest.TestCase):
    """Test text extraction from Cursor bubble JSON blobs."""

    def test_user_text_message(self):
        data = {"type": 1, "text": "Hello world", "bubbleId": "b1"}
        result = _extract_text_from_bubble(data)
        self.assertEqual(result, "Hello world")

    def test_assistant_text_message(self):
        data = {"type": 2, "text": "Here is the answer", "bubbleId": "b2"}
        result = _extract_text_from_bubble(data)
        self.assertEqual(result, "Here is the answer")

    def test_empty_text(self):
        data = {"type": 2, "text": "", "bubbleId": "b3"}
        result = _extract_text_from_bubble(data)
        self.assertEqual(result, "")

    def test_no_text_field(self):
        data = {"type": 2, "bubbleId": "b4"}
        result = _extract_text_from_bubble(data)
        self.assertEqual(result, "")

    def test_tool_output_json(self):
        output = json.dumps({"output": "command result here"})
        data = {
            "type": 2,
            "toolFormerData": {"name": "run_terminal_cmd", "output": output},
        }
        result = _extract_text_from_bubble(data)
        self.assertIn("command result here", result)

    def test_tool_output_string(self):
        data = {
            "type": 2,
            "toolFormerData": {"name": "read_file", "output": "file contents"},
        }
        result = _extract_text_from_bubble(data)
        self.assertIn("file contents", result)

    def test_tool_raw_args_command(self):
        raw_args = json.dumps({"command": "cat /etc/passwd"})
        data = {
            "type": 2,
            "toolFormerData": {"name": "run_terminal_cmd", "rawArgs": raw_args},
        }
        result = _extract_text_from_bubble(data)
        self.assertIn("cat /etc/passwd", result)

    def test_tool_output_with_contents(self):
        output = json.dumps({"contents": "file content from read_file"})
        data = {
            "type": 2,
            "toolFormerData": {"name": "read_file_v2", "output": output},
        }
        result = _extract_text_from_bubble(data)
        self.assertIn("file content from read_file", result)

    def test_text_and_tool_combined(self):
        output = json.dumps({"output": "tool output"})
        data = {
            "type": 2,
            "text": "Let me run this",
            "toolFormerData": {"name": "cmd", "output": output},
        }
        result = _extract_text_from_bubble(data)
        self.assertIn("Let me run this", result)
        self.assertIn("tool output", result)


class TestReadCursorTranscript(unittest.TestCase):
    """Test reading conversation from Cursor SQLite DB."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "state.vscdb")
        self.conn = _create_test_db(self.db_path)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_text_bubbles(self):
        _insert_bubble(self.conn, COMPOSER_ID, "b1", {"type": 1, "text": "Hello"})
        _insert_bubble(self.conn, COMPOSER_ID, "b2", {"type": 2, "text": "World"})

        text, seen = read_cursor_transcript(self.db_path, COMPOSER_ID)
        self.assertIn("Hello", text)
        self.assertIn("World", text)
        self.assertEqual(seen, {"b1", "b2"})

    def test_incremental_read_skips_seen(self):
        _insert_bubble(self.conn, COMPOSER_ID, "b1", {"type": 1, "text": "Old"})
        _insert_bubble(self.conn, COMPOSER_ID, "b2", {"type": 2, "text": "New"})

        text, seen = read_cursor_transcript(
            self.db_path, COMPOSER_ID, seen_bubble_ids={"b1"}
        )
        self.assertNotIn("Old", text)
        self.assertIn("New", text)
        self.assertEqual(seen, {"b1", "b2"})

    def test_empty_conversation(self):
        text, seen = read_cursor_transcript(self.db_path, COMPOSER_ID)
        self.assertEqual(text, "")
        self.assertEqual(seen, set())

    def test_tool_output_extracted(self):
        output = json.dumps({"output": "ls result"})
        _insert_bubble(
            self.conn,
            COMPOSER_ID,
            "b1",
            {
                "type": 2,
                "toolFormerData": {"name": "run_terminal_cmd", "output": output},
            },
        )

        text, seen = read_cursor_transcript(self.db_path, COMPOSER_ID)
        self.assertIn("ls result", text)

    def test_invalid_json_value_skipped(self):
        key = f"bubbleId:{COMPOSER_ID}:bad1"
        self.conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            (key, "not valid json"),
        )
        self.conn.commit()
        _insert_bubble(self.conn, COMPOSER_ID, "b1", {"type": 1, "text": "Good"})

        text, seen = read_cursor_transcript(self.db_path, COMPOSER_ID)
        self.assertIn("Good", text)
        self.assertIn("b1", seen)

    def test_non_dict_value_skipped(self):
        key = f"bubbleId:{COMPOSER_ID}:arr1"
        self.conn.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            (key, json.dumps([1, 2, 3])),
        )
        self.conn.commit()

        text, seen = read_cursor_transcript(self.db_path, COMPOSER_ID)
        self.assertEqual(text, "")

    def test_missing_db_returns_empty(self):
        text, seen = read_cursor_transcript("/nonexistent/state.vscdb", COMPOSER_ID)
        self.assertEqual(text, "")
        self.assertEqual(seen, set())

    def test_different_composer_isolated(self):
        _insert_bubble(self.conn, COMPOSER_ID, "b1", {"type": 1, "text": "Mine"})
        _insert_bubble(self.conn, "other-comp", "b2", {"type": 1, "text": "Theirs"})

        text, seen = read_cursor_transcript(self.db_path, COMPOSER_ID)
        self.assertIn("Mine", text)
        self.assertNotIn("Theirs", text)
        self.assertEqual(seen, {"b1"})


class TestGetCursorBubbleIds(unittest.TestCase):
    """Test getting all bubble IDs for first-scan skip."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "state.vscdb")
        self.conn = _create_test_db(self.db_path)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_returns_all_ids(self):
        _insert_bubble(self.conn, COMPOSER_ID, "b1", {"type": 1, "text": "A"})
        _insert_bubble(self.conn, COMPOSER_ID, "b2", {"type": 2, "text": "B"})
        _insert_bubble(self.conn, COMPOSER_ID, "b3", {"type": 2, "text": "C"})

        ids = get_cursor_bubble_ids(self.db_path, COMPOSER_ID)
        self.assertEqual(ids, {"b1", "b2", "b3"})

    def test_empty_conversation(self):
        ids = get_cursor_bubble_ids(self.db_path, COMPOSER_ID)
        self.assertEqual(ids, set())

    def test_missing_db(self):
        ids = get_cursor_bubble_ids("/nonexistent/state.vscdb", COMPOSER_ID)
        self.assertEqual(ids, set())


class TestScanCursorTranscriptIncremental(unittest.TestCase):
    """Test incremental scanning of Cursor transcripts."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "state.vscdb")
        self.conn = _create_test_db(self.db_path)
        self.state_dir = os.path.join(self.tmpdir, "state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.env_patches = {
            "AI_GUARDIAN_STATE_DIR": self.state_dir,
            "AI_GUARDIAN_CONFIG_DIR": self.state_dir,
        }

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_scan_skips_existing(self):
        _insert_bubble(self.conn, COMPOSER_ID, "b1", {"type": 1, "text": "Old content"})

        with mock.patch.dict(os.environ, self.env_patches):
            warnings = scan_cursor_transcript_incremental(self.db_path, COMPOSER_ID)
            self.assertEqual(warnings, [])

    def test_second_scan_reads_new_bubbles(self):
        _insert_bubble(self.conn, COMPOSER_ID, "b1", {"type": 1, "text": "Hello"})

        with mock.patch.dict(os.environ, self.env_patches):
            scan_cursor_transcript_incremental(self.db_path, COMPOSER_ID)

            _insert_bubble(
                self.conn, COMPOSER_ID, "b2", {"type": 2, "text": "New content"}
            )

            with mock.patch(
                "ai_guardian.scanners.transcript.cursor._scan_transcript_text",
                return_value=["WARNING: test"],
            ) as mock_scan:
                warnings = scan_cursor_transcript_incremental(self.db_path, COMPOSER_ID)
                self.assertEqual(warnings, ["WARNING: test"])
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertIn("New content", call_args[0][0])

    def test_nothing_new_returns_empty(self):
        _insert_bubble(self.conn, COMPOSER_ID, "b1", {"type": 1, "text": "Done"})

        with mock.patch.dict(os.environ, self.env_patches):
            scan_cursor_transcript_incremental(self.db_path, COMPOSER_ID)
            warnings = scan_cursor_transcript_incremental(self.db_path, COMPOSER_ID)
            self.assertEqual(warnings, [])


class TestCursorTranscriptAdapter(unittest.TestCase):
    """Test CursorTranscriptAdapter.can_scan()."""

    def setUp(self):
        self.adapter = CursorTranscriptAdapter()

    def test_can_scan_cursor_adapter(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Cursor IDE"
        result = self.adapter.can_scan({}, mock_hook_adapter)
        self.assertTrue(result)

    def test_cannot_scan_with_transcript_path(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Cursor IDE"
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
        self.assertEqual(self.adapter.name, "Cursor IDE")


if __name__ == "__main__":
    unittest.main()
