"""
Unit tests for Cline / ZooCode transcript scanning via JSON array files (Issue #937).

Tests reading conversation data from Cline's per-task
api_conversation_history.json files and feeding it into the transcript
scanning pipeline.
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from ai_guardian.scanners.transcript.cline import (
    ClineTranscriptAdapter,
    _extract_text_from_cline_message,
    get_cline_storage_dir,
    get_most_recent_task_dir,
    read_cline_task_transcript,
    scan_cline_transcript_incremental,
)


def _create_task_dir(base_dir, task_id, messages=None):
    """Create a Cline task directory with an api_conversation_history.json file."""
    task_dir = os.path.join(base_dir, task_id)
    os.makedirs(task_dir, exist_ok=True)
    history = os.path.join(task_dir, "api_conversation_history.json")
    with open(history, "w", encoding="utf-8") as f:
        json.dump(messages or [], f)
    return task_dir


TASK_ID = "test-task-001"


class TestGetClineStorageDir(unittest.TestCase):
    """Test Cline storage directory discovery."""

    def test_env_var_override_with_tasks_subdir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks_dir = os.path.join(tmpdir, "tasks")
            os.makedirs(tasks_dir)
            with mock.patch.dict(os.environ, {"CLINE_STORAGE_DIR": tmpdir}):
                result = get_cline_storage_dir()
                self.assertEqual(result, tasks_dir)

    def test_env_var_override_pointing_to_tasks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks_dir = os.path.join(tmpdir, "tasks")
            os.makedirs(tasks_dir)
            with mock.patch.dict(os.environ, {"CLINE_STORAGE_DIR": tasks_dir}):
                result = get_cline_storage_dir()
                self.assertEqual(result, tasks_dir)

    def test_env_var_missing_dir(self):
        with mock.patch.dict(os.environ, {"CLINE_STORAGE_DIR": "/nonexistent/path"}):
            result = get_cline_storage_dir()
            self.assertIsNone(result)

    def test_no_env_no_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLINE_STORAGE_DIR", None)
            with mock.patch(
                "ai_guardian.scanners.transcript.cline.os.path.isdir",
                return_value=False,
            ):
                result = get_cline_storage_dir()
                self.assertIsNone(result)


class TestExtractTextFromClineMessage(unittest.TestCase):
    """Test text extraction from Cline message objects."""

    def test_string_content(self):
        msg = {"role": "user", "content": "Hello world"}
        self.assertEqual(_extract_text_from_cline_message(msg), "Hello world")

    def test_text_block_content(self):
        msg = {
            "role": "user",
            "content": [{"type": "text", "text": "Hello from block"}],
        }
        self.assertEqual(_extract_text_from_cline_message(msg), "Hello from block")

    def test_multiple_text_blocks(self):
        msg = {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "First"},
                {"type": "text", "text": "Second"},
            ],
        }
        result = _extract_text_from_cline_message(msg)
        self.assertIn("First", result)
        self.assertIn("Second", result)

    def test_tool_result_string_content(self):
        msg = {
            "role": "user",
            "content": [{"type": "tool_result", "content": "command output here"}],
        }
        self.assertEqual(_extract_text_from_cline_message(msg), "command output here")

    def test_tool_result_nested_content(self):
        msg = {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "content": [{"type": "text", "text": "nested output"}],
                }
            ],
        }
        self.assertEqual(_extract_text_from_cline_message(msg), "nested output")

    def test_tool_use_input_command(self):
        msg = {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "name": "execute_command",
                    "input": {"command": "ls -la"},
                },
            ],
        }
        self.assertEqual(_extract_text_from_cline_message(msg), "ls -la")

    def test_tool_use_input_content(self):
        msg = {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "name": "write_file",
                    "input": {"content": "file data"},
                },
            ],
        }
        self.assertEqual(_extract_text_from_cline_message(msg), "file data")

    def test_empty_content_list(self):
        msg = {"role": "user", "content": []}
        self.assertEqual(_extract_text_from_cline_message(msg), "")

    def test_no_content_field(self):
        msg = {"role": "user"}
        self.assertEqual(_extract_text_from_cline_message(msg), "")

    def test_none_content(self):
        msg = {"role": "user", "content": None}
        self.assertEqual(_extract_text_from_cline_message(msg), "")

    def test_mixed_blocks(self):
        msg = {
            "role": "user",
            "content": [
                {"type": "text", "text": "Here is the result"},
                {"type": "tool_result", "content": "tool output"},
            ],
        }
        result = _extract_text_from_cline_message(msg)
        self.assertIn("Here is the result", result)
        self.assertIn("tool output", result)

    def test_non_dict_blocks_skipped(self):
        msg = {
            "role": "user",
            "content": ["plain string", {"type": "text", "text": "OK"}],
        }
        self.assertEqual(_extract_text_from_cline_message(msg), "OK")


class TestReadClineTaskTranscript(unittest.TestCase):
    """Test reading conversation from Cline task JSON files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_all_messages(self):
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "World"},
        ]
        task_dir = _create_task_dir(self.tmpdir, TASK_ID, messages)

        text, count = read_cline_task_transcript(task_dir)
        self.assertIn("Hello", text)
        self.assertIn("World", text)
        self.assertEqual(count, 2)

    def test_incremental_read_skips_seen(self):
        messages = [
            {"role": "user", "content": "Old message"},
            {"role": "assistant", "content": "New message"},
        ]
        task_dir = _create_task_dir(self.tmpdir, TASK_ID, messages)

        text, count = read_cline_task_transcript(task_dir, seen_count=1)
        self.assertNotIn("Old message", text)
        self.assertIn("New message", text)
        self.assertEqual(count, 2)

    def test_empty_conversation(self):
        task_dir = _create_task_dir(self.tmpdir, TASK_ID, [])
        text, count = read_cline_task_transcript(task_dir)
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_file_not_found(self):
        text, count = read_cline_task_transcript("/nonexistent/task")
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_invalid_json(self):
        task_dir = os.path.join(self.tmpdir, TASK_ID)
        os.makedirs(task_dir)
        with open(os.path.join(task_dir, "api_conversation_history.json"), "w") as f:
            f.write("not valid json{{{")

        text, count = read_cline_task_transcript(task_dir)
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_non_array_json(self):
        task_dir = os.path.join(self.tmpdir, TASK_ID)
        os.makedirs(task_dir)
        with open(os.path.join(task_dir, "api_conversation_history.json"), "w") as f:
            json.dump({"not": "an array"}, f)

        text, count = read_cline_task_transcript(task_dir)
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_truncated_file_resets(self):
        messages = [
            {"role": "user", "content": "Only one"},
        ]
        task_dir = _create_task_dir(self.tmpdir, TASK_ID, messages)

        text, count = read_cline_task_transcript(task_dir, seen_count=5)
        self.assertIn("Only one", text)
        self.assertEqual(count, 1)

    def test_nothing_new(self):
        messages = [{"role": "user", "content": "Done"}]
        task_dir = _create_task_dir(self.tmpdir, TASK_ID, messages)

        text, count = read_cline_task_transcript(task_dir, seen_count=1)
        self.assertEqual(text, "")
        self.assertEqual(count, 1)

    def test_non_dict_messages_skipped(self):
        task_dir = os.path.join(self.tmpdir, TASK_ID)
        os.makedirs(task_dir)
        with open(os.path.join(task_dir, "api_conversation_history.json"), "w") as f:
            json.dump(["plain string", {"role": "user", "content": "Valid"}], f)

        text, count = read_cline_task_transcript(task_dir)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)


class TestGetMostRecentTaskDir(unittest.TestCase):
    """Test most-recent task directory discovery."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_returns_most_recent(self):
        _create_task_dir(self.tmpdir, "old-task", [{"role": "user", "content": "Old"}])
        time.sleep(0.05)
        _create_task_dir(self.tmpdir, "new-task", [{"role": "user", "content": "New"}])

        result = get_most_recent_task_dir(self.tmpdir)
        self.assertIsNotNone(result)
        self.assertIn("new-task", result)

    def test_no_task_dirs(self):
        result = get_most_recent_task_dir(self.tmpdir)
        self.assertIsNone(result)

    def test_task_without_json(self):
        os.makedirs(os.path.join(self.tmpdir, "empty-task"))
        result = get_most_recent_task_dir(self.tmpdir)
        self.assertIsNone(result)

    def test_nonexistent_storage_dir(self):
        result = get_most_recent_task_dir("/nonexistent/storage")
        self.assertIsNone(result)


class TestScanClineTranscriptIncremental(unittest.TestCase):
    """Test incremental scanning of Cline transcripts."""

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
        messages = [{"role": "user", "content": "Old content"}]
        task_dir = _create_task_dir(self.tmpdir, TASK_ID, messages)

        with mock.patch.dict(os.environ, self.env_patches):
            warnings = scan_cline_transcript_incremental(task_dir)
            self.assertEqual(warnings, [])

    def test_second_scan_reads_new_messages(self):
        messages = [{"role": "user", "content": "Hello"}]
        task_dir = _create_task_dir(self.tmpdir, TASK_ID, messages)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_cline_transcript_incremental(task_dir)

            messages.append({"role": "assistant", "content": "New content"})
            with open(
                os.path.join(task_dir, "api_conversation_history.json"), "w"
            ) as f:
                json.dump(messages, f)

            with mock.patch(
                "ai_guardian.scanners.transcript.cline._scan_transcript_text",
                return_value=["WARNING: test"],
            ) as mock_scan:
                warnings = scan_cline_transcript_incremental(task_dir)
                self.assertEqual(warnings, ["WARNING: test"])
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertIn("New content", call_args[0][0])

    def test_nothing_new_returns_empty(self):
        messages = [{"role": "user", "content": "Done"}]
        task_dir = _create_task_dir(self.tmpdir, TASK_ID, messages)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_cline_transcript_incremental(task_dir)
            warnings = scan_cline_transcript_incremental(task_dir)
            self.assertEqual(warnings, [])


class TestClineTranscriptAdapter(unittest.TestCase):
    """Test ClineTranscriptAdapter.can_scan()."""

    def setUp(self):
        self.adapter = ClineTranscriptAdapter()

    def test_can_scan_cline_adapter(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Cline"
        result = self.adapter.can_scan({}, mock_hook_adapter)
        self.assertTrue(result)

    def test_cannot_scan_with_transcript_path(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Cline"
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
        self.assertEqual(self.adapter.name, "Cline")


if __name__ == "__main__":
    unittest.main()
