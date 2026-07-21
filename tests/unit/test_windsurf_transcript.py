"""
Unit tests for Windsurf transcript scanning via JSONL step files (Issue #938).

Tests reading conversation data from Windsurf's per-trajectory
JSONL files and feeding it into the transcript scanning pipeline.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from ai_guardian.scanners.transcript.windsurf import (
    WindsurfTranscriptAdapter,
    _extract_text_from_windsurf_step,
    get_windsurf_transcripts_dir,
    read_windsurf_transcript,
    scan_windsurf_transcript_incremental,
)
from tests.unit.transcript_helpers import write_jsonl as _write_jsonl

TRAJECTORY_ID = "test-trajectory-001"


class TestGetWindsurfTranscriptsDir(unittest.TestCase):
    """Test Windsurf transcripts directory discovery."""

    def test_env_var_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, {"WINDSURF_TRANSCRIPTS_DIR": tmpdir}):
                result = get_windsurf_transcripts_dir()
                self.assertEqual(result, tmpdir)

    def test_env_var_missing_dir(self):
        with mock.patch.dict(
            os.environ, {"WINDSURF_TRANSCRIPTS_DIR": "/nonexistent/path"}
        ):
            result = get_windsurf_transcripts_dir()
            self.assertIsNone(result)

    def test_no_env_uses_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            default_path = os.path.join(tmpdir, ".windsurf", "transcripts")
            os.makedirs(default_path)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("WINDSURF_TRANSCRIPTS_DIR", None)
                with mock.patch(
                    "ai_guardian.scanners.transcript.windsurf.os.path.expanduser",
                    return_value=default_path,
                ):
                    result = get_windsurf_transcripts_dir()
                    self.assertEqual(result, default_path)

    def test_no_env_no_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WINDSURF_TRANSCRIPTS_DIR", None)
            with mock.patch(
                "ai_guardian.scanners.transcript.windsurf.os.path.isdir",
                return_value=False,
            ):
                result = get_windsurf_transcripts_dir()
                self.assertIsNone(result)


class TestExtractTextFromWindsurfStep(unittest.TestCase):
    """Test text extraction from Windsurf JSONL step objects."""

    def test_user_input(self):
        step = {
            "status": "done",
            "type": "user_input",
            "user_input": {"user_response": "create a hello world file"},
        }
        self.assertEqual(
            _extract_text_from_windsurf_step(step), "create a hello world file"
        )

    def test_planner_response(self):
        step = {
            "status": "done",
            "type": "planner_response",
            "planner_response": {"response": "I'll create that file for you."},
        }
        self.assertEqual(
            _extract_text_from_windsurf_step(step),
            "I'll create that file for you.",
        )

    def test_code_action(self):
        step = {
            "status": "done",
            "type": "code_action",
            "code_action": {
                "new_content": "print('hello world')\n",
                "path": "/path/to/file.py",
            },
        }
        self.assertEqual(
            _extract_text_from_windsurf_step(step), "print('hello world')\n"
        )

    def test_unknown_type_walks_values(self):
        step = {
            "status": "done",
            "type": "run_command",
            "run_command": {
                "command_line": "ls -la",
                "output": "total 42",
            },
        }
        result = _extract_text_from_windsurf_step(step)
        self.assertIn("ls -la", result)
        self.assertIn("total 42", result)

    def test_missing_type(self):
        step = {"status": "done"}
        self.assertEqual(_extract_text_from_windsurf_step(step), "")

    def test_non_string_type(self):
        step = {"type": 42}
        self.assertEqual(_extract_text_from_windsurf_step(step), "")

    def test_missing_type_data(self):
        step = {"type": "user_input"}
        self.assertEqual(_extract_text_from_windsurf_step(step), "")

    def test_type_data_not_dict(self):
        step = {"type": "user_input", "user_input": "just a string"}
        self.assertEqual(_extract_text_from_windsurf_step(step), "")

    def test_missing_expected_field(self):
        step = {
            "type": "user_input",
            "user_input": {"rules_applied": {"always_on": ["rule.md"]}},
        }
        self.assertEqual(_extract_text_from_windsurf_step(step), "")

    def test_non_string_field_value(self):
        step = {
            "type": "user_input",
            "user_input": {"user_response": 42},
        }
        self.assertEqual(_extract_text_from_windsurf_step(step), "")


class TestReadWindsurfTranscript(unittest.TestCase):
    """Test reading conversation from Windsurf JSONL files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_all_lines(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        steps = [
            {"type": "user_input", "user_input": {"user_response": "Hello"}},
            {
                "type": "planner_response",
                "planner_response": {"response": "World"},
            },
        ]
        _write_jsonl(path, steps)

        text, count = read_windsurf_transcript(path)
        self.assertIn("Hello", text)
        self.assertIn("World", text)
        self.assertEqual(count, 2)

    def test_incremental_read_skips_seen(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        steps = [
            {"type": "user_input", "user_input": {"user_response": "Old"}},
            {"type": "user_input", "user_input": {"user_response": "New"}},
        ]
        _write_jsonl(path, steps)

        text, count = read_windsurf_transcript(path, seen_count=1)
        self.assertNotIn("Old", text)
        self.assertIn("New", text)
        self.assertEqual(count, 2)

    def test_empty_file(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        with open(path, "w") as f:
            f.write("")

        text, count = read_windsurf_transcript(path)
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_file_not_found(self):
        text, count = read_windsurf_transcript("/nonexistent/transcript.jsonl")
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_malformed_json_lines_skipped(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        with open(path, "w") as f:
            f.write("not valid json\n")
            f.write(
                json.dumps(
                    {
                        "type": "user_input",
                        "user_input": {"user_response": "Valid"},
                    }
                )
                + "\n"
            )

        text, count = read_windsurf_transcript(path)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)

    def test_truncated_file_resets(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        steps = [
            {"type": "user_input", "user_input": {"user_response": "Only"}},
        ]
        _write_jsonl(path, steps)

        text, count = read_windsurf_transcript(path, seen_count=5)
        self.assertIn("Only", text)
        self.assertEqual(count, 1)

    def test_nothing_new(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        steps = [
            {"type": "user_input", "user_input": {"user_response": "Done"}},
        ]
        _write_jsonl(path, steps)

        text, count = read_windsurf_transcript(path, seen_count=1)
        self.assertEqual(text, "")
        self.assertEqual(count, 1)

    def test_non_dict_lines_skipped(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        with open(path, "w") as f:
            f.write('"just a string"\n')
            f.write(
                json.dumps(
                    {
                        "type": "user_input",
                        "user_input": {"user_response": "Valid"},
                    }
                )
                + "\n"
            )

        text, count = read_windsurf_transcript(path)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)


class TestScanWindsurfTranscriptIncremental(unittest.TestCase):
    """Test incremental scanning of Windsurf transcripts."""

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
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        steps = [
            {"type": "user_input", "user_input": {"user_response": "Old content"}},
        ]
        _write_jsonl(path, steps)

        with mock.patch.dict(os.environ, self.env_patches):
            warnings = scan_windsurf_transcript_incremental(path, TRAJECTORY_ID)
            self.assertEqual(warnings, [])

    def test_second_scan_reads_new_lines(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        steps = [
            {"type": "user_input", "user_input": {"user_response": "Hello"}},
        ]
        _write_jsonl(path, steps)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_windsurf_transcript_incremental(path, TRAJECTORY_ID)

            steps.append(
                {
                    "type": "planner_response",
                    "planner_response": {"response": "New content"},
                }
            )
            _write_jsonl(path, steps)

            with mock.patch(
                "ai_guardian.scanners.transcript.common._scan_transcript_text",
                return_value=["WARNING: test"],
            ) as mock_scan:
                warnings = scan_windsurf_transcript_incremental(path, TRAJECTORY_ID)
                self.assertEqual(warnings, ["WARNING: test"])
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertIn("New content", call_args[0][0])

    def test_nothing_new_returns_empty(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        steps = [
            {"type": "user_input", "user_input": {"user_response": "Done"}},
        ]
        _write_jsonl(path, steps)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_windsurf_transcript_incremental(path, TRAJECTORY_ID)
            warnings = scan_windsurf_transcript_incremental(path, TRAJECTORY_ID)
            self.assertEqual(warnings, [])


class TestWindsurfTranscriptAdapter(unittest.TestCase):
    """Test WindsurfTranscriptAdapter.can_scan()."""

    def setUp(self):
        self.adapter = WindsurfTranscriptAdapter()

    def test_can_scan_windsurf_adapter(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Windsurf"
        result = self.adapter.can_scan({}, mock_hook_adapter)
        self.assertTrue(result)

    def test_cannot_scan_with_transcript_path(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "Windsurf"
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
        self.assertEqual(self.adapter.name, "Windsurf")

    def test_scan_incremental_no_dir(self):
        with mock.patch(
            "ai_guardian.scanners.transcript.windsurf.get_windsurf_transcripts_dir",
            return_value=None,
        ):
            result = self.adapter.scan_incremental({})
            self.assertEqual(result, [])

    def test_scan_incremental_no_trajectory_id(self):
        with mock.patch(
            "ai_guardian.scanners.transcript.windsurf.get_windsurf_transcripts_dir",
            return_value="/tmp/transcripts",
        ):
            result = self.adapter.scan_incremental({})
            self.assertEqual(result, [])

    def test_scan_incremental_file_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch(
                "ai_guardian.scanners.transcript.windsurf.get_windsurf_transcripts_dir",
                return_value=tmpdir,
            ):
                result = self.adapter.scan_incremental({"trajectory_id": "nonexistent"})
                self.assertEqual(result, [])

    def test_scan_incremental_uses_trajectory_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, f"{TRAJECTORY_ID}.jsonl")
            _write_jsonl(
                path,
                [
                    {
                        "type": "user_input",
                        "user_input": {"user_response": "test"},
                    }
                ],
            )

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.windsurf.get_windsurf_transcripts_dir",
                    return_value=tmpdir,
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.windsurf.scan_windsurf_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({"trajectory_id": TRAJECTORY_ID})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][0], path)
                self.assertEqual(mock_scan.call_args[0][1], TRAJECTORY_ID)

    def test_scan_incremental_falls_back_to_session_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sid = "session-fallback-id"
            path = os.path.join(tmpdir, f"{sid}.jsonl")
            _write_jsonl(
                path,
                [
                    {
                        "type": "user_input",
                        "user_input": {"user_response": "test"},
                    }
                ],
            )

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.windsurf.get_windsurf_transcripts_dir",
                    return_value=tmpdir,
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.windsurf.scan_windsurf_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({"session_id": sid})
                mock_scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
