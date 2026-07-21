"""
Unit tests for OpenClaw transcript scanning via JSONL files (Issue #942).

Tests reading conversation data from OpenClaw's per-session
JSONL transcript files and feeding it into the transcript scanning pipeline.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from ai_guardian.scanners.transcript.openclaw import (
    OpenClawTranscriptAdapter,
    _extract_text_from_openclaw_entry,
    get_most_recent_transcript,
    get_openclaw_transcripts_dir,
    read_openclaw_transcript,
    scan_openclaw_transcript_incremental,
)


def _write_jsonl(path, entries):
    """Write a list of entry dicts as a JSONL file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


SESSION_ID = "transcript-2026-05-22T09-00-00-000Z-a1b2c3d4"


class TestGetOpenClawTranscriptsDir(unittest.TestCase):
    """Test OpenClaw transcripts directory discovery."""

    def test_env_var_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": tmpdir}):
                result = get_openclaw_transcripts_dir()
                self.assertEqual(result, tmpdir)

    def test_env_var_missing_dir(self):
        with mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": "/nonexistent/path"}):
            result = get_openclaw_transcripts_dir()
            self.assertIsNone(result)

    def test_no_env_uses_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            default_path = os.path.join(tmpdir, ".openclaw", "transcripts")
            os.makedirs(default_path)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("OPENCLAW_STATE_DIR", None)
                with mock.patch(
                    "ai_guardian.scanners.transcript.openclaw.os.path.expanduser",
                    return_value=default_path,
                ):
                    result = get_openclaw_transcripts_dir()
                    self.assertEqual(result, default_path)

    def test_no_env_no_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENCLAW_STATE_DIR", None)
            with mock.patch(
                "ai_guardian.scanners.transcript.openclaw.os.path.isdir",
                return_value=False,
            ):
                result = get_openclaw_transcripts_dir()
                self.assertIsNone(result)


class TestExtractTextFromOpenClawEntry(unittest.TestCase):
    """Test text extraction from OpenClaw JSONL entry objects."""

    def test_string_content(self):
        entry = {"role": "user", "content": "Hello world"}
        self.assertEqual(_extract_text_from_openclaw_entry(entry), "Hello world")

    def test_dict_content_text_field(self):
        entry = {"role": "assistant", "content": {"text": "Response here"}}
        self.assertEqual(_extract_text_from_openclaw_entry(entry), "Response here")

    def test_dict_content_content_field(self):
        entry = {"role": "assistant", "content": {"content": "Nested content"}}
        self.assertEqual(_extract_text_from_openclaw_entry(entry), "Nested content")

    def test_list_content(self):
        entry = {
            "role": "assistant",
            "content": [
                {"text": "Part 1"},
                {"content": "Part 2"},
            ],
        }
        result = _extract_text_from_openclaw_entry(entry)
        self.assertIn("Part 1", result)
        self.assertIn("Part 2", result)

    def test_output_field(self):
        entry = {"role": "tool", "output": "command output here"}
        self.assertEqual(
            _extract_text_from_openclaw_entry(entry), "command output here"
        )

    def test_dict_arguments(self):
        entry = {
            "role": "tool",
            "arguments": {"command": "ls -la", "content": "file data"},
        }
        result = _extract_text_from_openclaw_entry(entry)
        self.assertIn("ls -la", result)
        self.assertIn("file data", result)

    def test_string_arguments(self):
        entry = {"role": "tool", "arguments": "echo hello"}
        self.assertEqual(_extract_text_from_openclaw_entry(entry), "echo hello")

    def test_empty_entry(self):
        self.assertEqual(_extract_text_from_openclaw_entry({}), "")

    def test_content_and_output(self):
        entry = {"content": "main", "output": "extra"}
        result = _extract_text_from_openclaw_entry(entry)
        self.assertIn("main", result)
        self.assertIn("extra", result)

    def test_non_string_content_ignored(self):
        entry = {"content": 42}
        self.assertEqual(_extract_text_from_openclaw_entry(entry), "")


class TestGetMostRecentTranscript(unittest.TestCase):
    """Test finding the most recently modified transcript file."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_finds_most_recent(self):
        old_dir = os.path.join(self.tmpdir, "2026-01-01", "session-old")
        new_dir = os.path.join(self.tmpdir, "2026-07-20", "session-new")
        os.makedirs(old_dir)
        os.makedirs(new_dir)
        _write_jsonl(
            os.path.join(old_dir, "transcript.jsonl"),
            [{"content": "old"}],
        )
        import time

        time.sleep(0.05)
        new_path = os.path.join(new_dir, "transcript.jsonl")
        _write_jsonl(new_path, [{"content": "new"}])

        result = get_most_recent_transcript(self.tmpdir)
        self.assertEqual(result, new_path)

    def test_empty_directory(self):
        result = get_most_recent_transcript(self.tmpdir)
        self.assertIsNone(result)

    def test_nonexistent_directory(self):
        result = get_most_recent_transcript("/nonexistent/dir")
        self.assertIsNone(result)

    def test_ignores_non_transcript_files(self):
        session_dir = os.path.join(self.tmpdir, "2026-01-01", "session1")
        os.makedirs(session_dir)
        with open(os.path.join(session_dir, "metadata.json"), "w") as f:
            f.write("{}")

        result = get_most_recent_transcript(self.tmpdir)
        self.assertIsNone(result)


class TestReadOpenClawTranscript(unittest.TestCase):
    """Test reading conversation from OpenClaw JSONL files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_all_lines(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        entries = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "World"},
        ]
        _write_jsonl(path, entries)

        text, count = read_openclaw_transcript(path)
        self.assertIn("Hello", text)
        self.assertIn("World", text)
        self.assertEqual(count, 2)

    def test_incremental_read_skips_seen(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        entries = [
            {"role": "user", "content": "Old"},
            {"role": "user", "content": "New"},
        ]
        _write_jsonl(path, entries)

        text, count = read_openclaw_transcript(path, seen_count=1)
        self.assertNotIn("Old", text)
        self.assertIn("New", text)
        self.assertEqual(count, 2)

    def test_empty_file(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        with open(path, "w") as f:
            f.write("")

        text, count = read_openclaw_transcript(path)
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_file_not_found(self):
        text, count = read_openclaw_transcript("/nonexistent/transcript.jsonl")
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_malformed_json_lines_skipped(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        with open(path, "w") as f:
            f.write("not valid json\n")
            f.write(json.dumps({"content": "Valid"}) + "\n")

        text, count = read_openclaw_transcript(path)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)

    def test_truncated_file_resets(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        entries = [{"content": "Only"}]
        _write_jsonl(path, entries)

        text, count = read_openclaw_transcript(path, seen_count=5)
        self.assertIn("Only", text)
        self.assertEqual(count, 1)

    def test_nothing_new(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        entries = [{"content": "Done"}]
        _write_jsonl(path, entries)

        text, count = read_openclaw_transcript(path, seen_count=1)
        self.assertEqual(text, "")
        self.assertEqual(count, 1)

    def test_non_dict_lines_skipped(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        with open(path, "w") as f:
            f.write('"just a string"\n')
            f.write(json.dumps({"content": "Valid"}) + "\n")

        text, count = read_openclaw_transcript(path)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)


class TestScanOpenClawTranscriptIncremental(unittest.TestCase):
    """Test incremental scanning of OpenClaw transcripts."""

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
        _write_jsonl(path, [{"content": "Old content"}])

        with mock.patch.dict(os.environ, self.env_patches):
            warnings = scan_openclaw_transcript_incremental(path, SESSION_ID)
            self.assertEqual(warnings, [])

    def test_second_scan_reads_new_lines(self):
        path = os.path.join(self.tmpdir, "transcript.jsonl")
        entries = [{"content": "Hello"}]
        _write_jsonl(path, entries)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_openclaw_transcript_incremental(path, SESSION_ID)

            entries.append({"content": "New content"})
            _write_jsonl(path, entries)

            with mock.patch(
                "ai_guardian.scanners.transcript.common._scan_transcript_text",
                return_value=["WARNING: test"],
            ) as mock_scan:
                warnings = scan_openclaw_transcript_incremental(path, SESSION_ID)
                self.assertEqual(warnings, ["WARNING: test"])
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertIn("New content", call_args[0][0])


class TestOpenClawTranscriptAdapter(unittest.TestCase):
    """Test OpenClawTranscriptAdapter.can_scan() and scan_incremental()."""

    def setUp(self):
        self.adapter = OpenClawTranscriptAdapter()

    def test_can_scan_with_openclaw_env(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "openclaw"}):
            result = self.adapter.can_scan({})
            self.assertTrue(result)

    def test_cannot_scan_without_env(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AI_GUARDIAN_IDE_TYPE", None)
            result = self.adapter.can_scan({})
            self.assertFalse(result)

    def test_cannot_scan_wrong_env(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "kiro"}):
            result = self.adapter.can_scan({})
            self.assertFalse(result)

    def test_cannot_scan_with_transcript_path(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "openclaw"}):
            result = self.adapter.can_scan({"transcript_path": "/some/file.jsonl"})
            self.assertFalse(result)

    def test_name(self):
        self.assertEqual(self.adapter.name, "OpenClaw")

    def test_scan_incremental_no_dir(self):
        with mock.patch(
            "ai_guardian.scanners.transcript.openclaw.get_openclaw_transcripts_dir",
            return_value=None,
        ):
            result = self.adapter.scan_incremental({})
            self.assertEqual(result, [])

    def test_scan_incremental_no_transcript(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch(
                "ai_guardian.scanners.transcript.openclaw.get_openclaw_transcripts_dir",
                return_value=tmpdir,
            ):
                result = self.adapter.scan_incremental({})
                self.assertEqual(result, [])

    def test_scan_incremental_uses_session_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = os.path.join(tmpdir, "2026-07-20", SESSION_ID)
            os.makedirs(session_dir)
            path = os.path.join(session_dir, "transcript.jsonl")
            _write_jsonl(path, [{"content": "test"}])

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.openclaw.get_openclaw_transcripts_dir",
                    return_value=tmpdir,
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.openclaw.scan_openclaw_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({"session_id": SESSION_ID})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][0], path)
                self.assertEqual(mock_scan.call_args[0][1], SESSION_ID)

    def test_scan_incremental_falls_back_to_most_recent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = os.path.join(tmpdir, "2026-07-20", "some-session")
            os.makedirs(session_dir)
            path = os.path.join(session_dir, "transcript.jsonl")
            _write_jsonl(path, [{"content": "test"}])

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.openclaw.get_openclaw_transcripts_dir",
                    return_value=tmpdir,
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.openclaw.scan_openclaw_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][0], path)
                self.assertEqual(mock_scan.call_args[0][1], "some-session")

    def test_scan_incremental_listdir_race(self):
        """Gracefully handles directory removal between discovery and listing."""
        with (
            mock.patch(
                "ai_guardian.scanners.transcript.openclaw.get_openclaw_transcripts_dir",
                return_value="/tmp/exists-briefly",
            ),
            mock.patch(
                "ai_guardian.scanners.transcript.openclaw.os.listdir",
                side_effect=OSError("No such file or directory"),
            ),
            mock.patch(
                "ai_guardian.scanners.transcript.openclaw.get_most_recent_transcript",
                return_value=None,
            ),
        ):
            result = self.adapter.scan_incremental({"session_id": "test-id"})
            self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
