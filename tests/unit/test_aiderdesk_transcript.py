"""
Unit tests for AiderDesk transcript scanning via Markdown chat history (Issue #942).

Tests reading conversation data from AiderDesk/Aider's Markdown
`.aider.chat.history.md` files and feeding it into the transcript scanning pipeline.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from ai_guardian.scanners.transcript.aiderdesk import (
    AiderDeskTranscriptAdapter,
    _extract_text_from_markdown,
    get_aiderdesk_history_path,
    read_aiderdesk_transcript,
    scan_aiderdesk_transcript_incremental,
)

SAMPLE_TRANSCRIPT = """\
# aider chat started at 2025-01-15 10:30:00

#### Fix the bug in the login function

I'll fix the bug. Here are the changes:

```python
def login(user, pw):
    return authenticate(user, pw)
```

> Tokens: 38k sent, 1.1k received. Cost: $0.12

#### Now add tests for the login function

I'll add tests for the login function.

```python
def test_login():
    assert login("admin", "secret123") is True
```

> Cost: $0.08
"""


class TestGetAiderDeskHistoryPath(unittest.TestCase):
    """Test AiderDesk history file discovery."""

    def test_env_var_override(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            f.write(b"# aider chat")
            path = f.name
        try:
            with mock.patch.dict(os.environ, {"AIDER_CHAT_HISTORY_FILE": path}):
                result = get_aiderdesk_history_path()
                self.assertEqual(result, path)
        finally:
            os.unlink(path)

    def test_env_var_missing_file(self):
        with mock.patch.dict(
            os.environ, {"AIDER_CHAT_HISTORY_FILE": "/nonexistent/file.md"}
        ):
            result = get_aiderdesk_history_path()
            self.assertIsNone(result)

    def test_cwd_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            history_path = os.path.join(tmpdir, ".aider.chat.history.md")
            with open(history_path, "w") as f:
                f.write("# aider chat")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AIDER_CHAT_HISTORY_FILE", None)
                with mock.patch("os.getcwd", return_value=tmpdir):
                    result = get_aiderdesk_history_path()
                    self.assertEqual(result, history_path)

    def test_no_file_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AIDER_CHAT_HISTORY_FILE", None)
                with mock.patch("os.getcwd", return_value=tmpdir):
                    result = get_aiderdesk_history_path()
                    self.assertIsNone(result)


class TestExtractTextFromMarkdown(unittest.TestCase):
    """Test Markdown text extraction."""

    def test_user_message_stripped(self):
        result = _extract_text_from_markdown("#### Fix the bug")
        self.assertIn("Fix the bug", result)
        self.assertNotIn("####", result)

    def test_session_header_removed(self):
        result = _extract_text_from_markdown("# aider chat started at 2025-01-15")
        self.assertEqual(result.strip(), "")

    def test_cost_blockquote_removed(self):
        result = _extract_text_from_markdown(
            "> Tokens: 38k sent, 1.1k received. Cost: $0.12"
        )
        self.assertEqual(result.strip(), "")

    def test_cost_only_blockquote_removed(self):
        result = _extract_text_from_markdown("> Cost: $0.08")
        self.assertEqual(result.strip(), "")

    def test_assistant_text_preserved(self):
        result = _extract_text_from_markdown("I'll fix the bug.")
        self.assertIn("I'll fix the bug.", result)

    def test_code_block_preserved(self):
        content = "```python\ndef hello():\n    pass\n```"
        result = _extract_text_from_markdown(content)
        self.assertIn("def hello():", result)

    def test_full_transcript(self):
        result = _extract_text_from_markdown(SAMPLE_TRANSCRIPT)
        self.assertIn("Fix the bug", result)
        self.assertIn("def login", result)
        self.assertIn("secret123", result)
        self.assertNotIn("# aider chat started", result)
        self.assertNotIn("Tokens: 38k", result)

    def test_non_cost_blockquote_preserved(self):
        result = _extract_text_from_markdown("> Some important note")
        self.assertIn("> Some important note", result)


class TestReadAiderDeskTranscript(unittest.TestCase):
    """Test reading conversation from Aider Markdown files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_full_file(self):
        path = os.path.join(self.tmpdir, "history.md")
        with open(path, "w") as f:
            f.write(SAMPLE_TRANSCRIPT)

        text, offset = read_aiderdesk_transcript(path)
        self.assertIn("Fix the bug", text)
        self.assertIn("secret123", text)
        self.assertGreater(offset, 0)

    def test_incremental_read(self):
        path = os.path.join(self.tmpdir, "history.md")
        initial = "#### First message\n\nFirst response.\n"
        with open(path, "w") as f:
            f.write(initial)

        _, offset = read_aiderdesk_transcript(path)

        with open(path, "a") as f:
            f.write("\n#### Second message\n\nSecond response with secret123.\n")

        text, new_offset = read_aiderdesk_transcript(path, byte_offset=offset)
        self.assertNotIn("First message", text)
        self.assertIn("Second message", text)
        self.assertIn("secret123", text)
        self.assertGreater(new_offset, offset)

    def test_nothing_new(self):
        path = os.path.join(self.tmpdir, "history.md")
        with open(path, "w") as f:
            f.write("#### Done\n")

        _, offset = read_aiderdesk_transcript(path)
        text, same_offset = read_aiderdesk_transcript(path, byte_offset=offset)
        self.assertEqual(text, "")
        self.assertEqual(same_offset, offset)

    def test_empty_file(self):
        path = os.path.join(self.tmpdir, "history.md")
        with open(path, "w") as f:
            pass

        text, offset = read_aiderdesk_transcript(path)
        self.assertEqual(text, "")
        self.assertEqual(offset, 0)

    def test_file_not_found(self):
        text, offset = read_aiderdesk_transcript("/nonexistent/history.md")
        self.assertEqual(text, "")
        self.assertEqual(offset, 0)


class TestScanAiderDeskTranscriptIncremental(unittest.TestCase):
    """Test incremental scanning of AiderDesk transcripts."""

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
        path = os.path.join(self.tmpdir, ".aider.chat.history.md")
        with open(path, "w") as f:
            f.write("#### Old content\n\nOld response.\n")

        with mock.patch.dict(os.environ, self.env_patches):
            warnings = scan_aiderdesk_transcript_incremental(path)
            self.assertEqual(warnings, [])

    def test_second_scan_reads_new_content(self):
        path = os.path.join(self.tmpdir, ".aider.chat.history.md")
        with open(path, "w") as f:
            f.write("#### First\n\nFirst response.\n")

        with mock.patch.dict(os.environ, self.env_patches):
            scan_aiderdesk_transcript_incremental(path)

            with open(path, "a") as f:
                f.write("\n#### New message\n\nNew content here.\n")

            with mock.patch(
                "ai_guardian.scanners.transcript.aiderdesk._scan_transcript_text",
                return_value=["WARNING: test"],
            ) as mock_scan:
                warnings = scan_aiderdesk_transcript_incremental(path)
                self.assertEqual(warnings, ["WARNING: test"])
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertIn("New content here", call_args[0][0])


class TestAiderDeskTranscriptAdapter(unittest.TestCase):
    """Test AiderDeskTranscriptAdapter.can_scan() and scan_incremental()."""

    def setUp(self):
        self.adapter = AiderDeskTranscriptAdapter()

    def test_can_scan_with_aiderdesk_env(self):
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "aiderdesk"}):
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
        with mock.patch.dict(os.environ, {"AI_GUARDIAN_IDE_TYPE": "aiderdesk"}):
            result = self.adapter.can_scan({"transcript_path": "/some/file.jsonl"})
            self.assertFalse(result)

    def test_name(self):
        self.assertEqual(self.adapter.name, "AiderDesk")

    def test_scan_incremental_no_history(self):
        with mock.patch(
            "ai_guardian.scanners.transcript.aiderdesk.get_aiderdesk_history_path",
            return_value=None,
        ):
            result = self.adapter.scan_incremental({})
            self.assertEqual(result, [])

    def test_scan_incremental_delegates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, ".aider.chat.history.md")
            with open(path, "w") as f:
                f.write("#### test\n")

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.aiderdesk.get_aiderdesk_history_path",
                    return_value=path,
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.aiderdesk.scan_aiderdesk_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][0], path)


if __name__ == "__main__":
    unittest.main()
