"""
Unit tests for Copilot Chat (VS Code) transcript scanning via JSONL delta
journal files (Issue #940).

Tests reading conversation data from VS Code's Copilot Chat session
JSONL files and feeding it into the transcript scanning pipeline.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from ai_guardian.scanners.transcript.copilot_chat import (
    CopilotChatTranscriptAdapter,
    _extract_text_from_chat_entry,
    _extract_text_from_request,
    _find_session_file,
    _walk_strings,
    get_copilot_chat_dirs,
    read_copilot_chat_transcript,
    scan_copilot_chat_transcript_incremental,
)


def _write_jsonl(path, entries):
    """Write a list of entry dicts as a JSONL file."""
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


SESSION_ID = "test-session-001"


class TestGetCopilotChatDirs(unittest.TestCase):
    """Test Copilot Chat directory discovery."""

    def test_env_var_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, {"COPILOT_CHAT_DATA_DIR": tmpdir}):
                result = get_copilot_chat_dirs()
                self.assertEqual(result, [tmpdir])

    def test_env_var_missing_dir(self):
        with mock.patch.dict(
            os.environ, {"COPILOT_CHAT_DATA_DIR": "/nonexistent/path"}
        ):
            with mock.patch(
                "ai_guardian.scanners.transcript.copilot_chat._get_vscode_user_dir",
                return_value="/nonexistent/User",
            ):
                result = get_copilot_chat_dirs()
                self.assertEqual(result, [])

    def test_no_env_finds_workspace_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            user_dir = os.path.join(tmpdir, "User")
            ws_dir = os.path.join(
                user_dir, "workspaceStorage", "abc123", "chatSessions"
            )
            os.makedirs(ws_dir)

            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("COPILOT_CHAT_DATA_DIR", None)
                with mock.patch(
                    "ai_guardian.scanners.transcript.copilot_chat._get_vscode_user_dir",
                    return_value=user_dir,
                ):
                    result = get_copilot_chat_dirs()
                    self.assertIn(ws_dir, result)

    def test_no_env_finds_global_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            user_dir = os.path.join(tmpdir, "User")
            global_dir = os.path.join(
                user_dir, "globalStorage", "emptyWindowChatSessions"
            )
            os.makedirs(global_dir)

            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("COPILOT_CHAT_DATA_DIR", None)
                with mock.patch(
                    "ai_guardian.scanners.transcript.copilot_chat._get_vscode_user_dir",
                    return_value=user_dir,
                ):
                    result = get_copilot_chat_dirs()
                    self.assertIn(global_dir, result)

    def test_no_dirs_exist(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("COPILOT_CHAT_DATA_DIR", None)
            with mock.patch(
                "ai_guardian.scanners.transcript.copilot_chat._get_vscode_user_dir",
                return_value="/nonexistent/User",
            ):
                result = get_copilot_chat_dirs()
                self.assertEqual(result, [])


class TestFindSessionFile(unittest.TestCase):
    """Test session file discovery."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_find_by_session_id(self):
        path = os.path.join(self.tmpdir, f"{SESSION_ID}.jsonl")
        with open(path, "w") as f:
            f.write("{}\n")

        result = _find_session_file([self.tmpdir], SESSION_ID)
        self.assertEqual(result, path)

    def test_fallback_to_most_recent(self):
        old = os.path.join(self.tmpdir, "old.jsonl")
        new = os.path.join(self.tmpdir, "new.jsonl")
        with open(old, "w") as f:
            f.write("{}\n")
        with open(new, "w") as f:
            f.write("{}\n")
        os.utime(old, (1000, 1000))
        os.utime(new, (2000, 2000))

        result = _find_session_file([self.tmpdir])
        self.assertEqual(result, new)

    def test_session_id_not_found_falls_back(self):
        other = os.path.join(self.tmpdir, "other.jsonl")
        with open(other, "w") as f:
            f.write("{}\n")

        result = _find_session_file([self.tmpdir], "nonexistent")
        self.assertEqual(result, other)

    def test_empty_dirs(self):
        result = _find_session_file([self.tmpdir])
        self.assertIsNone(result)

    def test_no_dirs(self):
        result = _find_session_file([])
        self.assertIsNone(result)


class TestWalkStrings(unittest.TestCase):
    """Test recursive string collection."""

    def test_string(self):
        self.assertEqual(_walk_strings("hello"), ["hello"])

    def test_empty_string(self):
        self.assertEqual(_walk_strings(""), [])

    def test_dict(self):
        result = _walk_strings({"a": "one", "b": "two"})
        self.assertEqual(sorted(result), ["one", "two"])

    def test_list(self):
        self.assertEqual(_walk_strings(["a", "b"]), ["a", "b"])

    def test_nested(self):
        data = {"a": [{"b": "deep"}], "c": "top"}
        result = _walk_strings(data)
        self.assertIn("deep", result)
        self.assertIn("top", result)

    def test_non_string_primitives(self):
        self.assertEqual(_walk_strings(42), [])
        self.assertEqual(_walk_strings(None), [])


class TestExtractTextFromRequest(unittest.TestCase):
    """Test text extraction from individual request objects."""

    def test_message_text(self):
        req = {"message": {"text": "user prompt"}, "response": {}}
        self.assertIn("user prompt", _extract_text_from_request(req))

    def test_message_prompt(self):
        req = {"message": {"prompt": "user prompt"}, "response": {}}
        self.assertIn("user prompt", _extract_text_from_request(req))

    def test_message_string(self):
        req = {"message": "direct string", "response": {}}
        self.assertIn("direct string", _extract_text_from_request(req))

    def test_response_value(self):
        req = {"message": {}, "response": {"value": "# Markdown answer"}}
        self.assertIn("# Markdown answer", _extract_text_from_request(req))

    def test_response_result(self):
        req = {"message": {}, "response": {"result": "output text"}}
        self.assertIn("output text", _extract_text_from_request(req))

    def test_response_nested_parts(self):
        req = {
            "message": {},
            "response": {
                "response": [
                    {"value": "part one"},
                    {"value": "part two"},
                ]
            },
        }
        text = _extract_text_from_request(req)
        self.assertIn("part one", text)
        self.assertIn("part two", text)

    def test_empty_request(self):
        self.assertEqual(_extract_text_from_request({}), "")

    def test_non_string_values_skipped(self):
        req = {"message": {"text": 42}, "response": {"value": None}}
        self.assertEqual(_extract_text_from_request(req), "")


class TestExtractTextFromChatEntry(unittest.TestCase):
    """Test text extraction from JSONL delta journal entries."""

    def test_kind_0_with_requests(self):
        entry = {
            "kind": 0,
            "v": {
                "sessionId": "abc",
                "requests": [
                    {
                        "requestId": "r1",
                        "message": {"text": "What is Python?"},
                        "response": {"value": "Python is a language."},
                    }
                ],
            },
        }
        text = _extract_text_from_chat_entry(entry)
        self.assertIn("What is Python?", text)
        self.assertIn("Python is a language.", text)

    def test_kind_0_multiple_requests(self):
        entry = {
            "kind": 0,
            "v": {
                "requests": [
                    {"message": {"text": "first"}, "response": {}},
                    {"message": {"text": "second"}, "response": {}},
                ],
            },
        }
        text = _extract_text_from_chat_entry(entry)
        self.assertIn("first", text)
        self.assertIn("second", text)

    def test_kind_0_no_requests(self):
        entry = {"kind": 0, "v": {"sessionId": "abc"}}
        self.assertEqual(_extract_text_from_chat_entry(entry), "")

    def test_kind_0_no_v(self):
        entry = {"kind": 0}
        self.assertEqual(_extract_text_from_chat_entry(entry), "")

    def test_kind_0_v_not_dict(self):
        entry = {"kind": 0, "v": "not a dict"}
        self.assertEqual(_extract_text_from_chat_entry(entry), "")

    def test_kind_1_string_value(self):
        entry = {"kind": 1, "k": ["customTitle"], "v": "My Chat Title"}
        text = _extract_text_from_chat_entry(entry)
        self.assertIn("My Chat Title", text)

    def test_kind_1_nested_value(self):
        entry = {
            "kind": 1,
            "k": ["requests", 0, "response"],
            "v": {"value": "updated answer"},
        }
        text = _extract_text_from_chat_entry(entry)
        self.assertIn("updated answer", text)

    def test_kind_2_array_append(self):
        entry = {
            "kind": 2,
            "k": ["requests"],
            "v": [{"message": {"text": "new question"}}],
        }
        text = _extract_text_from_chat_entry(entry)
        self.assertIn("new question", text)

    def test_kind_1_null_value(self):
        entry = {"kind": 1, "k": ["something"], "v": None}
        self.assertEqual(_extract_text_from_chat_entry(entry), "")

    def test_unknown_kind(self):
        entry = {"kind": 99, "v": {"text": "ignored"}}
        self.assertEqual(_extract_text_from_chat_entry(entry), "")

    def test_missing_kind(self):
        entry = {"v": {"text": "no kind"}}
        self.assertEqual(_extract_text_from_chat_entry(entry), "")

    def test_kind_0_non_dict_request_skipped(self):
        entry = {
            "kind": 0,
            "v": {"requests": ["not a dict", {"message": {"text": "valid"}}]},
        }
        text = _extract_text_from_chat_entry(entry)
        self.assertIn("valid", text)

    def test_kind_0_requests_not_list(self):
        entry = {"kind": 0, "v": {"requests": "not a list"}}
        self.assertEqual(_extract_text_from_chat_entry(entry), "")


class TestReadCopilotChatTranscript(unittest.TestCase):
    """Test reading conversation from Copilot Chat JSONL files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_read_all_lines(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [
            {
                "kind": 0,
                "v": {
                    "requests": [
                        {
                            "message": {"text": "Hello"},
                            "response": {"value": "World"},
                        }
                    ]
                },
            }
        ]
        _write_jsonl(path, entries)

        text, count = read_copilot_chat_transcript(path)
        self.assertIn("Hello", text)
        self.assertIn("World", text)
        self.assertEqual(count, 1)

    def test_incremental_read_skips_seen(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [
            {
                "kind": 0,
                "v": {"requests": [{"message": {"text": "Old"}, "response": {}}]},
            },
            {"kind": 1, "k": ["customTitle"], "v": "New Title"},
        ]
        _write_jsonl(path, entries)

        text, count = read_copilot_chat_transcript(path, seen_count=1)
        self.assertNotIn("Old", text)
        self.assertIn("New Title", text)
        self.assertEqual(count, 2)

    def test_empty_file(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        with open(path, "w") as f:
            f.write("")

        text, count = read_copilot_chat_transcript(path)
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_file_not_found(self):
        text, count = read_copilot_chat_transcript("/nonexistent/session.jsonl")
        self.assertEqual(text, "")
        self.assertEqual(count, 0)

    def test_malformed_json_lines_skipped(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        with open(path, "w") as f:
            f.write("not valid json\n")
            f.write(
                json.dumps(
                    {
                        "kind": 0,
                        "v": {
                            "requests": [{"message": {"text": "Valid"}, "response": {}}]
                        },
                    }
                )
                + "\n"
            )

        text, count = read_copilot_chat_transcript(path)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)

    def test_truncated_file_resets(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [
            {
                "kind": 0,
                "v": {"requests": [{"message": {"text": "Only"}, "response": {}}]},
            }
        ]
        _write_jsonl(path, entries)

        text, count = read_copilot_chat_transcript(path, seen_count=5)
        self.assertIn("Only", text)
        self.assertEqual(count, 1)

    def test_nothing_new(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [
            {
                "kind": 0,
                "v": {"requests": [{"message": {"text": "Done"}, "response": {}}]},
            }
        ]
        _write_jsonl(path, entries)

        text, count = read_copilot_chat_transcript(path, seen_count=1)
        self.assertEqual(text, "")
        self.assertEqual(count, 1)

    def test_non_dict_lines_skipped(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        with open(path, "w") as f:
            f.write('"just a string"\n')
            f.write(
                json.dumps(
                    {
                        "kind": 0,
                        "v": {
                            "requests": [{"message": {"text": "Valid"}, "response": {}}]
                        },
                    }
                )
                + "\n"
            )

        text, count = read_copilot_chat_transcript(path)
        self.assertIn("Valid", text)
        self.assertEqual(count, 2)

    def test_bom_handling(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        with open(path, "wb") as f:
            f.write(b"\xef\xbb\xbf")
            f.write(
                json.dumps(
                    {
                        "kind": 0,
                        "v": {
                            "requests": [
                                {"message": {"text": "BOM test"}, "response": {}}
                            ]
                        },
                    }
                ).encode("utf-8")
                + b"\n"
            )

        text, count = read_copilot_chat_transcript(path)
        self.assertIn("BOM test", text)
        self.assertEqual(count, 1)


class TestScanCopilotChatTranscriptIncremental(unittest.TestCase):
    """Test incremental scanning of Copilot Chat transcripts."""

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
        entries = [
            {
                "kind": 0,
                "v": {
                    "requests": [{"message": {"text": "Old content"}, "response": {}}]
                },
            }
        ]
        _write_jsonl(path, entries)

        with mock.patch.dict(os.environ, self.env_patches):
            warnings = scan_copilot_chat_transcript_incremental(path, SESSION_ID)
            self.assertEqual(warnings, [])

    def test_second_scan_reads_new_lines(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [
            {
                "kind": 0,
                "v": {"requests": [{"message": {"text": "Hello"}, "response": {}}]},
            }
        ]
        _write_jsonl(path, entries)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_copilot_chat_transcript_incremental(path, SESSION_ID)

            entries.append({"kind": 1, "k": ["customTitle"], "v": "New content"})
            _write_jsonl(path, entries)

            with mock.patch(
                "ai_guardian.scanners.transcript.common._scan_transcript_text",
                return_value=["WARNING: test"],
            ) as mock_scan:
                warnings = scan_copilot_chat_transcript_incremental(path, SESSION_ID)
                self.assertEqual(warnings, ["WARNING: test"])
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                self.assertIn("New content", call_args[0][0])

    def test_nothing_new_returns_empty(self):
        path = os.path.join(self.tmpdir, "session.jsonl")
        entries = [
            {
                "kind": 0,
                "v": {"requests": [{"message": {"text": "Done"}, "response": {}}]},
            }
        ]
        _write_jsonl(path, entries)

        with mock.patch.dict(os.environ, self.env_patches):
            scan_copilot_chat_transcript_incremental(path, SESSION_ID)
            warnings = scan_copilot_chat_transcript_incremental(path, SESSION_ID)
            self.assertEqual(warnings, [])


class TestCopilotChatTranscriptAdapter(unittest.TestCase):
    """Test CopilotChatTranscriptAdapter.can_scan() and scan_incremental()."""

    def setUp(self):
        self.adapter = CopilotChatTranscriptAdapter()

    def test_can_scan_copilot_adapter(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "GitHub Copilot"
        result = self.adapter.can_scan({}, mock_hook_adapter)
        self.assertTrue(result)

    def test_cannot_scan_with_transcript_path(self):
        mock_hook_adapter = mock.MagicMock()
        mock_hook_adapter.name = "GitHub Copilot"
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
        self.assertEqual(self.adapter.name, "GitHub Copilot")

    def test_scan_incremental_no_dirs(self):
        with mock.patch(
            "ai_guardian.scanners.transcript.copilot_chat.get_copilot_chat_dirs",
            return_value=[],
        ):
            result = self.adapter.scan_incremental({})
            self.assertEqual(result, [])

    def test_scan_incremental_no_session_file(self):
        with mock.patch(
            "ai_guardian.scanners.transcript.copilot_chat.get_copilot_chat_dirs",
            return_value=["/tmp/empty"],
        ):
            with mock.patch(
                "ai_guardian.scanners.transcript.copilot_chat._find_session_file",
                return_value=None,
            ):
                result = self.adapter.scan_incremental({})
                self.assertEqual(result, [])

    def test_scan_incremental_uses_session_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, f"{SESSION_ID}.jsonl")
            _write_jsonl(
                path,
                [
                    {
                        "kind": 0,
                        "v": {
                            "requests": [{"message": {"text": "test"}, "response": {}}]
                        },
                    }
                ],
            )

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.copilot_chat.get_copilot_chat_dirs",
                    return_value=[tmpdir],
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.copilot_chat.scan_copilot_chat_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({"sessionId": SESSION_ID})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][0], path)
                self.assertEqual(mock_scan.call_args[0][1], SESSION_ID)

    def test_scan_incremental_falls_back_to_session_id_field(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sid = "session-fallback-id"
            path = os.path.join(tmpdir, f"{sid}.jsonl")
            _write_jsonl(
                path,
                [
                    {
                        "kind": 0,
                        "v": {
                            "requests": [{"message": {"text": "test"}, "response": {}}]
                        },
                    }
                ],
            )

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.copilot_chat.get_copilot_chat_dirs",
                    return_value=[tmpdir],
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.copilot_chat.scan_copilot_chat_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({"session_id": sid})
                mock_scan.assert_called_once()

    def test_scan_incremental_derives_session_id_from_filename(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "auto-discovered.jsonl")
            _write_jsonl(
                path,
                [
                    {
                        "kind": 0,
                        "v": {
                            "requests": [{"message": {"text": "test"}, "response": {}}]
                        },
                    }
                ],
            )

            with (
                mock.patch(
                    "ai_guardian.scanners.transcript.copilot_chat.get_copilot_chat_dirs",
                    return_value=[tmpdir],
                ),
                mock.patch(
                    "ai_guardian.scanners.transcript.copilot_chat.scan_copilot_chat_transcript_incremental",
                    return_value=[],
                ) as mock_scan,
            ):
                self.adapter.scan_incremental({})
                mock_scan.assert_called_once()
                self.assertEqual(mock_scan.call_args[0][1], "auto-discovered")


if __name__ == "__main__":
    unittest.main()
