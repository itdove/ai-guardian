"""Tests for annotation-based suppression."""

import pytest
from unittest.mock import patch, MagicMock

from ai_guardian.annotations import (
    INLINE_MARKER,
    BLOCK_BEGIN_MARKER,
    BLOCK_END_MARKER,
    DEFAULT_SECRET_ALIASES,
    get_suppressed_lines,
    apply_suppressions,
    process_annotations,
)


class TestGetSuppressedLines:
    """Tests for the core annotation parsing logic."""

    def test_no_annotations(self):
        content = "line1\nline2\nline3"
        all_sup, secret_sup, info, warnings = get_suppressed_lines(content)
        assert all_sup == set()
        assert secret_sup == set()
        assert info == []
        assert warnings == []

    def test_empty_content(self):
        all_sup, secret_sup, info, warnings = get_suppressed_lines("")
        assert all_sup == set()
        assert secret_sup == set()
        assert info == []
        assert warnings == []

    # --- Inline ai-guardian:allow ---

    def test_inline_python_comment(self):
        content = 'ssn = "123-45-6789"  # ai-guardian:allow\nother_line'
        all_sup, _, info, _ = get_suppressed_lines(content)
        assert 0 in all_sup
        assert 1 not in all_sup
        assert len(info) == 1
        assert info[0]["type"] == "inline"
        assert info[0]["lines"] == [1]

    def test_inline_js_comment(self):
        content = 'key = "secret"  // ai-guardian:allow'
        all_sup, _, _, _ = get_suppressed_lines(content)
        assert 0 in all_sup

    def test_inline_html_comment(self):
        content = 'value: 123-45-6789  <!-- ai-guardian:allow -->'
        all_sup, _, _, _ = get_suppressed_lines(content)
        assert 0 in all_sup

    def test_inline_css_comment(self):
        content = 'secret: test  /* ai-guardian:allow */'
        all_sup, _, _, _ = get_suppressed_lines(content)
        assert 0 in all_sup

    def test_inline_sql_comment(self):
        content = "password = 'test'  -- ai-guardian:allow"
        all_sup, _, _, _ = get_suppressed_lines(content)
        assert 0 in all_sup

    def test_inline_multiple_lines(self):
        content = (
            'line1  # ai-guardian:allow\n'
            'line2\n'
            'line3  # ai-guardian:allow\n'
            'line4'
        )
        all_sup, _, info, _ = get_suppressed_lines(content)
        assert all_sup == {0, 2}
        assert len(info) == 2

    def test_inline_case_sensitive(self):
        content = 'ssn = "123"  # AI-GUARDIAN:ALLOW'
        all_sup, _, _, _ = get_suppressed_lines(content)
        assert all_sup == set()

    # --- Block annotations ---

    def test_block_basic(self):
        content = (
            '# ai-guardian:begin-allow\n'
            'ssn = "123-45-6789"\n'
            'key = "AKIA_EXAMPLE_KEY"\n'
            '# ai-guardian:end-allow\n'
            'other_line'
        )
        all_sup, _, info, _ = get_suppressed_lines(content)
        assert all_sup == {0, 1, 2, 3}
        assert 4 not in all_sup
        assert len(info) == 1
        assert info[0]["type"] == "block"
        assert info[0]["lines"] == [1, 2, 3, 4]

    def test_block_inclusive_markers(self):
        """Begin and end marker lines are themselves suppressed."""
        content = (
            '# ai-guardian:begin-allow\n'
            'secret\n'
            '# ai-guardian:end-allow'
        )
        all_sup, _, _, _ = get_suppressed_lines(content)
        assert 0 in all_sup  # begin-allow line
        assert 2 in all_sup  # end-allow line

    def test_block_multiple(self):
        content = (
            '# ai-guardian:begin-allow\n'
            'secret1\n'
            '# ai-guardian:end-allow\n'
            'normal_line\n'
            '# ai-guardian:begin-allow\n'
            'secret2\n'
            '# ai-guardian:end-allow'
        )
        all_sup, _, info, _ = get_suppressed_lines(content)
        assert all_sup == {0, 1, 2, 4, 5, 6}
        assert 3 not in all_sup
        assert len(info) == 2

    def test_block_nested(self):
        content = (
            '# ai-guardian:begin-allow\n'
            'outer\n'
            '# ai-guardian:begin-allow\n'
            'inner\n'
            '# ai-guardian:end-allow\n'
            'still outer\n'
            '# ai-guardian:end-allow'
        )
        all_sup, _, _, _ = get_suppressed_lines(content)
        assert all_sup == {0, 1, 2, 3, 4, 5, 6}

    # --- Unmatched markers ---

    def test_unmatched_begin_allow_ignored(self):
        """Unmatched begin-allow does NOT suppress anything."""
        content = (
            '# ai-guardian:begin-allow\n'
            'ssn = "123-45-6789"\n'
            'key = "AKIA_EXAMPLE_KEY"'
        )
        all_sup, _, _, warnings = get_suppressed_lines(content)
        assert all_sup == set()
        assert len(warnings) == 1
        assert "line 1" in warnings[0]

    def test_unmatched_end_allow_ignored(self):
        """Unmatched end-allow is silently ignored."""
        content = (
            'normal_line\n'
            '# ai-guardian:end-allow\n'
            'other_line'
        )
        all_sup, _, _, warnings = get_suppressed_lines(content)
        assert all_sup == set()
        assert warnings == []

    # --- begin-allow not treated as inline allow ---

    def test_begin_allow_not_inline(self):
        """ai-guardian:begin-allow must not trigger inline suppression."""
        content = (
            '# ai-guardian:begin-allow\n'
            'secret\n'
            'other'
        )
        # Unmatched begin-allow → ignored, nothing suppressed
        all_sup, _, _, _ = get_suppressed_lines(content)
        assert all_sup == set()

    # --- Secret-only annotations ---

    def test_gitleaks_allow(self):
        content = 'key = "AKIA..."  # gitleaks:allow\nother'
        _, secret_sup, info, _ = get_suppressed_lines(content)
        assert 0 in secret_sup
        assert 1 not in secret_sup
        assert info[0]["type"] == "inline_secrets"

    def test_notsecret_as_custom_alias(self):
        """notsecret is not a default — must be added via config."""
        content = 'token = "ghp_..."  # notsecret\nother'
        # Without config, notsecret is not recognized
        _, secret_sup_no_config, _, _ = get_suppressed_lines(content)
        assert 0 not in secret_sup_no_config
        # With config, notsecret is recognized
        config = {"inline_allow_secrets": ["notsecret"]}
        _, secret_sup, info, _ = get_suppressed_lines(content, config=config)
        assert 0 in secret_sup
        assert info[0]["type"] == "inline_secrets"

    def test_secret_alias_does_not_suppress_all(self):
        """gitleaks:allow must NOT appear in all_suppressed."""
        content = 'key = "AKIA..."  # gitleaks:allow'
        all_sup, secret_sup, _, _ = get_suppressed_lines(content)
        assert all_sup == set()
        assert 0 in secret_sup

    def test_secret_alias_inside_block(self):
        """Secret-only marker inside a block is already fully suppressed."""
        content = (
            '# ai-guardian:begin-allow\n'
            'key = "AKIA..."  # gitleaks:allow\n'
            '# ai-guardian:end-allow'
        )
        all_sup, secret_sup, _, _ = get_suppressed_lines(content)
        assert 1 in all_sup
        assert 1 in secret_sup

    def test_both_inline_allow_and_secret(self):
        """ai-guardian:allow takes precedence over gitleaks:allow on same line."""
        content = 'key = "AKIA..."  # ai-guardian:allow  # gitleaks:allow'
        all_sup, secret_sup, info, _ = get_suppressed_lines(content)
        assert 0 in all_sup
        assert len(info) == 1
        assert info[0]["type"] == "inline"

    # --- Configurable aliases ---

    def test_custom_inline_allow_alias(self):
        content = 'ssn = "123"  # nosec'
        config = {"inline_allow": ["nosec"]}
        all_sup, _, info, _ = get_suppressed_lines(content, config=config)
        assert 0 in all_sup
        assert info[0]["type"] == "inline"

    def test_custom_secret_alias(self):
        content = 'key = "AKIA..."  # noinspection'
        config = {"inline_allow_secrets": ["noinspection"]}
        _, secret_sup, info, _ = get_suppressed_lines(content, config=config)
        assert 0 in secret_sup

    def test_custom_aliases_extend_defaults(self):
        """User aliases extend defaults, not replace."""
        content = (
            'line1  # gitleaks:allow\n'
            'line2  # custom-ignore'
        )
        config = {"inline_allow_secrets": ["custom-ignore"]}
        _, secret_sup, _, _ = get_suppressed_lines(content, config=config)
        assert 0 in secret_sup  # default still works
        assert 1 in secret_sup  # custom also works

    def test_custom_block_begin_alias(self):
        content = (
            '# BEGIN-SUPPRESS\n'
            'secret\n'
            '# END-SUPPRESS'
        )
        config = {"block_begin": ["BEGIN-SUPPRESS"], "block_end": ["END-SUPPRESS"]}
        all_sup, _, _, _ = get_suppressed_lines(content, config=config)
        assert all_sup == {0, 1, 2}

    def test_custom_block_alongside_hardcoded(self):
        """Custom block aliases work alongside hardcoded ai-guardian:begin-allow."""
        content = (
            '# ai-guardian:begin-allow\n'
            'line1\n'
            '# ai-guardian:end-allow\n'
            '# custom-begin\n'
            'line2\n'
            '# custom-end'
        )
        config = {"block_begin": ["custom-begin"], "block_end": ["custom-end"]}
        all_sup, _, _, _ = get_suppressed_lines(content, config=config)
        assert all_sup == {0, 1, 2, 3, 4, 5}


class TestApplySuppressions:
    """Tests for content modification."""

    def test_no_suppressions(self):
        content = "line1\nline2\nline3"
        result = apply_suppressions(content, set())
        assert result == content

    def test_single_line(self):
        content = "line1\nline2\nline3"
        result = apply_suppressions(content, {1})
        assert result == "line1\n\nline3"

    def test_preserves_line_count(self):
        content = "line1\nline2\nline3\nline4"
        result = apply_suppressions(content, {0, 2})
        assert len(result.splitlines()) == len(content.splitlines())

    def test_multiple_lines(self):
        content = "a\nb\nc\nd\ne"
        result = apply_suppressions(content, {1, 3})
        assert result == "a\n\nc\n\ne"

    def test_all_lines(self):
        content = "a\nb\nc"
        result = apply_suppressions(content, {0, 1, 2})
        assert result == "\n\n"


class TestProcessAnnotations:
    """Integration tests for the full annotation pipeline."""

    def test_no_annotations(self):
        content = "line1\nline2"
        c_all, c_secret, info, warnings = process_annotations(content)
        assert c_all == content
        assert c_secret == content
        assert info == []
        assert warnings == []

    def test_inline_all_suppression(self):
        content = 'ssn = "123-45-6789"  # ai-guardian:allow\nother'
        c_all, c_secret, info, _ = process_annotations(content)
        assert c_all.splitlines()[0] == ""
        assert c_all.splitlines()[1] == "other"
        assert c_secret.splitlines()[0] == ""

    def test_block_suppression(self):
        content = (
            '# ai-guardian:begin-allow\n'
            'ssn = "123"\n'
            'key = "AKIA"\n'
            '# ai-guardian:end-allow\n'
            'clean_line'
        )
        c_all, c_secret, info, _ = process_annotations(content)
        lines = c_all.splitlines()
        assert lines[0] == ""
        assert lines[1] == ""
        assert lines[2] == ""
        assert lines[3] == ""
        assert lines[4] == "clean_line"

    def test_secret_only_suppression(self):
        """gitleaks:allow blanks line in secret content but not all content."""
        content = 'key = "AKIA..."  # gitleaks:allow\nother'
        c_all, c_secret, _, _ = process_annotations(content)
        assert c_all.splitlines()[0] == 'key = "AKIA..."  # gitleaks:allow'
        assert c_secret.splitlines()[0] == ""

    def test_mixed_annotations(self):
        content = (
            'normal\n'
            'pii = "123-45-6789"  # ai-guardian:allow\n'
            'key = "AKIA..."  # notsecret\n'
            '# ai-guardian:begin-allow\n'
            'secret_block\n'
            '# ai-guardian:end-allow\n'
            'clean'
        )
        config = {"inline_allow_secrets": ["notsecret"]}
        c_all, c_secret, info, _ = process_annotations(content, config=config)
        all_lines = c_all.splitlines()
        secret_lines = c_secret.splitlines()

        assert all_lines[0] == "normal"
        assert all_lines[1] == ""  # ai-guardian:allow
        assert all_lines[2] == 'key = "AKIA..."  # notsecret'  # not blanked for all
        assert all_lines[3] == ""  # block
        assert all_lines[4] == ""  # block
        assert all_lines[5] == ""  # block
        assert all_lines[6] == "clean"

        assert secret_lines[2] == ""  # blanked for secrets

    def test_file_path_in_info(self):
        content = 'x  # ai-guardian:allow'
        _, _, info, _ = process_annotations(content, file_path="/path/to/file.py")
        assert info[0]["file_path"] == "/path/to/file.py"

    def test_preserves_line_count_all(self):
        content = "a\nb  # ai-guardian:allow\nc\nd  # gitleaks:allow\ne"
        c_all, c_secret, _, _ = process_annotations(content)
        assert len(c_all.splitlines()) == 5
        assert len(c_secret.splitlines()) == 5

    def test_config_passed_through(self):
        content = 'line  # nosec\nother'
        config = {"inline_allow": ["nosec"]}
        c_all, _, info, _ = process_annotations(content, config=config)
        assert c_all.split("\n")[0] == ""
        assert c_all.split("\n")[1] == "other"
        assert info[0]["type"] == "inline"

    def test_unmatched_begin_warning(self):
        content = '# ai-guardian:begin-allow\nline'
        _, _, _, warnings = process_annotations(content)
        assert len(warnings) == 1
        assert "line 1" in warnings[0]


class TestAnnotationsIntegration:
    """Tests that verify annotation suppression works with scanning functions."""

    @patch('ai_guardian.annotations.logging')
    def test_logging_on_suppression(self, mock_logging):
        content = 'ssn = "123"  # ai-guardian:allow\nother'
        process_annotations(content)
        mock_logging.info.assert_called()

    def test_no_logging_when_nothing_suppressed(self):
        content = "clean_line1\nclean_line2"
        c_all, c_secret, info, warnings = process_annotations(content)
        assert info == []
        assert c_all == content
        assert c_secret == content
