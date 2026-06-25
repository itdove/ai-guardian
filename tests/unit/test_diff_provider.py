"""Tests for ai_guardian.diff_provider module."""

import subprocess
from unittest import mock

import pytest

from ai_guardian.diff_provider import (
    DiffProviderError,
    detect_platform,
    extract_file_contents_from_diff,
    filter_findings_by_changed_lines,
    get_changed_files_from_diff,
    get_merge_base,
    get_mr_diff,
    get_pr_diff,
    get_staged_diff,
    parse_mr_ref,
    parse_pr_ref,
    parse_unified_diff,
)

# --- Sample diffs for testing ---

SIMPLE_DIFF = """\
diff --git a/src/foo.py b/src/foo.py
index 1234567..abcdefg 100644
--- a/src/foo.py
+++ b/src/foo.py
@@ -10,6 +10,8 @@ def existing():
     pass
     pass
     pass
+    new_line_1()
+    new_line_2()
     pass
     pass
     pass
"""

MULTI_FILE_DIFF = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,3 +1,4 @@
 line1
+added_in_a
 line2
 line3
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -5,3 +5,4 @@
 line5
 line6
+added_in_b
 line7
"""

NEW_FILE_DIFF = """\
diff --git a/newfile.py b/newfile.py
new file mode 100644
--- /dev/null
+++ b/newfile.py
@@ -0,0 +1,3 @@
+line1
+line2
+line3
"""

DELETED_FILE_DIFF = """\
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1,3 +0,0 @@
-line1
-line2
-line3
"""

RENAME_DIFF = """\
diff --git a/old_name.py b/new_name.py
similarity index 90%
rename from old_name.py
rename to new_name.py
--- a/old_name.py
+++ b/new_name.py
@@ -1,3 +1,4 @@
 same
 same
+added
 same
"""

MULTI_HUNK_DIFF = """\
diff --git a/multi.py b/multi.py
--- a/multi.py
+++ b/multi.py
@@ -2,3 +2,4 @@
 ctx
+add_at_3
 ctx
 ctx
@@ -20,3 +21,4 @@
 ctx
+add_at_22
 ctx
 ctx
"""

BINARY_DIFF = """\
diff --git a/image.png b/image.png
Binary files a/image.png and b/image.png differ
"""


class TestParseUnifiedDiff:

    def test_simple_addition(self):
        result = parse_unified_diff(SIMPLE_DIFF)
        assert "src/foo.py" in result
        assert result["src/foo.py"] == {13, 14}

    def test_multiple_files(self):
        result = parse_unified_diff(MULTI_FILE_DIFF)
        assert result["a.py"] == {2}
        assert result["b.py"] == {7}

    def test_new_file(self):
        result = parse_unified_diff(NEW_FILE_DIFF)
        assert result["newfile.py"] == {1, 2, 3}

    def test_deleted_file(self):
        result = parse_unified_diff(DELETED_FILE_DIFF)
        assert "old.py" not in result

    def test_renamed_file(self):
        result = parse_unified_diff(RENAME_DIFF)
        assert "new_name.py" in result
        assert 3 in result["new_name.py"]

    def test_multiple_hunks(self):
        result = parse_unified_diff(MULTI_HUNK_DIFF)
        assert result["multi.py"] == {3, 22}

    def test_empty_diff(self):
        result = parse_unified_diff("")
        assert result == {}

    def test_binary_file_skipped(self):
        result = parse_unified_diff(BINARY_DIFF)
        assert result == {}

    def test_context_lines_advance_counter(self):
        diff = """\
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,5 +1,6 @@
 ctx1
 ctx2
 ctx3
+added_at_4
 ctx4
 ctx5
"""
        result = parse_unified_diff(diff)
        assert result["x.py"] == {4}

    def test_mixed_add_remove(self):
        diff = """\
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,4 +1,4 @@
 same
-old_line
+new_line
 same
 same
"""
        result = parse_unified_diff(diff)
        assert result["x.py"] == {2}


class TestGetChangedFilesFromDiff:

    def test_extracts_file_paths(self):
        result = get_changed_files_from_diff(MULTI_FILE_DIFF)
        assert result == ["a.py", "b.py"]

    def test_new_file(self):
        result = get_changed_files_from_diff(NEW_FILE_DIFF)
        assert result == ["newfile.py"]

    def test_deleted_file_excluded(self):
        result = get_changed_files_from_diff(DELETED_FILE_DIFF)
        assert result == []

    def test_empty_diff(self):
        result = get_changed_files_from_diff("")
        assert result == []

    def test_binary_file_excluded(self):
        result = get_changed_files_from_diff(BINARY_DIFF)
        assert result == []


class TestFilterFindingsByChangedLines:

    def test_keeps_findings_on_changed_lines(self):
        findings = [{"file_path": "a.py", "line_number": 5, "rule_id": "X"}]
        changed = {"a.py": {5, 6, 7}}
        result = filter_findings_by_changed_lines(findings, changed)
        assert len(result) == 1

    def test_removes_findings_on_unchanged_lines(self):
        findings = [{"file_path": "a.py", "line_number": 10, "rule_id": "X"}]
        changed = {"a.py": {5, 6, 7}}
        result = filter_findings_by_changed_lines(findings, changed)
        assert len(result) == 0

    def test_keeps_findings_without_line_number(self):
        findings = [{"file_path": "a.py", "line_number": None, "rule_id": "X"}]
        changed = {"a.py": {5}}
        result = filter_findings_by_changed_lines(findings, changed)
        assert len(result) == 1

    def test_keeps_findings_for_unknown_files(self):
        findings = [{"file_path": "unknown.py", "line_number": 1, "rule_id": "X"}]
        changed = {"a.py": {1}}
        result = filter_findings_by_changed_lines(findings, changed)
        assert len(result) == 1

    def test_empty_changed_lines(self):
        findings = [{"file_path": "a.py", "line_number": 1, "rule_id": "X"}]
        result = filter_findings_by_changed_lines(findings, {})
        assert len(result) == 1

    def test_mixed_findings(self):
        findings = [
            {"file_path": "a.py", "line_number": 5, "rule_id": "X"},
            {"file_path": "a.py", "line_number": 99, "rule_id": "Y"},
            {"file_path": "b.py", "line_number": 1, "rule_id": "Z"},
            {"file_path": "a.py", "line_number": None, "rule_id": "W"},
        ]
        changed = {"a.py": {5, 6}}
        result = filter_findings_by_changed_lines(findings, changed)
        assert len(result) == 3
        rule_ids = [f["rule_id"] for f in result]
        assert "X" in rule_ids
        assert "Z" in rule_ids
        assert "W" in rule_ids
        assert "Y" not in rule_ids


class TestDetectPlatform:

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_github_detected(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="git@github.com:user/repo.git\n"
        )
        assert detect_platform() == "github"

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_github_https(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="https://github.com/user/repo.git\n"
        )
        assert detect_platform() == "github"

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_gitlab_detected(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="git@gitlab.com:user/repo.git\n"
        )
        assert detect_platform() == "gitlab"

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_self_hosted_gitlab(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="https://gitlab.example.com/group/repo.git\n"
        )
        assert detect_platform() == "gitlab"

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_unknown_platform(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="https://bitbucket.org/user/repo.git\n"
        )
        assert detect_platform() == "unknown"

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_git_error(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="error")
        assert detect_platform() == "unknown"

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_git_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        assert detect_platform() == "unknown"


class TestGetMergeBase:

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_explicit_base(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0, stdout="abc123\n")
        result = get_merge_base(base_ref="origin/main")
        assert result == "abc123"
        mock_run.assert_called_once()

    @mock.patch("ai_guardian.diff_provider._detect_default_branch")
    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_auto_detect_base(self, mock_run, mock_detect):
        mock_detect.return_value = "origin/main"
        mock_run.return_value = mock.Mock(returncode=0, stdout="def456\n")
        result = get_merge_base()
        assert result == "def456"
        mock_detect.assert_called_once()

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_merge_base_fails(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=1, stdout="", stderr="fatal: not a commit"
        )
        with pytest.raises(DiffProviderError, match="merge base"):
            get_merge_base(base_ref="nonexistent")


class TestGetPRDiff:

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_success_with_number(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="diff content here\n", stderr=""
        )
        result = get_pr_diff("123")
        assert result == "diff content here\n"
        cmd = mock_run.call_args[0][0]
        assert cmd == ["gh", "pr", "diff", "123"]

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_success_with_url(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="diff from url\n", stderr=""
        )
        url = "https://github.com/owner/repo/pull/456"
        result = get_pr_diff(url)
        assert result == "diff from url\n"
        cmd = mock_run.call_args[0][0]
        assert cmd == ["gh", "pr", "diff", url]

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_gh_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        with pytest.raises(DiffProviderError, match="gh CLI not found"):
            get_pr_diff("123")

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_gh_error(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="not found")
        with pytest.raises(DiffProviderError, match="gh pr diff failed"):
            get_pr_diff("999")

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_gh_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="gh", timeout=30)
        with pytest.raises(DiffProviderError, match="timed out"):
            get_pr_diff("123")


class TestGetMRDiff:

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_success_with_number(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="mr diff content\n", stderr=""
        )
        result = get_mr_diff("42")
        assert result == "mr diff content\n"
        cmd = mock_run.call_args[0][0]
        assert cmd == ["glab", "mr", "diff", "42"]

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_success_with_url(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="mr diff from url\n", stderr=""
        )
        url = "https://gitlab.cee.redhat.com/atat/harness/-/merge_requests/127"
        result = get_mr_diff(url)
        assert result == "mr diff from url\n"
        cmd = mock_run.call_args[0][0]
        assert cmd == [
            "glab",
            "mr",
            "diff",
            "127",
            "--repo",
            "https://gitlab.cee.redhat.com/atat/harness",
        ]

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_glab_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        with pytest.raises(DiffProviderError, match="glab CLI not found"):
            get_mr_diff("42")

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_glab_error(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="error")
        with pytest.raises(DiffProviderError, match="glab mr diff failed"):
            get_mr_diff("42")

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_glab_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="glab", timeout=30)
        with pytest.raises(DiffProviderError, match="timed out"):
            get_mr_diff("42")


class TestParsePRRef:

    def test_integer_string(self):
        assert parse_pr_ref("123") == 123

    def test_github_url(self):
        assert parse_pr_ref("https://github.com/owner/repo/pull/456") == 456

    def test_github_url_with_trailing(self):
        assert parse_pr_ref("https://github.com/org/repo/pull/789/files") == 789

    def test_invalid_value(self):
        with pytest.raises(DiffProviderError, match="Cannot parse PR number"):
            parse_pr_ref("not-a-number-or-url")


class TestParseMRRef:

    def test_integer_string(self):
        mr_num, repo_url = parse_mr_ref("42")
        assert mr_num == 42
        assert repo_url is None

    def test_gitlab_url(self):
        url = "https://gitlab.com/group/project/-/merge_requests/127"
        mr_num, repo_url = parse_mr_ref(url)
        assert mr_num == 127
        assert repo_url == "https://gitlab.com/group/project"

    def test_self_hosted_gitlab_url(self):
        url = "https://gitlab.cee.redhat.com/atat/harness/-/merge_requests/127"
        mr_num, repo_url = parse_mr_ref(url)
        assert mr_num == 127
        assert repo_url == "https://gitlab.cee.redhat.com/atat/harness"

    def test_invalid_value(self):
        with pytest.raises(DiffProviderError, match="Cannot parse MR number"):
            parse_mr_ref("not-a-number-or-url")


class TestExtractFileContentsFromDiff:

    def test_simple_addition(self):
        result = extract_file_contents_from_diff(SIMPLE_DIFF)
        assert "src/foo.py" in result
        assert "new_line_1()" in result["src/foo.py"]
        assert "new_line_2()" in result["src/foo.py"]

    def test_context_lines_included(self):
        result = extract_file_contents_from_diff(SIMPLE_DIFF)
        assert "pass" in result["src/foo.py"]

    def test_multiple_files(self):
        result = extract_file_contents_from_diff(MULTI_FILE_DIFF)
        assert "a.py" in result
        assert "b.py" in result
        assert "added_in_a" in result["a.py"]
        assert "added_in_b" in result["b.py"]

    def test_new_file(self):
        result = extract_file_contents_from_diff(NEW_FILE_DIFF)
        assert "newfile.py" in result
        assert "line1" in result["newfile.py"]

    def test_deleted_file_excluded(self):
        result = extract_file_contents_from_diff(DELETED_FILE_DIFF)
        assert "old.py" not in result

    def test_renamed_file(self):
        result = extract_file_contents_from_diff(RENAME_DIFF)
        assert "new_name.py" in result
        assert "added" in result["new_name.py"]

    def test_empty_diff(self):
        result = extract_file_contents_from_diff("")
        assert result == {}

    def test_binary_diff(self):
        result = extract_file_contents_from_diff(BINARY_DIFF)
        assert result == {}

    def test_multiple_hunks(self):
        result = extract_file_contents_from_diff(MULTI_HUNK_DIFF)
        assert "multi.py" in result
        assert "add_at_3" in result["multi.py"]
        assert "add_at_22" in result["multi.py"]

    def test_deleted_lines_excluded(self):
        diff = """\
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,4 +1,4 @@
 same
-old_line
+new_line
 same
 same
"""
        result = extract_file_contents_from_diff(diff)
        assert "new_line" in result["x.py"]
        assert "old_line" not in result["x.py"]


class TestGetStagedDiff:

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="diff --cached output\n", stderr=""
        )
        result = get_staged_diff()
        assert result == "diff --cached output\n"
        cmd = mock_run.call_args[0][0]
        assert cmd == ["git", "diff", "--cached"]

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_custom_repo_path(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="staged diff\n", stderr=""
        )
        get_staged_diff(repo_path="/some/repo")
        assert mock_run.call_args[1]["cwd"] == "/some/repo"

    @mock.patch("ai_guardian.diff_provider.subprocess.run")
    def test_error(self, mock_run):
        mock_run.return_value = mock.Mock(
            returncode=1, stdout="", stderr="fatal: not a git repo"
        )
        with pytest.raises(DiffProviderError, match="git diff --cached failed"):
            get_staged_diff()
