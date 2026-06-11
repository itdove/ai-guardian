"""
Diff provider for ai-guardian scan command.

Resolves file lists and changed line ranges from git diffs, GitHub PRs,
and GitLab MRs. Used by scan_command() when --diff, --pr, --mr, or
--stdin-diff flags are provided.
"""

import logging
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class DiffProviderError(Exception):
    """Raised when diff operations fail."""


_PR_URL_RE = re.compile(r"/pull/(\d+)")
_MR_URL_RE = re.compile(r"^(https?://.+)/-/merge_requests/(\d+)")


def parse_pr_ref(value: str) -> int:
    """Parse PR number from integer string or GitHub URL."""
    try:
        return int(value)
    except ValueError:
        pass
    m = _PR_URL_RE.search(value)
    if m:
        return int(m.group(1))
    raise DiffProviderError(
        f"Cannot parse PR number from: {value}\n"
        "Expected: a number (e.g., 123) or a GitHub PR URL"
    )


def parse_mr_ref(value: str) -> tuple:
    """Parse MR ref from integer string or GitLab URL.

    Returns (mr_number: int, repo_url: Optional[str]).
    repo_url is the project URL when parsed from a URL, None when just a number.
    """
    try:
        return int(value), None
    except ValueError:
        pass
    m = _MR_URL_RE.search(value)
    if m:
        return int(m.group(2)), m.group(1)
    raise DiffProviderError(
        f"Cannot parse MR number from: {value}\n"
        "Expected: a number (e.g., 42) or a GitLab MR URL"
    )


def detect_platform(repo_path: str = ".") -> str:
    """Detect hosting platform from git remote URL.

    Returns "github", "gitlab", or "unknown".
    """
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10, cwd=repo_path,
        )
        if result.returncode != 0:
            return "unknown"
        url = result.stdout.strip().lower()
        if "github.com" in url:
            return "github"
        if "gitlab" in url:
            return "gitlab"
        return "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"


def get_merge_base(base_ref: Optional[str] = None, repo_path: str = ".") -> str:
    """Get the merge base commit between base_ref and HEAD.

    If base_ref is None, auto-detects the default branch.
    """
    if base_ref is None:
        base_ref = _detect_default_branch(repo_path)

    try:
        result = subprocess.run(
            ["git", "merge-base", base_ref, "HEAD"],
            capture_output=True, text=True, timeout=10, cwd=repo_path,
        )
    except subprocess.TimeoutExpired:
        raise DiffProviderError(
            f"git merge-base timed out for '{base_ref}'"
        )
    if result.returncode != 0:
        raise DiffProviderError(
            f"Failed to find merge base for '{base_ref}': {result.stderr.strip()}"
        )
    return result.stdout.strip()


def _detect_default_branch(repo_path: str = ".") -> str:
    """Auto-detect the default branch (origin/main, origin/master, etc.)."""
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "origin/HEAD"],
        capture_output=True, text=True, timeout=10, cwd=repo_path,
    )
    if result.returncode == 0:
        ref = result.stdout.strip()
        if ref and ref != "origin/HEAD":
            return ref

    for candidate in ["origin/main", "origin/master"]:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", candidate],
            capture_output=True, text=True, timeout=10, cwd=repo_path,
        )
        if result.returncode == 0:
            return candidate

    raise DiffProviderError(
        "Could not detect default branch. Use --base to specify explicitly."
    )


def get_diff_unified(
    base_ref: Optional[str] = None, repo_path: str = "."
) -> str:
    """Get unified diff between base and HEAD."""
    merge_base = get_merge_base(base_ref, repo_path)
    result = subprocess.run(
        ["git", "diff", f"{merge_base}...HEAD"],
        capture_output=True, text=True, timeout=60, cwd=repo_path,
    )
    if result.returncode != 0:
        raise DiffProviderError(f"git diff failed: {result.stderr.strip()}")
    return result.stdout


def get_staged_diff(repo_path: str = ".") -> str:
    """Get unified diff of staged changes (git diff --cached)."""
    result = subprocess.run(
        ["git", "diff", "--cached"],
        capture_output=True, text=True, timeout=60, cwd=repo_path,
    )
    if result.returncode != 0:
        raise DiffProviderError(
            f"git diff --cached failed: {result.stderr.strip()}"
        )
    return result.stdout


def _run_cli_diff(
    cmd: List[str],
    tool_name: str,
    install_url: str,
    repo_path: str = ".",
) -> str:
    """Run a CLI tool to fetch a diff, with common error handling."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, cwd=repo_path,
        )
    except FileNotFoundError:
        raise DiffProviderError(
            f"{tool_name} CLI not found. Install from {install_url}"
        )
    except subprocess.TimeoutExpired:
        raise DiffProviderError(
            f"{' '.join(cmd[:3])} timed out after 30 seconds"
        )
    if result.returncode != 0:
        raise DiffProviderError(
            f"{' '.join(cmd[:3])} failed: {result.stderr.strip()}"
        )
    return result.stdout


def get_pr_diff(pr_ref: str, repo_path: str = ".") -> str:
    """Get unified diff for a GitHub PR using gh CLI.

    Args:
        pr_ref: PR number or full GitHub PR URL (gh accepts both)
    """
    return _run_cli_diff(
        ["gh", "pr", "diff", str(pr_ref)],
        "gh", "https://cli.github.com/", repo_path,
    )


def get_mr_diff(mr_ref: str, repo_path: str = ".") -> str:
    """Get unified diff for a GitLab MR using glab CLI.

    Args:
        mr_ref: MR number or GitLab MR URL. URLs are parsed to extract
                the number and repo, passing --repo to glab for cross-project use.
    """
    mr_number, repo_url = parse_mr_ref(mr_ref)
    cmd = ["glab", "mr", "diff", str(mr_number)]
    if repo_url:
        cmd.extend(["--repo", repo_url])
    return _run_cli_diff(
        cmd, "glab", "https://gitlab.com/gitlab-org/cli", repo_path,
    )


_DIFF_FILE_HEADER = re.compile(r"^\+\+\+ (?:b/)?(.+)$", re.MULTILINE)
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)
_DIFF_START = re.compile(r"^diff --git ", re.MULTILINE)


def extract_file_contents_from_diff(diff_text: str) -> Dict[str, str]:
    """Extract new-side file content from a unified diff.

    For each modified/added file, concatenates context lines and
    additions from every hunk.  Deleted files (target /dev/null) are
    skipped.  The result is NOT the full file — only the sections
    covered by diff hunks — but it is enough for security scanning.

    Returns dict mapping relative file path to extracted content.
    """
    contents: Dict[str, List[str]] = {}
    current_file: Optional[str] = None

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_file = None
            continue

        if line.startswith("+++ "):
            match = _DIFF_FILE_HEADER.match(line)
            if match:
                path = match.group(1)
                if path == "/dev/null":
                    current_file = None
                else:
                    current_file = path
                    if current_file not in contents:
                        contents[current_file] = []
            else:
                current_file = None
            continue

        if line.startswith("--- "):
            continue

        if _HUNK_HEADER.match(line):
            continue

        if current_file is None:
            continue

        if line.startswith("+"):
            contents[current_file].append(line[1:])
        elif line.startswith("-"):
            pass
        elif line.startswith("\\"):
            pass
        else:
            contents[current_file].append(line[1:] if line.startswith(" ") else line)

    return {path: "\n".join(lines) for path, lines in contents.items() if lines}


def parse_unified_diff(diff_text: str) -> Dict[str, Set[int]]:
    """Parse unified diff to extract changed line numbers per file.

    Only tracks lines with '+' prefix (additions) since those are
    the lines present in the working tree.

    Returns dict mapping file path -> set of 1-based line numbers.
    """
    changed_lines: Dict[str, Set[int]] = {}
    current_file: Optional[str] = None
    current_line = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            match = _DIFF_FILE_HEADER.match(line)
            if match:
                current_file = match.group(1)
                if current_file == "/dev/null":
                    current_file = None
                elif current_file not in changed_lines:
                    changed_lines[current_file] = set()
            else:
                current_file = None
            continue

        if line.startswith("--- "):
            continue

        hunk_match = _HUNK_HEADER.match(line)
        if hunk_match:
            current_line = int(hunk_match.group(1))
            continue

        if current_file is None:
            continue

        if line.startswith("+"):
            changed_lines[current_file].add(current_line)
            current_line += 1
        elif line.startswith("-"):
            pass  # deleted lines don't advance new-file line counter
        elif line.startswith("\\"):
            pass  # "\ No newline at end of file"
        else:
            # context line
            current_line += 1

    return changed_lines


def get_changed_files_from_diff(diff_text: str) -> List[str]:
    """Extract file paths from unified diff +++ headers.

    Skips deleted files (target is /dev/null).
    """
    files = []
    for match in _DIFF_FILE_HEADER.finditer(diff_text):
        path = match.group(1)
        if path != "/dev/null":
            files.append(path)
    return files


def filter_findings_by_changed_lines(
    findings: List[Dict[str, Any]],
    changed_lines: Dict[str, Set[int]],
) -> List[Dict[str, Any]]:
    """Filter findings to only those on changed lines.

    Findings without line_number are conservatively kept (cannot prove
    they are not on changed lines). Findings for files not in
    changed_lines are also kept (may come from include/config scanning).
    """
    filtered = []
    for finding in findings:
        file_path = finding.get("file_path", "")
        line_num = finding.get("line_number")

        if line_num is None:
            filtered.append(finding)
            continue

        if file_path not in changed_lines:
            filtered.append(finding)
            continue

        if line_num in changed_lines[file_path]:
            filtered.append(finding)

    return filtered
