"""
Unit tests for ai-guardian self-protection feature (Issue #32)

Tests the IMMUTABLE_DENY_PATTERNS that protect:
- ai-guardian configuration files
- IDE hook configuration files (Claude, Cursor)
- ai-guardian package source code
"""

import json
import pytest
from ai_guardian.tool_policy import ToolPolicyChecker


@pytest.fixture
def policy_checker():
    """Create policy checker with empty config (only immutable deny patterns)."""
    return ToolPolicyChecker(config={"permissions": []})


# ============================================================================
# Parametrized: Write-blocks protected paths
# ============================================================================

WRITE_BLOCKED_PATHS = [
    pytest.param(
        "/home/user/.config/ai-guardian/ai-guardian.json", None,
        id="user-config-file",
    ),
    pytest.param(
        "/home/user/my-project/.ai-guardian.json", None,
        id="project-config-file",
    ),
    pytest.param(
        "/tmp/test-ai-guardian.json", None,
        id="any-ai-guardian-json",
    ),
    pytest.param(
        "/home/user/.cursor/hooks.json", None,
        id="cursor-hooks",
    ),
    pytest.param(
        "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py", None,
        id="package-source-site-packages",
    ),
]


@pytest.mark.parametrize("file_path,content", WRITE_BLOCKED_PATHS)
def test_write_blocks_protected_path(policy_checker, file_path, content):
    """AI cannot write to protected paths"""
    tool_input = {"file_path": file_path}
    if content is not None:
        tool_input["content"] = content

    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Write", "input": tool_input},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"Write to {file_path} should be blocked"
    assert error_msg is not None, "Error message should be provided"


# ============================================================================
# Parametrized: Write-blocks with content-aware hook checks
# ============================================================================

WRITE_BLOCKED_WITH_HOOKS_CONTENT = [
    pytest.param(
        "/home/user/.claude/settings.json",
        json.dumps({
            "hooks": {"PreToolUse": [{"matcher": "*", "hooks": []}]},
            "model": "claude-sonnet-4-5-20250514",
        }),
        id="claude-settings-with-hooks",
    ),
    pytest.param(
        "C:/Users/user/AppData/Roaming/Claude/settings.json",
        json.dumps({
            "hooks": {"PreToolUse": [{"matcher": "*"}]},
            "model": "claude-sonnet-4-5-20250514",
        }),
        id="windows-claude-settings-with-hooks",
    ),
]


@pytest.mark.parametrize("file_path,content", WRITE_BLOCKED_WITH_HOOKS_CONTENT)
def test_write_blocks_settings_with_hooks(policy_checker, file_path, content):
    """AI cannot write hooks to IDE settings files (content-aware, Issue #807)"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Write",
            "input": {"file_path": file_path, "content": content},
        },
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"Write with hooks to {file_path} should be blocked"
    assert "Hook Protection" in error_msg


# ============================================================================
# Parametrized: Edit-blocks protected paths
# ============================================================================

EDIT_BLOCKED_PATHS = [
    pytest.param(
        "/home/user/.config/ai-guardian/ai-guardian.json",
        '"enabled": true', '"enabled": false',
        id="user-config-file",
    ),
    pytest.param(
        "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
        "IMMUTABLE_DENY_PATTERNS", "DISABLED",
        id="package-source",
    ),
]


@pytest.mark.parametrize("file_path,old_string,new_string", EDIT_BLOCKED_PATHS)
def test_edit_blocks_protected_path(policy_checker, file_path, old_string, new_string):
    """AI cannot edit protected paths"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Edit",
            "input": {
                "file_path": file_path,
                "old_string": old_string,
                "new_string": new_string,
            },
        },
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"Edit of {file_path} should be blocked"
    assert "Protection:" in error_msg


def test_edit_blocks_claude_settings_hooks(policy_checker):
    """AI cannot edit hooks in ~/.claude/settings.json (content-aware, Issue #807)"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Edit",
            "input": {
                "file_path": "/home/user/.claude/settings.json",
                "old_string": '"hooks": {"PreToolUse": []}',
                "new_string": '"hooks": {}'
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, "Edit of Claude settings hooks should be blocked"
    assert "Hook Protection" in error_msg


# ============================================================================
# Parametrized: Bash command blocks
# ============================================================================

BASH_BLOCKED_COMMANDS = [
    # sed/awk on config
    pytest.param(
        "sed -i 's/enabled\":true/enabled\":false/' ~/.config/ai-guardian/ai-guardian.json",
        id="sed-on-config",
    ),
    pytest.param(
        "awk '{gsub(/enabled\":true/, \"enabled\":false\")}1' ai-guardian.json > tmp && mv tmp ai-guardian.json",
        id="awk-on-config",
    ),
    # sed on Claude settings and package source
    pytest.param(
        "sed -i 's/ai-guardian//' ~/.claude/settings.json",
        id="sed-on-claude-settings",
    ),
    pytest.param(
        "sed -i 's/IMMUTABLE/DISABLED/' /usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
        id="sed-on-package-source",
    ),
    # vim/nano on settings/hooks
    pytest.param(
        "vim ~/.claude/settings.json",
        id="vim-on-claude-settings",
    ),
    pytest.param(
        "nano ~/.cursor/hooks.json",
        id="nano-on-cursor-hooks",
    ),
    # echo/cat redirect
    pytest.param(
        "echo '{}' > ~/.config/ai-guardian/ai-guardian.json",
        id="echo-redirect-to-config",
    ),
    pytest.param(
        "cat /dev/null > ~/.claude/settings.json",
        id="redirect-to-claude-settings",
    ),
    # rm/mv
    pytest.param(
        "rm ~/.config/ai-guardian/ai-guardian.json",
        id="rm-config",
    ),
    pytest.param(
        "rm -f ~/.claude/settings.json",
        id="rm-claude-settings",
    ),
    pytest.param(
        "mv ~/.config/ai-guardian/ai-guardian.json /tmp/backup.json",
        id="mv-config",
    ),
    pytest.param(
        "mv .ai-guardian.json /tmp/backup.json",
        id="mv-hidden-config",
    ),
    # chmod/chattr
    pytest.param(
        "chmod 777 ~/.config/ai-guardian/ai-guardian.json",
        id="chmod-on-config",
    ),
    pytest.param(
        "chattr -i ~/.claude/settings.json",
        id="chattr-on-claude-settings",
    ),
    # cat/grep/head/tail/less/more on config/state/cache (Issue #512)
    pytest.param(
        "cat ~/.config/ai-guardian/ai-guardian.json",
        id="cat-config",
    ),
    pytest.param(
        "cat ~/.local/state/ai-guardian/violations.jsonl",
        id="cat-state",
    ),
    pytest.param(
        "cat ~/.cache/ai-guardian/patterns.toml",
        id="cat-cache",
    ),
    pytest.param(
        "cat ai-guardian.json",
        id="cat-any-ai-guardian-json",
    ),
    pytest.param(
        "grep -i 'allow' ~/.config/ai-guardian/ai-guardian.json",
        id="grep-config",
    ),
    pytest.param(
        "grep 'secret' ~/.local/state/ai-guardian/violations.jsonl",
        id="grep-state",
    ),
    pytest.param(
        "head -50 ~/.local/state/ai-guardian/ai-guardian.log",
        id="head-log",
    ),
    pytest.param(
        "tail -f ~/.local/state/ai-guardian/ai-guardian.log",
        id="tail-log",
    ),
    pytest.param(
        "less ai-guardian.json",
        id="less-config",
    ),
    pytest.param(
        "more ai-guardian.json",
        id="more-config",
    ),
    # Issue #188 - still blocks actual config
    pytest.param(
        "echo 'malicious content' > ~/.config/ai-guardian/ai-guardian.json",
        id="redirect-to-actual-config-issue-188",
    ),
]


@pytest.mark.parametrize("command", BASH_BLOCKED_COMMANDS)
def test_bash_blocks_command(policy_checker, command):
    """AI cannot use Bash to modify/read protected files"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Bash", "input": {"command": command}},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"Bash command should be blocked: {command}"


# ============================================================================
# Parametrized: .ai-read-deny Write blocks
# ============================================================================

AI_READ_DENY_WRITE_PATHS = [
    pytest.param(
        "/home/user/secrets/.ai-read-deny",
        id="write-marker",
    ),
    pytest.param(
        "/var/lib/sensitive/.ai-read-deny",
        id="write-absolute-path",
    ),
    pytest.param(
        "/home/user/project/a/b/c/.ai-read-deny",
        id="write-nested-path",
    ),
]


@pytest.mark.parametrize("file_path", AI_READ_DENY_WRITE_PATHS)
def test_write_blocks_ai_read_deny(policy_checker, file_path):
    """AI cannot write to .ai-read-deny marker files"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Write", "input": {"file_path": file_path}},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"Write to {file_path} should be blocked"
    assert error_msg is not None, "Error message should be provided"
    assert "Protection:" in error_msg
    assert "Directory Protection Marker" in error_msg


def test_edit_blocks_ai_read_deny_marker(policy_checker):
    """AI cannot edit .ai-read-deny marker file"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Edit",
            "input": {
                "file_path": "/home/user/secrets/.ai-read-deny",
                "old_string": "",
                "new_string": "test"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, "Edit of .ai-read-deny should be blocked"
    assert "Protection:" in error_msg
    assert "Directory Protection Marker" in error_msg


# ============================================================================
# Parametrized: .ai-read-deny Bash blocks
# ============================================================================

AI_READ_DENY_BASH_COMMANDS = [
    pytest.param("rm /home/user/secrets/.ai-read-deny", id="rm-absolute"),
    pytest.param("rm secrets/.ai-read-deny", id="rm-relative"),
    pytest.param("rm -rf /home/user/project/.ai-read-deny", id="rm-rf"),
    pytest.param("mv /home/user/secrets/.ai-read-deny /tmp/backup", id="mv"),
    pytest.param("mv .ai-read-deny .ai-read-deny.bak", id="mv-rename"),
    pytest.param("sed -i 's/test/new/' /home/user/secrets/.ai-read-deny", id="sed"),
    pytest.param("awk '{print}' .ai-read-deny > /tmp/out", id="awk"),
    pytest.param("echo '' > /home/user/secrets/.ai-read-deny", id="echo-redirect"),
    pytest.param("cat /dev/null > .ai-read-deny", id="cat-redirect"),
    pytest.param("chmod 777 /home/user/secrets/.ai-read-deny", id="chmod"),
    pytest.param("chattr +i /home/user/secrets/.ai-read-deny", id="chattr"),
    pytest.param("vim /home/user/secrets/.ai-read-deny", id="vim"),
    pytest.param("nano .ai-read-deny", id="nano"),
]


@pytest.mark.parametrize("command", AI_READ_DENY_BASH_COMMANDS)
def test_bash_blocks_ai_read_deny(policy_checker, command):
    """AI cannot use Bash to modify/delete .ai-read-deny markers"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Bash", "input": {"command": command}},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"Bash on .ai-read-deny should be blocked: {command}"


# ============================================================================
# Parametrized: Allow tests - Write
# ============================================================================

WRITE_ALLOWED_PATHS = [
    pytest.param(
        "/home/user/my-project/src/main.py", None,
        id="normal-file",
    ),
    pytest.param(
        "/home/user/my_ai_guardian_project/src/main.py", None,
        id="user-project-ai-guardian-in-name",
    ),
    pytest.param(
        "/home/user/backup_ai_guardian_configs/settings.json", None,
        id="backup-dir-ai-guardian",
    ),
    pytest.param(
        "/home/user/projects/ai_guardian_tutorial/example.py", None,
        id="tutorial-dir-ai-guardian",
    ),
    pytest.param(
        "/home/user/my-project/docs/ai-guardian-setup.md", None,
        id="doc-file-mentioning-ai-guardian-issue-188",
    ),
    pytest.param(
        "/home/user/ai-guardian/src/ai_guardian/__main__.py", "# Modified source",
        id="dev-source-main",
    ),
    pytest.param(
        "/home/user/ai-guardian/src/ai_guardian/__init__.py", "# Modified source",
        id="dev-source-init",
    ),
]


@pytest.mark.parametrize("file_path,content", WRITE_ALLOWED_PATHS)
def test_write_allows_non_protected(policy_checker, file_path, content):
    """AI can write to non-protected files and development source"""
    tool_input = {"file_path": file_path}
    if content is not None:
        tool_input["content"] = content

    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Write", "input": tool_input},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert is_allowed, f"Write to {file_path} should be allowed"
    assert error_msg is None, "No error message for allowed operation"


EDIT_ALLOWED_CASES = [
    pytest.param(
        "/home/user/my-project/README.md",
        "old", "new",
        id="normal-file",
    ),
    pytest.param(
        "/home/user/my_ai_guardian_project/config.py",
        "DEBUG = False", "DEBUG = True",
        id="user-project-ai-guardian-in-name",
    ),
    pytest.param(
        "/home/user/my-project/docs/tools.md",
        "ai-guardian v1.0", "ai-guardian v1.1",
        id="user-file-ai-guardian-content-issue-188",
    ),
]


@pytest.mark.parametrize("file_path,old_string,new_string", EDIT_ALLOWED_CASES)
def test_edit_allows_non_protected(policy_checker, file_path, old_string, new_string):
    """AI can edit non-protected files"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Edit",
            "input": {
                "file_path": file_path,
                "old_string": old_string,
                "new_string": new_string,
            },
        },
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert is_allowed, f"Edit of {file_path} should be allowed"


BASH_ALLOWED_COMMANDS = [
    pytest.param(
        "ls -la /home/user/my-project",
        id="normal-command",
    ),
    pytest.param(
        "sed -i 's/old/new/' /home/user/my_ai_guardian_project/config.py",
        id="sed-on-user-project-ai-guardian",
    ),
    pytest.param(
        "mv generate-ai-guardian-config.sh includes/",
        id="mv-user-script-ai-guardian-name",
    ),
    pytest.param(
        "mv my-ai-guardian-helper.py scripts/",
        id="mv-user-python-script-ai-guardian-name",
    ),
    # Issue #188 - legitimate content mentioning ai-guardian
    pytest.param(
        "echo 'The ai-guardian hook prevented the secret from being committed' > /tmp/review.md",
        id="write-code-review-mentioning-ai-guardian",
    ),
    pytest.param(
        "echo 'Install ai-guardian using pip install ai-guardian' > /home/user/docs/README.md",
        id="write-docs-about-ai-guardian",
    ),
    pytest.param(
        "cat <<'EOF' > /tmp/bug-report.txt\nThe ai-guardian configuration needs to be updated\nEOF",
        id="write-bug-report-mentioning-ai-guardian",
    ),
    pytest.param(
        "sed -i 's/old/new/' /home/user/my-project/docs/using-ai-guardian.md",
        id="sed-on-user-doc-file",
    ),
]


@pytest.mark.parametrize("command", BASH_ALLOWED_COMMANDS)
def test_bash_allows_command(policy_checker, command):
    """AI can use Bash for normal/legitimate commands"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Bash", "input": {"command": command}},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert is_allowed, f"Bash command should be allowed: {command}"
    assert error_msg is None, "No error for allowed operation"


# ============================================================================
# Parametrized: Read blocks (Issue #512)
# ============================================================================

READ_BLOCKED_PATHS = [
    pytest.param("/home/user/.config/ai-guardian/ai-guardian.json", id="user-config"),
    pytest.param("/home/user/my-project/.ai-guardian.json", id="project-config"),
    pytest.param("/home/user/.config/ai-guardian/profiles/default.json", id="config-directory"),
    pytest.param("/home/user/.local/state/ai-guardian/violations.jsonl", id="state-directory"),
    pytest.param("/home/user/.local/state/ai-guardian/ai-guardian.log", id="state-log"),
    pytest.param("/home/user/.local/state/ai-guardian/transcript_positions.json", id="state-transcript-positions"),
    pytest.param("/home/user/.cache/ai-guardian/patterns.toml", id="cache-directory"),
]


@pytest.mark.parametrize("file_path", READ_BLOCKED_PATHS)
def test_read_blocks_protected_path(policy_checker, file_path):
    """AI cannot read ai-guardian config/state/cache files (Issue #512)"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Read", "input": {"file_path": file_path}},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"Read of {file_path} should be blocked"


READ_ALLOWED_PATHS = [
    pytest.param("/home/user/my-project/src/main.py", id="normal-file"),
    pytest.param("/home/user/ai-guardian/src/ai_guardian/__init__.py", id="development-source"),
]


@pytest.mark.parametrize("file_path", READ_ALLOWED_PATHS)
def test_read_allows_non_protected(policy_checker, file_path):
    """AI can read normal/development files"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Read", "input": {"file_path": file_path}},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert is_allowed, f"Read of {file_path} should be allowed"
    assert error_msg is None


# ============================================================================
# Test: Error messages are clear
# ============================================================================

def test_error_message_format(policy_checker):
    """Error messages should be clear and helpful"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Edit",
            "input": {
                "file_path": "/home/user/.config/ai-guardian/ai-guardian.json",
                "old_string": "test",
                "new_string": "test2"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert "Protection:" in error_msg
    assert "ai-guardian.json" in error_msg
    assert "Edit" in error_msg
    assert "ai-guardian configuration" in error_msg
    assert "IDE hook configuration" in error_msg
    assert "package source code" in error_msg
    assert ".ai-read-deny marker files" in error_msg
    assert "cannot be disabled via configuration" in error_msg
    assert "Use your text editor to modify these files" in error_msg


def test_error_message_format_hook_protection(policy_checker):
    """Hook protection messages for mixed settings files (Issue #807)"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Edit",
            "input": {
                "file_path": "/home/user/.claude/settings.json",
                "old_string": '"hooks": {}',
                "new_string": '"hooks": {"PreToolUse": []}'
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed
    assert "Hook Protection" in error_msg
    assert "/home/user/.claude/settings.json" in error_msg
    assert "Edit" in error_msg
    assert "Non-hook settings" in error_msg
    assert "cannot be disabled via configuration" in error_msg


def test_error_message_marker_file_format(policy_checker):
    """Error message for .ai-read-deny should mention directory protection"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Write",
            "input": {
                "file_path": "/home/user/secrets/.ai-read-deny"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert "Protection:" in error_msg
    assert "/home/user/secrets/.ai-read-deny" in error_msg
    assert "Write" in error_msg
    assert "Directory Protection Marker" in error_msg
    assert ".ai-read-deny markers enforce directory protection" in error_msg
    assert "bypass directory protection" in error_msg
    assert "delete .ai-read-deny manually" in error_msg


# ============================================================================
# Test: Workaround tip for documentation files (Issue #65)
# ============================================================================

def test_error_message_includes_workaround_tip_for_write_protected_md_file(policy_checker):
    """Error message includes tip when writing to protected .md file with ai-guardian in name"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Write",
            "input": {
                "file_path": "/home/user/project/.config/ai-guardian/docs/setup.md"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed
    assert "\U0001f4a1 TIP" in error_msg
    assert "ai - guardian" in error_msg
    assert "with spaces" in error_msg
    assert "Writing ABOUT the tool" in error_msg


def test_error_message_for_pip_installed_readme(policy_checker):
    """Error message for pip-installed README explains it's production code"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Edit",
            "input": {
                "file_path": "/usr/lib/python3.12/site-packages/ai_guardian/README.md",
                "old_string": "old",
                "new_string": "new"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed
    assert "Pip-installed" in error_msg
    assert "security controls in production" in error_msg
    assert "git clone" in error_msg
    assert "Development source files CAN be edited" in error_msg


def test_error_message_includes_workaround_tip_for_protected_txt_in_docs(policy_checker):
    """Error message includes tip for protected .txt file with ai-guardian in path"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Write",
            "input": {
                "file_path": "/home/user/.config/ai-guardian/README.txt"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed
    assert "\U0001f4a1 TIP" in error_msg


NO_TIP_CASES = [
    pytest.param(
        "Write",
        {"file_path": "/home/user/.config/ai-guardian/ai-guardian.json"},
        id="protected-config-file",
    ),
    pytest.param(
        "Edit",
        {
            "file_path": "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
            "old_string": "old",
            "new_string": "new",
        },
        id="protected-python-source",
    ),
    pytest.param(
        "Write",
        {"file_path": "/home/user/.claude/hooks.json"},
        id="ide-settings-no-ai-guardian",
    ),
]


@pytest.mark.parametrize("tool_name_param,tool_input", NO_TIP_CASES)
def test_error_message_no_tip_for_non_doc_protected(policy_checker, tool_name_param, tool_input):
    """Error message should NOT include tip for actual protected config/source/IDE files"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": tool_name_param, "input": tool_input},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed
    assert "\U0001f4a1 TIP" not in error_msg


# ============================================================================
# Parametrized: Issue #113 - Fail-closed when file_path missing
# ============================================================================

MISSING_FILE_PATH_CASES = [
    pytest.param("Edit", {"input": {}}, id="edit-empty-input"),
    pytest.param("Write", {}, id="write-missing-input"),
    pytest.param("Read", {"input": {"limit": 100}}, id="read-other-params"),
    pytest.param("NotebookEdit", {"input": {}}, id="notebookedit-empty-input"),
]


@pytest.mark.parametrize("tool_name_param,tool_use_extra", MISSING_FILE_PATH_CASES)
def test_blocks_when_file_path_missing_issue_113(policy_checker, tool_name_param, tool_use_extra):
    """
    Issue #113: AI cannot bypass IMMUTABLE checks by sending malformed tool_input.
    For file-path tools, fail-closed (block) if file_path is missing.
    """
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": tool_name_param, **tool_use_extra},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"{tool_name_param} with missing file_path should be blocked"
    assert error_msg is not None, "Error message should be provided"
    assert "Missing required parameter" in error_msg
    assert "file_path" in error_msg


# ============================================================================
# Test: Read error message mentions MCP alternative (Issue #512)
# ============================================================================

def test_read_error_message_mentions_mcp_alternative(policy_checker):
    """Read error message should suggest MCP tools as safe alternative"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Read",
            "input": {
                "file_path": "/home/user/.config/ai-guardian/ai-guardian.json"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed
    assert "MCP tools" in error_msg
    assert "get_config()" in error_msg
    assert "get_violations()" in error_msg
    assert "doctor()" in error_msg


def test_read_error_message_for_state_file(policy_checker):
    """Read error message for state files should mention violations/logs"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Read",
            "input": {
                "file_path": "/home/user/.local/state/ai-guardian/violations.jsonl"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed
    assert "security state" in error_msg
    assert "detection results" in error_msg


def test_read_error_message_for_cache_file(policy_checker):
    """Read error message for cache files should mention patterns"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Read",
            "input": {
                "file_path": "/home/user/.cache/ai-guardian/patterns.toml"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed
    assert "cached security patterns" in error_msg
    assert "detection logic" in error_msg


if __name__ == '__main__':
    pytest.main([__file__])
