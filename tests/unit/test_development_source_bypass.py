"""
Unit tests for development source bypass feature

Tests the scoped bypass that allows contributors to edit development source code
while keeping config files, hooks, cache, and pip-installed code always protected.

This enables standard open-source contribution workflow (fork + PR + review).
"""

import json
import pytest
from pathlib import Path
from ai_guardian.tool_policy import ToolPolicyChecker


@pytest.fixture
def policy_checker():
    """Create policy checker with empty config."""
    return ToolPolicyChecker(config={"permissions": []})


# ============================================================================
# Test: _should_skip_immutable_protection logic
# ============================================================================

CONFIG_FILES_ALWAYS_PROTECTED = [
    pytest.param("/home/user/.config/ai-guardian/ai-guardian.json", id="user-config"),
    pytest.param("/home/user/project/.ai-guardian.json", id="project-config"),
    pytest.param("/home/user/.cache/ai-guardian/maintainer-status.json", id="cache"),
    pytest.param("/home/user/.claude/settings.json", id="claude-settings"),
    pytest.param("/home/user/.cursor/hooks.json", id="cursor-hooks"),
    pytest.param("/home/user/project/.ai-read-deny", id="ai-read-deny"),
]


@pytest.mark.parametrize("file_path", CONFIG_FILES_ALWAYS_PROTECTED)
def test_config_files_always_protected(policy_checker, file_path):
    """Config files are ALWAYS protected, even for repo owners"""
    result = policy_checker._should_skip_immutable_protection(file_path, "Write")
    assert not result, f"Config file should always be protected: {file_path}"


NON_SOURCE_FILES_PROTECTED = [
    pytest.param("/home/user/other-project/file.py", id="other-project"),
    pytest.param(
        "/usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
        id="site-packages",
    ),
]


@pytest.mark.parametrize("file_path", NON_SOURCE_FILES_PROTECTED)
def test_non_source_files_protected(policy_checker, file_path):
    """Non-source files are protected"""
    result = policy_checker._should_skip_immutable_protection(file_path, "Write")
    assert not result, f"Non-source file should be protected: {file_path}"


SOURCE_FILES_ALLOWED = [
    pytest.param(
        "/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
        id="src-tool-policy",
    ),
    pytest.param(
        "/home/user/ai-guardian/tests/test_self_protection.py",
        id="tests",
    ),
    pytest.param(
        "/home/user/ai-guardian/README.md",
        id="readme",
    ),
    pytest.param(
        "/home/user/ai-guardian/pyproject.toml",
        id="pyproject",
    ),
    pytest.param(
        "/home/user/ai-guardian/.github/workflows/test.yml",
        id="github-workflows",
    ),
]


@pytest.mark.parametrize("file_path", SOURCE_FILES_ALLOWED)
def test_source_files_allowed_for_contributors(policy_checker, file_path):
    """Source files allowed for contributors (fork + PR workflow)"""
    result = policy_checker._should_skip_immutable_protection(file_path, "Write")
    assert result, f"Source file should be allowed for contributors: {file_path}"


# ============================================================================
# Parametrized: Integration - contributor can write/edit source
# ============================================================================

CONTRIBUTOR_ALLOWED_WRITE_EDIT = [
    pytest.param(
        "Write",
        "/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
        id="write-source-code",
    ),
    pytest.param(
        "Edit",
        "/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
        id="edit-source-code",
    ),
    pytest.param(
        "Write",
        "/home/user/ai-guardian/tests/test_new_feature.py",
        id="write-tests",
    ),
    pytest.param(
        "Edit",
        "/home/user/ai-guardian/README.md",
        id="edit-documentation",
    ),
]


@pytest.mark.parametrize("tool_name,file_path", CONTRIBUTOR_ALLOWED_WRITE_EDIT)
def test_contributor_can_write_edit_source(policy_checker, tool_name, file_path):
    """Contributors can write/edit ai-guardian source code and tests"""
    tool_input = {"file_path": file_path}
    if tool_name == "Edit":
        tool_input.update({"old_string": "old", "new_string": "new"})

    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": tool_name, "input": tool_input},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert is_allowed, f"Contributors should be allowed to {tool_name} source code"
    assert error_msg is None


# ============================================================================
# Parametrized: Config/hooks/cache always blocked
# ============================================================================

CONTRIBUTOR_BLOCKED_PATHS = [
    pytest.param(
        "Write",
        "/home/user/.config/ai-guardian/ai-guardian.json",
        "Protection:",
        id="config-blocked",
    ),
    pytest.param(
        "Edit",
        "/home/user/.claude/settings.json",
        "Hook Protection",
        id="ide-hooks-blocked",
    ),
    pytest.param(
        "Write",
        "/home/user/.cache/ai-guardian/maintainer-status.json",
        "Protection:",
        id="cache-blocked",
    ),
]


@pytest.mark.parametrize("tool_name,file_path,expected_msg", CONTRIBUTOR_BLOCKED_PATHS)
def test_contributor_cannot_modify_protected(policy_checker, tool_name, file_path, expected_msg):
    """Contributors CANNOT modify config files, IDE hooks, or cache (always protected)"""
    tool_input = {"file_path": file_path}
    if tool_name == "Edit":
        tool_input.update({
            "old_string": '"hooks": {"PreToolUse": []}',
            "new_string": '"hooks": {}'
        })

    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": tool_name, "input": tool_input},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"{file_path} should be blocked for contributors"
    assert expected_msg in error_msg


def test_contributor_can_write_source(policy_checker):
    """Contributors can write to source code (fork + PR workflow)"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Write",
            "input": {
                "file_path": "/home/user/ai-guardian/src/ai_guardian/tool_policy.py",
                "content": "# Modified source code"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert is_allowed, "Contributors should be allowed to edit source code"
    assert error_msg is None, "No error for allowed operations"


# ============================================================================
# Test: Malicious prompt scenarios (Threat Model B)
# ============================================================================

MALICIOUS_PROMPT_BLOCKED = [
    pytest.param(
        "Edit",
        {
            "file_path": "/home/user/.config/ai-guardian/ai-guardian.json",
            "old_string": '"secret_scanning": true',
            "new_string": '"secret_scanning": false',
        },
        id="disable-secret-scanning",
    ),
    pytest.param(
        "Write",
        {
            "file_path": "/home/user/.cache/ai-guardian/maintainer-status.json",
            "content": '{"is_maintainer": true}',
        },
        id="poison-cache",
    ),
]


@pytest.mark.parametrize("tool_name,tool_input", MALICIOUS_PROMPT_BLOCKED)
def test_malicious_prompt_blocked(policy_checker, tool_name, tool_input):
    """Threat Model B: Malicious prompts cannot disable security or poison cache"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": tool_name, "input": tool_input},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, "Malicious prompt should be blocked"
    assert "Protection:" in error_msg


def test_bash_cache_poisoning_blocked(policy_checker):
    """Bash command trying to poison cache is blocked"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "Bash",
            "input": {
                "command": 'echo \'{"is_maintainer": true}\' > ~/.cache/ai-guardian/maintainer-status.json'
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, "Bash cache poisoning should be blocked"
    assert "Protection:" in error_msg


# ============================================================================
# Parametrized: Bash/PowerShell on dev source allowed (Issue #369)
# ============================================================================

BASH_ALLOWED_ON_DEV_SOURCE = [
    pytest.param(
        "sed -n '100,200p' /home/user/ai-guardian/src/ai_guardian/tool_policy.py",
        id="sed-read-ranges",
    ),
    pytest.param(
        "awk 'NR>=100 && NR<=200' /home/user/ai-guardian/src/ai_guardian/tool_policy.py",
        id="awk-on-dev-source",
    ),
    pytest.param(
        "sed -i 's/old/new/' /home/user/ai-guardian/ai_guardian/tool_policy.py",
        id="sed-alt-layout",
    ),
    pytest.param(
        "chmod +x /home/user/ai-guardian/src/ai_guardian/__main__.py",
        id="chmod-on-dev-source",
    ),
    pytest.param(
        "grep 'pattern' /home/user/ai-guardian/src/ai_guardian/tool_policy.py > /tmp/output.txt",
        id="redirect-with-dev-source",
    ),
]


@pytest.mark.parametrize("command", BASH_ALLOWED_ON_DEV_SOURCE)
def test_bash_on_dev_source_allowed(policy_checker, command):
    """Bash commands on dev source are allowed (Issue #369)"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": "Bash", "input": {"command": command}},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert is_allowed, f"Bash on dev source should be allowed: {command}"
    assert error_msg is None


BASH_BLOCKED_ON_PIP_INSTALLED = [
    pytest.param(
        "Bash",
        "sed -i 's/IMMUTABLE/DISABLED/' /usr/lib/python3.12/site-packages/ai_guardian/tool_policy.py",
        id="bash-sed-pip-installed",
    ),
    pytest.param(
        "PowerShell",
        "Set-Content -Path C:\\Python\\Lib\\site-packages\\ai_guardian\\tool_policy.py -Value ''",
        id="powershell-pip-installed",
    ),
]


@pytest.mark.parametrize("tool_name,command", BASH_BLOCKED_ON_PIP_INSTALLED)
def test_pip_installed_still_blocked(policy_checker, tool_name, command):
    """Bash/PowerShell on pip-installed package is still blocked"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {"name": tool_name, "input": {"command": command}},
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert not is_allowed, f"{tool_name} on pip-installed should still be blocked"
    assert "Protection:" in error_msg


def test_powershell_set_content_on_dev_source_allowed(policy_checker):
    """PowerShell Set-Content on dev source is allowed (Issue #369)"""
    hook_data = {
        "hook_event_name": "PreToolUse",
        "tool_use": {
            "name": "PowerShell",
            "input": {
                "command": "Set-Content -Path /home/user/ai-guardian/src/ai_guardian/__init__.py -Value '# test'"
            }
        }
    }

    is_allowed, error_msg, tool_name = policy_checker.check_tool_allowed(hook_data)

    assert is_allowed, "PowerShell Set-Content on dev source should be allowed"
    assert error_msg is None


if __name__ == '__main__':
    pytest.main([__file__])
