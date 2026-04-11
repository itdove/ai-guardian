#!/usr/bin/env python3
"""
Tests for ViolationLogger module
"""

import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from ai_guardian.violation_logger import ViolationLogger


@pytest.fixture
def temp_log_file():
    """Create a temporary log file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
        log_path = Path(f.name)

    yield log_path

    # Cleanup
    if log_path.exists():
        log_path.unlink()


@pytest.fixture
def violation_logger(temp_log_file):
    """Create a ViolationLogger instance with temp log file."""
    return ViolationLogger(log_path=temp_log_file)


def test_log_violation_creates_file(violation_logger, temp_log_file):
    """Test that logging a violation creates the log file."""
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Skill", "reason": "not in allow list"},
        context={"ide_type": "claude_code"},
        severity="warning"
    )

    assert temp_log_file.exists()


def test_log_violation_jsonl_format(violation_logger, temp_log_file):
    """Test that violations are logged in JSONL format."""
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Skill", "tool_value": "test-skill", "reason": "not in allow list"},
        context={"ide_type": "claude_code"},
        suggestion={"action": "add_allow_pattern"},
        severity="warning"
    )

    # Read and parse the log file
    with open(temp_log_file, 'r') as f:
        lines = f.readlines()

    assert len(lines) == 1

    entry = json.loads(lines[0])
    assert entry["violation_type"] == "tool_permission"
    assert entry["severity"] == "warning"
    assert entry["blocked"]["tool_name"] == "Skill"
    assert entry["blocked"]["tool_value"] == "test-skill"
    assert entry["context"]["ide_type"] == "claude_code"
    assert entry["suggestion"]["action"] == "add_allow_pattern"
    assert "timestamp" in entry
    assert entry["resolved"] is False


def test_log_multiple_violations(violation_logger, temp_log_file):
    """Test logging multiple violations."""
    for i in range(5):
        violation_logger.log_violation(
            violation_type="tool_permission",
            blocked={"tool_name": f"Tool{i}"},
            context={"project_path": "/test"},
            severity="warning"
        )

    with open(temp_log_file, 'r') as f:
        lines = f.readlines()

    assert len(lines) == 5


def test_get_recent_violations(violation_logger):
    """Test getting recent violations."""
    # Log some violations
    for i in range(5):
        violation_logger.log_violation(
            violation_type="tool_permission",
            blocked={"tool_name": f"Tool{i}"},
            context={},
            severity="warning"
        )

    violations = violation_logger.get_recent_violations(limit=10)
    assert len(violations) == 5

    # Should be in reverse order (most recent first)
    assert violations[0]["blocked"]["tool_name"] == "Tool4"
    assert violations[-1]["blocked"]["tool_name"] == "Tool0"


def test_get_recent_violations_with_limit(violation_logger):
    """Test getting violations with limit."""
    # Log 10 violations
    for i in range(10):
        violation_logger.log_violation(
            violation_type="tool_permission",
            blocked={"tool_name": f"Tool{i}"},
            context={},
            severity="warning"
        )

    violations = violation_logger.get_recent_violations(limit=3)
    assert len(violations) == 3

    # Should get the 3 most recent
    assert violations[0]["blocked"]["tool_name"] == "Tool9"
    assert violations[1]["blocked"]["tool_name"] == "Tool8"
    assert violations[2]["blocked"]["tool_name"] == "Tool7"


def test_get_recent_violations_filter_by_type(violation_logger):
    """Test filtering violations by type."""
    # Log different types
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Skill"},
        context={},
        severity="warning"
    )
    violation_logger.log_violation(
        violation_type="secret_detected",
        blocked={"file_path": "test.py"},
        context={},
        severity="critical"
    )
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Bash"},
        context={},
        severity="warning"
    )

    # Filter by tool_permission
    violations = violation_logger.get_recent_violations(
        limit=10,
        violation_type="tool_permission"
    )
    assert len(violations) == 2
    assert all(v["violation_type"] == "tool_permission" for v in violations)

    # Filter by secret_detected
    violations = violation_logger.get_recent_violations(
        limit=10,
        violation_type="secret_detected"
    )
    assert len(violations) == 1
    assert violations[0]["violation_type"] == "secret_detected"


def test_get_recent_violations_filter_by_resolved(violation_logger, temp_log_file):
    """Test filtering violations by resolved status."""
    # Log some violations
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Tool1"},
        context={},
        severity="warning"
    )

    # Get the timestamp
    violations = violation_logger.get_recent_violations(limit=10)
    timestamp = violations[0]["timestamp"]

    # Mark it as resolved
    violation_logger.mark_resolved(timestamp, action="approved")

    # Log another violation
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Tool2"},
        context={},
        severity="warning"
    )

    # Get only unresolved
    unresolved = violation_logger.get_recent_violations(limit=10, resolved=False)
    assert len(unresolved) == 1
    assert unresolved[0]["blocked"]["tool_name"] == "Tool2"

    # Get only resolved
    resolved = violation_logger.get_recent_violations(limit=10, resolved=True)
    assert len(resolved) == 1
    assert resolved[0]["blocked"]["tool_name"] == "Tool1"


def test_mark_resolved(violation_logger):
    """Test marking a violation as resolved."""
    # Log a violation
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "TestTool"},
        context={},
        severity="warning"
    )

    # Get the timestamp
    violations = violation_logger.get_recent_violations(limit=10)
    timestamp = violations[0]["timestamp"]

    # Mark as resolved
    result = violation_logger.mark_resolved(timestamp, action="approved", note="User approved")
    assert result is True

    # Verify it was marked resolved
    violations = violation_logger.get_recent_violations(limit=10)
    assert violations[0]["resolved"] is True
    assert violations[0]["resolved_action"] == "approved"
    assert violations[0]["resolved_note"] == "User approved"
    assert "resolved_at" in violations[0]


def test_mark_resolved_nonexistent(violation_logger):
    """Test marking a nonexistent violation as resolved."""
    result = violation_logger.mark_resolved("2026-04-11T00:00:00Z", action="approved")
    assert result is False


def test_clear_log(violation_logger, temp_log_file):
    """Test clearing the violations log."""
    # Log some violations
    for i in range(5):
        violation_logger.log_violation(
            violation_type="tool_permission",
            blocked={"tool_name": f"Tool{i}"},
            context={},
            severity="warning"
        )

    assert temp_log_file.exists()

    # Clear the log
    result = violation_logger.clear_log()
    assert result is True
    assert not temp_log_file.exists()

    # Verify no violations
    violations = violation_logger.get_recent_violations(limit=10)
    assert len(violations) == 0


def test_export_violations(violation_logger):
    """Test exporting violations to JSON."""
    # Log some violations
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Tool1"},
        context={},
        severity="warning"
    )
    violation_logger.log_violation(
        violation_type="secret_detected",
        blocked={"file_path": "test.py"},
        context={},
        severity="critical"
    )

    # Export to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        export_path = Path(f.name)

    try:
        result = violation_logger.export_violations(export_path)
        assert result is True
        assert export_path.exists()

        # Verify exported data
        with open(export_path, 'r') as f:
            exported = json.load(f)

        assert len(exported) == 2
        assert exported[0]["violation_type"] == "secret_detected"  # Most recent first
        assert exported[1]["violation_type"] == "tool_permission"
    finally:
        if export_path.exists():
            export_path.unlink()


def test_export_violations_with_filter(violation_logger):
    """Test exporting violations with type filter."""
    # Log different types
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Tool1"},
        context={},
        severity="warning"
    )
    violation_logger.log_violation(
        violation_type="secret_detected",
        blocked={"file_path": "test.py"},
        context={},
        severity="critical"
    )

    # Export only tool_permission violations
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        export_path = Path(f.name)

    try:
        result = violation_logger.export_violations(
            export_path,
            violation_type="tool_permission"
        )
        assert result is True

        with open(export_path, 'r') as f:
            exported = json.load(f)

        assert len(exported) == 1
        assert exported[0]["violation_type"] == "tool_permission"
    finally:
        if export_path.exists():
            export_path.unlink()


def test_log_rotation_max_entries(temp_log_file):
    """Test log rotation based on max_entries."""
    config = {
        "enabled": True,
        "max_entries": 5,
        "retention_days": 30,
        "log_types": ["tool_permission"]
    }

    violation_logger = ViolationLogger(log_path=temp_log_file, config=config)

    # Log 10 violations
    for i in range(10):
        violation_logger.log_violation(
            violation_type="tool_permission",
            blocked={"tool_name": f"Tool{i}"},
            context={},
            severity="warning"
        )

    # Should only keep the last 5
    violations = violation_logger.get_recent_violations(limit=100)
    assert len(violations) <= 5

    # Should keep the most recent ones
    if len(violations) == 5:
        assert violations[0]["blocked"]["tool_name"] == "Tool9"


def test_logging_disabled(temp_log_file):
    """Test that logging can be disabled."""
    config = {
        "enabled": False,
        "max_entries": 1000,
        "retention_days": 30,
        "log_types": ["tool_permission"]
    }

    violation_logger = ViolationLogger(log_path=temp_log_file, config=config)

    # Try to log a violation
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Tool1"},
        context={},
        severity="warning"
    )

    # Log file should either not exist or be empty
    if temp_log_file.exists():
        # If the fixture created the file, it should be empty
        with open(temp_log_file, 'r') as f:
            content = f.read()
        assert content == "", "Log file should be empty when logging is disabled"
    # Otherwise, it should not exist
    # (This handles the case where the directory wasn't created)


def test_log_type_filtering(temp_log_file):
    """Test that only configured violation types are logged."""
    config = {
        "enabled": True,
        "max_entries": 1000,
        "retention_days": 30,
        "log_types": ["tool_permission", "secret_detected"]  # Only these types
    }

    violation_logger = ViolationLogger(log_path=temp_log_file, config=config)

    # Log allowed type
    violation_logger.log_violation(
        violation_type="tool_permission",
        blocked={"tool_name": "Tool1"},
        context={},
        severity="warning"
    )

    # Log disallowed type
    violation_logger.log_violation(
        violation_type="prompt_injection",
        blocked={"pattern": "test"},
        context={},
        severity="high"
    )

    # Only tool_permission should be logged
    violations = violation_logger.get_recent_violations(limit=10)
    assert len(violations) == 1
    assert violations[0]["violation_type"] == "tool_permission"


def test_violation_types():
    """Test all violation types with expected schema."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
        log_path = Path(f.name)

    try:
        violation_logger = ViolationLogger(log_path=log_path)

        # Test tool_permission
        violation_logger.log_violation(
            violation_type="tool_permission",
            blocked={
                "tool_name": "Skill",
                "tool_value": "daf-jira",
                "matcher": "Skill",
                "reason": "not in allow list"
            },
            context={"ide_type": "claude_code"},
            suggestion={
                "action": "add_allow_pattern",
                "rule": {"matcher": "Skill", "mode": "allow", "patterns": ["daf-jira"]}
            },
            severity="warning"
        )

        # Test directory_blocking
        violation_logger.log_violation(
            violation_type="directory_blocking",
            blocked={
                "file_path": "/home/user/secrets/config.yaml",
                "denied_directory": "/home/user/secrets",
                "reason": ".ai-read-deny marker found"
            },
            context={"project_path": "/home/user/project"},
            suggestion={
                "action": "remove_deny_marker",
                "file_path": "/home/user/secrets/.ai-read-deny"
            },
            severity="warning"
        )

        # Test secret_detected
        violation_logger.log_violation(
            violation_type="secret_detected",
            blocked={
                "file_path": "config.py",
                "secret_type": "AWS Access Key",
                "reason": "Gitleaks detected sensitive information"
            },
            context={"ide_type": "claude_code"},
            suggestion={
                "action": "review_and_remove_secret"
            },
            severity="critical"
        )

        # Test prompt_injection
        violation_logger.log_violation(
            violation_type="prompt_injection",
            blocked={
                "pattern": "ignore previous instructions",
                "confidence": 0.95,
                "method": "heuristic"
            },
            context={"ide_type": "cursor"},
            suggestion={
                "action": "add_allowlist_pattern"
            },
            severity="high"
        )

        # Verify all were logged
        violations = violation_logger.get_recent_violations(limit=10)
        assert len(violations) == 4

        # Check each violation type
        types = {v["violation_type"] for v in violations}
        assert types == {"tool_permission", "directory_blocking", "secret_detected", "prompt_injection"}

    finally:
        if log_path.exists():
            log_path.unlink()
