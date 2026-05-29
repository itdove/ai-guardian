"""Tests for the ai-guardian metrics command (Issue #469)."""

import argparse
import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_guardian.metrics import (
    MetricsComputer,
    MetricsReport,
    _parse_since,
    _parse_timestamp,
    format_csv,
    format_human,
    format_json,
    metrics_command,
)
from ai_guardian.violation_counter import ViolationCounter


def _make_violation(
    violation_type="tool_permission",
    severity="warning",
    timestamp=None,
    file_path="/test/file.py",
    tool_name="Bash",
    action="block",
    session_id="session-1",
    resolved=False,
):
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "timestamp": timestamp,
        "violation_type": violation_type,
        "severity": severity,
        "blocked": {"file_path": file_path, "tool_name": tool_name},
        "context": {"action": action, "session_id": session_id},
        "suggestion": {},
        "resolved": resolved,
        "resolved_at": None,
        "resolved_action": None,
    }


def _write_violations(state_dir, violations):
    log_path = Path(state_dir) / "violations.jsonl"
    with open(log_path, "w", encoding="utf-8") as f:
        for v in violations:
            f.write(json.dumps(v) + "\n")


def _now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _days_ago_iso(days):
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.isoformat().replace("+00:00", "Z")


class TestParseTimestamp:
    def test_utc_z_suffix(self):
        dt = _parse_timestamp("2026-05-01T10:00:00Z")
        assert dt.year == 2026
        assert dt.month == 5
        assert dt.tzinfo is not None

    def test_with_offset(self):
        dt = _parse_timestamp("2026-05-01T10:00:00+00:00")
        assert dt.year == 2026

    def test_none_returns_epoch(self):
        dt = _parse_timestamp(None)
        assert dt.year == 1970

    def test_empty_returns_epoch(self):
        dt = _parse_timestamp("")
        assert dt.year == 1970

    def test_invalid_returns_epoch(self):
        dt = _parse_timestamp("not-a-date")
        assert dt.year == 1970

    def test_naive_becomes_utc(self):
        dt = _parse_timestamp("2026-05-01T10:00:00")
        assert dt.tzinfo is not None


class TestParseSince:
    def test_days_format(self):
        cutoff = _parse_since("30d")
        now = datetime.now(timezone.utc)
        diff = now - cutoff
        assert 29 <= diff.days <= 31

    def test_days_format_short(self):
        cutoff = _parse_since("7d")
        now = datetime.now(timezone.utc)
        diff = now - cutoff
        assert 6 <= diff.days <= 8

    def test_iso_date(self):
        cutoff = _parse_since("2026-01-15")
        assert cutoff.year == 2026
        assert cutoff.month == 1
        assert cutoff.day == 15

    def test_empty_defaults_30d(self):
        cutoff = _parse_since("")
        now = datetime.now(timezone.utc)
        diff = now - cutoff
        assert 29 <= diff.days <= 31

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Invalid --since"):
            _parse_since("foobar")


class TestMetricsComputer:
    def test_empty_log(self, _isolate_config_dir):
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.total_violations == 0

    def test_missing_log(self, _isolate_config_dir):
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.total_violations == 0

    def test_single_violation(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.total_violations == 1
        assert report.unresolved_count == 1
        assert report.resolved_count == 0

    def test_multiple_types(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(violation_type="tool_permission"),
            _make_violation(violation_type="tool_permission"),
            _make_violation(violation_type="secret_detected"),
            _make_violation(violation_type="prompt_injection"),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.total_violations == 4
        assert report.by_type["tool_permission"] == 2
        assert report.by_type["secret_detected"] == 1
        assert report.by_type["prompt_injection"] == 1

    def test_severity_counts(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(severity="warning"),
            _make_violation(severity="warning"),
            _make_violation(severity="high"),
            _make_violation(severity="critical"),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.by_severity["warning"] == 2
        assert report.by_severity["high"] == 1
        assert report.by_severity["critical"] == 1

    def test_time_filtering(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(timestamp=_now_iso()),
            _make_violation(timestamp=_days_ago_iso(5)),
            _make_violation(timestamp=_days_ago_iso(15)),
            _make_violation(timestamp=_days_ago_iso(60)),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=7)
        report = computer.compute()
        assert report.total_violations == 2

    def test_type_filtering(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(violation_type="tool_permission"),
            _make_violation(violation_type="secret_detected"),
            _make_violation(violation_type="secret_detected"),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30, violation_type="secret_detected")
        report = computer.compute()
        assert report.total_violations == 2
        assert "tool_permission" not in report.by_type

    def test_top_files(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(file_path="/a.py"),
            _make_violation(file_path="/a.py"),
            _make_violation(file_path="/a.py"),
            _make_violation(file_path="/b.py"),
            _make_violation(file_path="/b.py"),
            _make_violation(file_path="/c.py"),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert len(report.top_files) == 3
        assert report.top_files[0] == ("/a.py", 3)
        assert report.top_files[1] == ("/b.py", 2)

    def test_top_tools(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(tool_name="Bash"),
            _make_violation(tool_name="Bash"),
            _make_violation(tool_name="Read"),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.top_tools[0] == ("Bash", 2)
        assert report.top_tools[1] == ("Read", 1)

    def test_session_count(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(session_id="s1"),
            _make_violation(session_id="s1"),
            _make_violation(session_id="s2"),
            _make_violation(session_id="s3"),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.session_count == 3

    def test_resolved_counts(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(resolved=True),
            _make_violation(resolved=True),
            _make_violation(resolved=False),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.resolved_count == 2
        assert report.unresolved_count == 1

    def test_time_trend(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        today = datetime.now(timezone.utc)
        yesterday = today - timedelta(days=1)
        violations = [
            _make_violation(timestamp=today.isoformat().replace("+00:00", "Z")),
            _make_violation(timestamp=today.isoformat().replace("+00:00", "Z")),
            _make_violation(timestamp=yesterday.isoformat().replace("+00:00", "Z")),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert len(report.time_trend) == 2
        total_from_trend = sum(t["count"] for t in report.time_trend)
        assert total_from_trend == 3

    def test_action_counts(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(action="block"),
            _make_violation(action="block"),
            _make_violation(action="redacted"),
            _make_violation(action="warn"),
        ]
        _write_violations(state_dir, violations)
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.by_action["block"] == 2
        assert report.by_action["redacted"] == 1
        assert report.by_action["warn"] == 1

    def test_malformed_lines_skipped(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        log_path = Path(state_dir) / "violations.jsonl"
        with open(log_path, "w") as f:
            f.write("not valid json\n")
            f.write(json.dumps(_make_violation()) + "\n")
            f.write("{bad json\n")
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.total_violations == 1


class TestFormatHuman:
    def test_empty_report(self):
        report = MetricsReport()
        output = format_human(report)
        assert "No violations found" in output

    def test_contains_sections(self):
        report = MetricsReport(
            total_violations=10,
            resolved_count=3,
            unresolved_count=7,
            session_count=2,
            by_type={"tool_permission": 6, "secret_detected": 4},
            by_severity={"warning": 8, "high": 2},
            by_action={"block": 10},
            top_files=[("/a.py", 5), ("/b.py", 3)],
            top_tools=[("Bash", 7)],
            time_trend=[{"date": "2026-05-01", "count": 10}],
        )
        output = format_human(report)
        assert "Summary" in output
        assert "By Type" in output
        assert "By Severity" in output
        assert "By Action" in output
        assert "Top Files" in output
        assert "Top Tools" in output
        assert "Daily Trend" in output
        assert "10" in output
        assert "tool_permission" in output

    def test_percentages(self):
        report = MetricsReport(
            total_violations=100,
            by_type={"tool_permission": 75, "secret_detected": 25},
        )
        output = format_human(report)
        assert "75.0%" in output
        assert "25.0%" in output


class TestFormatJson:
    def test_valid_json(self):
        report = MetricsReport(total_violations=5)
        output = format_json(report)
        data = json.loads(output)
        assert data["summary"]["total"] == 5

    def test_structure(self):
        report = MetricsReport(
            total_violations=2,
            resolved_count=1,
            unresolved_count=1,
            session_count=1,
            by_type={"tool_permission": 2},
            by_severity={"warning": 2},
            by_action={"block": 2},
            top_files=[("/a.py", 2)],
            top_tools=[("Bash", 2)],
            time_trend=[{"date": "2026-05-01", "count": 2}],
            time_range_start="2026-04-01T00:00:00+00:00",
            time_range_end="2026-05-01T00:00:00+00:00",
        )
        output = format_json(report)
        data = json.loads(output)
        assert "time_range" in data
        assert "summary" in data
        assert "by_type" in data
        assert "by_severity" in data
        assert "by_action" in data
        assert "top_files" in data
        assert "top_tools" in data
        assert "time_trend" in data
        assert data["top_files"][0]["path"] == "/a.py"
        assert data["top_tools"][0]["tool"] == "Bash"

    def test_empty_report(self):
        report = MetricsReport()
        output = format_json(report)
        data = json.loads(output)
        assert data["summary"]["total"] == 0


class TestFormatCsv:
    def test_header_row(self):
        stream = io.StringIO()
        format_csv([], stream)
        stream.seek(0)
        reader = csv.reader(stream)
        header = next(reader)
        assert "timestamp" in header
        assert "violation_type" in header
        assert "severity" in header

    def test_data_rows(self):
        violations = [
            _make_violation(violation_type="secret_detected", severity="high"),
            _make_violation(violation_type="tool_permission", severity="warning"),
        ]
        stream = io.StringIO()
        format_csv(violations, stream)
        stream.seek(0)
        reader = csv.reader(stream)
        rows = list(reader)
        assert len(rows) == 3  # header + 2 data rows
        assert rows[1][1] == "secret_detected"
        assert rows[2][1] == "tool_permission"

    def test_empty_violations(self):
        stream = io.StringIO()
        format_csv([], stream)
        stream.seek(0)
        reader = csv.reader(stream)
        rows = list(reader)
        assert len(rows) == 1  # header only


class TestMetricsCommand:
    def _make_args(self, json_flag=False, csv_flag=False, since="30d", type=None,
                   reset=False, metrics_yes=False):
        return argparse.Namespace(json=json_flag, csv=csv_flag, since=since,
                                  type=type, reset=reset, metrics_yes=metrics_yes)

    def test_default_output(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        result = metrics_command(self._make_args())
        assert result == 0
        captured = capsys.readouterr()
        assert "AI Guardian Metrics" in captured.out

    def test_json_output(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        result = metrics_command(self._make_args(json_flag=True))
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["total"] == 1

    def test_csv_output(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        result = metrics_command(self._make_args(csv_flag=True))
        assert result == 0
        captured = capsys.readouterr()
        assert "timestamp" in captured.out

    def test_since_filter(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [
            _make_violation(timestamp=_now_iso()),
            _make_violation(timestamp=_days_ago_iso(60)),
        ])
        result = metrics_command(self._make_args(since="7d", json_flag=True))
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["total"] == 1

    def test_type_filter(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [
            _make_violation(violation_type="tool_permission"),
            _make_violation(violation_type="secret_detected"),
        ])
        result = metrics_command(self._make_args(type="secret_detected", json_flag=True))
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["total"] == 1

    def test_empty_log(self, _isolate_config_dir, capsys):
        result = metrics_command(self._make_args())
        assert result == 0
        captured = capsys.readouterr()
        assert "No violations found" in captured.out

    def test_invalid_since(self, _isolate_config_dir, capsys):
        result = metrics_command(self._make_args(since="foobar"))
        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid --since" in captured.err

    def test_reset_with_yes(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [
            _make_violation(violation_type="secret_detected"),
            _make_violation(violation_type="secret_detected"),
            _make_violation(violation_type="tool_permission"),
        ])
        counter_path = Path(state_dir) / "violation_counters.json"
        counter = ViolationCounter(counter_path=counter_path)
        for _ in range(50):
            counter.increment("secret_detected")

        result = metrics_command(self._make_args(reset=True, metrics_yes=True))
        assert result == 0
        captured = capsys.readouterr()
        assert "Counters reset" in captured.out
        assert "3" in captured.out

        data = counter.get_counters()
        assert data["total"] == 3

    def test_reset_cancelled(self, _isolate_config_dir, capsys, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "n")
        result = metrics_command(self._make_args(reset=True))
        assert result == 0
        captured = capsys.readouterr()
        assert "Cancelled" in captured.out


class TestCumulativeFields:
    def test_compute_includes_cumulative(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        counter_path = Path(state_dir) / "violation_counters.json"
        counter = ViolationCounter(counter_path=counter_path)
        counter.increment("secret_detected")
        counter.increment("secret_detected")
        counter.increment("tool_permission")

        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.cumulative_total == 3
        assert report.cumulative_by_type["secret_detected"] == 2
        assert report.cumulative_by_type["tool_permission"] == 1
        assert report.cumulative_since != ""

    def test_compute_cumulative_defaults_no_file(self, _isolate_config_dir):
        computer = MetricsComputer(since_days=30)
        report = computer.compute()
        assert report.cumulative_total == 0
        assert report.cumulative_by_type == {}
        assert report.cumulative_since == ""

    def test_format_human_shows_cumulative(self, _isolate_config_dir):
        report = MetricsReport(
            total_violations=5,
            cumulative_total=100,
            cumulative_by_type={"secret_detected": 60, "pii_detected": 40},
            cumulative_since="2026-03-01T00:00:00Z",
            by_type={"secret_detected": 3, "pii_detected": 2},
        )
        output = format_human(report)
        assert "Cumulative Totals" in output
        assert "100" in output
        assert "2026-03-01" in output

    def test_format_json_includes_cumulative(self, _isolate_config_dir):
        report = MetricsReport(
            total_violations=5,
            cumulative_total=200,
            cumulative_by_type={"secret_detected": 120},
            cumulative_since="2026-04-01T00:00:00Z",
        )
        output = format_json(report)
        data = json.loads(output)
        assert "cumulative" in data
        assert data["cumulative"]["total"] == 200
        assert data["cumulative"]["by_type"]["secret_detected"] == 120
        assert data["cumulative"]["since"] == "2026-04-01T00:00:00Z"

    def test_format_human_hides_cumulative_when_zero(self, _isolate_config_dir):
        report = MetricsReport(total_violations=5)
        output = format_human(report)
        assert "Cumulative Totals" not in output
