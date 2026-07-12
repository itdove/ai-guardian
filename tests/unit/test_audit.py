"""Tests for the ai-guardian audit command (Issue #476)."""

import argparse
import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ai_guardian.reporting.audit import (
    AuditComputer,
    AuditReport,
    VIOLATION_TYPE_TO_FEATURE,
    audit_command,
    format_audit_csv,
    format_audit_html,
    format_audit_human,
    format_audit_json,
)


def _make_violation(
    violation_type="tool_permission",
    severity="warning",
    timestamp=None,
    file_path="/test/file.py",
    tool_name="Bash",
    action="block",
    session_id="session-1",
    resolved=False,
    resolved_at=None,
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
        "resolved_at": resolved_at,
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


class TestAuditComputer:
    def test_empty_log(self, _isolate_config_dir):
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert report.total_violations == 0

    def test_single_violation(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert report.total_violations == 1
        assert report.unresolved_count == 1
        assert report.resolved_count == 0
        assert report.resolution_pct == 0.0

    def test_multiple_types(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(violation_type="tool_permission"),
            _make_violation(violation_type="tool_permission"),
            _make_violation(violation_type="secret_detected"),
            _make_violation(violation_type="prompt_injection"),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert report.total_violations == 4
        assert report.by_type["tool_permission"] == 2
        assert report.by_type["secret_detected"] == 1

    def test_severity_filter(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(severity="warning"),
            _make_violation(severity="critical"),
            _make_violation(severity="critical"),
            _make_violation(severity="high"),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="30d", severity="critical")
        report = computer.compute()
        assert report.total_violations == 2
        assert report.by_severity.get("critical") == 2
        assert "warning" not in report.by_severity

    def test_time_filtering_since(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(timestamp=_now_iso()),
            _make_violation(timestamp=_days_ago_iso(5)),
            _make_violation(timestamp=_days_ago_iso(15)),
            _make_violation(timestamp=_days_ago_iso(60)),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="7d")
        report = computer.compute()
        assert report.total_violations == 2

    def test_until_filter(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(timestamp=_days_ago_iso(10)),
            _make_violation(timestamp=_days_ago_iso(5)),
            _make_violation(timestamp=_now_iso()),
        ]
        _write_violations(state_dir, violations)
        until_date = (datetime.now(timezone.utc) - timedelta(days=3)).strftime(
            "%Y-%m-%d"
        )
        computer = AuditComputer(since="30d", until=until_date)
        report = computer.compute()
        assert report.total_violations == 2

    def test_trend_comparison(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(timestamp=_days_ago_iso(1)),
            _make_violation(timestamp=_days_ago_iso(2)),
            _make_violation(timestamp=_days_ago_iso(3)),
            _make_violation(timestamp=_days_ago_iso(10)),
            _make_violation(timestamp=_days_ago_iso(11)),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="7d")
        report = computer.compute()
        assert report.total_violations == 3
        assert report.prev_period_total == 2
        assert report.trend_change_pct is not None
        assert report.trend_change_pct == pytest.approx(50.0, abs=1)

    def test_trend_no_previous(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation(timestamp=_now_iso())])
        computer = AuditComputer(since="7d")
        report = computer.compute()
        assert report.total_violations == 1
        assert report.prev_period_total == 0
        assert report.trend_change_pct is None

    def test_resolution_metrics(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        ts = _days_ago_iso(2)
        ra = _days_ago_iso(1)
        violations = [
            _make_violation(resolved=True, timestamp=ts, resolved_at=ra),
            _make_violation(resolved=True, timestamp=ts, resolved_at=ra),
            _make_violation(resolved=False),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert report.resolved_count == 2
        assert report.unresolved_count == 1
        assert report.resolution_pct == pytest.approx(66.7, abs=1)
        assert report.avg_resolution_seconds is not None
        assert report.avg_resolution_seconds > 0

    def test_compliance_summary(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(violation_type="secret_detected"),
            _make_violation(violation_type="pii_detected"),
            _make_violation(violation_type="tool_permission"),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert "secret_scanning" in report.violations_per_feature
        assert report.violations_per_feature["secret_scanning"] == 1
        assert report.violations_per_feature["scan_pii"] == 1
        assert report.violations_per_feature["permissions"] == 1

    def test_session_count(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(session_id="s1"),
            _make_violation(session_id="s1"),
            _make_violation(session_id="s2"),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert report.session_count == 2

    def test_top_files(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(file_path="/a.py"),
            _make_violation(file_path="/a.py"),
            _make_violation(file_path="/a.py"),
            _make_violation(file_path="/b.py"),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert report.top_files[0] == ("/a.py", 3)
        assert report.top_files[1] == ("/b.py", 1)

    def test_top_tools(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        violations = [
            _make_violation(tool_name="Bash"),
            _make_violation(tool_name="Bash"),
            _make_violation(tool_name="Read"),
        ]
        _write_violations(state_dir, violations)
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert report.top_tools[0] == ("Bash", 2)

    def test_security_posture_good(self, _isolate_config_dir):
        features = {
            "secret_scanning": True,
            "scan_pii": True,
            "prompt_injection": True,
            "ssrf_protection": True,
        }
        posture = AuditComputer._compute_posture(features, critical_unresolved=0)
        assert posture == "GOOD"

    def test_security_posture_fair(self, _isolate_config_dir):
        features = {
            "secret_scanning": True,
            "scan_pii": True,
            "prompt_injection": True,
            "ssrf_protection": False,
        }
        posture = AuditComputer._compute_posture(features, critical_unresolved=0)
        assert posture == "FAIR"

    def test_security_posture_needs_attention(self, _isolate_config_dir):
        features = {
            "secret_scanning": False,
            "scan_pii": False,
            "prompt_injection": True,
            "ssrf_protection": False,
        }
        posture = AuditComputer._compute_posture(features, critical_unresolved=5)
        assert posture == "NEEDS ATTENTION"

    def test_security_posture_unknown(self, _isolate_config_dir):
        posture = AuditComputer._compute_posture({}, critical_unresolved=0)
        assert posture == "UNKNOWN"

    def test_malformed_lines_skipped(self, _isolate_config_dir):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        log_path = Path(state_dir) / "violations.jsonl"
        with open(log_path, "w") as f:
            f.write("not valid json\n")
            f.write(json.dumps(_make_violation()) + "\n")
            f.write("{bad json\n")
        computer = AuditComputer(since="30d")
        report = computer.compute()
        assert report.total_violations == 1


class TestFormatAuditHuman:
    def test_empty_report(self):
        report = AuditReport()
        output = format_audit_human(report)
        assert "No violations found" in output
        assert "AI Guardian Audit Report" in output

    def test_contains_sections(self):
        report = AuditReport(
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
            resolution_pct=30.0,
            security_posture="GOOD",
        )
        output = format_audit_human(report)
        assert "Violations: 10 total" in output
        assert "Severity:" in output
        assert "Actions taken:" in output
        assert "Top files:" in output
        assert "Top tools:" in output
        assert "Resolution:" in output
        assert "GOOD" in output

    def test_trend_percentage(self):
        report = AuditReport(
            total_violations=10,
            by_type={"tool_permission": 10},
            by_severity={"warning": 10},
            by_action={"block": 10},
            prev_period_total=20,
            trend_change_pct=-50.0,
        )
        output = format_audit_human(report)
        assert "50%" in output
        assert "decrease" in output

    def test_compliance_section(self):
        report = AuditReport(
            compliance_features={"secret_scanning": True, "scan_pii": False},
            violations_per_feature={"secret_scanning": 5},
        )
        output = format_audit_human(report)
        assert "Compliance Summary:" in output
        assert "enabled" in output
        assert "disabled" in output


class TestFormatAuditJson:
    def test_valid_json(self):
        report = AuditReport(total_violations=5)
        output = format_audit_json(report)
        data = json.loads(output)
        assert data["summary"]["total"] == 5

    def test_structure(self):
        report = AuditReport(
            total_violations=2,
            resolved_count=1,
            unresolved_count=1,
            session_count=1,
            by_type={"tool_permission": 2},
            by_severity={"warning": 2},
            by_action={"block": 2},
            top_files=[("/a.py", 2)],
            top_tools=[("Bash", 2)],
            top_types=[("tool_permission", 2)],
            time_trend=[{"date": "2026-05-01", "count": 2}],
            time_range_start="2026-04-01T00:00:00+00:00",
            time_range_end="2026-05-01T00:00:00+00:00",
            prev_period_total=4,
            trend_change_pct=-50.0,
            resolution_pct=50.0,
            compliance_features={"secret_scanning": True},
            violations_per_feature={"secret_scanning": 1},
            security_posture="GOOD",
        )
        output = format_audit_json(report)
        data = json.loads(output)
        assert "time_range" in data
        assert "summary" in data
        assert "by_type" in data
        assert "by_severity" in data
        assert "by_action" in data
        assert "trends" in data
        assert "top_violations" in data
        assert "resolution" in data
        assert "compliance" in data
        assert "security_posture" in data
        assert data["trends"]["change_pct"] == -50.0
        assert data["resolution"]["rate_pct"] == 50.0
        assert data["compliance"]["features"]["secret_scanning"] is True

    def test_empty_report(self):
        report = AuditReport()
        output = format_audit_json(report)
        data = json.loads(output)
        assert data["summary"]["total"] == 0


class TestFormatAuditHtml:
    def test_valid_html(self):
        report = AuditReport(total_violations=5, by_type={"test": 5})
        output = format_audit_html(report)
        assert output.startswith("<!DOCTYPE html>")
        assert "<html" in output
        assert "</html>" in output

    def test_self_contained(self):
        report = AuditReport(
            total_violations=3,
            by_type={"tool_permission": 3},
            by_severity={"warning": 3},
            time_trend=[{"date": "2026-05-01", "count": 3}],
        )
        output = format_audit_html(report)
        cleaned = output.replace("http://www.w3.org/2000/svg", "")
        assert "http://" not in cleaned
        assert "https://" not in cleaned

    def test_contains_svg_chart(self):
        report = AuditReport(
            total_violations=3,
            time_trend=[
                {"date": "2026-05-01", "count": 2},
                {"date": "2026-05-02", "count": 3},
            ],
        )
        output = format_audit_html(report)
        assert "<svg" in output

    def test_sections_present(self):
        report = AuditReport(
            total_violations=5,
            by_type={"secret_detected": 5},
            by_severity={"warning": 5},
            by_action={"block": 5},
            top_files=[("/a.py", 3)],
            top_tools=[("Bash", 5)],
            compliance_features={"secret_scanning": True},
        )
        output = format_audit_html(report)
        assert "Violations by Type" in output
        assert "Severity Distribution" in output
        assert "Actions Taken" in output
        assert "Top Files" in output
        assert "Resolution Metrics" in output
        assert "Compliance Summary" in output


class TestFormatAuditCsv:
    def test_header_row(self):
        stream = io.StringIO()
        format_audit_csv([], stream)
        stream.seek(0)
        reader = csv.reader(stream)
        header = next(reader)
        assert "timestamp" in header
        assert "violation_type" in header
        assert "resolved_at" in header

    def test_data_rows(self):
        violations = [
            _make_violation(violation_type="secret_detected", severity="high"),
            _make_violation(violation_type="tool_permission", severity="warning"),
        ]
        stream = io.StringIO()
        format_audit_csv(violations, stream)
        stream.seek(0)
        reader = csv.reader(stream)
        rows = list(reader)
        assert len(rows) == 3
        assert rows[1][1] == "secret_detected"
        assert rows[2][1] == "tool_permission"

    def test_empty_violations(self):
        stream = io.StringIO()
        format_audit_csv([], stream)
        stream.seek(0)
        reader = csv.reader(stream)
        rows = list(reader)
        assert len(rows) == 1


class TestAuditCommand:
    def _make_args(
        self,
        html=False,
        json_flag=False,
        csv_flag=False,
        since="30d",
        until=None,
        type=None,
        severity=None,
    ):
        return argparse.Namespace(
            html=html,
            json=json_flag,
            csv=csv_flag,
            since=since,
            until=until,
            type=type,
            severity=severity,
        )

    def test_default_output(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        result = audit_command(self._make_args())
        assert result == 0
        captured = capsys.readouterr()
        assert "AI Guardian Audit Report" in captured.out

    def test_json_output(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        result = audit_command(self._make_args(json_flag=True))
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["total"] == 1

    def test_html_output(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        result = audit_command(self._make_args(html=True))
        assert result == 0
        captured = capsys.readouterr()
        assert "<!DOCTYPE html>" in captured.out

    def test_csv_output(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(state_dir, [_make_violation()])
        result = audit_command(self._make_args(csv_flag=True))
        assert result == 0
        captured = capsys.readouterr()
        assert "timestamp" in captured.out
        assert "resolved_at" in captured.out

    def test_severity_filter(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(
            state_dir,
            [
                _make_violation(severity="warning"),
                _make_violation(severity="critical"),
            ],
        )
        result = audit_command(self._make_args(severity="critical", json_flag=True))
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["total"] == 1

    def test_since_until(self, _isolate_config_dir, capsys):
        state_dir = os.environ["AI_GUARDIAN_STATE_DIR"]
        _write_violations(
            state_dir,
            [
                _make_violation(timestamp=_days_ago_iso(10)),
                _make_violation(timestamp=_days_ago_iso(5)),
                _make_violation(timestamp=_now_iso()),
            ],
        )
        until_date = (datetime.now(timezone.utc) - timedelta(days=3)).strftime(
            "%Y-%m-%d"
        )
        result = audit_command(
            self._make_args(since="30d", until=until_date, json_flag=True)
        )
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["total"] == 2

    def test_empty_log(self, _isolate_config_dir, capsys):
        result = audit_command(self._make_args())
        assert result == 0
        captured = capsys.readouterr()
        assert "No violations found" in captured.out

    def test_invalid_since(self, _isolate_config_dir, capsys):
        result = audit_command(self._make_args(since="foobar"))
        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid --since" in captured.err

    def test_invalid_until(self, _isolate_config_dir, capsys):
        result = audit_command(self._make_args(until="foobar"))
        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid --until" in captured.err


class TestAggregate:
    def test_single_pass_parity(self):
        """Verify _aggregate produces same results as individual helpers."""
        ts1 = _days_ago_iso(2)
        ra1 = _days_ago_iso(1)
        violations = [
            _make_violation(
                violation_type="secret_detected",
                severity="critical",
                file_path="/a.py",
                tool_name="Bash",
                session_id="s1",
                resolved=True,
                timestamp=ts1,
                resolved_at=ra1,
            ),
            _make_violation(
                violation_type="tool_permission",
                severity="warning",
                file_path="/a.py",
                tool_name="Read",
                session_id="s1",
            ),
            _make_violation(
                violation_type="pii_detected",
                severity="critical",
                file_path="/b.py",
                tool_name="Bash",
                session_id="s2",
            ),
        ]
        agg = AuditComputer._aggregate(violations)

        assert agg.resolved_count == 1
        assert agg.critical_unresolved == 1
        assert agg.sessions == {"s1", "s2"}
        assert agg.by_type["secret_detected"] == 1
        assert agg.by_type["tool_permission"] == 1
        assert agg.by_type["pii_detected"] == 1
        assert agg.by_severity["critical"] == 2
        assert agg.by_severity["warning"] == 1
        assert agg.files["/a.py"] == 2
        assert agg.files["/b.py"] == 1
        assert agg.tools["Bash"] == 2
        assert agg.tools["Read"] == 1
        assert len(agg.resolution_deltas) == 1
        assert agg.resolution_deltas[0] > 0
        assert agg.per_feature["secret_scanning"] == 1
        assert agg.per_feature["scan_pii"] == 1
        assert agg.per_feature["permissions"] == 1
        assert len(agg.dates) > 0

    def test_empty_violations(self):
        agg = AuditComputer._aggregate([])
        assert agg.resolved_count == 0
        assert agg.critical_unresolved == 0
        assert len(agg.sessions) == 0
        assert len(agg.by_type) == 0


class TestViolationTypeMapping:
    def test_all_types_mapped(self):
        expected_types = [
            "secret_detected",
            "pii_detected",
            "prompt_injection",
            "jailbreak_detected",
            "ssrf_blocked",
            "config_file_exfil",
            "directory_blocking",
            "tool_permission",
        ]
        for vtype in expected_types:
            assert vtype in VIOLATION_TYPE_TO_FEATURE
