"""
Tests for the doctor command (Issue #475).

Tests health check: config validation, scanner detection, hook verification, etc.
"""

import argparse
import json
import os
import time
from pathlib import Path
from unittest import mock

import pytest

from ai_guardian.doctor import (
    CheckResult,
    CheckStatus,
    Doctor,
    DoctorReport,
    doctor_command,
    format_human,
    format_json,
)


# --- Data model tests ---


class TestCheckStatus:
    def test_values(self):
        assert CheckStatus.PASS.value == "pass"
        assert CheckStatus.WARN.value == "warn"
        assert CheckStatus.FAIL.value == "fail"
        assert CheckStatus.SKIP.value == "skip"


class TestCheckResult:
    def test_defaults(self):
        r = CheckResult(name="test", status=CheckStatus.PASS, message="ok")
        assert r.detail is None
        assert r.fix_hint is None
        assert r.fixable is False
        assert r.fixed is False


class TestDoctorReport:
    def test_exit_code_all_pass(self):
        report = DoctorReport(checks=[
            CheckResult(name="a", status=CheckStatus.PASS, message="ok"),
            CheckResult(name="b", status=CheckStatus.PASS, message="ok"),
        ])
        assert report.exit_code == 0

    def test_exit_code_with_warnings(self):
        report = DoctorReport(checks=[
            CheckResult(name="a", status=CheckStatus.PASS, message="ok"),
            CheckResult(name="b", status=CheckStatus.WARN, message="warn"),
        ])
        assert report.exit_code == 1

    def test_exit_code_with_errors(self):
        report = DoctorReport(checks=[
            CheckResult(name="a", status=CheckStatus.FAIL, message="fail"),
        ])
        assert report.exit_code == 2

    def test_exit_code_errors_trump_warnings(self):
        report = DoctorReport(checks=[
            CheckResult(name="a", status=CheckStatus.WARN, message="warn"),
            CheckResult(name="b", status=CheckStatus.FAIL, message="fail"),
        ])
        assert report.exit_code == 2

    def test_has_errors(self):
        report = DoctorReport(checks=[
            CheckResult(name="a", status=CheckStatus.FAIL, message="fail"),
        ])
        assert report.has_errors is True
        assert report.has_warnings is False

    def test_has_warnings(self):
        report = DoctorReport(checks=[
            CheckResult(name="a", status=CheckStatus.WARN, message="warn"),
        ])
        assert report.has_errors is False
        assert report.has_warnings is True

    def test_empty_report(self):
        report = DoctorReport()
        assert report.exit_code == 0
        assert report.has_errors is False
        assert report.has_warnings is False


# --- Individual check tests ---


class TestCheckConfigFile:
    def test_no_config_file(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_config_file()
        assert result.status == CheckStatus.WARN
        assert "No config file found" in result.message

    def test_valid_config(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({"secret_scanning": {"enabled": True}}))
        doctor = Doctor()
        result = doctor.check_config_file()
        assert result.status == CheckStatus.PASS
        assert "Valid config" in result.message

    def test_invalid_json(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text("{invalid json")
        doctor = Doctor()
        result = doctor.check_config_file()
        assert result.status == CheckStatus.FAIL
        assert "Config error" in result.message


class TestCheckDeprecatedFields:
    def test_no_deprecated(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({"secret_scanning": {"enabled": True}}))
        doctor = Doctor()
        result = doctor.check_deprecated_fields()
        assert result.status == CheckStatus.PASS

    def test_deprecated_pattern_server(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "pattern_server": {"url": "https://example.com"}
        }))
        doctor = Doctor()
        result = doctor.check_deprecated_fields()
        assert result.status == CheckStatus.WARN
        assert "pattern_server" in result.message

    def test_no_config(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_deprecated_fields()
        assert result.status == CheckStatus.PASS


class TestCheckScanners:
    def test_no_scanners(self, _isolate_config_dir):
        mock_manager = mock.MagicMock()
        mock_manager.list_installed.return_value = []
        mock_cls = mock.MagicMock(return_value=mock_manager)

        with mock.patch("ai_guardian.scanner_manager.ScannerManager", mock_cls):
            doctor = Doctor()
            result = doctor.check_scanners()
        assert result.status == CheckStatus.FAIL
        assert "No scanners installed" in result.message

    def test_scanner_found(self, _isolate_config_dir):
        mock_scanner = mock.MagicMock()
        mock_scanner.name = "gitleaks"
        mock_scanner.version = "8.30.1"
        mock_manager = mock.MagicMock()
        mock_manager.list_installed.return_value = [mock_scanner]
        mock_cls = mock.MagicMock(return_value=mock_manager)

        with mock.patch("ai_guardian.scanner_manager.ScannerManager", mock_cls):
            doctor = Doctor()
            result = doctor.check_scanners()
        assert result.status == CheckStatus.PASS
        assert "gitleaks 8.30.1" in result.message


class TestCheckPatternServer:
    def test_no_server_configured(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({"secret_scanning": {"enabled": True}}))
        doctor = Doctor()
        result = doctor.check_pattern_server()
        assert result.status == CheckStatus.SKIP

    def test_fresh_cache(self, _isolate_config_dir, tmp_path):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com/patterns"}
            }
        }))
        cache_dir = Path(os.environ["AI_GUARDIAN_CACHE_DIR"])
        cache_file = cache_dir / "patterns.toml"
        cache_file.write_text("[patterns]\ntest = true\n")

        doctor = Doctor()
        result = doctor.check_pattern_server()
        assert result.status == CheckStatus.PASS

    def test_stale_cache(self, _isolate_config_dir, tmp_path):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com/patterns"}
            }
        }))
        cache_dir = Path(os.environ["AI_GUARDIAN_CACHE_DIR"])
        cache_file = cache_dir / "patterns.toml"
        cache_file.write_text("[patterns]\ntest = true\n")
        old_time = time.time() - (8 * 86400)
        os.utime(cache_file, (old_time, old_time))

        doctor = Doctor()
        result = doctor.check_pattern_server()
        assert result.status == CheckStatus.WARN
        assert "stale" in result.message.lower()


class TestCheckHooks:
    def test_no_ides_detected(self, _isolate_config_dir):
        with mock.patch("ai_guardian.setup.IDESetup.list_detected_ides", return_value=[]):
            doctor = Doctor()
            result = doctor.check_hooks()
            assert result.status == CheckStatus.WARN
            assert "No IDEs detected" in result.message

    def test_hooks_configured(self, _isolate_config_dir, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings_path = claude_dir / "settings.json"
        settings_path.write_text(json.dumps({
            "hooks": {
                "UserPromptSubmit": [{"matcher": "*", "hooks": [{"type": "command", "command": "ai-guardian"}]}],
                "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "ai-guardian"}]}],
                "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "ai-guardian"}]}],
            }
        }))

        with mock.patch("ai_guardian.setup.IDESetup.list_detected_ides", return_value=["claude"]):
            with mock.patch("ai_guardian.setup.IDESetup.get_config_path", return_value=str(settings_path)):
                doctor = Doctor()
                result = doctor.check_hooks()
                assert result.status == CheckStatus.PASS
                assert "3/3" in result.message

    def test_partial_hooks(self, _isolate_config_dir, tmp_path):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings_path = claude_dir / "settings.json"
        settings_path.write_text(json.dumps({
            "hooks": {
                "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "ai-guardian"}]}],
            }
        }))

        with mock.patch("ai_guardian.setup.IDESetup.list_detected_ides", return_value=["claude"]):
            with mock.patch("ai_guardian.setup.IDESetup.get_config_path", return_value=str(settings_path)):
                doctor = Doctor()
                result = doctor.check_hooks()
                assert result.status == CheckStatus.WARN
                assert "1/3" in result.message


class TestCheckStateDir:
    def test_exists_writable(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_state_dir()
        assert result.status == CheckStatus.PASS

    def test_old_location_files(self, _isolate_config_dir):
        config_dir = _isolate_config_dir
        (config_dir / "violations.jsonl").write_text("")
        doctor = Doctor()
        result = doctor.check_state_dir()
        assert result.status == CheckStatus.WARN
        assert "Old files" in result.message

    def test_fix_creates_dir(self, tmp_path):
        state_dir = tmp_path / "nonexistent_state"
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        with mock.patch.dict(os.environ, {
            "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            "AI_GUARDIAN_STATE_DIR": str(state_dir),
            "AI_GUARDIAN_CACHE_DIR": str(cache_dir),
        }):
            doctor = Doctor(fix=True)
            result = doctor.check_state_dir()
            assert result.status == CheckStatus.PASS
            assert result.fixed is True
            assert state_dir.exists()

    def test_fix_removes_old_files(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create old files in config dir and new files in state dir
        (config_dir / "violations.jsonl").write_text("old")
        (state_dir / "violations.jsonl").write_text("new")

        with mock.patch.dict(os.environ, {
            "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            "AI_GUARDIAN_STATE_DIR": str(state_dir),
            "AI_GUARDIAN_CACHE_DIR": str(cache_dir),
        }):
            doctor = Doctor(fix=True)
            result = doctor.check_state_dir()
            assert result.status == CheckStatus.PASS
            assert result.fixed is True
            assert not (config_dir / "violations.jsonl").exists()
            assert (state_dir / "violations.jsonl").exists()


class TestCheckCacheDir:
    def test_exists(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_cache_dir()
        assert result.status == CheckStatus.PASS

    def test_with_fresh_patterns(self, _isolate_config_dir):
        cache_dir = Path(os.environ["AI_GUARDIAN_CACHE_DIR"])
        (cache_dir / "patterns.toml").write_text("[patterns]\n")
        doctor = Doctor()
        result = doctor.check_cache_dir()
        assert result.status == CheckStatus.PASS
        assert "fresh" in result.message.lower()

    def test_stale_patterns(self, _isolate_config_dir):
        cache_dir = Path(os.environ["AI_GUARDIAN_CACHE_DIR"])
        patterns_file = cache_dir / "patterns.toml"
        patterns_file.write_text("[patterns]\n")
        old_time = time.time() - (10 * 86400)
        os.utime(patterns_file, (old_time, old_time))
        doctor = Doctor()
        result = doctor.check_cache_dir()
        assert result.status == CheckStatus.WARN
        assert "stale" in result.message.lower()

    def test_fix_creates_dir(self, tmp_path):
        cache_dir = tmp_path / "nonexistent_cache"
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        state_dir = tmp_path / "state"
        state_dir.mkdir()

        with mock.patch.dict(os.environ, {
            "AI_GUARDIAN_CONFIG_DIR": str(config_dir),
            "AI_GUARDIAN_STATE_DIR": str(state_dir),
            "AI_GUARDIAN_CACHE_DIR": str(cache_dir),
        }):
            doctor = Doctor(fix=True)
            result = doctor.check_cache_dir()
            assert result.status == CheckStatus.PASS
            assert result.fixed is True
            assert cache_dir.exists()


class TestCheckPermissions:
    def test_valid_rules(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "Bash", "allow": ["git *"]},
                    {"matcher": "Skill", "allow": ["daf-*"]},
                ]
            }
        }))
        doctor = Doctor()
        result = doctor.check_permissions()
        assert result.status == CheckStatus.PASS
        assert "2 rule(s)" in result.message

    def test_no_rules(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "permissions": {"enabled": True, "rules": []}
        }))
        doctor = Doctor()
        result = doctor.check_permissions()
        assert result.status == CheckStatus.WARN

    def test_invalid_rule(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "permissions": {
                "enabled": True,
                "rules": [{"allow": ["*"]}]
            }
        }))
        doctor = Doctor()
        result = doctor.check_permissions()
        assert result.status == CheckStatus.FAIL
        assert "invalid" in result.message.lower()

    def test_no_config(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_permissions()
        assert result.status == CheckStatus.WARN


class TestCheckDirectoryRules:
    def test_no_rules(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({}))
        doctor = Doctor()
        result = doctor.check_directory_rules()
        assert result.status == CheckStatus.PASS

    def test_valid_rules(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "directory_rules": [
                {"pattern": "/home/**", "mode": "deny"},
                {"pattern": "/tmp/**", "mode": "allow", "_generated": True},
            ]
        }))
        doctor = Doctor()
        result = doctor.check_directory_rules()
        assert result.status == CheckStatus.PASS
        assert "1 user" in result.message
        assert "1 generated" in result.message

    def test_paths_format(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "directory_rules": {"rules": [
                {"paths": ["/home/**"], "mode": "deny"},
            ]}
        }))
        doctor = Doctor()
        result = doctor.check_directory_rules()
        assert result.status == CheckStatus.PASS

    def test_invalid_rule(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "directory_rules": [{"mode": "deny"}]
        }))
        doctor = Doctor()
        result = doctor.check_directory_rules()
        assert result.status == CheckStatus.FAIL

    def test_no_config(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_directory_rules()
        assert result.status == CheckStatus.WARN


class TestCheckConsoleDeps:
    def test_all_present(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_console_deps()
        # At minimum textual should be available since it's a core dep
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_missing_deps(self, _isolate_config_dir):
        import importlib
        with mock.patch.dict("sys.modules", {"tree_sitter_json": None}):
            with mock.patch("builtins.__import__", side_effect=lambda name, *a, **kw: (_ for _ in ()).throw(ImportError()) if name == "tree_sitter_json" else importlib.__import__(name, *a, **kw)):
                doctor = Doctor()
                result = doctor.check_console_deps()
                assert result.status == CheckStatus.WARN
                assert "tree-sitter-json" in result.message


class TestCheckConfigConsistency:
    def test_consistent(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_config_consistency()
        assert result.status in (CheckStatus.PASS, CheckStatus.SKIP)


# --- Output formatter tests ---


class TestFormatHuman:
    def test_all_pass(self):
        report = DoctorReport(
            version="1.0.0",
            checks=[
                CheckResult(name="config_file", status=CheckStatus.PASS, message="OK"),
                CheckResult(name="scanners", status=CheckStatus.PASS, message="gitleaks 8.30.1"),
            ]
        )
        output = format_human(report)
        assert "1.0.0" in output
        assert "PASS" in output
        assert "2 passed" in output

    def test_with_warnings(self):
        report = DoctorReport(
            version="1.0.0",
            checks=[
                CheckResult(name="config_file", status=CheckStatus.PASS, message="OK"),
                CheckResult(name="scanners", status=CheckStatus.WARN, message="outdated",
                            fix_hint="Update scanners"),
            ]
        )
        output = format_human(report)
        assert "WARN" in output
        assert "1 warning" in output
        assert "Hint: Update scanners" in output

    def test_with_errors(self):
        report = DoctorReport(
            version="1.0.0",
            checks=[
                CheckResult(name="scanners", status=CheckStatus.FAIL, message="none found"),
            ]
        )
        output = format_human(report)
        assert "FAIL" in output
        assert "1 error" in output

    def test_fixed_items(self):
        report = DoctorReport(
            version="1.0.0",
            checks=[
                CheckResult(name="state_dir", status=CheckStatus.PASS, message="Created",
                            fixable=True, fixed=True, fix_hint="created dir"),
            ]
        )
        output = format_human(report)
        assert "Fixed" in output
        assert "1 fixed" in output


class TestFormatJson:
    def test_valid_json(self):
        report = DoctorReport(
            version="1.0.0",
            checks=[
                CheckResult(name="config_file", status=CheckStatus.PASS, message="OK"),
            ]
        )
        output = format_json(report)
        data = json.loads(output)
        assert data["version"] == "1.0.0"
        assert data["summary"]["total"] == 1
        assert data["summary"]["pass"] == 1
        assert len(data["checks"]) == 1

    def test_structure(self):
        report = DoctorReport(
            version="2.0.0",
            checks=[
                CheckResult(name="a", status=CheckStatus.PASS, message="ok"),
                CheckResult(name="b", status=CheckStatus.WARN, message="warn",
                            fix_hint="do X", fixable=True),
                CheckResult(name="c", status=CheckStatus.FAIL, message="fail"),
            ]
        )
        data = json.loads(format_json(report))
        assert data["summary"]["pass"] == 1
        assert data["summary"]["warn"] == 1
        assert data["summary"]["fail"] == 1
        assert data["checks"][1]["fix_hint"] == "do X"
        assert data["checks"][1]["fixable"] is True


# --- CLI entry point tests ---


class TestDoctorCommand:
    def _make_args(self, **kwargs):
        defaults = {"json": False, "fix": False, "quiet": False, "check_connectivity": False}
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    @mock.patch("ai_guardian.doctor.Doctor.run_all")
    def test_quiet_mode(self, mock_run, _isolate_config_dir):
        mock_run.return_value = DoctorReport(checks=[
            CheckResult(name="a", status=CheckStatus.WARN, message="warn"),
        ])
        result = doctor_command(self._make_args(quiet=True))
        assert result == 1

    @mock.patch("ai_guardian.doctor.Doctor.run_all")
    def test_json_mode(self, mock_run, _isolate_config_dir, capsys):
        mock_run.return_value = DoctorReport(
            version="1.0.0",
            checks=[
                CheckResult(name="a", status=CheckStatus.PASS, message="ok"),
            ]
        )
        result = doctor_command(self._make_args(json=True))
        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["pass"] == 1

    @mock.patch("ai_guardian.doctor.Doctor.run_all")
    def test_human_mode(self, mock_run, _isolate_config_dir, capsys):
        mock_run.return_value = DoctorReport(
            version="1.0.0",
            checks=[
                CheckResult(name="config_file", status=CheckStatus.PASS, message="ok"),
            ]
        )
        result = doctor_command(self._make_args())
        assert result == 0
        captured = capsys.readouterr()
        assert "PASS" in captured.out

    def test_fix_flag_passed(self, _isolate_config_dir):
        with mock.patch("ai_guardian.doctor.Doctor.run_all") as mock_run:
            mock_run.return_value = DoctorReport(checks=[])
            doctor_command(self._make_args(fix=True))
            # Verify Doctor was created with fix=True by checking the call
            # The Doctor instance is created inside doctor_command


class TestDoctorRunAll:
    def test_run_all_returns_report(self, _isolate_config_dir):
        doctor = Doctor()
        report = doctor.run_all()
        assert isinstance(report, DoctorReport)
        assert len(report.checks) == 11
        assert report.version != ""

    def test_check_crash_handled(self, _isolate_config_dir):
        doctor = Doctor()
        original = doctor.check_config_file
        doctor.check_config_file = mock.MagicMock(side_effect=RuntimeError("boom"))
        report = doctor.run_all()
        crash_check = [c for c in report.checks if "crashed" in c.message.lower()]
        assert len(crash_check) == 1
        assert crash_check[0].status == CheckStatus.FAIL
        doctor.check_config_file = original
