"""
Unit tests for support bundle module.
"""

import argparse
import json
import os
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from ai_guardian.support_bundle import (
    _sanitize_config,
    _sanitize_violations,
    _get_system_info,
    _get_bundle_status,
    _get_gcs_token_from_adc,
    _get_gcs_token_from_gcloud,
    _load_bundle_from_path,
    _send_to_gcs,
    prepare_bundle,
    send_bundle,
    support_command,
    _active_bundles,
    _cleanup_bundle,
)


class TestSanitizeConfig:
    """Test config sanitization."""

    def test_redacts_sensitive_keys(self):
        config = {
            "secret_scanning": {"enabled": True},
            "pattern_server": {"auth_token": "my-secret-token", "url": "https://example.com/patterns"},
        }
        sanitized, count = _sanitize_config(config)
        assert sanitized["pattern_server"]["auth_token"] == "[REDACTED]"
        assert sanitized["pattern_server"]["url"] == "[REDACTED]"
        assert count == 2

    def test_strips_comments(self):
        config = {
            "_comment_test": "This is a comment",
            "enabled": True,
        }
        sanitized, _ = _sanitize_config(config)
        assert "_comment_test" not in sanitized
        assert sanitized["enabled"] is True

    def test_preserves_non_sensitive(self):
        config = {"secret_scanning": {"enabled": True, "action": "block"}}
        sanitized, count = _sanitize_config(config)
        assert sanitized["secret_scanning"]["enabled"] is True
        assert sanitized["secret_scanning"]["action"] == "block"
        assert count == 0


class TestSanitizeViolations:
    """Test violation sanitization."""

    def test_truncates_file_paths(self):
        violations = [{
            "timestamp": "2026-05-09T10:00:00Z",
            "violation_type": "secret_detected",
            "context": {"file_path": "/home/user/project/src/secrets.py"},
        }]
        sanitized, count = _sanitize_violations(violations)
        assert sanitized[0]["context"]["file_path"] == str(Path("...") / "src" / "secrets.py")
        assert count >= 1

    def test_removes_content_preview(self):
        violations = [{
            "context": {"content_preview": "password = 'hunter2'", "file_path": ""},
        }]
        sanitized, count = _sanitize_violations(violations)
        assert "content_preview" not in sanitized[0]["context"]


class TestGetSystemInfo:
    """Test system info collection."""

    def test_returns_expected_fields(self):
        info = _get_system_info()
        assert "ai_guardian_version" in info
        assert "python_version" in info
        assert "platform" in info
        assert "os" in info


class TestPrepareBundle:
    """Test bundle preparation."""

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_creates_bundle(self, mock_config):
        mock_config.return_value = {"export_destination": "~/support", "bundle_ttl_minutes": 30}

        result = prepare_bundle()

        assert "bundle_id" in result
        assert result["bundle_id"].startswith("support-")
        assert "temp_path" in result
        assert "files" in result
        assert len(result["files"]) > 0

        # System info should always be present
        file_names = [f["name"] for f in result["files"]]
        assert "system-info.json" in file_names

        # Cleanup
        _cleanup_bundle(result["bundle_id"])

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_bundle_files_exist_on_disk(self, mock_config):
        mock_config.return_value = {"export_destination": "~/support"}

        result = prepare_bundle()
        temp_path = Path(result["temp_path"])
        assert temp_path.exists()

        for f in result["files"]:
            assert (temp_path / f["name"]).exists()

        _cleanup_bundle(result["bundle_id"])


class TestSendBundle:
    """Test bundle sending."""

    def test_rejects_unknown_bundle_id(self):
        result = send_bundle("nonexistent-bundle")
        assert result["status"] == "error"
        assert "not found" in result["message"]

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_sends_to_local_directory(self, mock_config, tmp_path):
        dest = tmp_path / "support-output"
        mock_config.return_value = {"export_destination": str(dest), "bundle_ttl_minutes": 30}

        bundle = prepare_bundle()
        result = send_bundle(bundle["bundle_id"])

        assert result["status"] == "sent"
        assert dest.exists()

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_defaults_to_xdg_state_dir(self, mock_config):
        """When no export_destination configured, defaults to XDG state dir."""
        mock_config.return_value = {}

        bundle = prepare_bundle()
        assert "support-bundles" in bundle["destination"]

        result = send_bundle(bundle["bundle_id"])
        assert result["status"] == "sent"

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_cleanup_after_send(self, mock_config, tmp_path):
        dest = tmp_path / "output"
        mock_config.return_value = {"export_destination": str(dest), "bundle_ttl_minutes": 30}

        bundle = prepare_bundle()
        bundle_id = bundle["bundle_id"]
        temp_path = Path(bundle["temp_path"])

        send_bundle(bundle_id)

        assert not temp_path.exists()
        assert bundle_id not in _active_bundles


class TestPrepareBundleFlags:
    """Test prepare_bundle with filtering flags."""

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_no_log_excludes_log_file(self, mock_config):
        mock_config.return_value = {"export_destination": "~/support"}
        result = prepare_bundle(include_log=False)
        file_names = [f["name"] for f in result["files"]]
        assert "ai-guardian.log" not in file_names
        assert "system-info.json" in file_names
        _cleanup_bundle(result["bundle_id"])

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_no_violations_excludes_violations(self, mock_config):
        mock_config.return_value = {"export_destination": "~/support"}
        result = prepare_bundle(include_violations=False)
        file_names = [f["name"] for f in result["files"]]
        assert "violations.json" not in file_names
        assert "system-info.json" in file_names
        _cleanup_bundle(result["bundle_id"])

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_output_path_copies_files(self, mock_config, tmp_path):
        output_dir = tmp_path / "my-bundle"
        mock_config.return_value = {"export_destination": "~/support"}
        result = prepare_bundle(output_path=str(output_dir))
        assert output_dir.exists()
        assert "output_path" in result
        for f in result["files"]:
            assert (output_dir / f["name"]).exists()
        _cleanup_bundle(result["bundle_id"])

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_both_exclusions(self, mock_config):
        mock_config.return_value = {}
        result = prepare_bundle(include_log=False, include_violations=False)
        file_names = [f["name"] for f in result["files"]]
        assert "ai-guardian.log" not in file_names
        assert "violations.json" not in file_names
        assert "system-info.json" in file_names
        _cleanup_bundle(result["bundle_id"])


class TestLoadBundleFromPath:
    """Test _load_bundle_from_path helper."""

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_valid_directory(self, mock_config, tmp_path):
        mock_config.return_value = {}
        bundle_dir = tmp_path / "support-20260511-abcd1234"
        bundle_dir.mkdir()
        (bundle_dir / "system-info.json").write_text("{}")
        bundle_id = _load_bundle_from_path(str(bundle_dir))
        assert bundle_id is not None
        assert bundle_id in _active_bundles
        _cleanup_bundle(bundle_id)

    def test_nonexistent_directory(self):
        result = _load_bundle_from_path("/nonexistent/path")
        assert result is None

    def test_empty_directory(self, tmp_path):
        empty_dir = tmp_path / "empty-bundle"
        empty_dir.mkdir()
        result = _load_bundle_from_path(str(empty_dir))
        assert result is None

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_uses_dir_name_as_bundle_id(self, mock_config, tmp_path):
        mock_config.return_value = {}
        bundle_dir = tmp_path / "support-20260511-test1234"
        bundle_dir.mkdir()
        (bundle_dir / "config.json").write_text("{}")
        bundle_id = _load_bundle_from_path(str(bundle_dir))
        assert bundle_id == "support-20260511-test1234"
        _cleanup_bundle(bundle_id)


class TestGetBundleStatus:
    """Test _get_bundle_status helper."""

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_returns_expected_fields(self, mock_config):
        mock_config.return_value = {"export_destination": "~/support", "bundle_ttl_minutes": 15}
        status = _get_bundle_status()
        assert "destination" in status
        assert "destination_type" in status
        assert "auth_method" in status
        assert "auth_configured" in status
        assert "bundle_ttl_minutes" in status
        assert "pending_bundles" in status
        assert status["bundle_ttl_minutes"] == 15

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_local_destination_type(self, mock_config):
        mock_config.return_value = {"export_destination": "~/support"}
        status = _get_bundle_status()
        assert status["destination_type"] == "local"

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_s3_destination_type(self, mock_config):
        mock_config.return_value = {"export_destination": "s3://bucket/prefix"}
        status = _get_bundle_status()
        assert status["destination_type"] == "s3"

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_no_destination_defaults(self, mock_config):
        mock_config.return_value = {}
        status = _get_bundle_status()
        assert status["destination_type"] == "local"
        assert "support-bundles" in status["destination"]


class TestSupportCommand:
    """Test support_command CLI entry point."""

    def _make_args(self, support_command_val=None, **kwargs):
        defaults = {
            "support_command": support_command_val,
            "json": False,
            "no_log": False,
            "no_violations": False,
            "output": None,
            "prepare": False,
            "yes": False,
            "bundle": None,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_prepare_subcommand(self, mock_config, capsys):
        mock_config.return_value = {"export_destination": "~/support"}
        args = self._make_args(support_command_val="prepare")
        result = support_command(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "support-" in captured.out

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_prepare_json(self, mock_config, capsys):
        mock_config.return_value = {}
        args = self._make_args(support_command_val="prepare", json=True)
        result = support_command(args)
        assert result == 0
        data = json.loads(capsys.readouterr().out)
        assert "bundle_id" in data
        assert "files" in data

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_prepare_no_log(self, mock_config, capsys):
        mock_config.return_value = {}
        args = self._make_args(support_command_val="prepare", no_log=True, json=True)
        result = support_command(args)
        assert result == 0
        data = json.loads(capsys.readouterr().out)
        file_names = [f["name"] for f in data["files"]]
        assert "ai-guardian.log" not in file_names

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_prepare_with_output(self, mock_config, tmp_path, capsys):
        output_dir = tmp_path / "my-output"
        mock_config.return_value = {}
        args = self._make_args(support_command_val="prepare", output=str(output_dir))
        result = support_command(args)
        assert result == 0
        assert output_dir.exists()

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_send_with_prepare_and_yes(self, mock_config, tmp_path, capsys):
        dest = tmp_path / "send-dest"
        mock_config.return_value = {"export_destination": str(dest), "bundle_ttl_minutes": 30}
        args = self._make_args(support_command_val="send", prepare=True, yes=True)
        result = support_command(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "Sent" in captured.out or "sent" in captured.out

    @patch("ai_guardian.support_bundle._get_support_config")
    @patch("builtins.input", return_value="n")
    @patch("sys.stdin")
    def test_send_with_prepare_user_declines(self, mock_stdin, mock_input, mock_config, capsys):
        mock_stdin.isatty.return_value = True
        mock_config.return_value = {"export_destination": "~/support"}
        args = self._make_args(support_command_val="send", prepare=True)
        result = support_command(args)
        assert result == 1

    @patch("ai_guardian.support_bundle._get_support_config")
    @patch("builtins.input", return_value="y")
    @patch("sys.stdin")
    def test_send_with_prepare_user_confirms(self, mock_stdin, mock_input, mock_config, tmp_path, capsys):
        mock_stdin.isatty.return_value = True
        dest = tmp_path / "confirmed-dest"
        mock_config.return_value = {"export_destination": str(dest), "bundle_ttl_minutes": 30}
        args = self._make_args(support_command_val="send", prepare=True)
        result = support_command(args)
        assert result == 0

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_send_with_bundle_path(self, mock_config, tmp_path, capsys):
        dest = tmp_path / "dest"
        bundle_dir = tmp_path / "support-20260511-test1234"
        bundle_dir.mkdir()
        (bundle_dir / "system-info.json").write_text('{"test": true}')
        mock_config.return_value = {"export_destination": str(dest), "bundle_ttl_minutes": 30}
        args = self._make_args(support_command_val="send", bundle=str(bundle_dir), yes=True)
        result = support_command(args)
        assert result == 0

    def test_send_no_bundle_available(self, capsys):
        args = self._make_args(support_command_val="send")
        result = support_command(args)
        assert result == 1
        captured = capsys.readouterr()
        assert "prepare" in captured.err.lower()

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_status_subcommand(self, mock_config, capsys):
        mock_config.return_value = {"export_destination": "~/support", "bundle_ttl_minutes": 30}
        args = self._make_args(support_command_val="status")
        result = support_command(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "Destination" in captured.out or "destination" in captured.out

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_status_json(self, mock_config, capsys):
        mock_config.return_value = {"export_destination": "~/support", "bundle_ttl_minutes": 30}
        args = self._make_args(support_command_val="status", json=True)
        result = support_command(args)
        assert result == 0
        data = json.loads(capsys.readouterr().out)
        assert "destination" in data

    def test_no_subcommand_shows_usage(self, capsys):
        args = self._make_args()
        result = support_command(args)
        assert result == 1
        captured = capsys.readouterr()
        assert "usage" in captured.err.lower() or "support" in captured.err.lower()


class TestGCSDestinationType:
    """Test GCS destination type detection."""

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_gcs_destination_type(self, mock_config):
        mock_config.return_value = {"export_destination": "gs://my-bucket"}
        status = _get_bundle_status()
        assert status["destination_type"] == "gcs"

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_gcs_destination_with_trailing_slash(self, mock_config):
        mock_config.return_value = {"export_destination": "gs://my-bucket/"}
        status = _get_bundle_status()
        assert status["destination_type"] == "gcs"


class TestGCSTokenFromADC:
    """Test ADC credential discovery."""

    @patch("ai_guardian.support_bundle.urlopen")
    def test_reads_authorized_user_credentials(self, mock_urlopen, tmp_path):
        creds_file = tmp_path / "adc.json"
        creds_file.write_text(json.dumps({
            "type": "authorized_user",
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "refresh_token": "test-refresh-token",
        }))

        mock_response = MagicMock()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.read.return_value = json.dumps({"access_token": "test-token-123"}).encode()
        mock_urlopen.return_value = mock_response

        with patch.dict(os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": str(creds_file)}):
            token = _get_gcs_token_from_adc()

        assert token == "test-token-123"

    def test_returns_none_when_no_credentials(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("pathlib.Path.exists", return_value=False):
                token = _get_gcs_token_from_adc()
        assert token is None

    def test_skips_non_authorized_user_type(self, tmp_path):
        creds_file = tmp_path / "service-account.json"
        creds_file.write_text(json.dumps({
            "type": "service_account",
            "project_id": "test-project",
        }))

        with patch.dict(os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": str(creds_file)}):
            token = _get_gcs_token_from_adc()

        assert token is None


class TestGCSTokenFromGcloud:
    """Test gcloud CLI fallback."""

    @patch("subprocess.run")
    def test_returns_token_from_gcloud(self, mock_run):
        mock_run.return_value = MagicMock(stdout="gcloud-token-456\n")
        token = _get_gcs_token_from_gcloud()
        assert token == "gcloud-token-456"
        mock_run.assert_called_once_with(
            ["gcloud", "auth", "print-access-token"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

    @patch("subprocess.run", side_effect=FileNotFoundError("gcloud not found"))
    def test_returns_none_when_gcloud_missing(self, mock_run):
        token = _get_gcs_token_from_gcloud()
        assert token is None

    @patch("subprocess.run")
    def test_returns_none_for_empty_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="")
        token = _get_gcs_token_from_gcloud()
        assert token is None


class TestSendToGCS:
    """Test GCS upload."""

    def _make_bundle_dir(self, tmp_path):
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / ".ai-read-deny").touch()
        (bundle_dir / "config.json").write_text('{"test": true}')
        (bundle_dir / "system-info.json").write_text('{"version": "1.0"}')
        return bundle_dir

    @patch("ai_guardian.support_bundle._get_gcs_token_from_adc", return_value="test-token")
    @patch("ai_guardian.support_bundle._get_support_config", return_value={})
    @patch("ai_guardian.support_bundle.urlopen")
    def test_upload_success(self, mock_urlopen, mock_config, mock_adc, tmp_path):
        bundle_dir = self._make_bundle_dir(tmp_path)

        mock_response = MagicMock()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.read.return_value = b"{}"
        mock_urlopen.return_value = mock_response

        result = _send_to_gcs(
            "support-20260511-abc123", bundle_dir,
            "gs://my-bucket/ai-guardian/support/config-bundle/"
        )

        assert result["status"] == "sent"
        assert "gs://my-bucket/" in result["destination"]
        assert "support-20260511-abc123" in result["destination"]
        assert "2 files uploaded" in result["message"]
        assert mock_urlopen.call_count == 2

    @patch("ai_guardian.support_bundle._get_gcs_token_from_adc", return_value="test-token")
    @patch("ai_guardian.support_bundle._get_support_config", return_value={})
    @patch("ai_guardian.support_bundle.urlopen")
    def test_upload_uses_correct_object_path(self, mock_urlopen, mock_config, mock_adc, tmp_path):
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "config.json").write_text('{"test": true}')

        mock_response = MagicMock()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.read.return_value = b"{}"
        mock_urlopen.return_value = mock_response

        _send_to_gcs(
            "support-20260511-abc123", bundle_dir,
            "gs://my-bucket/ai-guardian/support/config-bundle"
        )

        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert "ai-guardian%2Fsupport%2Fconfig-bundle%2Fsupport-20260511-abc123%2Fconfig.json" in request.full_url

    @patch("ai_guardian.support_bundle._get_gcs_token_from_adc", return_value=None)
    @patch("ai_guardian.support_bundle._get_gcs_token_from_gcloud", return_value=None)
    @patch("ai_guardian.support_bundle._get_support_config", return_value={})
    def test_no_credentials_error(self, mock_config, mock_gcloud, mock_adc, tmp_path):
        bundle_dir = self._make_bundle_dir(tmp_path)

        result = _send_to_gcs("support-20260511-abc123", bundle_dir, "gs://my-bucket/prefix/")

        assert result["status"] == "error"
        assert "credentials" in result["message"].lower()
        assert "gcloud auth" in result["message"]

    @patch("ai_guardian.support_bundle._get_gcs_token_from_adc", return_value=None)
    @patch("ai_guardian.support_bundle._get_gcs_token_from_gcloud", return_value=None)
    @patch("ai_guardian.support_bundle._get_support_config")
    def test_config_token_env_fallback(self, mock_config, mock_gcloud, mock_adc, tmp_path):
        mock_config.return_value = {"auth": {"token_env": "MY_GCS_TOKEN"}}
        bundle_dir = self._make_bundle_dir(tmp_path)

        with patch("ai_guardian.support_bundle.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_response.read.return_value = b"{}"
            mock_urlopen.return_value = mock_response

            with patch.dict(os.environ, {"MY_GCS_TOKEN": "env-token-789"}):
                result = _send_to_gcs("support-20260511-abc123", bundle_dir, "gs://my-bucket/prefix/")

        assert result["status"] == "sent"

    @patch("ai_guardian.support_bundle._get_gcs_token_from_adc", return_value="test-token")
    @patch("ai_guardian.support_bundle._get_support_config", return_value={})
    @patch("ai_guardian.support_bundle.urlopen")
    def test_http_error(self, mock_urlopen, mock_config, mock_adc, tmp_path):
        bundle_dir = self._make_bundle_dir(tmp_path)

        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError(
            url="https://storage.googleapis.com/...",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=None,
        )

        result = _send_to_gcs("support-20260511-abc123", bundle_dir, "gs://my-bucket/prefix/")

        assert result["status"] == "error"
        assert "403" in result["message"]

    @patch("ai_guardian.support_bundle._get_support_config")
    def test_send_bundle_routes_to_gcs(self, mock_config, tmp_path):
        mock_config.return_value = {
            "export_destination": "gs://test-bucket/ai-guardian/support/config-bundle/",
            "bundle_ttl_minutes": 30,
        }

        bundle = prepare_bundle()
        bundle_id = bundle["bundle_id"]

        with patch("ai_guardian.support_bundle._send_to_gcs") as mock_gcs:
            mock_gcs.return_value = {"status": "sent", "destination": "gs://test-bucket/...", "message": "ok"}
            result = send_bundle(bundle_id)

        assert mock_gcs.called
        assert result["status"] == "sent"
