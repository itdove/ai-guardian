"""
Tests for scanner_manager module.
"""

import shutil
from unittest import mock

import pytest

from ai_guardian.scanner_manager import ScannerManager, InstalledScanner


class TestScannerManager:
    """Tests for ScannerManager class."""

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    def test_list_installed_empty(self, mock_run, mock_which):
        """Test listing scanners when none are installed."""
        mock_which.return_value = None

        manager = ScannerManager()
        scanners = manager.list_installed()

        assert scanners == []

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    def test_list_installed_gitleaks(self, mock_run, mock_which):
        """Test listing when gitleaks is installed."""
        # Mock gitleaks found, others not found
        mock_which.side_effect = lambda name: (
            "/usr/local/bin/gitleaks" if name == "gitleaks" else None
        )

        # Mock version output
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="8.30.1", stderr=""
        )

        manager = ScannerManager()
        scanners = manager.list_installed()

        assert len(scanners) == 1
        assert scanners[0].name == "gitleaks"
        assert scanners[0].version == "8.30.1"
        assert scanners[0].path == "/usr/local/bin/gitleaks"

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    def test_list_installed_multiple(self, mock_run, mock_which):
        """Test listing when multiple scanners are installed."""
        # Mock all scanners found
        def which_mock(name):
            return f"/usr/local/bin/{name}"

        mock_which.side_effect = which_mock

        # Mock version outputs
        def run_mock(cmd, **kwargs):
            if "gitleaks" in cmd:
                return mock.Mock(returncode=0, stdout="8.30.1", stderr="")
            elif "betterleaks" in cmd:
                return mock.Mock(returncode=0, stdout="1.1.2", stderr="")
            elif "leaktk" in cmd:
                return mock.Mock(returncode=0, stdout="0.2.10", stderr="")
            return mock.Mock(returncode=1, stdout="", stderr="")

        mock_run.side_effect = run_mock

        manager = ScannerManager()
        scanners = manager.list_installed()

        assert len(scanners) == 3
        scanner_names = {s.name for s in scanners}
        assert scanner_names == {"gitleaks", "betterleaks", "leaktk"}

    @mock.patch("subprocess.run")
    def test_get_version_success(self, mock_run):
        """Test successful version extraction."""
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="gitleaks version 8.30.1", stderr=""
        )

        manager = ScannerManager()
        version = manager._get_version("gitleaks")

        assert version == "8.30.1"

    @mock.patch("subprocess.run")
    def test_get_version_with_v_prefix(self, mock_run):
        """Test version extraction with 'v' prefix."""
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="v8.30.1", stderr=""
        )

        manager = ScannerManager()
        version = manager._get_version("gitleaks")

        assert version == "8.30.1"

    @mock.patch("subprocess.run")
    def test_get_version_failure(self, mock_run):
        """Test version extraction when command fails."""
        mock_run.return_value = mock.Mock(returncode=1, stdout="", stderr="")

        manager = ScannerManager()
        version = manager._get_version("gitleaks")

        assert version == "unknown"

    @mock.patch("subprocess.run")
    def test_get_version_timeout(self, mock_run):
        """Test version extraction when command times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("gitleaks", 5)

        manager = ScannerManager()
        version = manager._get_version("gitleaks")

        assert version == "unknown"

    def test_is_default_scanner_no_config(self):
        """Test default scanner when no config exists."""
        manager = ScannerManager(config={})

        # Gitleaks should be default when no config
        assert manager._is_default_scanner("gitleaks")
        assert not manager._is_default_scanner("betterleaks")
        assert not manager._is_default_scanner("leaktk")

    def test_is_default_scanner_with_config(self):
        """Test default scanner with configured engines."""
        config = {
            "secret_scanning": {"engines": ["betterleaks", "gitleaks"]}
        }
        manager = ScannerManager(config=config)

        # First engine in list should be default
        assert not manager._is_default_scanner("gitleaks")
        assert manager._is_default_scanner("betterleaks")
        assert not manager._is_default_scanner("leaktk")

    def test_is_default_scanner_with_dict_config(self):
        """Test default scanner with dict-based engine config."""
        config = {
            "secret_scanning": {
                "engines": [
                    {"type": "leaktk"},
                    {"type": "gitleaks"}
                ]
            }
        }
        manager = ScannerManager(config=config)

        assert not manager._is_default_scanner("gitleaks")
        assert not manager._is_default_scanner("betterleaks")
        assert manager._is_default_scanner("leaktk")

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    def test_get_scanner_info_found(self, mock_run, mock_which):
        """Test getting info for installed scanner."""
        mock_which.side_effect = lambda name: (
            "/usr/local/bin/gitleaks" if name == "gitleaks" else None
        )
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="8.30.1", stderr=""
        )

        manager = ScannerManager()
        scanner = manager.get_scanner_info("gitleaks")

        assert scanner is not None
        assert scanner.name == "gitleaks"
        assert scanner.version == "8.30.1"
        assert scanner.path == "/usr/local/bin/gitleaks"

    @mock.patch("shutil.which")
    def test_get_scanner_info_not_found(self, mock_which):
        """Test getting info for non-installed scanner."""
        mock_which.return_value = None

        manager = ScannerManager()
        scanner = manager.get_scanner_info("gitleaks")

        assert scanner is None

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    @mock.patch("builtins.print")
    def test_print_scanner_list_empty(self, mock_print, mock_run, mock_which):
        """Test printing when no scanners installed."""
        mock_which.return_value = None

        manager = ScannerManager()
        manager.print_scanner_list()

        # Should print installation instructions
        print_calls = [str(call) for call in mock_print.call_args_list]
        output = "\n".join(print_calls)
        assert "No scanners installed" in output
        assert "ai-guardian scanner install" in output

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    @mock.patch("builtins.print")
    def test_print_scanner_list_verbose(self, mock_print, mock_run, mock_which):
        """Test printing scanner list with verbose flag."""
        mock_which.side_effect = lambda name: (
            f"/usr/local/bin/{name}" if name == "gitleaks" else None
        )
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="8.30.1", stderr=""
        )

        manager = ScannerManager()
        manager.print_scanner_list(verbose=True)

        # Should print path with verbose
        print_calls = [str(call) for call in mock_print.call_args_list]
        output = "\n".join(print_calls)
        assert "gitleaks" in output
        assert "8.30.1" in output
        assert "/usr/local/bin/gitleaks" in output

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    @mock.patch("builtins.print")
    def test_print_scanner_info(self, mock_print, mock_run, mock_which):
        """Test printing scanner info."""
        mock_which.side_effect = lambda name: (
            "/usr/local/bin/gitleaks" if name == "gitleaks" else None
        )
        mock_run.return_value = mock.Mock(
            returncode=0, stdout="8.30.1", stderr=""
        )

        manager = ScannerManager()
        manager.print_scanner_info("gitleaks")

        # Should print scanner details
        print_calls = [str(call) for call in mock_print.call_args_list]
        output = "\n".join(print_calls)
        assert "gitleaks" in output
        assert "8.30.1" in output
        assert "/usr/local/bin/gitleaks" in output
        assert "github.com" in output

    @mock.patch("shutil.which")
    @mock.patch("builtins.print")
    def test_print_scanner_info_not_installed(self, mock_print, mock_which):
        """Test printing info for non-installed scanner."""
        mock_which.return_value = None

        manager = ScannerManager()
        manager.print_scanner_info("gitleaks")

        # Should print installation message
        print_calls = [str(call) for call in mock_print.call_args_list]
        output = "\n".join(print_calls)
        assert "not installed" in output.lower()
        assert "ai-guardian scanner install" in output
