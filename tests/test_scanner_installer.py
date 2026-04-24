"""
Tests for scanner_installer module.
"""

import platform
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from ai_guardian.scanner_installer import ScannerInstaller, InstallMethod


class TestScannerInstaller:
    """Tests for ScannerInstaller class."""

    def test_detect_platform(self):
        """Test platform detection."""
        installer = ScannerInstaller()
        platform_arch = installer.detect_platform()

        # Should be in format "system_arch"
        assert "_" in platform_arch

        # Should match one of expected platforms
        expected_platforms = {
            "darwin_arm64",
            "darwin_x64",
            "linux_x64",
            "linux_arm64",
            "linux_armv7",
            "linux_armv6",
            "linux_x32",
            "windows_x64",
            "windows_arm64",
            "windows_x32",
        }
        assert platform_arch in expected_platforms

    def test_get_github_repo(self):
        """Test GitHub repository lookup."""
        installer = ScannerInstaller()

        assert installer.get_github_repo("gitleaks") == "gitleaks/gitleaks"
        assert installer.get_github_repo("betterleaks") == "betterleaks/betterleaks"
        assert installer.get_github_repo("leaktk") == "leaktk/leaktk"

    def test_get_pinned_version(self):
        """Test pinned version lookup."""
        installer = ScannerInstaller()

        # Should return version strings (without 'v' prefix)
        gitleaks_version = installer.get_pinned_version("gitleaks")
        assert gitleaks_version != "unknown"
        assert not gitleaks_version.startswith("v")
        assert "." in gitleaks_version  # Should be semantic version

    @mock.patch("ai_guardian.scanner_installer.requests")
    def test_get_latest_version_from_github(self, mock_requests):
        """Test fetching latest version from GitHub API."""
        # Mock successful GitHub API response
        mock_response = mock.Mock()
        mock_response.raise_for_status = mock.Mock()
        mock_response.json.return_value = {"tag_name": "v8.30.1"}
        mock_requests.get.return_value = mock_response

        installer = ScannerInstaller()
        version = installer.get_latest_version("gitleaks")

        assert version == "8.30.1"  # Should strip 'v' prefix
        mock_requests.get.assert_called_once()

    @mock.patch("ai_guardian.scanner_installer.requests")
    def test_get_latest_version_fallback_to_pinned(self, mock_requests):
        """Test fallback to pinned version when GitHub API fails."""
        # Mock failed GitHub API response
        mock_requests.get.side_effect = Exception("Network error")

        installer = ScannerInstaller()
        version = installer.get_latest_version("gitleaks")

        # Should fall back to pinned version
        assert version != "unknown"
        assert "." in version

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    def test_install_via_package_manager_brew(self, mock_run, mock_which):
        """Test installation via Homebrew (macOS)."""
        # Mock platform detection and brew availability
        with mock.patch("platform.system", return_value="Darwin"):
            mock_which.return_value = "/opt/homebrew/bin/brew"
            mock_run.return_value = mock.Mock(returncode=0)

            installer = ScannerInstaller()
            success = installer.install_via_package_manager("gitleaks")

            assert success
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "brew"
            assert "install" in args
            assert "gitleaks" in args

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    def test_install_via_package_manager_apt(self, mock_run, mock_which):
        """Test installation via apt-get (Linux)."""
        # Mock platform detection and apt availability
        with mock.patch("platform.system", return_value="Linux"):
            mock_which.side_effect = lambda cmd: (
                "/usr/bin/apt-get" if cmd == "apt-get" else None
            )
            mock_run.return_value = mock.Mock(returncode=0)

            installer = ScannerInstaller()
            success = installer.install_via_package_manager("gitleaks")

            assert success
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "apt-get" in args
            assert "install" in args

    def test_install_unsupported_scanner(self):
        """Test that installing unsupported scanner raises ValueError."""
        installer = ScannerInstaller()

        with pytest.raises(ValueError, match="Unsupported scanner"):
            installer.install("invalid_scanner")

    @mock.patch("ai_guardian.scanner_installer.ScannerInstaller.get_latest_version")
    @mock.patch("ai_guardian.scanner_installer.ScannerInstaller.install_from_download")
    @mock.patch(
        "ai_guardian.scanner_installer.ScannerInstaller.install_via_package_manager"
    )
    def test_install_with_explicit_version(
        self, mock_pkg_mgr, mock_download, mock_get_latest
    ):
        """Test installation with explicit version flag."""
        mock_pkg_mgr.return_value = False  # Package manager fails
        mock_download.return_value = Path("/fake/path/gitleaks")

        installer = ScannerInstaller()
        success = installer.install("gitleaks", version="8.30.1")

        # Should use explicit version, not call get_latest_version
        mock_get_latest.assert_not_called()
        mock_download.assert_called_once_with("gitleaks", "8.30.1")
        assert success

    @mock.patch("ai_guardian.scanner_installer.ScannerInstaller.get_latest_version")
    @mock.patch("ai_guardian.scanner_installer.ScannerInstaller.get_pinned_version")
    @mock.patch("ai_guardian.scanner_installer.ScannerInstaller.install_from_download")
    @mock.patch(
        "ai_guardian.scanner_installer.ScannerInstaller.install_via_package_manager"
    )
    def test_install_with_use_pinned(
        self, mock_pkg_mgr, mock_download, mock_get_pinned, mock_get_latest
    ):
        """Test installation with use_pinned flag."""
        mock_pkg_mgr.return_value = False  # Package manager fails
        mock_download.return_value = Path("/fake/path/gitleaks")
        mock_get_pinned.return_value = "8.29.0"

        installer = ScannerInstaller()
        success = installer.install("gitleaks", use_pinned=True)

        # Should use pinned version, not call get_latest_version
        mock_get_latest.assert_not_called()
        mock_get_pinned.assert_called_once()
        mock_download.assert_called_once_with("gitleaks", "8.29.0")
        assert success

    @mock.patch("shutil.which")
    @mock.patch("subprocess.run")
    def test_verify_installation_success(self, mock_run, mock_which):
        """Test successful installation verification."""
        mock_which.return_value = "/usr/local/bin/gitleaks"
        mock_run.return_value = mock.Mock(returncode=0)

        installer = ScannerInstaller()
        assert installer.verify_installation("gitleaks")

    @mock.patch("shutil.which")
    def test_verify_installation_not_found(self, mock_which):
        """Test verification when scanner not found."""
        mock_which.return_value = None

        # Create temp install_dir for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            installer = ScannerInstaller(install_dir=Path(temp_dir))
            assert not installer.verify_installation("gitleaks")

    @mock.patch("ai_guardian.scanner_installer.requests")
    def test_install_from_download_network_error(self, mock_requests):
        """Test download failure handling."""
        mock_requests.get.side_effect = Exception("Network error")

        with tempfile.TemporaryDirectory() as temp_dir:
            installer = ScannerInstaller(install_dir=Path(temp_dir))

            with pytest.raises(RuntimeError, match="Failed to download"):
                installer.install_from_download("gitleaks", "8.30.1")

    def test_init_creates_install_dir(self):
        """Test that installer creates install directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            install_dir = Path(temp_dir) / "new_dir" / "bin"
            assert not install_dir.exists()

            installer = ScannerInstaller(install_dir=install_dir)
            assert install_dir.exists()
            assert installer.install_dir == install_dir


class TestPlatformDetection:
    """Tests for platform-specific detection."""

    @mock.patch("platform.system")
    @mock.patch("platform.machine")
    def test_darwin_arm64(self, mock_machine, mock_system):
        """Test detection of macOS ARM64 (Apple Silicon)."""
        mock_system.return_value = "Darwin"
        mock_machine.return_value = "arm64"

        installer = ScannerInstaller()
        assert installer.detect_platform() == "darwin_arm64"

    @mock.patch("platform.system")
    @mock.patch("platform.machine")
    def test_darwin_x64(self, mock_machine, mock_system):
        """Test detection of macOS x64 (Intel)."""
        mock_system.return_value = "Darwin"
        mock_machine.return_value = "x86_64"

        installer = ScannerInstaller()
        assert installer.detect_platform() == "darwin_x64"

    @mock.patch("platform.system")
    @mock.patch("platform.machine")
    def test_linux_x64(self, mock_machine, mock_system):
        """Test detection of Linux x64."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "x86_64"

        installer = ScannerInstaller()
        assert installer.detect_platform() == "linux_x64"

    @mock.patch("platform.system")
    @mock.patch("platform.machine")
    def test_windows_x64(self, mock_machine, mock_system):
        """Test detection of Windows x64."""
        mock_system.return_value = "Windows"
        mock_machine.return_value = "AMD64"

        installer = ScannerInstaller()
        assert installer.detect_platform() == "windows_x64"

    @mock.patch("platform.system")
    @mock.patch("platform.machine")
    def test_linux_arm64(self, mock_machine, mock_system):
        """Test detection of Linux ARM64."""
        mock_system.return_value = "Linux"
        mock_machine.return_value = "aarch64"

        installer = ScannerInstaller()
        assert installer.detect_platform() == "linux_arm64"
