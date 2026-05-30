"""Unit tests for desktop_utils module."""

import subprocess
import unittest
from unittest.mock import MagicMock, call, patch

from ai_guardian.desktop_utils import (
    _get_default_browser, _try_kdotool, _try_xdotool, _try_wmctrl, open_url,
)


class TestGetDefaultBrowser(unittest.TestCase):

    @patch("shutil.which", return_value="/usr/bin/firefox")
    @patch("subprocess.run")
    def test_returns_browser_name(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(stdout="firefox.desktop\n")
        self.assertEqual(_get_default_browser(), "firefox")
        mock_which.assert_called_once_with("firefox")

    @patch("shutil.which", return_value="/usr/bin/google-chrome")
    @patch("subprocess.run")
    def test_chrome_desktop_file(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(stdout="google-chrome.desktop\n")
        self.assertEqual(_get_default_browser(), "google-chrome")

    @patch("subprocess.run")
    def test_returns_none_when_xdg_settings_missing(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        self.assertIsNone(_get_default_browser())

    @patch("subprocess.run")
    def test_returns_none_on_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired("xdg-settings", 3)
        self.assertIsNone(_get_default_browser())

    @patch("subprocess.run")
    def test_returns_none_for_non_desktop_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="")
        self.assertIsNone(_get_default_browser())

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run")
    def test_returns_none_when_browser_not_in_path(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(stdout="org.mozilla.firefox.desktop\n")
        self.assertIsNone(_get_default_browser())


class TestTryKdotool(unittest.TestCase):

    @patch("subprocess.run")
    def test_returns_true_on_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(_try_kdotool())

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_returns_false_when_not_installed(self, mock_run):
        self.assertFalse(_try_kdotool())

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("kdotool", 3))
    def test_returns_false_on_timeout(self, mock_run):
        self.assertFalse(_try_kdotool())


class TestTryXdotool(unittest.TestCase):

    @patch("subprocess.run")
    def test_returns_true_on_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(_try_xdotool())

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_returns_false_when_not_installed(self, mock_run):
        self.assertFalse(_try_xdotool())

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("xdotool", 3))
    def test_returns_false_on_timeout(self, mock_run):
        self.assertFalse(_try_xdotool())


class TestTryWmctrl(unittest.TestCase):

    @patch("subprocess.run")
    def test_returns_true_on_first_match(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(_try_wmctrl())
        mock_run.assert_called_once()

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_returns_false_when_not_installed(self, mock_run):
        self.assertFalse(_try_wmctrl())

    @patch("subprocess.run")
    def test_tries_multiple_browsers(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        self.assertFalse(_try_wmctrl())
        self.assertEqual(mock_run.call_count, 4)


class TestOpenUrl(unittest.TestCase):

    @patch("ai_guardian.desktop_utils.webbrowser")
    @patch("ai_guardian.desktop_utils.platform")
    def test_non_linux_uses_webbrowser(self, mock_platform, mock_wb):
        mock_platform.system.return_value = "Darwin"
        open_url("http://localhost:8080")
        mock_wb.open.assert_called_once_with("http://localhost:8080")

    @patch("ai_guardian.desktop_utils._raise_browser_window")
    @patch("ai_guardian.desktop_utils.webbrowser")
    @patch("ai_guardian.desktop_utils.subprocess.Popen")
    @patch("ai_guardian.desktop_utils._get_default_browser", return_value="firefox")
    @patch("ai_guardian.desktop_utils.platform")
    def test_linux_launches_browser_and_raises(
        self, mock_platform, mock_get_browser, mock_popen, mock_wb, mock_raise
    ):
        mock_platform.system.return_value = "Linux"
        open_url("http://localhost:8080")
        mock_popen.assert_called_once_with(["firefox", "http://localhost:8080"])
        mock_wb.open.assert_not_called()
        mock_raise.assert_called_once()

    @patch("ai_guardian.desktop_utils._raise_browser_window")
    @patch("ai_guardian.desktop_utils.webbrowser")
    @patch("ai_guardian.desktop_utils._get_default_browser", return_value=None)
    @patch("ai_guardian.desktop_utils.platform")
    def test_linux_falls_back_when_browser_unknown(
        self, mock_platform, mock_get_browser, mock_wb, mock_raise
    ):
        mock_platform.system.return_value = "Linux"
        open_url("http://localhost:8080")
        mock_wb.open.assert_called_once_with("http://localhost:8080")
        mock_raise.assert_called_once()

    @patch("ai_guardian.desktop_utils._raise_browser_window")
    @patch("ai_guardian.desktop_utils.webbrowser")
    @patch("ai_guardian.desktop_utils.subprocess.Popen", side_effect=OSError)
    @patch("ai_guardian.desktop_utils._get_default_browser", return_value="firefox")
    @patch("ai_guardian.desktop_utils.platform")
    def test_linux_falls_back_on_launch_failure(
        self, mock_platform, mock_get_browser, mock_popen, mock_wb, mock_raise
    ):
        mock_platform.system.return_value = "Linux"
        open_url("http://localhost:8080")
        mock_wb.open.assert_called_once_with("http://localhost:8080")
        mock_raise.assert_called_once()


if __name__ == "__main__":
    unittest.main()
