"""Tests for daemon system tray integration."""

from unittest import mock

import pytest

from ai_guardian.daemon.tray import DaemonTray, is_tray_available


class TestIsTrayAvailable:
    def test_returns_bool(self):
        result = is_tray_available()
        assert isinstance(result, bool)


class TestDaemonTrayWithoutPystray:
    def test_start_without_pystray_is_noop(self):
        with mock.patch("ai_guardian.daemon.tray.HAS_PYSTRAY", False):
            tray = DaemonTray(
                get_stats_callback=lambda: {},
                stop_callback=lambda: None,
                pause_callback=lambda: None,
            )
            tray.start()
            # Should not raise, just log and return

    def test_stop_without_icon_is_noop(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        tray.stop()  # Should not raise

    def test_update_status_without_icon(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        tray.update_status("paused")  # Should not raise
        assert tray._status == "paused"


class TestDaemonTrayCallbacks:
    def test_header_text_running(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        header = tray._header_text()
        assert "AI Guardian" in header
        assert "Running" in header

    def test_header_text_paused(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "paused"
        header = tray._header_text()
        assert "Paused" in header

    def test_requests_text(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"request_count": 1234},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._requests_text()
        assert "1,234" in text
        assert "Requests:" in text

    def test_blocked_text_with_percentage(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"blocked_count": 28, "request_count": 1234},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._blocked_text()
        assert "28" in text
        assert "2.3%" in text

    def test_blocked_text_zero_requests(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"blocked_count": 0, "request_count": 0},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._blocked_text()
        assert "0" in text
        assert "%" not in text

    def test_warnings_text(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"warning_count": 42},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._warnings_text()
        assert "42" in text
        assert "Warned:" in text

    def test_log_only_text(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"log_only_count": 15},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._log_only_text()
        assert "15" in text
        assert "Logged:" in text

    def test_violations_text(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"violation_count": 5},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._violations_text()
        assert "5" in text
        assert "Violations:" in text

    def test_critical_text(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"critical_count": 1},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._critical_text()
        assert "1" in text
        assert "Critical:" in text

    def test_warning_severity_text(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"warning_severity_count": 4},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._warning_severity_text()
        assert "4" in text
        assert "Warning:" in text

    def test_last_block_text_none(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"last_block_type": None, "last_block_seconds_ago": None},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._last_block_text()
        assert "none" in text

    def test_last_block_text_recent(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"last_block_type": "secret_detected", "last_block_seconds_ago": 120},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._last_block_text()
        assert "secret_detected" in text
        assert "2m ago" in text

    def test_last_block_text_hours(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"last_block_type": "prompt_injection", "last_block_seconds_ago": 7200},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        text = tray._last_block_text()
        assert "prompt_injection" in text
        assert "2h ago" in text

    def test_quit_calls_stop_callback(self):
        stopped = []
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: stopped.append(True),
            pause_callback=lambda: None,
        )
        tray._on_quit(mock.MagicMock(), mock.MagicMock())
        assert stopped == [True]

    def test_open_console_launches_subprocess(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("shutil.which", return_value="/usr/bin/ai-guardian"):
            with mock.patch("platform.system", return_value="Linux"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._on_open_console(mock.MagicMock(), mock.MagicMock())
                    mock_popen.assert_called_once()

    def test_pause_calls_callback_with_duration(self):
        paused_durations = []
        tray = DaemonTray(
            get_stats_callback=lambda: {"pause_remaining_seconds": 900},
            stop_callback=lambda: None,
            pause_callback=lambda mins: paused_durations.append(mins),
        )
        tray._on_pause(15)
        assert paused_durations == [15]
        assert tray._status == "paused"
        tray._stop_pause_timer()

    def test_resume_calls_callback_with_zero(self):
        paused_durations = []
        tray = DaemonTray(
            get_stats_callback=lambda: {"pause_remaining_seconds": 0},
            stop_callback=lambda: None,
            pause_callback=lambda mins: paused_durations.append(mins),
        )
        tray._status = "paused"
        tray._on_resume(mock.MagicMock(), mock.MagicMock())
        assert paused_durations == [0]
        assert tray._status == "running"

    def test_resume_label_shows_remaining_time(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"pause_remaining_seconds": 125},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "paused"
        label = tray._resume_menu_label()
        assert "2m" in label
        assert "5s" in label


class TestFormatTimeAgo:
    def test_seconds(self):
        assert DaemonTray._format_time_ago(30) == "30s ago"

    def test_minutes(self):
        assert DaemonTray._format_time_ago(120) == "2m ago"

    def test_hours(self):
        assert DaemonTray._format_time_ago(7200) == "2h ago"

    def test_days(self):
        assert DaemonTray._format_time_ago(172800) == "2d ago"

    def test_none(self):
        assert DaemonTray._format_time_ago(None) == ""

    def test_zero(self):
        assert DaemonTray._format_time_ago(0) == "0s ago"

    def test_just_under_minute(self):
        assert DaemonTray._format_time_ago(59) == "59s ago"

    def test_exactly_one_minute(self):
        assert DaemonTray._format_time_ago(60) == "1m ago"


class TestCrossPlatform:
    def test_update_icon_noop_without_icon(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._update_icon()  # No icon set — should not raise

    def test_dispatch_to_main_without_pyobjc(self):
        called = []
        with mock.patch.dict("sys.modules", {"PyObjCTools": None, "PyObjCTools.AppHelper": None}):
            tray = DaemonTray(
                get_stats_callback=lambda: {},
                stop_callback=lambda: None,
                pause_callback=lambda mins: None,
            )
            tray._dispatch_to_main(lambda: called.append(True))
        assert called == [True]

    def test_update_icon_without_icon(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        # No icon — should not raise
        tray._update_icon()

    def test_console_launch_linux(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Linux"):
            with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/gnome-terminal" if x == "gnome-terminal" else None):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._on_open_console(mock.MagicMock(), mock.MagicMock())
                    mock_popen.assert_called_once()
                    args = mock_popen.call_args[0][0]
                    assert "gnome-terminal" in args[0]

    def test_console_launch_linux_kgx_fallback(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Linux"):
            with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/kgx" if x == "kgx" else None):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._on_open_console(mock.MagicMock(), mock.MagicMock())
                    mock_popen.assert_called_once()
                    args = mock_popen.call_args[0][0]
                    assert args[0] == "kgx"

    def test_console_launch_windows(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Windows"):
            with mock.patch("subprocess.Popen") as mock_popen:
                tray._on_open_console(mock.MagicMock(), mock.MagicMock())
                mock_popen.assert_called_once()
                call_args = str(mock_popen.call_args)
                assert "start" in call_args


class TestDaemonTrayIcon:
    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_create_icon_running(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        tray._status = "running"
        icon = tray._create_icon()
        assert icon is not None
        assert icon.size == (64, 64)

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_create_icon_paused(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        tray._status = "paused"
        icon = tray._create_icon()
        assert icon is not None

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_create_icon_error(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        tray._status = "error"
        icon = tray._create_icon()
        assert icon is not None

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_fallback_icon_when_no_project_icon(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        fallback = tray._create_fallback_icon(64)
        assert fallback is not None
        assert fallback.size == (64, 64)

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_find_icon_path_returns_path_or_none(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        result = tray._find_icon_path()
        # May return a path (dev) or None (CI) — both are valid
        if result is not None:
            from pathlib import Path
            assert Path(result).exists()
