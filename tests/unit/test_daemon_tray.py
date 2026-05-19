"""Tests for daemon system tray integration."""

from unittest import mock

import pytest

from ai_guardian.daemon.discovery import DaemonTarget
from ai_guardian.daemon.tray import (
    DaemonTray,
    is_tray_available,
    _suppress_gtk_stderr,
    _restore_stderr,
)


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
    def test_quit_calls_stop_callback(self):
        stopped = []
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: stopped.append(True),
            pause_callback=lambda: None,
        )
        tray._on_quit(mock.MagicMock(), mock.MagicMock())
        assert stopped == [True]

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


class TestFlashReload:
    def test_flash_reload_is_noop(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "running"
        tray.flash_reload()
        assert tray._status == "running"

    def test_flash_reload_preserves_paused(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "paused"
        tray.flash_reload()
        assert tray._status == "paused"


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

    def test_console_launch_linux(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Linux"):
            with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/gnome-terminal" if x == "gnome-terminal" else None):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._launch_console()
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
                    tray._launch_console()
                    mock_popen.assert_called_once()
                    args = mock_popen.call_args[0][0]
                    assert args[0] == "kgx"

    def test_console_launch_macos(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/local/bin/ai-guardian"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._launch_console()
                    mock_popen.assert_called_once()
                    script = mock_popen.call_args[0][0][2]
                    assert "osascript" in mock_popen.call_args[0][0][0]
                    assert 'do script ""' in script
                    assert "delay 2" in script
                    assert '/usr/local/bin/ai-guardian console' in script

    def test_console_launch_macos_deferred_command(self):
        """Command is sent after shell init to avoid interactive prompts (issue #599)."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/local/bin/ai-guardian"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._launch_console()
                    script = mock_popen.call_args[0][0][2]
                    lines = script.split("\n")
                    do_script_lines = [l.strip() for l in lines if "do script" in l]
                    assert len(do_script_lines) == 2
                    assert do_script_lines[0] == 'set currentTab to do script ""'
                    assert "in currentTab" in do_script_lines[1]

    def test_console_launch_macos_fallback_sys_executable(self):
        """Falls back to sys.executable when shutil.which returns None."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value=None):
                with mock.patch("sys.executable", "/usr/bin/python3"):
                    with mock.patch("subprocess.Popen") as mock_popen:
                        tray._launch_console()
                        script = mock_popen.call_args[0][0][2]
                        assert "/usr/bin/python3 -m ai_guardian console" in script

    def test_console_launch_windows(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Windows"):
            with mock.patch("subprocess.Popen") as mock_popen:
                tray._launch_console()
                mock_popen.assert_called_once()
                call_args = str(mock_popen.call_args)
                assert "start" in call_args


class TestDaemonTrayIcon:
    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_create_icon_returns_image(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        icon = tray._create_icon()
        assert icon is not None
        assert icon.mode == "RGBA"

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_fallback_icon_when_no_tray_icon(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        with mock.patch.object(DaemonTray, "_find_tray_icon_path", return_value=None):
            icon = tray._create_icon()
        assert icon is not None
        assert icon.size == (22, 22)

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_find_tray_icon_path_returns_path_or_none(self):
        result = DaemonTray._find_tray_icon_path()
        if result is not None:
            from pathlib import Path
            assert Path(result).exists()

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_find_tray_icon_path_macos(self):
        with mock.patch("platform.system", return_value="Darwin"):
            result = DaemonTray._find_tray_icon_path()
        if result is not None:
            assert "Template" in result

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_find_tray_icon_path_windows(self):
        with mock.patch("platform.system", return_value="Windows"):
            result = DaemonTray._find_tray_icon_path()
        if result is not None:
            assert "16" in result

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_find_tray_icon_path_linux(self):
        with mock.patch("platform.system", return_value="Linux"):
            result = DaemonTray._find_tray_icon_path()
        if result is not None:
            assert "22" in result

    def test_all_required_tray_icon_sizes_exist(self):
        from pathlib import Path
        images_dir = Path(__file__).resolve().parent.parent.parent / "images"
        required = [
            "tray-icon-16.png",
            "tray-icon-22.png",
            "tray-icon-32.png",
            "tray-iconTemplate.png",
            "tray-iconTemplate@2x.png",
        ]
        for name in required:
            assert (images_dir / name).exists(), f"Missing tray icon: {name}"

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_tray_icon_png_dimensions(self):
        from pathlib import Path
        from PIL import Image
        images_dir = Path(__file__).resolve().parent.parent.parent / "images"
        expected_sizes = {
            "tray-icon-16.png": (16, 16),
            "tray-icon-22.png": (22, 22),
            "tray-icon-32.png": (32, 32),
            "tray-iconTemplate.png": (22, 22),
            "tray-iconTemplate@2x.png": (44, 44),
        }
        for name, expected in expected_sizes.items():
            img = Image.open(images_dir / name)
            assert img.size == expected, f"{name}: expected {expected}, got {img.size}"
            assert img.mode in ("RGBA", "P"), f"{name}: expected RGBA mode"


class TestRunPlatformBranching:
    """Verify _run() never passes setup= callback (issue #564, #602)."""

    def test_run_on_linux_no_setup_callback(self):
        """setup= breaks icon visibility on newer GNOME (issue #602)."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_icon = mock.MagicMock()
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray, \
             mock.patch("platform.system", return_value="Linux"), \
             mock.patch("ai_guardian.daemon.tray._suppress_gtk_stderr", return_value=42), \
             mock.patch("ai_guardian.daemon.tray.threading") as mock_threading:
            mock_pystray.Icon.return_value = mock_icon
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.MenuItem = mock.MagicMock()
            tray._start_stats_refresh = mock.MagicMock()
            tray._create_icon = mock.MagicMock()
            tray._run()
            mock_icon.run.assert_called_once()
            _, kwargs = mock_icon.run.call_args
            assert "setup" not in kwargs
            mock_threading.Timer.assert_called_once_with(
                2.0, _restore_stderr, args=[42]
            )
            mock_threading.Timer.return_value.start.assert_called_once()

    def test_run_on_macos_no_setup_callback(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_icon = mock.MagicMock()
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray, \
             mock.patch("platform.system", return_value="Darwin"):
            mock_pystray.Icon.return_value = mock_icon
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.MenuItem = mock.MagicMock()
            tray._start_stats_refresh = mock.MagicMock()
            tray._create_icon = mock.MagicMock()
            tray._run()
            mock_icon.run.assert_called_once()
            _, kwargs = mock_icon.run.call_args
            assert "setup" not in kwargs


class TestSuppressGtkStderr:
    def test_returns_none_on_non_linux(self):
        with mock.patch("platform.system", return_value="Darwin"):
            assert _suppress_gtk_stderr() is None

    def test_returns_fd_on_linux(self):
        import os
        with mock.patch("platform.system", return_value="Linux"):
            saved_fd = _suppress_gtk_stderr()
            assert saved_fd is not None
            _restore_stderr(saved_fd)

    def test_restore_with_none_is_noop(self):
        _restore_stderr(None)

    def test_roundtrip_preserves_stderr(self):
        import os
        import sys
        with mock.patch("platform.system", return_value="Linux"):
            original_fd = os.dup(2)
            try:
                saved_fd = _suppress_gtk_stderr()
                assert saved_fd is not None
                _restore_stderr(saved_fd)
                # stderr should still work
                sys.stderr.write("")
                sys.stderr.flush()
            finally:
                os.close(original_fd)


class TestSingleDaemonFlatMenu:
    """Tests for flat menu layout when exactly one daemon is discovered."""

    def _make_tray(self, targets=None):
        tray = DaemonTray(
            get_stats_callback=lambda: {"request_count": 10, "blocked_count": 2},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        if targets is not None:
            tray._targets = targets
        return tray

    def test_is_single_daemon_with_one_target(self):
        tray = self._make_tray([DaemonTarget(name="local", runtime="local", status="running")])
        assert tray._is_single_daemon() is True
        assert tray._is_multi_daemon() is False

    def test_is_multi_daemon_with_two_targets(self):
        tray = self._make_tray([
            DaemonTarget(name="local", runtime="local", status="running"),
            DaemonTarget(name="remote", runtime="container", status="running"),
        ])
        assert tray._is_multi_daemon() is True
        assert tray._is_single_daemon() is False

    def test_is_multi_daemon_with_zero_targets(self):
        tray = self._make_tray([])
        assert tray._is_multi_daemon() is True
        assert tray._is_single_daemon() is False

    def test_daemon_status_label_running(self):
        t = DaemonTarget(name="my-host", runtime="local", status="running")
        label = DaemonTray._daemon_status_label(t)
        assert label == "● my-host"

    def test_daemon_status_label_stopped(self):
        t = DaemonTarget(name="my-host", runtime="local", status="stopped")
        label = DaemonTray._daemon_status_label(t)
        assert "⚠" in label
        assert "daemon not running" in label

    def test_daemon_status_label_container(self):
        t = DaemonTarget(name="sandbox", runtime="container",
                         container_engine="podman", status="running")
        label = DaemonTray._daemon_status_label(t)
        assert "● sandbox (podman)" == label

    def test_daemon_status_label_kubernetes(self):
        t = DaemonTarget(name="k8s-pod", runtime="kubernetes", status="running")
        label = DaemonTray._daemon_status_label(t)
        assert "● k8s-pod (kubernetes)" == label

    def test_flat_menu_with_single_container_target(self):
        """Single container daemon uses flat layout — same as local."""
        tray = self._make_tray([
            DaemonTarget(name="carbonite-prod", runtime="container",
                         container_engine="podman", status="running"),
        ])
        assert tray._is_single_daemon() is True

    def test_dynamic_switch_flat_to_nested(self):
        """Layout switches dynamically when targets change count."""
        tray = self._make_tray([
            DaemonTarget(name="local", runtime="local", status="running"),
        ])
        assert tray._is_single_daemon() is True

        tray._targets.append(
            DaemonTarget(name="remote", runtime="container", status="running")
        )
        assert tray._is_single_daemon() is False
        assert tray._is_multi_daemon() is True

        tray._targets.pop()
        assert tray._is_single_daemon() is True


class TestIDESetupMenu:
    """Tests for the Local Setup... IDE submenu."""

    def test_launch_ide_setup_builds_correct_command(self):
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/local/bin/ai-guardian"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    DaemonTray._launch_ide_setup("claude")
                    mock_popen.assert_called_once()
                    script = mock_popen.call_args[0][0][2]
                    assert "setup --ide claude" in script

    def test_launch_ide_setup_keeps_terminal_open_macos(self):
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/local/bin/ai-guardian"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    DaemonTray._launch_ide_setup("claude")
                    script = mock_popen.call_args[0][0][2]
                    assert "close" not in script
                    assert "repeat" not in script

    def test_launch_ide_setup_fallback_sys_executable(self):
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value=None):
                with mock.patch("sys.executable", "/usr/bin/python3"):
                    with mock.patch("subprocess.Popen") as mock_popen:
                        DaemonTray._launch_ide_setup("cursor")
                        script = mock_popen.call_args[0][0][2]
                        assert "/usr/bin/python3 -m ai_guardian setup --ide cursor" in script

    def test_launch_ide_setup_linux_keeps_terminal_open(self):
        with mock.patch("platform.system", return_value="Linux"):
            with mock.patch("shutil.which", side_effect=lambda x: {
                "ai-guardian": "/usr/bin/ai-guardian",
                "gnome-terminal": "/usr/bin/gnome-terminal",
            }.get(x)):
                with mock.patch("subprocess.Popen") as mock_popen:
                    DaemonTray._launch_ide_setup("copilot")
                    mock_popen.assert_called_once()
                    args = mock_popen.call_args[0][0]
                    assert "gnome-terminal" in args[0]
                    shell_cmd = args[-1]
                    assert "setup --ide copilot" in shell_cmd
                    assert "Press Enter to close" in shell_cmd

    def test_build_ide_setup_menu_returns_items(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            items = tray._build_ide_setup_menu_items()
            assert len(items) == 1
            top_call = mock_pystray.MenuItem.call_args_list[-1]
            assert top_call[0][0] == "Local Setup..."

    def test_build_ide_setup_menu_has_all_supported_ides(self):
        from ai_guardian.setup import IDESetup

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_ide_setup_menu_items()
            item_names = [
                call[0][0] for call in mock_pystray.MenuItem.call_args_list[:-1]
            ]
            assert "Create Config..." in item_names
            for ide_cfg in IDESetup.IDE_CONFIGS.values():
                assert ide_cfg["name"] in item_names

    def test_launch_create_config_builds_correct_command(self):
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/local/bin/ai-guardian"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    DaemonTray._launch_create_config()
                    script = mock_popen.call_args[0][0][2]
                    assert "setup --create-config" in script
                    assert "close" not in script
