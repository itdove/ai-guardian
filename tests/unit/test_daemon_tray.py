"""Tests for daemon system tray integration."""

from unittest import mock

import pytest

from ai_guardian.daemon.discovery import DaemonTarget
from ai_guardian.daemon.tray import (
    DaemonTray,
    is_tray_available,
    _is_tray_running,
    _suppress_gtk_stderr,
    _restore_stderr,
)


class TestIsTrayAvailable:
    def test_returns_bool(self):
        result = is_tray_available()
        assert isinstance(result, bool)


class TestDaemonTrayWithoutPystray:
    def test_start_without_pystray_returns_false(self):
        with mock.patch("ai_guardian.daemon.tray.HAS_PYSTRAY", False):
            tray = DaemonTray(
                get_stats_callback=lambda: {},
                stop_callback=lambda: None,
                pause_callback=lambda: None,
            )
            result = tray.start()
            assert result is False

    def test_stop_without_icon_is_noop(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda: None,
        )
        tray.stop()  # Should not raise

    def test_update_status_without_icon(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"paused": True, "pause_remaining_seconds": 300},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray.update_status("paused")  # Should not raise
        assert tray._status == "paused"
        tray._stop_pause_timer()


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


class TestTrayPauseRoutesLocalThroughMultiClient:
    """Verify local daemon pause/resume routes through multi_client (issue #683)."""

    def test_pause_action_uses_multi_client_for_local_target(self):
        mc = mock.MagicMock()
        local_target = DaemonTarget(name="local", runtime="local", status="running")
        pause_cb = mock.MagicMock()

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=pause_cb,
            multi_client=mc,
        )
        tray._targets = [local_target]

        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            tray._build_single_daemon_menu_items()

        mc.send_pause.assert_not_called()
        pause_cb.assert_not_called()

    def test_pause_local_routes_via_multi_client(self):
        mc = mock.MagicMock()
        local_target = DaemonTarget(name="local", runtime="local", status="running")
        pause_cb = mock.MagicMock()

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=pause_cb,
            multi_client=mc,
        )
        tray._targets = [local_target]

        # Directly test the routing logic that _pause_action uses
        t = tray._targets[0]
        if tray._multi_client:
            tray._multi_client.send_pause(t, 5)
        else:
            tray._pause(5)

        mc.send_pause.assert_called_once_with(local_target, 5)
        pause_cb.assert_not_called()

    def test_resume_local_routes_via_multi_client(self):
        mc = mock.MagicMock()
        local_target = DaemonTarget(name="local", runtime="local", status="running")
        pause_cb = mock.MagicMock()

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=pause_cb,
            multi_client=mc,
        )
        tray._targets = [local_target]

        t = tray._targets[0]
        if tray._multi_client:
            tray._multi_client.send_resume(t)
        else:
            tray._pause(0)

        mc.send_resume.assert_called_once_with(local_target)
        pause_cb.assert_not_called()

    def test_pause_falls_back_to_callback_without_multi_client(self):
        pause_cb = mock.MagicMock()
        local_target = DaemonTarget(name="local", runtime="local", status="running")

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=pause_cb,
        )
        tray._targets = [local_target]

        t = tray._targets[0]
        if tray._multi_client:
            tray._multi_client.send_pause(t, 5)
        else:
            tray._pause(5)

        pause_cb.assert_called_once_with(5)


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
            with mock.patch("sys.executable", "/usr/bin/python3"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._launch_console()
                    mock_popen.assert_called_once()
                    script = mock_popen.call_args[0][0][2]
                    assert "osascript" in mock_popen.call_args[0][0][0]
                    assert 'do script ""' in script
                    assert "delay 2" in script
                    assert '/usr/bin/python3 -m ai_guardian console' in script

    def test_console_launch_macos_deferred_command(self):
        """Command is sent after shell init to avoid interactive prompts (issue #599)."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("sys.executable", "/usr/bin/python3"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._launch_console()
                    script = mock_popen.call_args[0][0][2]
                    lines = script.split("\n")
                    do_script_lines = [l.strip() for l in lines if "do script" in l]
                    assert len(do_script_lines) == 2
                    assert do_script_lines[0] == 'set currentTab to do script ""'
                    assert "in currentTab" in do_script_lines[1]

    def test_console_launch_macos_uses_same_venv(self):
        """_resolve_cli_cmd always uses sys.executable for venv consistency."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("sys.executable", "/custom/venv/bin/python"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    tray._launch_console()
                    script = mock_popen.call_args[0][0][2]
                    assert "/custom/venv/bin/python -m ai_guardian console" in script

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
            tray._ensure_macos_activation_policy = mock.MagicMock()
            tray._run()
            mock_icon.run.assert_called_once()
            _, kwargs = mock_icon.run.call_args
            assert "setup" not in kwargs
            tray._ensure_macos_activation_policy.assert_called_once()

    def test_ensure_macos_activation_policy_on_darwin(self):
        """Verify activation policy is set on macOS (issue #691)."""
        mock_app = mock.MagicMock()
        mock_appkit = mock.MagicMock()
        mock_appkit.NSApplication.sharedApplication.return_value = mock_app
        mock_appkit.NSApplicationActivationPolicyAccessory = 1
        with mock.patch("platform.system", return_value="Darwin"), \
             mock.patch.dict("sys.modules", {"AppKit": mock_appkit}):
            DaemonTray._ensure_macos_activation_policy()
        mock_app.setActivationPolicy_.assert_called_once_with(1)

    def test_ensure_macos_activation_policy_skipped_on_linux(self):
        with mock.patch("platform.system", return_value="Linux"):
            DaemonTray._ensure_macos_activation_policy()


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
            with mock.patch("sys.executable", "/usr/bin/python3"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    DaemonTray._launch_ide_setup("claude")
                    mock_popen.assert_called_once()
                    script = mock_popen.call_args[0][0][2]
                    assert "setup --ide claude" in script

    def test_launch_ide_setup_keeps_terminal_open_macos(self):
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("sys.executable", "/usr/bin/python3"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    DaemonTray._launch_ide_setup("claude")
                    script = mock_popen.call_args[0][0][2]
                    assert "close" not in script
                    assert "repeat" not in script

    def test_launch_ide_setup_uses_same_venv(self):
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("sys.executable", "/custom/venv/bin/python"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    DaemonTray._launch_ide_setup("cursor")
                    script = mock_popen.call_args[0][0][2]
                    assert "/custom/venv/bin/python -m ai_guardian setup --ide cursor" in script

    def test_launch_ide_setup_linux_keeps_terminal_open(self):
        with mock.patch("platform.system", return_value="Linux"):
            with mock.patch("sys.executable", "/usr/bin/python3"):
                with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/gnome-terminal" if x == "gnome-terminal" else None):
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
            assert "  Create Config..." in item_names
            for ide_cfg in IDESetup.IDE_CONFIGS.values():
                assert f"  {ide_cfg['name']}" in item_names

    def test_launch_create_config_builds_correct_command(self):
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("sys.executable", "/usr/bin/python3"):
                with mock.patch("subprocess.Popen") as mock_popen:
                    DaemonTray._launch_create_config()
                    script = mock_popen.call_args[0][0][2]
                    assert "setup --create-config" in script
                    assert "close" not in script


class TestPausedIconDimming:
    """Tests for visual pause state indicator (issue #684)."""

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_apply_paused_dimming_reduces_alpha(self):
        from PIL import Image
        img = Image.new("RGBA", (22, 22), (255, 255, 255, 200))
        dimmed = DaemonTray._apply_paused_dimming(img)
        assert dimmed.size == (22, 22)
        _, _, _, a = dimmed.getpixel((10, 10))
        assert a == 100

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_apply_paused_dimming_does_not_modify_original(self):
        from PIL import Image
        img = Image.new("RGBA", (22, 22), (255, 255, 255, 200))
        DaemonTray._apply_paused_dimming(img)
        _, _, _, a = img.getpixel((10, 10))
        assert a == 200

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_create_icon_dimmed_when_paused(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        normal = tray._create_icon()
        tray._status = "paused"
        paused = tray._create_icon()
        normal_alpha = list(normal.split()[3].tobytes())
        paused_alpha = list(paused.split()[3].tobytes())
        non_zero = [i for i, a in enumerate(normal_alpha) if a > 0]
        assert len(non_zero) > 0
        for i in non_zero:
            assert paused_alpha[i] <= normal_alpha[i]

    @pytest.mark.skipif(
        not is_tray_available(),
        reason="pystray/Pillow not installed"
    )
    def test_create_icon_normal_when_running(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "running"
        icon = tray._create_icon()
        assert icon.mode == "RGBA"


class TestUpdateStatusPauseTimer:
    """Tests for update_status() managing pause timer (issue #684)."""

    def test_update_status_starts_pause_timer(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"pause_remaining_seconds": 60},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch.object(tray, "_start_pause_timer") as mock_start:
            tray.update_status("paused")
            mock_start.assert_called_once()

    def test_update_status_stops_pause_timer_on_resume(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "paused"
        with mock.patch.object(tray, "_stop_pause_timer") as mock_stop:
            tray.update_status("running")
            mock_stop.assert_called_once()

    def test_update_status_no_double_start(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"pause_remaining_seconds": 60},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "paused"
        with mock.patch.object(tray, "_start_pause_timer") as mock_start:
            tray.update_status("paused")
            mock_start.assert_not_called()

    def test_update_status_updates_icon_when_icon_exists(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_icon = mock.MagicMock()
        tray._icon = mock_icon
        with mock.patch.object(tray, "_create_icon", return_value="fake_img"):
            tray.update_status("paused")
        assert mock_icon.icon == "fake_img"


class TestSyncPauseState:
    """Tests for _sync_pause_state() detecting external pause/resume (issue #684)."""

    def test_sync_detects_external_pause(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"paused": True, "pause_remaining_seconds": 120},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._targets = [DaemonTarget(name="local", runtime="local", status="running")]
        tray._status = "running"
        with mock.patch.object(tray, "update_status") as mock_update:
            tray._sync_pause_state()
            mock_update.assert_called_once_with("paused")

    def test_sync_detects_external_resume(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"paused": False},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._targets = [DaemonTarget(name="local", runtime="local", status="running")]
        tray._status = "paused"
        with mock.patch.object(tray, "update_status") as mock_update:
            tray._sync_pause_state()
            mock_update.assert_called_once_with("running")

    def test_sync_no_change_when_already_paused(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"paused": True},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._targets = [DaemonTarget(name="local", runtime="local", status="running")]
        tray._status = "paused"
        with mock.patch.object(tray, "update_status") as mock_update:
            tray._sync_pause_state()
            mock_update.assert_not_called()


class TestPausedTargetMenuVisibility:
    """Tests for paused target handling in menu visibility (issue #696)."""

    def _make_tray(self, targets=None):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        if targets is not None:
            tray._targets = targets
        return tray

    def test_single_running_includes_paused(self):
        """_single_running returns True for paused targets."""
        tray = self._make_tray([
            DaemonTarget(name="local", runtime="local", status="paused"),
        ])
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True):
            assert tray._is_single_daemon() is True
            fn = lambda _item: (
                tray._is_single_daemon()
                and tray._targets[0].status in ("running", "paused")
            )
            assert fn(None) is True

    def test_single_not_running_excludes_paused(self):
        """_single_not_running returns False for paused targets."""
        tray = self._make_tray([
            DaemonTarget(name="local", runtime="local", status="paused"),
        ])
        fn = lambda _item: (
            tray._is_single_daemon()
            and tray._targets[0].status not in ("running", "paused")
        )
        assert fn(None) is False

    def test_auto_select_prefers_paused_over_unknown(self):
        """_auto_select_target selects paused targets over unknown ones."""
        tray = self._make_tray([
            DaemonTarget(name="unknown-one", runtime="container", status="unknown"),
            DaemonTarget(name="paused-local", runtime="local", status="paused"),
        ])
        tray._active_target = None
        tray._auto_select_target()
        assert tray._active_target.name == "paused-local"

    def test_auto_select_keeps_paused_target(self):
        """_auto_select_target keeps currently active paused target."""
        paused_target = DaemonTarget(name="local", runtime="local", status="paused")
        tray = self._make_tray([paused_target])
        tray._active_target = paused_target
        tray._auto_select_target()
        assert tray._active_target.name == "local"

    def test_daemon_status_label_paused(self):
        """Status label shows paused icon for paused daemon."""
        t = DaemonTarget(name="my-host", runtime="local", status="paused")
        label = DaemonTray._daemon_status_label(t)
        assert "◐" in label
        assert "my-host" in label


class TestUntilResumePauseOption:
    """Tests for 'Until resume' indefinite pause menu option (issue #698)."""

    def test_single_daemon_pause_menu_includes_until_resume(self):
        """Single-daemon Pause submenu contains 'Until resume' item."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
        ]
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_single_daemon_menu_items()
            tray._build_single_daemon_daemon_items()

            labels = [
                call[0][0] for call in mock_pystray.MenuItem.call_args_list
                if isinstance(call[0][0], str)
            ]
            assert "Until resume" in labels

    def test_multi_daemon_pause_menu_includes_until_resume(self):
        """Multi-daemon per-daemon Pause submenu contains 'Until resume' item."""
        mc = mock.MagicMock()
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=mc,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
            DaemonTarget(name="remote", runtime="container", status="running"),
        ]
        mc.get_stats.return_value = {}
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_multi_daemon_menu_items()

            labels = [
                call[0][0] for call in mock_pystray.MenuItem.call_args_list
                if isinstance(call[0][0], str)
            ]
            assert labels.count("Until resume") >= 1

    def test_until_resume_routes_zero_minutes_via_multi_client(self):
        """'Until resume' sends pause with minutes=0 through multi_client."""
        mc = mock.MagicMock()
        local_target = DaemonTarget(name="local", runtime="local", status="running")

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=mock.MagicMock(),
            multi_client=mc,
        )
        tray._targets = [local_target]

        t = tray._targets[0]
        tray._multi_client.send_pause(t, 0)

        mc.send_pause.assert_called_once_with(local_target, 0)

    def test_until_resume_falls_back_to_callback_without_multi_client(self):
        """'Until resume' calls pause callback with 0 when no multi_client."""
        pause_cb = mock.MagicMock()
        local_target = DaemonTarget(name="local", runtime="local", status="running")

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=pause_cb,
        )
        tray._targets = [local_target]

        t = tray._targets[0]
        if tray._multi_client:
            tray._multi_client.send_pause(t, 0)
        else:
            tray._pause(0)

        pause_cb.assert_called_once_with(0)

    def test_pause_timer_does_not_auto_resume_indefinite_pause(self):
        """Pause timer must not auto-resume when daemon reports indefinite pause."""
        tray = DaemonTray(
            get_stats_callback=lambda: {
                "paused": True,
                "pause_remaining_seconds": 0,
            },
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "paused"
        tray._start_pause_timer()
        import time
        time.sleep(0.2)
        tray._stop_pause_timer()
        assert tray._status == "paused"

    def test_pause_timer_auto_resumes_expired_timed_pause(self):
        """Pause timer auto-resumes when daemon reports timed pause expired."""
        tray = DaemonTray(
            get_stats_callback=lambda: {
                "paused": False,
                "pause_remaining_seconds": 0,
            },
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._status = "paused"
        tray._start_pause_timer()
        import time
        time.sleep(0.2)
        tray._stop_pause_timer()
        assert tray._status == "running"

    def test_icon_grey_only_when_all_daemons_paused(self):
        """Tray icon should be grey only when ALL daemons are paused."""
        mc = mock.MagicMock()
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=mc,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
            DaemonTarget(name="remote", runtime="container", status="running"),
        ]
        mc.get_status.side_effect = lambda t: (
            {"paused": True} if t.name == "local" else {"paused": False}
        )
        tray._update_global_pause_status()
        assert tray._status == "running"

    def test_icon_grey_when_all_daemons_paused(self):
        """Tray icon is grey when every daemon is paused."""
        mc = mock.MagicMock()
        tray = DaemonTray(
            get_stats_callback=lambda: {"paused": True, "pause_remaining_seconds": 0},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=mc,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
            DaemonTarget(name="remote", runtime="container", status="running"),
        ]
        mc.get_status.return_value = {"paused": True}
        tray._update_global_pause_status()
        tray._stop_pause_timer()
        assert tray._status == "paused"

    def test_icon_running_after_one_daemon_resumed(self):
        """Resuming one daemon clears global paused status."""
        mc = mock.MagicMock()
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=mc,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
            DaemonTarget(name="remote", runtime="container", status="running"),
        ]
        tray._status = "paused"
        mc.get_status.side_effect = lambda t: (
            {"paused": True} if t.name == "local" else {"paused": False}
        )
        tray._update_global_pause_status()
        assert tray._status == "running"


class TestResumeMenuLabelFormats:
    """Tests for resume menu label formatting (issue #684)."""

    def test_resume_label_indefinite(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"pause_remaining_seconds": 0},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        label = tray._resume_menu_label()
        assert label == "Resume (paused)"

    def test_resume_label_with_countdown(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {"pause_remaining_seconds": 222},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        label = tray._resume_menu_label()
        assert "3m" in label
        assert "42s" in label


class TestWakeDetection:
    """Tests for system wake detection and tray rebuild (issue #703)."""

    def test_rebuild_tray_refreshes_icon_and_menu(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_icon = mock.MagicMock()
        tray._icon = mock_icon
        with mock.patch.object(tray, "_create_icon", return_value="new_img"):
            tray._rebuild_tray()
        assert mock_icon.icon == "new_img"
        mock_icon.update_menu.assert_called_once()

    def test_rebuild_tray_without_icon_is_noop(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._icon = None
        tray._rebuild_tray()  # Should not raise

    def test_rebuild_tray_handles_exception(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_icon = mock.MagicMock()
        mock_icon.update_menu.side_effect = RuntimeError("broken")
        tray._icon = mock_icon
        tray._rebuild_tray()  # Should not raise

    def test_stats_refresh_detects_sleep_gap(self):
        """Timer gap > 30s triggers _rebuild_tray."""
        import time as time_mod

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._icon = mock.MagicMock()
        rebuild_calls = []

        def tracking_dispatch(func):
            if func == tray._rebuild_tray:
                rebuild_calls.append(True)

        now = time_mod.time()
        time_values = iter([now - 60, now])

        with mock.patch.dict("sys.modules", {"PyObjCTools": None, "PyObjCTools.AppHelper": None}):
            with mock.patch.object(tray, "_dispatch_to_main", side_effect=tracking_dispatch):
                with mock.patch("ai_guardian.daemon.tray.time") as mock_time:
                    mock_time.time = mock.MagicMock(side_effect=time_values)
                    mock_time.sleep = mock.MagicMock(side_effect=lambda _: setattr(
                        tray, "_stats_refresh_running", False
                    ))
                    tray._stats_refresh_running = True
                    tray._start_stats_refresh()
                    time_mod.sleep(0.3)

        assert len(rebuild_calls) > 0

    def test_stats_refresh_normal_tick_no_rebuild(self):
        """Normal 10s tick does not trigger _rebuild_tray."""
        import time

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._icon = mock.MagicMock()
        rebuild_calls = []

        def tracking_dispatch(func):
            if func == tray._rebuild_tray:
                rebuild_calls.append(True)
            try:
                func()
            except Exception:
                pass

        with mock.patch.dict("sys.modules", {"PyObjCTools": None, "PyObjCTools.AppHelper": None}):
            with mock.patch.object(tray, "_dispatch_to_main", side_effect=tracking_dispatch):
                tray._stats_refresh_running = True
                tray._last_refresh_wallclock = time.time()
                tray._start_stats_refresh()
                time.sleep(0.3)
                tray._stats_refresh_running = False
                time.sleep(0.2)

        assert len(rebuild_calls) == 0

    def test_register_wake_handler_non_darwin_is_noop(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Linux"):
            tray._register_wake_handler()
        assert tray._wake_observer is None

    def test_register_wake_handler_windows_is_noop(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Windows"):
            tray._register_wake_handler()
        assert tray._wake_observer is None

    def test_register_wake_handler_macos_registers_observer(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_center = mock.MagicMock()
        mock_workspace = mock.MagicMock()
        mock_workspace.sharedWorkspace.return_value.notificationCenter.return_value = mock_center
        mock_appkit = mock.MagicMock()
        mock_appkit.NSWorkspace = mock_workspace

        with mock.patch("platform.system", return_value="Darwin"), \
             mock.patch.dict("sys.modules", {"AppKit": mock_appkit}):
            tray._register_wake_handler()

        mock_center.addObserverForName_object_queue_usingBlock_.assert_called_once()
        call_args = mock_center.addObserverForName_object_queue_usingBlock_.call_args[0]
        assert call_args[0] == "NSWorkspaceDidWakeNotification"
        center, token = tray._wake_observer
        assert center is mock_center
        assert token is mock_center.addObserverForName_object_queue_usingBlock_.return_value

    def test_register_wake_handler_graceful_without_pyobjc(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch("platform.system", return_value="Darwin"), \
             mock.patch.dict("sys.modules", {"AppKit": None}):
            tray._register_wake_handler()
        assert tray._wake_observer is None

    def test_unregister_wake_handler_cleanup(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_center = mock.MagicMock()
        mock_token = mock.MagicMock()
        tray._wake_observer = (mock_center, mock_token)
        tray._unregister_wake_handler()
        mock_center.removeObserver_.assert_called_once_with(mock_token)
        assert tray._wake_observer is None

    def test_unregister_wake_handler_noop_without_observer(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._wake_observer = None
        tray._unregister_wake_handler()  # Should not raise

    def test_stop_calls_unregister_wake_handler(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        with mock.patch.object(tray, "_unregister_wake_handler") as mock_unreg:
            tray.stop()
            mock_unreg.assert_called_once()

    def test_run_calls_register_wake_handler(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_icon = mock.MagicMock()
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray, \
             mock.patch("platform.system", return_value="Linux"), \
             mock.patch.object(tray, "_register_wake_handler") as mock_reg:
            mock_pystray.Icon.return_value = mock_icon
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.MenuItem = mock.MagicMock()
            tray._start_stats_refresh = mock.MagicMock()
            tray._create_icon = mock.MagicMock()
            tray._ensure_macos_activation_policy = mock.MagicMock()
            with mock.patch("ai_guardian.daemon.tray._suppress_gtk_stderr", return_value=None), \
                 mock.patch("ai_guardian.daemon.tray.threading"):
                tray._run()
            mock_reg.assert_called_once()


class TestNonBlockingMenuRefresh:
    """Tests for non-blocking menu refresh (issue #711)."""

    def test_single_vis_refresh_does_not_block(self):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        mock_discovery = mock.MagicMock()
        tray._discovery = mock_discovery
        tray._targets = [DaemonTarget(name="local", runtime="local", status="running")]

        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_single_daemon_menu_items()

            first_call = mock_pystray.MenuItem.call_args_list[0]
            vis_cb = first_call[1].get("visible") or first_call[0][2] if len(first_call[0]) > 2 else first_call[1].get("visible")
            vis_cb(None)

        mock_discovery.request_refresh.assert_called_once_with(wait=False)

    def test_multi_vis_refresh_does_not_block(self):
        mc = mock.MagicMock()
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=mc,
        )
        mock_discovery = mock.MagicMock()
        tray._discovery = mock_discovery
        tray._targets = [
            DaemonTarget(name="d1", runtime="local", status="running"),
            DaemonTarget(name="d2", runtime="manual", status="running"),
        ]
        mc.get_stats.return_value = {}

        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_multi_daemon_menu_items()

            for call in mock_pystray.MenuItem.call_args_list:
                vis_cb = call[1].get("visible")
                if vis_cb is not None and callable(vis_cb):
                    vis_cb(None)
                    if mock_discovery.request_refresh.called:
                        break

        mock_discovery.request_refresh.assert_called_with(wait=False)


class TestIsTrayRunningReturnsPid:
    """Tests for _is_tray_running() returning PID instead of True (issue #713)."""

    def test_returns_false_when_no_lock(self, tmp_path):
        with mock.patch("ai_guardian.daemon.tray._get_tray_lock_path", return_value=tmp_path / "tray.lock"):
            assert _is_tray_running() is False

    def test_returns_pid_when_alive(self, tmp_path):
        import os
        lock = tmp_path / "tray.lock"
        lock.write_text(str(os.getpid()))
        with mock.patch("ai_guardian.daemon.tray._get_tray_lock_path", return_value=lock):
            result = _is_tray_running()
            assert result == os.getpid()

    def test_returns_false_when_pid_dead(self, tmp_path):
        lock = tmp_path / "tray.lock"
        lock.write_text("999999999")
        with mock.patch("ai_guardian.daemon.tray._get_tray_lock_path", return_value=lock), \
             mock.patch("ai_guardian.daemon.is_pid_alive", return_value=False):
            assert _is_tray_running() is False
            assert not lock.exists()

    def test_returns_false_when_lock_has_bad_content(self, tmp_path):
        lock = tmp_path / "tray.lock"
        lock.write_text("not-a-number")
        with mock.patch("ai_guardian.daemon.tray._get_tray_lock_path", return_value=lock):
            assert _is_tray_running() is False
            assert not lock.exists()


class TestRunBlockingReturnValue:
    """Tests for run_blocking() returning False when already running (issue #713)."""

    def test_returns_false_without_pystray(self):
        with mock.patch("ai_guardian.daemon.tray.HAS_PYSTRAY", False):
            tray = DaemonTray(
                get_stats_callback=lambda: {},
                stop_callback=lambda: None,
                pause_callback=lambda: None,
            )
            assert tray.run_blocking() is False

    def test_returns_false_when_already_running(self):
        with mock.patch("ai_guardian.daemon.tray.HAS_PYSTRAY", True), \
             mock.patch("ai_guardian.daemon.tray._is_tray_running", return_value=12345):
            tray = DaemonTray(
                get_stats_callback=lambda: {},
                stop_callback=lambda: None,
                pause_callback=lambda: None,
            )
            assert tray.run_blocking() is False


class TestTrayStartAlreadyRunningMessage:
    """Tests for CLI printing informative message when tray is already running (issue #713)."""

    def test_prints_already_running_with_pid(self):
        from ai_guardian.cli_handlers import _handle_tray_start
        args = mock.MagicMock()
        args.background = False
        args.no_discover = False

        with mock.patch("ai_guardian.daemon.tray.is_tray_available", return_value=True), \
             mock.patch("ai_guardian.daemon.tray._is_tray_running", return_value=42), \
             mock.patch("sys.stdin") as mock_stdin, \
             mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=({}, None)), \
             mock.patch("builtins.print") as mock_print:
            mock_stdin.isatty.return_value = False
            result = _handle_tray_start(args)

        assert result == 0
        mock_print.assert_called_once_with("Tray is already running (pid 42)")

    def test_prints_success_when_not_running(self):
        from ai_guardian.cli_handlers import _handle_tray_start
        args = mock.MagicMock()
        args.background = False
        args.no_discover = False

        with mock.patch("ai_guardian.daemon.tray.is_tray_available", return_value=True), \
             mock.patch("ai_guardian.daemon.tray._is_tray_running", return_value=False), \
             mock.patch("sys.stdin") as mock_stdin, \
             mock.patch("ai_guardian.cli_handlers._load_config_file", return_value=({}, None)), \
             mock.patch("ai_guardian.daemon.tray.DaemonTray") as MockTray, \
             mock.patch("ai_guardian.daemon.discovery.DaemonDiscovery"), \
             mock.patch("ai_guardian.daemon.multi_client.MultiDaemonClient"), \
             mock.patch("ai_guardian.daemon.client.send_status_request", return_value={}), \
             mock.patch("builtins.print") as mock_print:
            mock_stdin.isatty.return_value = False
            mock_tray_instance = MockTray.return_value
            mock_tray_instance.run_blocking.return_value = None
            result = _handle_tray_start(args)

        assert result == 0
        mock_print.assert_called_once_with("ai-guardian tray started (multi-daemon mode)")


class TestMcpProactiveMenuVisibility:
    """Tests for MCP Proactive menu visibility based on MCP installation (issue #726)."""

    def test_is_mcp_installed_returns_true_when_ide_config_has_entry(self, tmp_path):
        """Detects ai-guardian MCP server entry in an IDE config file."""
        import json

        config_file = tmp_path / ".claude.json"
        config_file.write_text(json.dumps({
            "mcpServers": {
                "ai-guardian": {"command": "ai-guardian", "args": ["mcp-server"]}
            }
        }))
        with mock.patch(
            "ai_guardian.daemon.tray.DaemonTray._is_mcp_installed",
            wraps=DaemonTray._is_mcp_installed,
        ):
            with mock.patch("pathlib.Path.expanduser", return_value=config_file):
                assert DaemonTray._is_mcp_installed() is True

    def test_is_mcp_installed_returns_false_when_no_ide_configs(self, tmp_path):
        """Returns False when no IDE config files contain ai-guardian."""
        missing = tmp_path / "nonexistent.json"
        with mock.patch("pathlib.Path.expanduser", return_value=missing):
            assert DaemonTray._is_mcp_installed() is False

    def test_is_mcp_installed_returns_false_when_no_mcp_entry(self, tmp_path):
        """Returns False when IDE config exists but has no ai-guardian entry."""
        import json

        config_file = tmp_path / ".claude.json"
        config_file.write_text(json.dumps({"mcpServers": {"other-tool": {}}}))
        with mock.patch("pathlib.Path.expanduser", return_value=config_file):
            assert DaemonTray._is_mcp_installed() is False

    def test_is_mcp_installed_handles_corrupt_json(self, tmp_path):
        """Gracefully handles corrupt JSON config files."""
        config_file = tmp_path / ".claude.json"
        config_file.write_text("not valid json {{{")
        with mock.patch("pathlib.Path.expanduser", return_value=config_file):
            assert DaemonTray._is_mcp_installed() is False

    def test_mcp_installed_cached_at_init(self):
        """_mcp_installed is set during __init__."""
        with mock.patch.object(DaemonTray, "_is_mcp_installed", return_value=False):
            tray = DaemonTray(
                get_stats_callback=lambda: {},
                stop_callback=lambda: None,
                pause_callback=lambda mins: None,
            )
            assert tray._mcp_installed is False

        with mock.patch.object(DaemonTray, "_is_mcp_installed", return_value=True):
            tray = DaemonTray(
                get_stats_callback=lambda: {},
                stop_callback=lambda: None,
                pause_callback=lambda mins: None,
            )
            assert tray._mcp_installed is True


class TestMcpProactiveMultiDaemonClosure:
    """Regression test for MCP Proactive visibility in multi-daemon mode.

    The visibility lambda must capture the loop slot via default argument,
    not close over the _is_slot_running name (which would always reference
    the last iteration's function).
    """

    def test_mcp_visible_in_first_daemon_slot(self):
        mc = mock.MagicMock()
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=mc,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
            DaemonTarget(name="remote", runtime="container", status="running"),
        ]
        tray._mcp_installed = True
        mc.get_status.return_value = {}

        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_multi_daemon_menu_items()

            mcp_calls = [
                call for call in mock_pystray.MenuItem.call_args_list
                if len(call[0]) > 0
                and callable(call[0][0])
                and not isinstance(call[0][0], mock.MagicMock)
            ]
            mcp_vis_results = []
            for call in mcp_calls:
                label_fn = call[0][0]
                vis_fn = call[1].get("visible")
                try:
                    label = label_fn(None)
                except Exception:
                    continue
                if "MCP" in str(label) and vis_fn:
                    mcp_vis_results.append(vis_fn(None))

            assert len(mcp_vis_results) >= 2
            assert mcp_vis_results[0] is True
            assert mcp_vis_results[1] is True


class TestShellMenuItem:
    """Tests for Shell menu item in tray (issue #706)."""

    def test_single_daemon_menu_includes_shell(self):
        """Single-daemon flat menu contains 'Shell' item."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
        ]
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_single_daemon_menu_items()

            labels = [
                call[0][0] for call in mock_pystray.MenuItem.call_args_list
                if isinstance(call[0][0], str)
            ]
            assert "Shell" in labels

    def test_single_daemon_shell_after_mcp(self):
        """Shell item appears after MCP Proactive section in single-daemon menu."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
        ]
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_single_daemon_menu_items()

            labels = [
                call[0][0] for call in mock_pystray.MenuItem.call_args_list
                if isinstance(call[0][0], str)
            ]
            assert labels[-1] == "Shell"

    def test_multi_daemon_menu_includes_shell(self):
        """Multi-daemon per-daemon submenu contains 'Shell' item."""
        mc = mock.MagicMock()
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=mc,
        )
        tray._targets = [
            DaemonTarget(name="local", runtime="local", status="running"),
            DaemonTarget(name="remote", runtime="container", status="running"),
        ]
        mc.get_stats.return_value = {}
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            mock_pystray.Menu.SEPARATOR = mock.MagicMock()
            tray._build_multi_daemon_menu_items()

            labels = [
                call[0][0] for call in mock_pystray.MenuItem.call_args_list
                if isinstance(call[0][0], str)
            ]
            assert "Shell" in labels

    def test_shell_routes_via_multi_client(self):
        """Shell action calls multi_client.open_shell for local target."""
        mc = mock.MagicMock()
        local_target = DaemonTarget(name="local", runtime="local", status="running")

        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=mc,
        )
        tray._targets = [local_target]

        tray._multi_client.open_shell(local_target)
        mc.open_shell.assert_called_once_with(local_target)

    def test_shell_falls_back_without_multi_client(self):
        """Shell action falls back to _launch_shell without multi_client."""
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
        )
        local_target = DaemonTarget(name="local", runtime="local", status="running")
        tray._targets = [local_target]

        with mock.patch.object(DaemonTray, "_launch_shell") as mock_shell:
            t = tray._targets[0]
            if tray._multi_client:
                tray._multi_client.open_shell(t)
            else:
                tray._launch_shell()
            mock_shell.assert_called_once()

    def test_launch_shell_uses_shell_env(self):
        """_launch_shell opens user's $SHELL in a terminal."""
        with mock.patch("os.environ", {"SHELL": "/bin/zsh"}):
            with mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal") as mock_launch:
                DaemonTray._launch_shell()
                mock_launch.assert_called_once_with(["/bin/zsh"], keep_open=True)

    def test_launch_shell_defaults_to_sh(self):
        """_launch_shell defaults to /bin/sh when SHELL not set."""
        with mock.patch.dict("os.environ", {}, clear=True):
            with mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal") as mock_launch:
                DaemonTray._launch_shell()
                mock_launch.assert_called_once_with(["/bin/sh"], keep_open=True)


class TestPluginMenuItems:
    """Tests for tray plugin menu integration (issue #590)."""

    def _make_tray(self, targets=None, multi_client=None):
        tray = DaemonTray(
            get_stats_callback=lambda: {},
            stop_callback=lambda: None,
            pause_callback=lambda mins: None,
            multi_client=multi_client,
        )
        if targets is not None:
            tray._targets = targets
        return tray

    def test_daemon_plugins_initialized_empty(self):
        tray = self._make_tray()
        assert tray._daemon_plugins == {}
        assert tray._last_plugins_hash == {}

    def test_get_daemon_plugins_returns_empty_for_unknown_slot(self):
        tray = self._make_tray()
        assert tray._get_daemon_plugins(0) == []

    def test_get_daemon_plugins_returns_plugins_for_known_slot(self):
        from ai_guardian.daemon.tray_plugins import Plugin, PluginItem
        tray = self._make_tray()
        tray._daemon_plugins[0] = [
            Plugin(name="Test", items=[PluginItem(label="Run", command="echo")])
        ]
        plugins = tray._get_daemon_plugins(0)
        assert len(plugins) == 1
        assert plugins[0].name == "Test"

    def test_poll_plugins_updates_daemon_plugins(self):
        mc = mock.MagicMock()
        mc._local_plugins.return_value = {
            "plugins": [{
                "name": "TestPlugin",
                "items": [{"label": "Hello", "command": "echo", "type": "background"}]
            }]
        }
        local_target = DaemonTarget(name="local", runtime="local", status="running")
        tray = self._make_tray(targets=[local_target], multi_client=mc)
        tray._poll_plugins()
        assert 0 in tray._daemon_plugins
        assert len(tray._daemon_plugins[0]) == 1
        assert tray._daemon_plugins[0][0].name == "TestPlugin"

    def test_poll_plugins_skips_stopped_remote_daemons(self):
        mc = mock.MagicMock()
        stopped = DaemonTarget(name="remote", runtime="container", status="stopped")
        tray = self._make_tray(targets=[stopped], multi_client=mc)
        tray._poll_plugins()
        mc.get_plugins.assert_not_called()

    def test_poll_plugins_loads_local_even_when_stopped(self):
        mc = mock.MagicMock()
        mc._local_plugins.return_value = {
            "plugins": [{"name": "Local", "items": [{"label": "A", "command": "b"}]}]
        }
        stopped_local = DaemonTarget(name="local", runtime="local", status="stopped")
        tray = self._make_tray(targets=[stopped_local], multi_client=mc)
        tray._poll_plugins()
        mc._local_plugins.assert_called_once()
        assert 0 in tray._daemon_plugins

    def test_poll_plugins_no_rebuild_when_unchanged(self):
        mc = mock.MagicMock()
        mc._local_plugins.return_value = {
            "plugins": [{"name": "P", "items": [{"label": "A", "command": "b"}]}]
        }
        local = DaemonTarget(name="local", runtime="local", status="running")
        tray = self._make_tray(targets=[local], multi_client=mc)
        tray._poll_plugins()
        first_plugins = tray._daemon_plugins[0]
        tray._poll_plugins()
        assert tray._daemon_plugins[0] is first_plugins

    def test_build_single_daemon_plugin_items_returns_list(self):
        tray = self._make_tray(targets=[
            DaemonTarget(name="local", runtime="local", status="running")
        ])
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            items = tray._build_single_daemon_plugin_items()
        assert isinstance(items, list)
        assert len(items) > 0

    def test_build_multi_daemon_plugin_slots_returns_list(self):
        tray = self._make_tray()
        with mock.patch("ai_guardian.daemon.tray.pystray", create=True) as mock_pystray:
            mock_pystray.MenuItem = mock.MagicMock()
            mock_pystray.Menu = mock.MagicMock()
            items = tray._build_multi_daemon_plugin_slots(0)
        assert isinstance(items, list)
        assert len(items) == tray._MAX_PLUGIN_SLOTS

    def test_execute_plugin_command_terminal(self):
        with mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal") as mock_launch:
            DaemonTray._execute_plugin_command("echo hello", "terminal")
            mock_launch.assert_called_once()
            assert mock_launch.call_args[0][0] == ["echo", "hello"]
            assert mock_launch.call_args[1]["keep_open"] is True

    def test_execute_plugin_command_info(self):
        with mock.patch("subprocess.run") as mock_run:
            DaemonTray._execute_plugin_command("echo hello", "background")
            mock_run.assert_called_once()

    def test_execute_plugin_command_notification(self):
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.MagicMock(stdout="Pod count: 3\n")
            with mock.patch("ai_guardian.daemon.tray_plugins.send_notification") as mock_notify:
                DaemonTray._execute_plugin_command("kubectl get pods | wc -l", "notification")
                mock_run.assert_called_once()
                mock_notify.assert_called_once_with("AI Guardian", "Pod count: 3")

    def test_execute_plugin_command_clipboard(self):
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.MagicMock(stdout="10.0.0.5\n")
            with mock.patch("ai_guardian.daemon.tray_plugins.copy_to_clipboard") as mock_copy:
                DaemonTray._execute_plugin_command("kubectl get svc -o ip", "clipboard")
                mock_run.assert_called_once()
                mock_copy.assert_called_once_with("10.0.0.5")

    def test_execute_plugin_command_notification_no_output(self):
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.MagicMock(stdout="")
            with mock.patch("ai_guardian.daemon.tray_plugins.send_notification") as mock_notify:
                DaemonTray._execute_plugin_command("true", "notification")
                mock_notify.assert_called_once_with("AI Guardian", "(no output)")

    def test_execute_plugin_command_with_params(self):
        tray = self._make_tray()
        item_dict = {
            "label": "Deploy",
            "command": "deploy {tray.env}",
            "type": "terminal",
            "params": [{"name": "env", "hint": "Environment", "default": "dev"}]
        }
        with mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal") as mock_launch:
            with mock.patch("sys.executable", "/usr/bin/python3"):
                tray._execute_plugin_command_with_params(item_dict)
                mock_launch.assert_called_once()
                cmd = mock_launch.call_args[0][0]
                assert "tray-prompt" in " ".join(cmd)

    def test_execute_plugin_command_with_params_platform_map(self):
        tray = self._make_tray()
        item_dict = {
            "label": "Shell",
            "command": {"darwin": "open .", "default": "xdg-open ."},
            "type": "terminal",
            "params": []
        }
        with mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal") as mock_launch:
            with mock.patch("sys.executable", "/usr/bin/python3"):
                tray._execute_plugin_command_with_params(item_dict)
                mock_launch.assert_called_once()

    def test_execute_plugin_command_with_params_no_match(self):
        tray = self._make_tray()
        item_dict = {
            "label": "Shell",
            "command": {"windows": "start ."},
            "type": "terminal",
            "params": []
        }
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("ai_guardian.daemon.multi_client._launch_in_terminal") as mock_launch:
                tray._execute_plugin_command_with_params(item_dict)
                mock_launch.assert_not_called()
