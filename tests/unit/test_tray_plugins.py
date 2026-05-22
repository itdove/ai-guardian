"""Tests for tray menu plugin loader and command utilities."""

import json
import os
from unittest import mock

import pytest

from ai_guardian.daemon.tray_plugins import (
    Plugin,
    PluginItem,
    PluginParam,
    dict_to_plugins,
    load_plugins,
    plugins_to_dict,
    resolve_command,
    substitute_params,
)


class TestLoadPlugins:
    def test_loads_single_plugin_file(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "TestPlugin",
            "items": [
                {"label": "Hello", "command": "echo hello", "type": "background"}
            ]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 1
        assert plugins[0].name == "TestPlugin"
        assert len(plugins[0].items) == 1
        assert plugins[0].items[0].label == "Hello"
        assert plugins[0].items[0].command == "echo hello"
        assert plugins[0].items[0].type == "background"

    def test_loads_multiple_plugin_files(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        for i in range(3):
            (plugins_dir / f"plugin{i}.json").write_text(json.dumps({
                "name": f"Plugin{i}",
                "items": [{"label": "Action", "command": f"cmd{i}"}]
            }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 3

    def test_skips_malformed_json(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "bad.json").write_text("not valid json {{{")
        (plugins_dir / "good.json").write_text(json.dumps({
            "name": "Good",
            "items": [{"label": "Ok", "command": "true"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 1
        assert plugins[0].name == "Good"

    def test_skips_plugin_missing_name(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "noname.json").write_text(json.dumps({
            "items": [{"label": "X", "command": "y"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 0

    def test_skips_plugin_missing_items(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "noitems.json").write_text(json.dumps({
            "name": "NoItems"
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 0

    def test_returns_empty_when_dir_missing(self, tmp_path):
        plugins = load_plugins(tmp_path / "nonexistent")
        assert plugins == []

    def test_returns_empty_when_dir_empty(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        plugins = load_plugins(plugins_dir)
        assert plugins == []

    def test_validates_item_requires_label(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [
                {"command": "echo missing label"},
                {"label": "Good", "command": "echo ok"},
            ]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 1
        assert len(plugins[0].items) == 1
        assert plugins[0].items[0].label == "Good"

    def test_validates_item_requires_command(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [
                {"label": "No Command"},
                {"label": "Good", "command": "echo ok"},
            ]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins[0].items) == 1
        assert plugins[0].items[0].label == "Good"

    def test_parses_params_correctly(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{
                "label": "Deploy",
                "command": "deploy {branch}",
                "type": "terminal",
                "params": [
                    {"name": "branch", "hint": "Git branch", "default": "main"}
                ]
            }]
        }))
        plugins = load_plugins(plugins_dir)
        item = plugins[0].items[0]
        assert len(item.params) == 1
        assert item.params[0].name == "branch"
        assert item.params[0].hint == "Git branch"
        assert item.params[0].default == "main"
        assert item.params[0].options is None

    def test_parses_params_with_options(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{
                "label": "Deploy",
                "command": "deploy --env {env}",
                "params": [
                    {"name": "env", "options": ["dev", "staging", "prod"]}
                ]
            }]
        }))
        plugins = load_plugins(plugins_dir)
        param = plugins[0].items[0].params[0]
        assert param.name == "env"
        assert param.options == ["dev", "staging", "prod"]

    def test_ignores_non_json_files(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "readme.txt").write_text("not a plugin")
        (plugins_dir / "good.json").write_text(json.dumps({
            "name": "Good",
            "items": [{"label": "Ok", "command": "true"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 1

    def test_default_type_is_terminal(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "bash"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].type == "terminal"

    def test_invalid_type_defaults_to_terminal(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "bash", "type": "bogus"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].type == "terminal"

    def test_command_as_platform_map(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{
                "label": "Shell",
                "command": {"darwin": "open -a Terminal", "default": "bash"}
            }]
        }))
        plugins = load_plugins(plugins_dir)
        assert isinstance(plugins[0].items[0].command, dict)

    def test_uses_default_dir_when_none(self):
        with mock.patch("ai_guardian.daemon.get_tray_plugins_dir") as m:
            m.return_value = mock.MagicMock()
            m.return_value.is_dir.return_value = False
            plugins = load_plugins()
            m.assert_called_once()
            assert plugins == []

    def test_skips_param_missing_name(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{
                "label": "Deploy",
                "command": "deploy",
                "params": [
                    {"hint": "no name field"},
                    {"name": "good", "hint": "valid"}
                ]
            }]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins[0].items[0].params) == 1
        assert plugins[0].items[0].params[0].name == "good"


class TestResolveCommand:
    def test_string_command_returned_as_is(self):
        assert resolve_command("echo hello") == "echo hello"

    def test_platform_map_returns_darwin_on_macos(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            result = resolve_command({"darwin": "open .", "linux": "xdg-open ."})
            assert result == "open ."

    def test_platform_map_returns_linux(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            result = resolve_command({"darwin": "open .", "linux": "xdg-open ."})
            assert result == "xdg-open ."

    def test_platform_map_returns_windows(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Windows"
            result = resolve_command({"windows": "start .", "linux": "xdg-open ."})
            assert result == "start ."

    def test_platform_map_falls_back_to_default(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            result = resolve_command({"darwin": "open .", "default": "xdg-open ."})
            assert result == "xdg-open ."

    def test_platform_map_returns_none_when_no_match(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            result = resolve_command({"darwin": "open .", "windows": "start ."})
            assert result is None

    def test_platform_map_returns_none_when_empty_dict(self):
        assert resolve_command({}) is None

    def test_non_dict_non_string_returns_none(self):
        assert resolve_command(42) is None

    def test_platform_key_is_lowercase(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            result = resolve_command({"darwin": "open ."})
            assert result == "open ."


class TestSubstituteParams:
    def test_substitutes_single_param(self):
        result = substitute_params("echo {msg}", {"msg": "hello"})
        assert result == "echo hello"

    def test_substitutes_multiple_params(self):
        result = substitute_params(
            "deploy --branch {branch} --env {env}",
            {"branch": "main", "env": "prod"},
        )
        assert result == "deploy --branch main --env prod"

    def test_missing_param_replaced_with_empty(self):
        result = substitute_params("echo {missing}", {})
        assert result == "echo "

    def test_no_params_returns_original(self):
        result = substitute_params("echo hello", {})
        assert result == "echo hello"

    def test_extra_values_ignored(self):
        result = substitute_params("echo {a}", {"a": "1", "b": "2"})
        assert result == "echo 1"

    def test_partial_params_fills_known_clears_unknown(self):
        result = substitute_params("{a} and {b}", {"a": "yes"})
        assert result == "yes and "


class TestPluginsToDict:
    def test_serializes_simple_plugin(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(label="Hello", command="echo hi", type="background")]
        )]
        result = plugins_to_dict(plugins)
        assert result == {
            "plugins": [{
                "name": "Test",
                "items": [{"label": "Hello", "command": "echo hi", "type": "background"}]
            }]
        }

    def test_serializes_plugin_with_params(self):
        plugins = [Plugin(
            name="Deploy",
            items=[PluginItem(
                label="Go",
                command="deploy {env}",
                type="terminal",
                params=[PluginParam(name="env", hint="Environment", default="dev", options=["dev", "prod"])]
            )]
        )]
        result = plugins_to_dict(plugins)
        item = result["plugins"][0]["items"][0]
        assert item["params"] == [
            {"name": "env", "hint": "Environment", "default": "dev", "options": ["dev", "prod"]}
        ]

    def test_serializes_empty_list(self):
        result = plugins_to_dict([])
        assert result == {"plugins": []}

    def test_items_without_params_have_no_params_key(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(label="Run", command="bash")]
        )]
        result = plugins_to_dict(plugins)
        assert "params" not in result["plugins"][0]["items"][0]

    def test_serializes_platform_map_command(self):
        cmd_map = {"darwin": "open .", "default": "xdg-open ."}
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(label="Open", command=cmd_map)]
        )]
        result = plugins_to_dict(plugins)
        assert result["plugins"][0]["items"][0]["command"] == cmd_map

    def test_roundtrip_through_dict(self):
        original = [Plugin(
            name="Roundtrip",
            items=[
                PluginItem(label="Simple", command="echo 1", type="background"),
                PluginItem(
                    label="Params",
                    command="deploy {env}",
                    type="terminal",
                    params=[PluginParam(name="env", hint="Env", default="dev")],
                ),
            ]
        )]
        data = plugins_to_dict(original)
        restored = dict_to_plugins(data)
        assert len(restored) == 1
        assert restored[0].name == "Roundtrip"
        assert len(restored[0].items) == 2
        assert restored[0].items[0].label == "Simple"
        assert restored[0].items[1].params[0].name == "env"


class TestSendNotification:
    def test_macos_uses_osascript(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run") as mock_run:
                from ai_guardian.daemon.tray_plugins import send_notification
                result = send_notification("Title", "Hello world")
                assert result is True
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert args[0] == "osascript"

    def test_linux_uses_notify_send(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            with mock.patch("subprocess.run") as mock_run:
                from ai_guardian.daemon.tray_plugins import send_notification
                result = send_notification("Title", "Hello")
                assert result is True
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert args[0] == "notify-send"

    def test_returns_false_on_unknown_platform(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "FreeBSD"
            from ai_guardian.daemon.tray_plugins import send_notification
            assert send_notification("T", "M") is False

    def test_returns_false_on_error(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run", side_effect=FileNotFoundError):
                from ai_guardian.daemon.tray_plugins import send_notification
                assert send_notification("T", "M") is False

    def test_escapes_quotes_in_message(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run") as mock_run:
                from ai_guardian.daemon.tray_plugins import send_notification
                send_notification("Title", 'He said "hello"')
                script = mock_run.call_args[0][0][2]
                assert '\\"' in script


class TestCopyToClipboard:
    def test_macos_uses_pbcopy(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run") as mock_run:
                from ai_guardian.daemon.tray_plugins import copy_to_clipboard
                result = copy_to_clipboard("hello")
                assert result is True
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert args == ["pbcopy"]
                assert mock_run.call_args[1]["input"] == b"hello"

    def test_linux_uses_xclip(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            with mock.patch("shutil.which", return_value="/usr/bin/xclip"):
                with mock.patch("subprocess.run") as mock_run:
                    from ai_guardian.daemon.tray_plugins import copy_to_clipboard
                    result = copy_to_clipboard("hello")
                    assert result is True
                    args = mock_run.call_args[0][0]
                    assert "xclip" in args[0]

    def test_linux_falls_back_to_xsel(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            with mock.patch("shutil.which", side_effect=lambda x: "/usr/bin/xsel" if x == "xsel" else None):
                with mock.patch("subprocess.run") as mock_run:
                    from ai_guardian.daemon.tray_plugins import copy_to_clipboard
                    result = copy_to_clipboard("hello")
                    assert result is True
                    args = mock_run.call_args[0][0]
                    assert "xsel" in args[0]

    def test_linux_returns_false_when_no_tool(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            with mock.patch("shutil.which", return_value=None):
                from ai_guardian.daemon.tray_plugins import copy_to_clipboard
                assert copy_to_clipboard("hello") is False

    def test_returns_false_on_unknown_platform(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "FreeBSD"
            from ai_guardian.daemon.tray_plugins import copy_to_clipboard
            assert copy_to_clipboard("hello") is False

    def test_returns_false_on_error(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run", side_effect=OSError("broken")):
                from ai_guardian.daemon.tray_plugins import copy_to_clipboard
                assert copy_to_clipboard("hello") is False


class TestDictToPlugins:
    def test_deserializes_valid_data(self):
        data = {
            "plugins": [{
                "name": "Test",
                "items": [{"label": "Run", "command": "bash"}]
            }]
        }
        plugins = dict_to_plugins(data)
        assert len(plugins) == 1
        assert plugins[0].name == "Test"

    def test_skips_invalid_entries(self):
        data = {
            "plugins": [
                {"name": "Good", "items": [{"label": "A", "command": "b"}]},
                {"invalid": "data"},
            ]
        }
        plugins = dict_to_plugins(data)
        assert len(plugins) == 1
        assert plugins[0].name == "Good"

    def test_returns_empty_for_missing_plugins_key(self):
        plugins = dict_to_plugins({})
        assert plugins == []

    def test_returns_empty_for_empty_plugins(self):
        plugins = dict_to_plugins({"plugins": []})
        assert plugins == []
