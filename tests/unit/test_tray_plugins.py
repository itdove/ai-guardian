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
    filter_plugins_by_tags,
    load_plugins,
    plugins_to_dict,
    resolve_command,
    show_dialog,
    substitute_params,
    substitute_target_vars,
    validate_param_value,
    wrap_for_target,
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
                "command": "deploy {tray.branch}",
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

    def test_modal_type_accepted(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Version", "command": "ai-guardian --version", "type": "modal"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].type == "modal"

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


    def test_parses_run_on_target_true(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Doctor", "command": "ai-guardian doctor",
                       "run_on_target": True}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].run_on_target is True

    def test_parses_run_on_target_false(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Logs", "command": "podman logs {container_id}",
                       "run_on_target": False}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].run_on_target is False

    def test_default_run_on_target_is_false(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "echo hi"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].run_on_target is False


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

    def test_empty_string_platform_value_not_falsy_fallthrough(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            result = resolve_command({"darwin": "", "default": "fallback"})
            assert result == ""


class TestSubstituteParams:
    def test_substitutes_single_param(self):
        result = substitute_params("echo {tray.msg}", {"msg": "hello"})
        assert result == "echo hello"

    def test_substitutes_multiple_params(self):
        result = substitute_params(
            "deploy --branch {tray.branch} --env {tray.env}",
            {"branch": "main", "env": "prod"},
        )
        assert result == "deploy --branch main --env prod"

    def test_missing_param_replaced_with_empty(self):
        result = substitute_params("echo {tray.missing}", {})
        assert result == "echo "

    def test_no_params_returns_original(self):
        result = substitute_params("echo hello", {})
        assert result == "echo hello"

    def test_extra_values_ignored(self):
        result = substitute_params("echo {tray.a}", {"a": "1", "b": "2"})
        assert result == "echo 1"

    def test_partial_params_fills_known_clears_unknown(self):
        result = substitute_params("{tray.a} and {tray.b}", {"a": "yes"})
        assert result == "yes and "

    def test_non_tray_braces_left_untouched(self):
        result = substitute_params("echo {json} and {tray.name}", {"name": "hi"})
        assert result == "echo {json} and hi"

    def test_shell_variables_left_untouched(self):
        result = substitute_params("echo $HOME {tray.x}", {"x": "val"})
        assert result == "echo $HOME val"

    def test_tray_working_dir_substituted(self):
        result = substitute_params(
            "cd {tray.working_dir} && make",
            {"working_dir": "/home/user/project"},
        )
        assert result == "cd /home/user/project && make"


class TestSubstituteTargetVars:
    """Tests for target variable substitution in plugin commands."""

    def _make_target(self, **kwargs):
        from ai_guardian.daemon.discovery import DaemonTarget
        defaults = dict(
            name="test-daemon", runtime="container",
            host="192.168.1.10", port=63152,
            container_id="a1b2c3d4e5f6a1b2",
            container_engine="podman",
            pod_name="guardian-pod-1",
            namespace="ai-guardian",
        )
        defaults.update(kwargs)
        return DaemonTarget(**defaults)

    def test_substitutes_container_id(self):
        target = self._make_target()
        result = substitute_target_vars("podman logs {container_id}", target)
        assert result == "podman logs a1b2c3d4e5f6a1b2"

    def test_substitutes_host_and_port(self):
        target = self._make_target()
        result = substitute_target_vars("curl http://{host}:{port}/api/health", target)
        assert result == "curl http://192.168.1.10:63152/api/health"

    def test_substitutes_name(self):
        target = self._make_target()
        result = substitute_target_vars("echo {name}", target)
        assert result == "echo test-daemon"

    def test_substitutes_container_engine(self):
        target = self._make_target(container_engine="docker")
        result = substitute_target_vars("{container_engine} ps", target)
        assert result == "docker ps"

    def test_substitutes_pod_name_and_namespace(self):
        target = self._make_target()
        result = substitute_target_vars(
            "kubectl logs {pod_name} -n {namespace}", target,
        )
        assert result == "kubectl logs guardian-pod-1 -n ai-guardian"

    def test_none_field_becomes_empty(self):
        target = self._make_target(container_id=None)
        result = substitute_target_vars("logs {container_id}", target)
        assert result == "logs "

    def test_no_target_returns_template_unchanged(self):
        result = substitute_target_vars("echo {container_id}", None)
        assert result == "echo {container_id}"

    def test_non_target_braces_left_untouched(self):
        target = self._make_target()
        result = substitute_target_vars("echo {json} {tray.x} {name}", target)
        assert result == "echo {json} {tray.x} test-daemon"

    def test_multiple_same_variable(self):
        target = self._make_target()
        result = substitute_target_vars(
            "{container_id} and {container_id}", target,
        )
        assert result == "a1b2c3d4e5f6a1b2 and a1b2c3d4e5f6a1b2"

    def test_port_converted_to_string(self):
        target = self._make_target(port=8080)
        result = substitute_target_vars(":{port}", target)
        assert result == ":8080"

    def test_no_placeholders_returns_original(self):
        target = self._make_target()
        result = substitute_target_vars("echo hello world", target)
        assert result == "echo hello world"

    def test_substitutes_working_dir(self):
        target = self._make_target(working_dir="/home/user/project")
        result = substitute_target_vars(
            "cd {working_dir} && make build", target,
        )
        assert result == "cd /home/user/project && make build"

    def test_working_dir_none_becomes_empty(self):
        target = self._make_target(working_dir=None)
        result = substitute_target_vars("cd {working_dir}", target)
        assert result == "cd "


class TestNeedsShell:
    """Tests for _needs_shell shell-operator detection."""

    def test_simple_command(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("echo hello") is False

    def test_double_ampersand(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("uname -a && lsb_release -a") is True

    def test_pipe(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("ps aux | grep python") is True

    def test_semicolon(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("echo hello; echo world") is True

    def test_redirect_out(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("ai-guardian doctor > /tmp/report.txt") is True

    def test_redirect_append(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("echo line >> /tmp/log.txt") is True

    def test_double_pipe(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("cmd1 || cmd2") is True

    def test_redirect_in(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("wc -l < input.txt") is True

    def test_heredoc(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("cat << EOF") is True

    def test_no_operators(self):
        from ai_guardian.daemon.tray_plugins import _needs_shell
        assert _needs_shell("ai-guardian --version") is False


class TestWrapForTarget:
    """Tests for run_on_target command wrapping."""

    def _make_target(self, **kwargs):
        from ai_guardian.daemon.discovery import DaemonTarget
        defaults = dict(name="test", runtime="local")
        defaults.update(kwargs)
        return DaemonTarget(**defaults)

    def test_local_runtime_no_wrapping(self):
        target = self._make_target(runtime="local")
        result = wrap_for_target(["ai-guardian", "doctor"], target)
        assert result == ["ai-guardian", "doctor"]

    def test_container_runtime_wraps_with_engine_exec(self):
        target = self._make_target(
            runtime="container",
            container_id="a1b2c3d4e5f6a1b2",
            container_engine="podman",
        )
        result = wrap_for_target(["ai-guardian", "doctor"], target)
        assert result == [
            "podman", "exec", "-it", "a1b2c3d4e5f6a1b2",
            "ai-guardian", "doctor",
        ]

    def test_container_runtime_docker_engine(self):
        target = self._make_target(
            runtime="container",
            container_id="a1b2c3d4e5f6a1b2",
            container_engine="docker",
        )
        result = wrap_for_target(["ai-guardian", "doctor"], target)
        assert result[0] == "docker"

    def test_container_runtime_defaults_to_podman(self):
        target = self._make_target(
            runtime="container",
            container_id="a1b2c3d4e5f6a1b2",
            container_engine=None,
        )
        result = wrap_for_target(["ai-guardian", "doctor"], target)
        assert result[0] == "podman"

    def test_container_runtime_non_interactive(self):
        target = self._make_target(
            runtime="container",
            container_id="a1b2c3d4e5f6a1b2",
            container_engine="podman",
        )
        result = wrap_for_target(
            ["ai-guardian", "doctor"], target, interactive=False,
        )
        assert "-it" not in result
        assert result == [
            "podman", "exec", "a1b2c3d4e5f6a1b2",
            "ai-guardian", "doctor",
        ]

    def test_container_runtime_invalid_id_falls_back_to_local(self):
        target = self._make_target(
            runtime="container", container_id=".invalid",
        )
        cmd = ["ai-guardian", "doctor"]
        result = wrap_for_target(cmd, target)
        assert result == cmd

    def test_container_runtime_missing_id_falls_back_to_local(self):
        target = self._make_target(
            runtime="container", container_id=None,
        )
        cmd = ["ai-guardian", "doctor"]
        result = wrap_for_target(cmd, target)
        assert result == cmd

    def test_kubernetes_runtime_wraps_with_kube_cli(self):
        target = self._make_target(
            runtime="kubernetes",
            pod_name="guardian-pod-1",
            namespace="ai-guardian",
        )
        with mock.patch("shutil.which", return_value=None):
            result = wrap_for_target(["ai-guardian", "doctor"], target)
        assert result == [
            "kubectl", "exec", "-it",
            "guardian-pod-1", "-n", "ai-guardian", "--",
            "ai-guardian", "doctor",
        ]

    def test_kubernetes_runtime_prefers_oc(self):
        target = self._make_target(
            runtime="kubernetes",
            pod_name="guardian-pod-1",
            namespace="ai-guardian",
        )
        with mock.patch("shutil.which", return_value="/usr/bin/oc"):
            result = wrap_for_target(["ai-guardian", "doctor"], target)
        assert result[0] == "oc"

    def test_kubernetes_default_namespace(self):
        target = self._make_target(
            runtime="kubernetes",
            pod_name="guardian-pod-1",
            namespace=None,
        )
        with mock.patch("shutil.which", return_value=None):
            result = wrap_for_target(["ai-guardian", "doctor"], target)
        assert "-n" in result
        ns_idx = result.index("-n")
        assert result[ns_idx + 1] == "default"

    def test_kubernetes_missing_pod_falls_back_to_local(self):
        target = self._make_target(
            runtime="kubernetes", pod_name=None,
        )
        cmd = ["ai-guardian", "doctor"]
        result = wrap_for_target(cmd, target)
        assert result == cmd

    def test_kubernetes_non_interactive(self):
        target = self._make_target(
            runtime="kubernetes",
            pod_name="guardian-pod-1",
            namespace="default",
        )
        with mock.patch("shutil.which", return_value=None):
            result = wrap_for_target(
                ["ai-guardian", "doctor"], target, interactive=False,
            )
        assert "-it" not in result

    def test_manual_runtime_runs_locally(self):
        target = self._make_target(runtime="manual")
        cmd = ["ai-guardian", "doctor"]
        result = wrap_for_target(cmd, target)
        assert result == cmd

    def test_unknown_runtime_runs_locally(self):
        target = self._make_target(runtime="unknown")
        cmd = ["ai-guardian", "doctor"]
        result = wrap_for_target(cmd, target)
        assert result == cmd


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
                command="deploy {tray.env}",
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

    def test_serializes_run_on_target_true(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(
                label="Doctor", command="ai-guardian doctor",
                run_on_target=True,
            )]
        )]
        result = plugins_to_dict(plugins)
        assert result["plugins"][0]["items"][0]["run_on_target"] is True

    def test_serializes_run_on_target_false_omitted(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(label="Logs", command="podman logs abc")]
        )]
        result = plugins_to_dict(plugins)
        assert "run_on_target" not in result["plugins"][0]["items"][0]

    def test_roundtrip_through_dict(self):
        original = [Plugin(
            name="Roundtrip",
            items=[
                PluginItem(label="Simple", command="echo 1", type="background"),
                PluginItem(
                    label="Params",
                    command="deploy {tray.env}",
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

    def test_roundtrip_preserves_run_on_target(self):
        original = [Plugin(
            name="Roundtrip",
            items=[
                PluginItem(
                    label="Doctor", command="ai-guardian doctor",
                    run_on_target=True,
                ),
                PluginItem(label="Logs", command="podman logs abc"),
            ]
        )]
        data = plugins_to_dict(original)
        restored = dict_to_plugins(data)
        assert restored[0].items[0].run_on_target is True
        assert restored[0].items[1].run_on_target is False


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

    def test_linux_includes_icon_flag(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            with mock.patch("ai_guardian.daemon.tray_plugins._find_icon", return_value="/path/to/icon.png"):
                with mock.patch("subprocess.run") as mock_run:
                    from ai_guardian.daemon.tray_plugins import send_notification
                    result = send_notification("Title", "Hello")
                    assert result is True
                    args = mock_run.call_args[0][0]
                    assert "--icon" in args
                    assert "/path/to/icon.png" in args

    def test_linux_no_icon_when_not_found(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            with mock.patch("ai_guardian.daemon.tray_plugins._find_icon", return_value=""):
                with mock.patch("subprocess.run") as mock_run:
                    from ai_guardian.daemon.tray_plugins import send_notification
                    result = send_notification("Title", "Hello")
                    assert result is True
                    args = mock_run.call_args[0][0]
                    assert "--icon" not in args

    def test_windows_loads_custom_icon(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Windows"
            with mock.patch("ai_guardian.daemon.tray_plugins._find_icon", return_value="C:\\icons\\shield.png"):
                with mock.patch("subprocess.run") as mock_run:
                    from ai_guardian.daemon.tray_plugins import send_notification
                    result = send_notification("Title", "Hello")
                    assert result is True
                    ps_cmd = mock_run.call_args[0][0][2]
                    assert "Bitmap" in ps_cmd
                    assert "shield.png" in ps_cmd

    def test_windows_fallback_icon_when_not_found(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Windows"
            with mock.patch("ai_guardian.daemon.tray_plugins._find_icon", return_value=""):
                with mock.patch("subprocess.run") as mock_run:
                    from ai_guardian.daemon.tray_plugins import send_notification
                    result = send_notification("Title", "Hello")
                    assert result is True
                    ps_cmd = mock_run.call_args[0][0][2]
                    assert "SystemIcons" in ps_cmd
                    assert "Bitmap" not in ps_cmd


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


class TestShowDialog:
    def test_macos_uses_osascript(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run") as mock_run:
                result = show_dialog("Test Title", "Hello world")
                assert result is True
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert args[0] == "osascript"
                assert "display dialog" in args[2]

    def test_linux_uses_zenity(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Linux"
            with mock.patch("subprocess.run") as mock_run:
                result = show_dialog("Test Title", "Hello")
                assert result is True
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert args[0] == "zenity"

    def test_windows_uses_powershell(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Windows"
            with mock.patch("subprocess.run") as mock_run:
                result = show_dialog("Test Title", "Hello")
                assert result is True
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert args[0] == "powershell"
                assert "MessageBox" in args[2]

    def test_returns_false_on_unknown_platform(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "FreeBSD"
            assert show_dialog("T", "M") is False

    def test_returns_false_on_error(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run", side_effect=FileNotFoundError):
                assert show_dialog("T", "M") is False

    def test_escapes_quotes_in_message(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run") as mock_run:
                show_dialog("Title", 'He said "hello"')
                script = mock_run.call_args[0][0][2]
                assert '\\"' in script

    def test_macos_includes_icon_when_found(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("ai_guardian.daemon.tray_plugins._find_icon", return_value="/path/to/icon.icns"):
                with mock.patch("subprocess.run") as mock_run:
                    result = show_dialog("Title", "Hello")
                    assert result is True
                    script = mock_run.call_args[0][0][2]
                    assert "icon" in script.lower()

    def test_multiline_message_on_macos(self):
        with mock.patch("ai_guardian.daemon.tray_plugins.platform") as m:
            m.system.return_value = "Darwin"
            with mock.patch("subprocess.run") as mock_run:
                show_dialog("Title", "line1\nline2\nline3")
                script = mock_run.call_args[0][0][2]
                assert "return" in script


class TestPluginTags:
    def test_tags_parsed_from_json(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "tagged.json").write_text(json.dumps({
            "name": "Carbonite",
            "tags": ["carbonite", "container"],
            "items": [{"label": "Status", "command": "echo ok"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 1
        assert plugins[0].tags == ["carbonite", "container"]

    def test_tags_missing_defaults_to_empty(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "untagged.json").write_text(json.dumps({
            "name": "Generic",
            "items": [{"label": "Run", "command": "bash"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].tags == []

    def test_tags_invalid_type_ignored(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "badtag.json").write_text(json.dumps({
            "name": "Bad",
            "tags": "not-a-list",
            "items": [{"label": "Go", "command": "go"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].tags == []

    def test_tags_filters_non_string_entries(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "mixed.json").write_text(json.dumps({
            "name": "Mixed",
            "tags": ["valid", 42, "", None, "also-valid"],
            "items": [{"label": "Do", "command": "do"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].tags == ["valid", "also-valid"]

    def test_tags_included_in_serialization(self):
        plugins = [Plugin(
            name="Tagged",
            tags=["carbonite"],
            items=[PluginItem(label="Run", command="echo")]
        )]
        result = plugins_to_dict(plugins)
        assert result["plugins"][0]["tags"] == ["carbonite"]

    def test_tags_omitted_when_empty(self):
        plugins = [Plugin(
            name="Untagged",
            items=[PluginItem(label="Run", command="echo")]
        )]
        result = plugins_to_dict(plugins)
        assert "tags" not in result["plugins"][0]

    def test_tags_roundtrip(self):
        original = [Plugin(
            name="Roundtrip",
            tags=["carbonite", "staging"],
            items=[PluginItem(label="Go", command="echo 1")]
        )]
        data = plugins_to_dict(original)
        restored = dict_to_plugins(data)
        assert restored[0].tags == ["carbonite", "staging"]

    def test_tags_roundtrip_empty(self):
        original = [Plugin(
            name="Roundtrip",
            items=[PluginItem(label="Go", command="echo 1")]
        )]
        data = plugins_to_dict(original)
        restored = dict_to_plugins(data)
        assert restored[0].tags == []


class TestFilterPluginsByTags:
    def _make_plugin(self, name, tags=None):
        return Plugin(
            name=name,
            tags=tags or [],
            items=[PluginItem(label="Action", command="echo")],
        )

    def test_untagged_plugin_no_daemon_tags(self):
        plugins = [self._make_plugin("Generic")]
        assert filter_plugins_by_tags(plugins, None) == plugins
        assert filter_plugins_by_tags(plugins, []) == plugins

    def test_untagged_plugin_with_daemon_tags(self):
        plugins = [self._make_plugin("Generic")]
        assert filter_plugins_by_tags(plugins, ["carbonite"]) == plugins

    def test_tagged_plugin_matching_daemon(self):
        plugins = [self._make_plugin("Carbonite", ["carbonite"])]
        result = filter_plugins_by_tags(plugins, ["carbonite", "container"])
        assert len(result) == 1
        assert result[0].name == "Carbonite"

    def test_tagged_plugin_no_match(self):
        plugins = [self._make_plugin("Carbonite", ["carbonite"])]
        result = filter_plugins_by_tags(plugins, ["staging"])
        assert len(result) == 0

    def test_tagged_plugin_no_daemon_tags(self):
        plugins = [self._make_plugin("Carbonite", ["carbonite"])]
        assert filter_plugins_by_tags(plugins, None) == []
        assert filter_plugins_by_tags(plugins, []) == []

    def test_mixed_tagged_and_untagged(self):
        plugins = [
            self._make_plugin("Generic"),
            self._make_plugin("Carbonite", ["carbonite"]),
            self._make_plugin("Staging", ["staging"]),
        ]
        result = filter_plugins_by_tags(plugins, ["carbonite"])
        assert len(result) == 2
        assert result[0].name == "Generic"
        assert result[1].name == "Carbonite"

    def test_plugin_multiple_tags_one_matches(self):
        plugins = [self._make_plugin("Multi", ["carbonite", "staging"])]
        result = filter_plugins_by_tags(plugins, ["staging"])
        assert len(result) == 1

    def test_plugin_multiple_tags_none_match(self):
        plugins = [self._make_plugin("Multi", ["carbonite", "staging"])]
        result = filter_plugins_by_tags(plugins, ["production"])
        assert len(result) == 0

    def test_exact_string_match(self):
        plugins = [self._make_plugin("Carbon", ["carbonite"])]
        result = filter_plugins_by_tags(plugins, ["carbon"])
        assert len(result) == 0


class TestPluginScope:
    def test_scope_parsed_from_json(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "global.json").write_text(json.dumps({
            "name": "Quick Links",
            "scope": "global",
            "items": [{"label": "Docs", "command": "echo docs"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 1
        assert plugins[0].scope == "global"

    def test_scope_daemon_explicit(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "daemon.json").write_text(json.dumps({
            "name": "Daemon Plugin",
            "scope": "daemon",
            "items": [{"label": "Run", "command": "echo"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].scope == "daemon"

    def test_scope_missing_defaults_to_daemon(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "noscope.json").write_text(json.dumps({
            "name": "No Scope",
            "items": [{"label": "Run", "command": "echo"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].scope == "daemon"

    def test_scope_invalid_defaults_to_daemon(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "invalid.json").write_text(json.dumps({
            "name": "Invalid Scope",
            "scope": "invalid_value",
            "items": [{"label": "Run", "command": "echo"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].scope == "daemon"

    def test_scope_included_in_serialization(self):
        plugins = [Plugin(
            name="Global",
            scope="global",
            items=[PluginItem(label="Run", command="echo")]
        )]
        result = plugins_to_dict(plugins)
        assert result["plugins"][0]["scope"] == "global"

    def test_scope_daemon_omitted_in_serialization(self):
        plugins = [Plugin(
            name="Daemon",
            items=[PluginItem(label="Run", command="echo")]
        )]
        result = plugins_to_dict(plugins)
        assert "scope" not in result["plugins"][0]

    def test_scope_roundtrip_global(self):
        original = [Plugin(
            name="Roundtrip",
            scope="global",
            items=[PluginItem(label="Go", command="echo 1")]
        )]
        data = plugins_to_dict(original)
        restored = dict_to_plugins(data)
        assert restored[0].scope == "global"

    def test_scope_roundtrip_daemon(self):
        original = [Plugin(
            name="Roundtrip",
            items=[PluginItem(label="Go", command="echo 1")]
        )]
        data = plugins_to_dict(original)
        restored = dict_to_plugins(data)
        assert restored[0].scope == "daemon"

    def test_mixed_scopes_loaded(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "01-global.json").write_text(json.dumps({
            "name": "Global",
            "scope": "global",
            "items": [{"label": "Docs", "command": "echo docs"}]
        }))
        (plugins_dir / "02-daemon.json").write_text(json.dumps({
            "name": "Daemon",
            "items": [{"label": "Status", "command": "echo status"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert len(plugins) == 2
        global_plugins = [p for p in plugins if p.scope == "global"]
        daemon_plugins = [p for p in plugins if p.scope == "daemon"]
        assert len(global_plugins) == 1
        assert len(daemon_plugins) == 1


class TestParseParamTyped:
    """Tests for typed parameter parsing."""

    def test_default_type_is_string(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "x", "hint": "val"}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].params[0].type == "string"

    def test_type_int_parsed(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "count", "type": "int", "min": 1, "max": 10}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        p = plugins[0].items[0].params[0]
        assert p.type == "int"
        assert p.min == 1.0
        assert p.max == 10.0

    def test_type_boolean_parsed(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "flag", "type": "boolean", "default": "true"}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        p = plugins[0].items[0].params[0]
        assert p.type == "boolean"
        assert p.default == "true"

    def test_options_without_type_infers_choice(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "env", "options": ["dev", "prod"]}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].params[0].type == "choice"

    def test_options_with_explicit_type_uses_type(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "tag", "type": "combobox", "options": ["latest", "stable"]}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].params[0].type == "combobox"

    def test_invalid_type_defaults_to_string(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "x", "type": "bogus"}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].params[0].type == "string"

    def test_required_false_parsed(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "tag", "required": False}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].params[0].required is False

    def test_required_default_is_true(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "x"}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].params[0].required is True

    def test_pattern_parsed(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "branch", "pattern": "^[a-z]+$"}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].params[0].pattern == "^[a-z]+$"

    def test_invalid_min_max_ignored(self, tmp_path):
        plugins_dir = tmp_path / "tray-plugins"
        plugins_dir.mkdir()
        (plugins_dir / "test.json").write_text(json.dumps({
            "name": "Test",
            "items": [{"label": "Run", "command": "cmd", "params": [
                {"name": "x", "type": "int", "min": "not-a-number", "max": None}
            ]}]
        }))
        plugins = load_plugins(plugins_dir)
        p = plugins[0].items[0].params[0]
        assert p.min is None
        assert p.max is None


class TestValidateParamValue:
    """Tests for validate_param_value."""

    def test_required_empty_fails(self):
        p = PluginParam(name="x", required=True)
        ok, err = validate_param_value(p, "")
        assert not ok
        assert "required" in err

    def test_not_required_empty_passes(self):
        p = PluginParam(name="x", required=False)
        ok, err = validate_param_value(p, "")
        assert ok

    def test_string_no_validation(self):
        p = PluginParam(name="x", type="string")
        ok, _ = validate_param_value(p, "anything")
        assert ok

    def test_string_with_pattern_match(self):
        p = PluginParam(name="x", type="string", pattern="^[a-z]+$")
        ok, _ = validate_param_value(p, "abc")
        assert ok

    def test_string_with_pattern_no_match(self):
        p = PluginParam(name="x", type="string", pattern="^[a-z]+$")
        ok, err = validate_param_value(p, "ABC123")
        assert not ok
        assert "pattern" in err

    def test_int_valid(self):
        p = PluginParam(name="n", type="int")
        ok, _ = validate_param_value(p, "42")
        assert ok

    def test_int_invalid(self):
        p = PluginParam(name="n", type="int")
        ok, err = validate_param_value(p, "abc")
        assert not ok
        assert "integer" in err

    def test_int_below_min(self):
        p = PluginParam(name="n", type="int", min=5.0)
        ok, err = validate_param_value(p, "3")
        assert not ok
        assert ">=" in err

    def test_int_above_max(self):
        p = PluginParam(name="n", type="int", max=10.0)
        ok, err = validate_param_value(p, "15")
        assert not ok
        assert "<=" in err

    def test_int_within_bounds(self):
        p = PluginParam(name="n", type="int", min=1.0, max=10.0)
        ok, _ = validate_param_value(p, "5")
        assert ok

    def test_int_at_boundary(self):
        p = PluginParam(name="n", type="int", min=1.0, max=10.0)
        ok1, _ = validate_param_value(p, "1")
        ok2, _ = validate_param_value(p, "10")
        assert ok1 and ok2

    def test_number_valid_float(self):
        p = PluginParam(name="n", type="number")
        ok, _ = validate_param_value(p, "3.14")
        assert ok

    def test_number_invalid(self):
        p = PluginParam(name="n", type="number")
        ok, err = validate_param_value(p, "abc")
        assert not ok
        assert "number" in err

    def test_number_bounds(self):
        p = PluginParam(name="n", type="number", min=0.0, max=1.0)
        ok1, _ = validate_param_value(p, "0.5")
        ok2, err2 = validate_param_value(p, "1.5")
        assert ok1
        assert not ok2

    def test_boolean_true(self):
        p = PluginParam(name="f", type="boolean")
        ok, _ = validate_param_value(p, "true")
        assert ok

    def test_boolean_false(self):
        p = PluginParam(name="f", type="boolean")
        ok, _ = validate_param_value(p, "false")
        assert ok

    def test_boolean_case_insensitive(self):
        p = PluginParam(name="f", type="boolean")
        ok, _ = validate_param_value(p, "True")
        assert ok

    def test_boolean_invalid(self):
        p = PluginParam(name="f", type="boolean")
        ok, err = validate_param_value(p, "yes")
        assert not ok
        assert "true or false" in err

    def test_choice_valid(self):
        p = PluginParam(name="env", type="choice", options=["dev", "prod"])
        ok, _ = validate_param_value(p, "dev")
        assert ok

    def test_choice_invalid(self):
        p = PluginParam(name="env", type="choice", options=["dev", "prod"])
        ok, err = validate_param_value(p, "staging")
        assert not ok
        assert "one of" in err

    def test_combobox_accepts_any(self):
        p = PluginParam(name="tag", type="combobox", options=["latest", "stable"])
        ok, _ = validate_param_value(p, "custom-tag")
        assert ok


class TestParamSerializationTyped:
    """Tests for serialization of typed PluginParam fields."""

    def test_serializes_type_when_not_string(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(
                label="Run", command="cmd",
                params=[PluginParam(name="n", type="int", min=1.0, max=10.0)],
            )]
        )]
        result = plugins_to_dict(plugins)
        p = result["plugins"][0]["items"][0]["params"][0]
        assert p["type"] == "int"
        assert p["min"] == 1.0
        assert p["max"] == 10.0

    def test_omits_type_when_string(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(
                label="Run", command="cmd",
                params=[PluginParam(name="x")],
            )]
        )]
        result = plugins_to_dict(plugins)
        p = result["plugins"][0]["items"][0]["params"][0]
        assert "type" not in p

    def test_serializes_required_false(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(
                label="Run", command="cmd",
                params=[PluginParam(name="x", required=False)],
            )]
        )]
        result = plugins_to_dict(plugins)
        p = result["plugins"][0]["items"][0]["params"][0]
        assert p["required"] is False

    def test_omits_required_when_true(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(
                label="Run", command="cmd",
                params=[PluginParam(name="x", required=True)],
            )]
        )]
        result = plugins_to_dict(plugins)
        p = result["plugins"][0]["items"][0]["params"][0]
        assert "required" not in p

    def test_serializes_pattern(self):
        plugins = [Plugin(
            name="Test",
            items=[PluginItem(
                label="Run", command="cmd",
                params=[PluginParam(name="b", pattern="^[a-z]+$")],
            )]
        )]
        result = plugins_to_dict(plugins)
        p = result["plugins"][0]["items"][0]["params"][0]
        assert p["pattern"] == "^[a-z]+$"

    def test_roundtrip_typed_params(self):
        original = [Plugin(
            name="RT",
            items=[PluginItem(
                label="Go", command="cmd",
                params=[
                    PluginParam(name="n", type="int", min=1.0, max=10.0, required=True),
                    PluginParam(name="tag", type="combobox", options=["a", "b"], required=False),
                    PluginParam(name="flag", type="boolean", default="true"),
                    PluginParam(name="branch", pattern="^[a-z]+$"),
                ],
            )]
        )]
        data = plugins_to_dict(original)
        restored = dict_to_plugins(data)
        params = restored[0].items[0].params
        assert params[0].type == "int"
        assert params[0].min == 1.0
        assert params[0].max == 10.0
        assert params[1].type == "combobox"
        assert params[1].required is False
        assert params[2].type == "boolean"
        assert params[3].pattern == "^[a-z]+$"


class TestPluginTarget:
    """Tests for the PluginItem target field."""

    def test_target_omitted_defaults_to_none(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "t.json").write_text(json.dumps({
            "name": "P", "items": [{"label": "A", "command": "cmd"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].target is None

    def test_target_select_parsed(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "t.json").write_text(json.dumps({
            "name": "P",
            "items": [{"label": "A", "command": "cmd", "target": "select"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].target == "select"

    def test_target_all_parsed(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "t.json").write_text(json.dumps({
            "name": "P",
            "items": [{"label": "A", "command": "cmd", "target": "all"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].target == "all"

    def test_target_containers_parsed(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "t.json").write_text(json.dumps({
            "name": "P",
            "items": [{"label": "A", "command": "cmd", "target": "containers"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].target == "containers"

    def test_target_invalid_defaults_to_none(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "t.json").write_text(json.dumps({
            "name": "P",
            "items": [{"label": "A", "command": "cmd", "target": "bogus"}]
        }))
        plugins = load_plugins(plugins_dir)
        assert plugins[0].items[0].target is None

    def test_target_serialized_when_set(self):
        from ai_guardian.daemon.tray_plugins import _item_to_dict
        item = PluginItem(label="A", command="cmd", target="select")
        d = _item_to_dict(item)
        assert d["target"] == "select"

    def test_target_omitted_when_none(self):
        from ai_guardian.daemon.tray_plugins import _item_to_dict
        item = PluginItem(label="A", command="cmd", target=None)
        d = _item_to_dict(item)
        assert "target" not in d

    def test_target_roundtrip(self):
        original = [Plugin(
            name="T",
            items=[PluginItem(label="A", command="cmd", target="all")]
        )]
        data = plugins_to_dict(original)
        restored = dict_to_plugins(data)
        assert restored[0].items[0].target == "all"

    def test_container_name_in_target_vars(self):
        from ai_guardian.daemon.discovery import DaemonTarget
        t = DaemonTarget(
            name="my-project", runtime="container",
            container_name="sandbox-1",
        )
        result = substitute_target_vars("check {container_name}", t)
        assert "sandbox-1" in result
