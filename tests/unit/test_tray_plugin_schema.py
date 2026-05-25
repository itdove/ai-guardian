"""Tests for the tray plugin JSON schema."""

import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "src" / "ai_guardian" / "schemas" / "tray-plugin.schema.json"
)


@pytest.fixture
def schema():
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _validate(instance, schema):
    jsonschema.validate(instance, schema)


class TestValidPlugins:
    def test_minimal_plugin(self, schema):
        _validate({
            "name": "My Plugin",
            "items": [{"label": "Hello", "command": "echo hello"}],
        }, schema)

    def test_all_fields(self, schema):
        _validate({
            "name": "Full Plugin",
            "items": [
                {
                    "label": "Action",
                    "command": "echo {tray.name}",
                    "type": "notification",
                    "run_on_target": True,
                    "params": [
                        {
                            "name": "name",
                            "hint": "Your name",
                            "default": "World",
                            "options": ["Alice", "Bob"],
                        }
                    ],
                }
            ],
        }, schema)

    def test_platform_map_command(self, schema):
        _validate({
            "name": "Cross-Platform",
            "items": [
                {
                    "label": "Open",
                    "command": {
                        "darwin": "open .",
                        "linux": "xdg-open .",
                        "windows": "explorer .",
                        "default": "echo unsupported",
                    },
                }
            ],
        }, schema)

    def test_platform_map_single_key(self, schema):
        _validate({
            "name": "Mac Only",
            "items": [
                {"label": "Say", "command": {"darwin": "say hello"}},
            ],
        }, schema)

    def test_multiple_items(self, schema):
        _validate({
            "name": "Multi",
            "items": [
                {"label": "A", "command": "cmd-a"},
                {"label": "B", "command": "cmd-b", "type": "background"},
                {"label": "C", "command": "cmd-c", "type": "clipboard"},
            ],
        }, schema)

    def test_all_execution_types(self, schema):
        for exec_type in ("terminal", "background", "notification", "clipboard", "modal"):
            _validate({
                "name": "Types",
                "items": [{"label": "X", "command": "cmd", "type": exec_type}],
            }, schema)

    def test_param_minimal(self, schema):
        _validate({
            "name": "P",
            "items": [
                {
                    "label": "X",
                    "command": "echo {tray.val}",
                    "params": [{"name": "val"}],
                }
            ],
        }, schema)

    def test_schema_ref_allowed(self, schema):
        _validate({
            "$schema": "https://raw.githubusercontent.com/itdove/ai-guardian/main/src/ai_guardian/schemas/tray-plugin.schema.json",
            "name": "With Schema Ref",
            "items": [{"label": "X", "command": "echo ok"}],
        }, schema)


class TestInvalidPlugins:
    def test_missing_name(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({"items": [{"label": "X", "command": "cmd"}]}, schema)

    def test_empty_name(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "",
                "items": [{"label": "X", "command": "cmd"}],
            }, schema)

    def test_missing_items(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({"name": "NoItems"}, schema)

    def test_empty_items(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({"name": "Empty", "items": []}, schema)

    def test_too_many_items(self, schema):
        items = [{"label": f"Item{i}", "command": f"cmd{i}"} for i in range(13)]
        with pytest.raises(jsonschema.ValidationError):
            _validate({"name": "TooMany", "items": items}, schema)

    def test_missing_label(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [{"command": "cmd"}],
            }, schema)

    def test_missing_command(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [{"label": "X"}],
            }, schema)

    def test_invalid_type(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [{"label": "X", "command": "cmd", "type": "invalid"}],
            }, schema)

    def test_empty_platform_map(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [{"label": "X", "command": {}}],
            }, schema)

    def test_unknown_platform_key(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [{"label": "X", "command": {"freebsd": "cmd"}}],
            }, schema)

    def test_extra_property_on_root(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [{"label": "X", "command": "cmd"}],
                "unknown_field": True,
            }, schema)

    def test_extra_property_on_item(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [{"label": "X", "command": "cmd", "typo": True}],
            }, schema)

    def test_missing_param_name(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [
                    {
                        "label": "X",
                        "command": "cmd",
                        "params": [{"hint": "no name"}],
                    }
                ],
            }, schema)

    def test_extra_property_on_param(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [
                    {
                        "label": "X",
                        "command": "cmd",
                        "params": [{"name": "x", "extra": True}],
                    }
                ],
            }, schema)

    def test_name_not_string(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": 123,
                "items": [{"label": "X", "command": "cmd"}],
            }, schema)

    def test_command_not_string_or_object(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [{"label": "X", "command": 42}],
            }, schema)

    def test_run_on_target_not_boolean(self, schema):
        with pytest.raises(jsonschema.ValidationError):
            _validate({
                "name": "P",
                "items": [
                    {"label": "X", "command": "cmd", "run_on_target": "yes"},
                ],
            }, schema)
