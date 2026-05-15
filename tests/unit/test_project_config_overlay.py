"""
Tests for project-level ai-guardian.json config overlay (Issue #594).

Tests cover:
- deep_merge() function: basic merge, list concat, immutable fields, global-only sections
- get_project_config_path(): discovery logic, env var, git root, CWD
- _load_config_file(): dual-config merge, cache invalidation, backward compat
- Self-protection: agent cannot read project-level config
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from ai_guardian.config_utils import (
    GLOBAL_ONLY_SECTIONS,
    deep_merge,
    get_project_config_path,
    _clear_project_config_cache,
    _deep_merge_section,
    _get_immutable_info,
)
from ai_guardian.config_loaders import _clear_config_cache, _load_config_file


class TestDeepMerge:
    """Tests for the deep_merge() utility function."""

    def test_basic_scalar_override(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_dict_merge(self):
        base = {"section": {"a": 1, "b": 2}}
        override = {"section": {"b": 3, "c": 4}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result == {"section": {"a": 1, "b": 3, "c": 4}}

    def test_list_concatenation(self):
        base = {"items": [1, 2]}
        override = {"items": [3, 4]}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result == {"items": [1, 2, 3, 4]}

    def test_global_only_sections_skipped(self):
        base = {"daemon": {"host": "localhost"}, "prompt_injection": {"enabled": True}}
        override = {"daemon": {"host": "remote"}, "prompt_injection": {"enabled": False}}
        result = deep_merge(base, override)
        assert result["daemon"]["host"] == "localhost"
        assert result["prompt_injection"]["enabled"] is False

    def test_all_global_only_sections_filtered(self):
        base = {}
        override = {section: {"value": True} for section in GLOBAL_ONLY_SECTIONS}
        override["prompt_injection"] = {"enabled": False}
        result = deep_merge(base, override)
        for section in GLOBAL_ONLY_SECTIONS:
            assert section not in result
        assert result["prompt_injection"]["enabled"] is False

    def test_immutable_fields_enforced(self):
        base = {
            "secret_scanning": {
                "enabled": True,
                "immutable": ["enabled", "engines"],
                "engines": ["gitleaks"],
                "action": "block",
            }
        }
        override = {
            "secret_scanning": {
                "enabled": False,
                "engines": ["betterleaks"],
                "action": "warn",
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["enabled"] is True
        assert result["secret_scanning"]["engines"] == ["gitleaks"]
        assert result["secret_scanning"]["action"] == "warn"

    def test_immutable_true_locks_entire_section(self):
        base = {
            "secret_scanning": {
                "enabled": True,
                "immutable": True,
                "action": "block",
            }
        }
        override = {
            "secret_scanning": {
                "enabled": False,
                "action": "warn",
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["enabled"] is True
        assert result["secret_scanning"]["action"] == "block"

    def test_immutable_kept_in_result(self):
        base = {
            "secret_scanning": {
                "enabled": True,
                "immutable": ["enabled"],
            }
        }
        override = {}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["immutable"] == ["enabled"]

    def test_override_adds_new_sections(self):
        base = {"a": 1}
        override = {"b": 2}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result == {"a": 1, "b": 2}

    def test_does_not_mutate_inputs(self):
        base = {"section": {"a": 1}}
        override = {"section": {"b": 2}}
        base_copy = json.loads(json.dumps(base))
        override_copy = json.loads(json.dumps(override))
        deep_merge(base, override, global_only_sections=frozenset())
        assert base == base_copy
        assert override == override_copy

    def test_empty_base(self):
        result = deep_merge({}, {"a": 1}, global_only_sections=frozenset())
        assert result == {"a": 1}

    def test_empty_override(self):
        result = deep_merge({"a": 1}, {}, global_only_sections=frozenset())
        assert result == {"a": 1}

    def test_both_empty(self):
        result = deep_merge({}, {}, global_only_sections=frozenset())
        assert result == {}

    def test_comment_keys_skipped(self):
        base = {"a": 1}
        override = {"_comment": "test", "_comment2": "test2", "a": 2}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result == {"a": 2}
        assert "_comment" not in result

    def test_deeply_nested_merge(self):
        base = {"a": {"b": {"c": 1, "d": 2}}}
        override = {"a": {"b": {"d": 3, "e": 4}}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result == {"a": {"b": {"c": 1, "d": 3, "e": 4}}}

    def test_allowlist_patterns_concatenation(self):
        """Project can add to global allowlist_patterns."""
        base = {
            "prompt_injection": {
                "allowlist_patterns": ["__init__"],
            }
        }
        override = {
            "prompt_injection": {
                "allowlist_patterns": ["__main__", "__all__"],
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["prompt_injection"]["allowlist_patterns"] == [
            "__init__", "__main__", "__all__"
        ]

    def test_immutable_with_list_field(self):
        """Immutable prevents list concatenation for locked fields."""
        base = {
            "secret_scanning": {
                "immutable": ["ignore_files"],
                "ignore_files": ["*.key"],
            }
        }
        override = {
            "secret_scanning": {
                "ignore_files": ["*.pem"],
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["ignore_files"] == ["*.key"]


class TestGetImmutableInfo:
    def test_boolean_true_locks_section(self):
        section_locked, locked_fields = _get_immutable_info({"immutable": True})
        assert section_locked is True
        assert locked_fields is None

    def test_array_locks_fields(self):
        section_locked, locked_fields = _get_immutable_info({"immutable": ["enabled", "action"]})
        assert section_locked is False
        assert locked_fields == ["enabled", "action"]

    def test_false_no_lock(self):
        section_locked, locked_fields = _get_immutable_info({"immutable": False})
        assert section_locked is False
        assert locked_fields is None

    def test_absent_no_lock(self):
        section_locked, locked_fields = _get_immutable_info({"enabled": True})
        assert section_locked is False
        assert locked_fields is None

    def test_non_dict_no_lock(self):
        section_locked, locked_fields = _get_immutable_info("not a dict")
        assert section_locked is False
        assert locked_fields is None


class TestGetProjectConfigPath:
    def setup_method(self):
        _clear_project_config_cache()

    def test_returns_none_when_no_config(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {
                "AI_GUARDIAN_PROJECT_CONFIG": str(Path(td) / "nonexistent.json"),
            }):
                _clear_project_config_cache()
                result = get_project_config_path()
                assert result is None

    def test_env_var_override(self):
        with tempfile.TemporaryDirectory() as td:
            config_path = Path(td) / "custom-config.json"
            config_path.write_text("{}")
            with mock.patch.dict(os.environ, {
                "AI_GUARDIAN_PROJECT_CONFIG": str(config_path),
            }):
                _clear_project_config_cache()
                result = get_project_config_path()
                assert result == config_path

    def test_caches_result(self):
        with tempfile.TemporaryDirectory() as td:
            config_path = Path(td) / "custom-config.json"
            config_path.write_text("{}")
            with mock.patch.dict(os.environ, {
                "AI_GUARDIAN_PROJECT_CONFIG": str(config_path),
            }):
                _clear_project_config_cache()
                result1 = get_project_config_path()
                result2 = get_project_config_path()
                assert result1 == result2
                assert result1 == config_path


class TestLoadConfigFileMerge:
    """Tests for _load_config_file() with project config overlay."""

    def test_global_only_returns_global(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({"secret_scanning": {"enabled": True}}))
        _clear_config_cache()
        config, error = _load_config_file()
        assert error is None
        assert config["secret_scanning"]["enabled"] is True

    def test_project_overlay_merges(self, _isolate_config_dir, tmp_path):
        global_config = {"secret_scanning": {"enabled": True, "action": "block"}}
        project_config = {"secret_scanning": {"action": "warn"}}

        global_path = _isolate_config_dir / "ai-guardian.json"
        global_path.write_text(json.dumps(global_config))

        project_path = tmp_path / "project_config.json"
        project_path.write_text(json.dumps(project_config))

        with mock.patch.dict(os.environ, {
            "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
        }):
            _clear_config_cache()
            config, error = _load_config_file()
            assert error is None
            assert config["secret_scanning"]["enabled"] is True
            assert config["secret_scanning"]["action"] == "warn"

    def test_immutable_enforced_in_merge(self, _isolate_config_dir, tmp_path):
        global_config = {
            "secret_scanning": {
                "enabled": True,
                "immutable": ["enabled"],
                "action": "block",
            }
        }
        project_config = {
            "secret_scanning": {
                "enabled": False,
                "action": "warn",
            }
        }

        global_path = _isolate_config_dir / "ai-guardian.json"
        global_path.write_text(json.dumps(global_config))

        project_path = tmp_path / "project_config.json"
        project_path.write_text(json.dumps(project_config))

        with mock.patch.dict(os.environ, {
            "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
        }):
            _clear_config_cache()
            config, error = _load_config_file()
            assert error is None
            assert config["secret_scanning"]["enabled"] is True
            assert config["secret_scanning"]["action"] == "warn"
            assert config["secret_scanning"]["immutable"] == ["enabled"]

    def test_global_only_sections_not_overridden(self, _isolate_config_dir, tmp_path):
        global_config = {"daemon": {"host": "localhost"}}
        project_config = {"daemon": {"host": "remote"}}

        global_path = _isolate_config_dir / "ai-guardian.json"
        global_path.write_text(json.dumps(global_config))

        project_path = tmp_path / "project_config.json"
        project_path.write_text(json.dumps(project_config))

        with mock.patch.dict(os.environ, {
            "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
        }):
            _clear_config_cache()
            config, error = _load_config_file()
            assert error is None
            assert config["daemon"]["host"] == "localhost"

    def test_no_project_config_backward_compat(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({"prompt_injection": {"enabled": True}}))
        _clear_config_cache()
        config, error = _load_config_file()
        assert error is None
        assert config["prompt_injection"]["enabled"] is True

    def test_cache_invalidation_on_global_change(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({"prompt_injection": {"enabled": True}}))
        _clear_config_cache()

        config1, _ = _load_config_file()
        assert config1["prompt_injection"]["enabled"] is True

        import time
        time.sleep(0.05)
        config_path.write_text(json.dumps({"prompt_injection": {"enabled": False}}))

        config2, _ = _load_config_file()
        assert config2["prompt_injection"]["enabled"] is False

    def test_invalid_project_config_ignored(self, _isolate_config_dir, tmp_path):
        global_config = {"secret_scanning": {"enabled": True}}
        global_path = _isolate_config_dir / "ai-guardian.json"
        global_path.write_text(json.dumps(global_config))

        project_path = tmp_path / "bad_project.json"
        project_path.write_text("not valid json {{{")

        with mock.patch.dict(os.environ, {
            "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
        }):
            _clear_config_cache()
            config, error = _load_config_file()
            assert config is not None
            assert config["secret_scanning"]["enabled"] is True

    def test_empty_global_config(self, _isolate_config_dir):
        """Empty config {} should not return None."""
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({}))
        _clear_config_cache()
        config, error = _load_config_file()
        assert config is not None
        assert config == {}


class TestSelfProtection:
    """Verify the agent is blocked from reading project-level config."""

    def test_project_config_matches_immutable_pattern(self):
        from ai_guardian.tool_policy import IMMUTABLE_DENY_PATTERNS
        read_patterns = IMMUTABLE_DENY_PATTERNS.get("Read", [])
        assert any("ai-guardian.json" in p for p in read_patterns), (
            "IMMUTABLE_DENY_PATTERNS must block reading *ai-guardian.json"
        )

    def test_project_config_blocked_for_write(self):
        from ai_guardian.tool_policy import IMMUTABLE_DENY_PATTERNS
        write_patterns = IMMUTABLE_DENY_PATTERNS.get("Write", [])
        assert any("ai-guardian.json" in p for p in write_patterns)

    def test_project_config_blocked_for_edit(self):
        from ai_guardian.tool_policy import IMMUTABLE_DENY_PATTERNS
        edit_patterns = IMMUTABLE_DENY_PATTERNS.get("Edit", [])
        assert any("ai-guardian.json" in p for p in edit_patterns)

    def test_read_blocked_via_policy_checker(self, _isolate_config_dir, tmp_path):
        """ToolPolicyChecker blocks Read of project ai-guardian.json."""
        from ai_guardian.tool_policy import ToolPolicyChecker

        project_config = tmp_path / "ai-guardian.json"
        project_config.write_text("{}")

        checker = ToolPolicyChecker(config={
            "permissions": {"enabled": True, "rules": []}
        })
        hook_data = {
            "tool_name": "Read",
            "parameters": {"file_path": str(project_config)},
        }
        allowed, error_msg, _ = checker.check_tool_allowed(hook_data)
        assert not allowed
        assert error_msg is not None


class TestGlobalOnlySections:
    """Test that GLOBAL_ONLY_SECTIONS contains the expected entries."""

    def test_expected_sections(self):
        expected = {"daemon", "mcp_server", "support", "security_instructions",
                    "on_scan_error", "remote_configs"}
        assert GLOBAL_ONLY_SECTIONS == expected

    def test_is_frozenset(self):
        assert isinstance(GLOBAL_ONLY_SECTIONS, frozenset)
