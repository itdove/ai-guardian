"""
Tests for project-level ai-guardian.json config overlay (Issue #594).

Tests cover:
- deep_merge() function: basic merge, list concat, immutable fields, global-only sections
- get_project_config_path(): discovery logic, env var, git root, CWD
- _load_config_file(): dual-config merge, cache invalidation, backward compat
- Self-protection: agent cannot read project-level config
"""

import json
import logging
import os
import tempfile
from pathlib import Path
from unittest import mock


from ai_guardian.config_utils import (
    GLOBAL_ONLY_SECTIONS,
    deep_merge,
    get_project_config_path,
    _clear_project_config_cache,
    _find_config_in_dir,
    _get_immutable_info,
    _is_tightening,
    set_project_dir_override,
    clear_project_dir_override,
)
from ai_guardian.config_loaders import (
    _clear_config_cache,
    _load_config_file,
    _normalize_permissions,
)


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
        override = {
            "daemon": {"host": "remote"},
            "prompt_injection": {"enabled": False},
        }
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
            "__init__",
            "__main__",
            "__all__",
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
        section_locked, locked_fields, tighten_only = _get_immutable_info(
            {"immutable": True}
        )
        assert section_locked is True
        assert locked_fields is None
        assert tighten_only is False

    def test_array_locks_fields(self):
        section_locked, locked_fields, tighten_only = _get_immutable_info(
            {"immutable": ["enabled", "action"]}
        )
        assert section_locked is False
        assert locked_fields == ["enabled", "action"]
        assert tighten_only is False

    def test_false_no_lock(self):
        section_locked, locked_fields, tighten_only = _get_immutable_info(
            {"immutable": False}
        )
        assert section_locked is False
        assert locked_fields is None
        assert tighten_only is False

    def test_absent_no_lock(self):
        section_locked, locked_fields, tighten_only = _get_immutable_info(
            {"enabled": True}
        )
        assert section_locked is False
        assert locked_fields is None
        assert tighten_only is False

    def test_non_dict_no_lock(self):
        section_locked, locked_fields, tighten_only = _get_immutable_info("not a dict")
        assert section_locked is False
        assert locked_fields is None
        assert tighten_only is False

    def test_tighten_only(self):
        section_locked, locked_fields, tighten_only = _get_immutable_info(
            {"immutable": "tighten-only"}
        )
        assert section_locked is False
        assert locked_fields is None
        assert tighten_only is True


class TestGetProjectConfigPath:
    def setup_method(self):
        _clear_project_config_cache()

    def test_returns_none_when_no_config(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(
                os.environ,
                {
                    "AI_GUARDIAN_PROJECT_CONFIG": str(Path(td) / "nonexistent.json"),
                },
            ):
                _clear_project_config_cache()
                result = get_project_config_path()
                assert result is None

    def test_env_var_override(self):
        with tempfile.TemporaryDirectory() as td:
            config_path = Path(td) / "custom-config.json"
            config_path.write_text("{}")
            with mock.patch.dict(
                os.environ,
                {
                    "AI_GUARDIAN_PROJECT_CONFIG": str(config_path),
                },
            ):
                _clear_project_config_cache()
                result = get_project_config_path()
                assert result == config_path

    def test_caches_result(self):
        with tempfile.TemporaryDirectory() as td:
            config_path = Path(td) / "custom-config.json"
            config_path.write_text("{}")
            with mock.patch.dict(
                os.environ,
                {
                    "AI_GUARDIAN_PROJECT_CONFIG": str(config_path),
                },
            ):
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

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
            },
        ):
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

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
            },
        ):
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

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
            },
        ):
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

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
            },
        ):
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
        from ai_guardian.tool_patterns import IMMUTABLE_DENY_PATTERNS

        read_patterns = IMMUTABLE_DENY_PATTERNS.get("Read", [])
        assert any(
            "ai-guardian.json" in p for p in read_patterns
        ), "IMMUTABLE_DENY_PATTERNS must block reading *ai-guardian.json"

    def test_project_config_blocked_for_write(self):
        from ai_guardian.tool_patterns import IMMUTABLE_DENY_PATTERNS

        write_patterns = IMMUTABLE_DENY_PATTERNS.get("Write", [])
        assert any("ai-guardian.json" in p for p in write_patterns)

    def test_project_config_blocked_for_edit(self):
        from ai_guardian.tool_patterns import IMMUTABLE_DENY_PATTERNS

        edit_patterns = IMMUTABLE_DENY_PATTERNS.get("Edit", [])
        assert any("ai-guardian.json" in p for p in edit_patterns)

    def test_read_blocked_via_policy_checker(self, _isolate_config_dir, tmp_path):
        """ToolPolicyChecker blocks Read of project ai-guardian.json."""
        from ai_guardian.tool_policy import ToolPolicyChecker

        project_config = tmp_path / "ai-guardian.json"
        project_config.write_text("{}")

        checker = ToolPolicyChecker(
            config={"permissions": {"enabled": True, "rules": []}}
        )
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
        expected = {
            "daemon",
            "mcp_server",
            "support",
            "security_instructions",
            "on_scan_error",
            "remote_configs",
        }
        assert GLOBAL_ONLY_SECTIONS == expected

    def test_is_frozenset(self):
        assert isinstance(GLOBAL_ONLY_SECTIONS, frozenset)


class TestFindConfigInDir:
    """Tests for _find_config_in_dir helper."""

    def test_finds_new_location(self, tmp_path):
        config_dir = tmp_path / ".ai-guardian"
        config_dir.mkdir()
        config_file = config_dir / "ai-guardian.json"
        config_file.write_text("{}")
        assert _find_config_in_dir(tmp_path) == config_file

    def test_finds_legacy_location(self, tmp_path):
        legacy = tmp_path / "ai-guardian.json"
        legacy.write_text("{}")
        assert _find_config_in_dir(tmp_path) == legacy

    def test_prefers_new_over_legacy(self, tmp_path):
        config_dir = tmp_path / ".ai-guardian"
        config_dir.mkdir()
        new_file = config_dir / "ai-guardian.json"
        new_file.write_text("{}")
        (tmp_path / "ai-guardian.json").write_text("{}")
        assert _find_config_in_dir(tmp_path) == new_file

    def test_returns_none_when_empty(self, tmp_path):
        assert _find_config_in_dir(tmp_path) is None


class TestThreadLocalOverride:
    """Tests for thread-local project directory override (daemon use)."""

    def test_override_used_for_discovery(self, tmp_path, _isolate_config_dir):
        project_dir = tmp_path / "my_project"
        project_dir.mkdir()
        config_dir = project_dir / ".ai-guardian"
        config_dir.mkdir()
        config_file = config_dir / "ai-guardian.json"
        config_file.write_text(json.dumps({"test": True}))

        _clear_project_config_cache()
        _clear_config_cache()

        set_project_dir_override(str(project_dir))
        try:
            result = get_project_config_path()
            assert result is not None
            assert result == config_file
        finally:
            clear_project_dir_override()

    def test_override_cleared_restores_normal(self, tmp_path, _isolate_config_dir):
        project_dir = tmp_path / "my_project"
        project_dir.mkdir()
        config_dir = project_dir / ".ai-guardian"
        config_dir.mkdir()
        (config_dir / "ai-guardian.json").write_text("{}")

        set_project_dir_override(str(project_dir))
        result_with = get_project_config_path()
        assert result_with is not None

        clear_project_dir_override()
        _clear_project_config_cache()
        result_without = get_project_config_path()
        assert result_without != result_with or result_without is None

    def test_override_bypasses_cache(self, tmp_path, _isolate_config_dir):
        """Each call with override active re-discovers (no stale cache)."""
        project_a = tmp_path / "project_a"
        project_a.mkdir()
        config_a = project_a / ".ai-guardian"
        config_a.mkdir()
        (config_a / "ai-guardian.json").write_text(json.dumps({"project": "a"}))

        project_b = tmp_path / "project_b"
        project_b.mkdir()
        config_b = project_b / ".ai-guardian"
        config_b.mkdir()
        (config_b / "ai-guardian.json").write_text(json.dumps({"project": "b"}))

        try:
            set_project_dir_override(str(project_a))
            result_a = get_project_config_path()
            assert "project_a" in str(result_a)

            set_project_dir_override(str(project_b))
            result_b = get_project_config_path()
            assert "project_b" in str(result_b)
        finally:
            clear_project_dir_override()

    def test_override_with_no_config_returns_none(self, tmp_path, _isolate_config_dir):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        set_project_dir_override(str(empty_dir))
        try:
            result = get_project_config_path()
            assert result is None
        finally:
            clear_project_dir_override()


class TestNormalizePermissions:
    """Tests for _normalize_permissions() — Issue #724."""

    def test_list_format_normalized_to_dict(self):
        config = {
            "permissions": [
                {"matcher": "Skill", "mode": "allow", "patterns": ["*"]},
            ]
        }
        result = _normalize_permissions(config)
        assert isinstance(result["permissions"], dict)
        assert result["permissions"]["enabled"] is True
        assert result["permissions"]["rules"] == config["permissions"]

    def test_dict_format_unchanged(self):
        config = {
            "permissions": {
                "enabled": True,
                "rules": [{"matcher": "Skill", "mode": "deny"}],
            }
        }
        result = _normalize_permissions(config)
        assert result["permissions"] == config["permissions"]

    def test_none_config_passes_through(self):
        assert _normalize_permissions(None) is None

    def test_missing_permissions_key_unchanged(self):
        config = {"secret_scanning": {"enabled": True}}
        result = _normalize_permissions(config)
        assert "permissions" not in result

    def test_does_not_mutate_input(self):
        original_list = [{"matcher": "Skill", "mode": "allow"}]
        config = {"permissions": original_list}
        _normalize_permissions(config)
        assert config["permissions"] is original_list

    def test_deprecation_warning_logged(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            _normalize_permissions(
                {"permissions": [{"matcher": "Skill", "mode": "allow"}]}
            )
        assert "DEPRECATED" in caplog.text
        assert "array format" in caplog.text

    def test_no_warning_for_dict_format(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            _normalize_permissions({"permissions": {"enabled": True, "rules": []}})
        assert "DEPRECATED" not in caplog.text


class TestPermissionsMergeFormats:
    """Integration tests for merging permissions across formats — Issue #724."""

    def test_list_global_dict_project_preserves_both(
        self, _isolate_config_dir, tmp_path
    ):
        """User-level (old list) + project-level (new dict) merges both rule sets."""
        global_config = {
            "permissions": [
                {
                    "matcher": "mcp__*",
                    "mode": "allow",
                    "patterns": ["mcp__allowlist__*"],
                },
                {"matcher": "Skill", "mode": "allow", "patterns": ["*"]},
            ]
        }
        project_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "Skill", "mode": "deny", "action": "warn"},
                ],
            }
        }

        global_path = _isolate_config_dir / "ai-guardian.json"
        global_path.write_text(json.dumps(global_config))

        project_path = tmp_path / "project_config.json"
        project_path.write_text(json.dumps(project_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
            },
        ):
            _clear_config_cache()
            config, error = _load_config_file()
            assert error is None
            assert isinstance(config["permissions"], dict)
            assert config["permissions"]["enabled"] is True
            assert len(config["permissions"]["rules"]) == 3

    def test_dict_global_list_project_preserves_both(
        self, _isolate_config_dir, tmp_path
    ):
        """User-level (new dict) + project-level (old list) merges both rule sets."""
        global_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {"matcher": "mcp__*", "mode": "allow"},
                ],
            }
        }
        project_config = {
            "permissions": [
                {"matcher": "Skill", "mode": "deny"},
            ]
        }

        global_path = _isolate_config_dir / "ai-guardian.json"
        global_path.write_text(json.dumps(global_config))

        project_path = tmp_path / "project_config.json"
        project_path.write_text(json.dumps(project_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
            },
        ):
            _clear_config_cache()
            config, error = _load_config_file()
            assert error is None
            assert isinstance(config["permissions"], dict)
            assert config["permissions"]["enabled"] is True
            assert len(config["permissions"]["rules"]) == 2

    def test_both_list_format_merges_correctly(self, _isolate_config_dir, tmp_path):
        """Both configs using old list format still merge correctly."""
        global_config = {
            "permissions": [
                {"matcher": "mcp__*", "mode": "allow"},
            ]
        }
        project_config = {
            "permissions": [
                {"matcher": "Skill", "mode": "deny"},
            ]
        }

        global_path = _isolate_config_dir / "ai-guardian.json"
        global_path.write_text(json.dumps(global_config))

        project_path = tmp_path / "project_config.json"
        project_path.write_text(json.dumps(project_config))

        with mock.patch.dict(
            os.environ,
            {
                "AI_GUARDIAN_PROJECT_CONFIG": str(project_path),
            },
        ):
            _clear_config_cache()
            config, error = _load_config_file()
            assert error is None
            assert isinstance(config["permissions"], dict)
            assert len(config["permissions"]["rules"]) == 2

    def test_single_config_list_format_normalized(self, _isolate_config_dir):
        """Single config with old list format is still normalized."""
        config_data = {
            "permissions": [
                {"matcher": "Skill", "mode": "allow"},
            ]
        }

        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps(config_data))

        _clear_config_cache()
        config, error = _load_config_file()
        assert error is None
        assert isinstance(config["permissions"], dict)
        assert config["permissions"]["enabled"] is True
        assert len(config["permissions"]["rules"]) == 1


class TestIsTightening:
    """Tests for the _is_tightening() helper function."""

    def test_action_tighten_warn_to_block(self):
        assert _is_tightening("action", "warn", "block") is True

    def test_action_loosen_block_to_warn(self):
        assert _is_tightening("action", "block", "warn") is False

    def test_action_equal(self):
        assert _is_tightening("action", "block", "block") is True

    def test_action_tighten_allow_to_redact(self):
        assert _is_tightening("action", "allow", "redact") is True

    def test_action_loosen_redact_to_log_only(self):
        assert _is_tightening("action", "redact", "log-only") is False

    def test_action_unknown_values(self):
        assert _is_tightening("action", "block", "unknown") is False

    def test_sensitivity_increase(self):
        assert _is_tightening("sensitivity", "medium", "high") is True

    def test_sensitivity_decrease(self):
        assert _is_tightening("sensitivity", "high", "low") is False

    def test_sensitivity_equal(self):
        assert _is_tightening("sensitivity", "high", "high") is True

    def test_sensitivity_low_to_medium(self):
        assert _is_tightening("sensitivity", "low", "medium") is True

    def test_enabled_enable_is_tightening(self):
        assert _is_tightening("enabled", False, True) is True

    def test_enabled_disable_is_loosening(self):
        assert _is_tightening("enabled", True, False) is False

    def test_enabled_same_true(self):
        assert _is_tightening("enabled", True, True) is True

    def test_enabled_same_false(self):
        assert _is_tightening("enabled", False, False) is True

    def test_unknown_field_equal_ok(self):
        assert _is_tightening("detector", "heuristic", "heuristic") is True

    def test_unknown_field_change_blocked(self):
        assert _is_tightening("detector", "heuristic", "ml") is False


class TestTightenOnlyMerge:
    """Tests for tighten-only immutable mode in deep_merge()."""

    def test_action_tighten_allowed(self):
        """action: warn -> block is tightening, should be accepted."""
        base = {
            "secret_scanning": {
                "enabled": True,
                "action": "warn",
                "immutable": "tighten-only",
            }
        }
        override = {"secret_scanning": {"action": "block"}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["action"] == "block"

    def test_action_loosen_blocked(self):
        """action: block -> warn is loosening, should be rejected."""
        base = {
            "secret_scanning": {
                "enabled": True,
                "action": "block",
                "immutable": "tighten-only",
            }
        }
        override = {"secret_scanning": {"action": "warn"}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["action"] == "block"

    def test_action_equal_allowed(self):
        """Same action value should be accepted."""
        base = {
            "secret_scanning": {
                "action": "block",
                "immutable": "tighten-only",
            }
        }
        override = {"secret_scanning": {"action": "block"}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["action"] == "block"

    def test_enable_allowed(self):
        """enabled: false -> true is tightening (enabling scanning)."""
        base = {
            "secret_scanning": {
                "enabled": False,
                "immutable": "tighten-only",
            }
        }
        override = {"secret_scanning": {"enabled": True}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["enabled"] is True

    def test_disable_blocked(self):
        """enabled: true -> false is loosening (disabling scanning)."""
        base = {
            "secret_scanning": {
                "enabled": True,
                "immutable": "tighten-only",
            }
        }
        override = {"secret_scanning": {"enabled": False}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["enabled"] is True

    def test_sensitivity_increase_allowed(self):
        """sensitivity: medium -> high is tightening."""
        base = {
            "prompt_injection": {
                "sensitivity": "medium",
                "immutable": "tighten-only",
            }
        }
        override = {"prompt_injection": {"sensitivity": "high"}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["prompt_injection"]["sensitivity"] == "high"

    def test_sensitivity_decrease_blocked(self):
        """sensitivity: high -> low is loosening."""
        base = {
            "prompt_injection": {
                "sensitivity": "high",
                "immutable": "tighten-only",
            }
        }
        override = {"prompt_injection": {"sensitivity": "low"}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["prompt_injection"]["sensitivity"] == "high"

    def test_list_add_allowed(self):
        """Adding items to allowlist_patterns is allowed (superset)."""
        base = {
            "secret_scanning": {
                "allowlist_patterns": ["pattern1"],
                "immutable": "tighten-only",
            }
        }
        override = {
            "secret_scanning": {
                "allowlist_patterns": ["pattern1", "pattern2"],
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert "pattern1" in result["secret_scanning"]["allowlist_patterns"]
        assert "pattern2" in result["secret_scanning"]["allowlist_patterns"]

    def test_list_remove_blocked(self):
        """Removing items from allowlist_patterns is blocked."""
        base = {
            "secret_scanning": {
                "allowlist_patterns": ["pattern1", "pattern2"],
                "immutable": "tighten-only",
            }
        }
        override = {
            "secret_scanning": {
                "allowlist_patterns": ["pattern1"],
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert "pattern1" in result["secret_scanning"]["allowlist_patterns"]
        assert "pattern2" in result["secret_scanning"]["allowlist_patterns"]

    def test_list_add_new_items_only(self):
        """When removal blocked, new items from override are still added."""
        base = {
            "secret_scanning": {
                "ignore_files": ["*.key"],
                "immutable": "tighten-only",
            }
        }
        override = {
            "secret_scanning": {
                "ignore_files": ["*.pem"],
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert "*.key" in result["secret_scanning"]["ignore_files"]
        assert "*.pem" in result["secret_scanning"]["ignore_files"]

    def test_backward_compat_immutable_true(self):
        """immutable: true still locks entire section."""
        base = {
            "secret_scanning": {
                "enabled": True,
                "action": "block",
                "immutable": True,
            }
        }
        override = {"secret_scanning": {"action": "warn", "enabled": False}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["enabled"] is True
        assert result["secret_scanning"]["action"] == "block"

    def test_backward_compat_immutable_false(self):
        """immutable: false still allows full override."""
        base = {
            "secret_scanning": {
                "action": "block",
                "immutable": False,
            }
        }
        override = {"secret_scanning": {"action": "warn"}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["action"] == "warn"

    def test_backward_compat_immutable_list(self):
        """immutable: [fields] still locks listed fields only."""
        base = {
            "secret_scanning": {
                "enabled": True,
                "action": "block",
                "immutable": ["enabled"],
            }
        }
        override = {"secret_scanning": {"enabled": False, "action": "warn"}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["enabled"] is True
        assert result["secret_scanning"]["action"] == "warn"

    def test_warning_logged_when_loosening_blocked(self, caplog):
        """Verify warning is logged when override blocked."""
        base = {
            "secret_scanning": {
                "action": "block",
                "immutable": "tighten-only",
            }
        }
        override = {"secret_scanning": {"action": "warn"}}
        with caplog.at_level(logging.WARNING, logger="ai_guardian.config_utils"):
            result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["action"] == "block"
        assert any("cannot be loosened" in msg for msg in caplog.messages)

    def test_new_fields_added_in_tighten_only(self):
        """New fields not in base can be added even in tighten-only mode."""
        base = {
            "secret_scanning": {
                "enabled": True,
                "immutable": "tighten-only",
            }
        }
        override = {"secret_scanning": {"action": "block"}}
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["action"] == "block"

    def test_nested_dict_tighten_only_propagates(self):
        """Tighten-only mode applies to nested dicts within a tighten-only section."""
        base = {
            "prompt_injection": {
                "immutable": "tighten-only",
                "unicode_detection": {
                    "enabled": True,
                    "action": "warn",
                },
            }
        }
        override = {
            "prompt_injection": {
                "unicode_detection": {
                    "action": "block",
                },
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["prompt_injection"]["unicode_detection"]["action"] == "block"

    def test_nested_dict_tighten_only_blocks_loosening(self):
        """Tighten-only blocks loosening in nested dicts."""
        base = {
            "prompt_injection": {
                "immutable": "tighten-only",
                "unicode_detection": {
                    "enabled": True,
                    "action": "block",
                },
            }
        }
        override = {
            "prompt_injection": {
                "unicode_detection": {
                    "action": "warn",
                },
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["prompt_injection"]["unicode_detection"]["action"] == "block"

    def test_multiple_fields_tighten_only(self):
        """Multiple fields can be tightened in one override."""
        base = {
            "secret_scanning": {
                "enabled": False,
                "action": "warn",
                "sensitivity": "low",
                "immutable": "tighten-only",
            }
        }
        override = {
            "secret_scanning": {
                "enabled": True,
                "action": "block",
                "sensitivity": "high",
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["enabled"] is True
        assert result["secret_scanning"]["action"] == "block"
        assert result["secret_scanning"]["sensitivity"] == "high"

    def test_mixed_tighten_and_loosen_partial_applied(self):
        """When some fields tighten and some loosen, only tightening is applied."""
        base = {
            "secret_scanning": {
                "enabled": True,
                "action": "block",
                "sensitivity": "low",
                "immutable": "tighten-only",
            }
        }
        override = {
            "secret_scanning": {
                "enabled": False,
                "action": "warn",
                "sensitivity": "high",
            }
        }
        result = deep_merge(base, override, global_only_sections=frozenset())
        assert result["secret_scanning"]["enabled"] is True
        assert result["secret_scanning"]["action"] == "block"
        assert result["secret_scanning"]["sensitivity"] == "high"
