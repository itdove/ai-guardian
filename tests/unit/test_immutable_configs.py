"""
Unit tests for immutable config feature (Issue #67)

Tests the ability for remote configs to mark sections and matchers as immutable,
preventing local configs from overriding them.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase
from ai_guardian.tool_policy import ToolPolicyChecker


class ImmutableConfigTest(TestCase):
    """Test suite for immutable configuration enforcement"""

    # ========================================================================
    # Test: Per-Matcher Immutability
    # ========================================================================

    def test_immutable_matcher_blocks_local_override(self):
        """Remote config with immutable matcher blocks local rules for that matcher"""
        # Simulate remote config with immutable Skill matcher
        remote_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*", "gh-cli"],
                        "immutable": True
                    }
                ]
            }
        }

        # Simulate local config trying to add more Skill rules
        local_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["my-custom-skill"]
                    }
                ]
            }
        }

        # Create checker and merge configs
        checker = ToolPolicyChecker()

        # Extract immutability constraints
        immutable_matchers = checker._get_immutable_matchers([remote_config])
        assert "Skill" in immutable_matchers

        # Merge with immutability enforcement
        result = checker._merge_configs({}, local_config, immutable_matchers, set())
        result = checker._merge_configs(result, remote_config, set(), set())

        # Verify: local Skill rule should be filtered out
        skill_patterns = []
        permissions_obj = result.get("permissions", {})
        rules = permissions_obj.get("rules", []) if isinstance(permissions_obj, dict) else permissions_obj
        for rule in rules:
            if rule.get("matcher") == "Skill":
                skill_patterns.extend(rule.get("patterns", []))

        # Should only have remote patterns, not local ones
        assert "daf-*" in skill_patterns
        assert "gh-cli" in skill_patterns
        assert "my-custom-skill" not in skill_patterns

    def test_non_immutable_matcher_allows_local_rules(self):
        """Local configs can still add rules for non-immutable matchers"""
        # Remote config with immutable Skill matcher
        remote_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"],
                        "immutable": True
                    }
                ]
            }
        }

        # Local config adds MCP rules (not immutable)
        local_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "mcp__*",
                        "mode": "allow",
                        "patterns": ["mcp__notebooklm-mcp__*"]
                    }
                ]
            }
        }

        checker = ToolPolicyChecker()
        immutable_matchers = checker._get_immutable_matchers([remote_config])

        result = checker._merge_configs({}, local_config, immutable_matchers, set())
        result = checker._merge_configs(result, remote_config, set(), set())

        # Verify: MCP rule should be present (not immutable)
        mcp_found = False
        permissions_obj = result.get("permissions", {})
        rules = permissions_obj.get("rules", []) if isinstance(permissions_obj, dict) else permissions_obj
        for rule in rules:
            if rule.get("matcher") == "mcp__*":
                mcp_found = True
                assert "mcp__notebooklm-mcp__*" in rule.get("patterns", [])

        assert mcp_found

    def test_multiple_immutable_matchers(self):
        """Multiple matchers can be marked as immutable"""
        remote_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"],
                        "immutable": True
                    },
                    {
                        "matcher": "Bash",
                        "mode": "deny",
                        "patterns": ["*rm -rf*"],
                        "immutable": True
                    }
                ]
            }
        }

        local_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["custom-*"]
                    },
                    {
                        "matcher": "Bash",
                        "mode": "allow",
                        "patterns": ["*safe-command*"]
                    }
                ]
            }
        }

        checker = ToolPolicyChecker()
        immutable_matchers = checker._get_immutable_matchers([remote_config])

        assert "Skill" in immutable_matchers
        assert "Bash" in immutable_matchers

        result = checker._merge_configs({}, local_config, immutable_matchers, set())
        result = checker._merge_configs(result, remote_config, set(), set())

        # Both Skill and Bash local rules should be filtered out
        permissions_obj = result.get("permissions", {})
        rules = permissions_obj.get("rules", []) if isinstance(permissions_obj, dict) else permissions_obj
        for rule in rules:
            if rule.get("matcher") == "Skill":
                assert "custom-*" not in rule.get("patterns", [])
            if rule.get("matcher") == "Bash":
                assert "*safe-command*" not in rule.get("patterns", [])

    # ========================================================================
    # Test: Section Immutability
    # ========================================================================

    def test_immutable_section_blocks_local_override(self):
        """Remote config with immutable section blocks entire section from local override"""
        remote_config = {
            "prompt_injection": {
                "enabled": True,
                "sensitivity": "high",
                "detector": "heuristic",
                "immutable": True
            }
        }

        local_config = {
            "prompt_injection": {
                "enabled": False,
                "sensitivity": "low"
            }
        }

        checker = ToolPolicyChecker()
        immutable_sections = checker._get_immutable_sections([remote_config])

        assert "prompt_injection" in immutable_sections

        result = checker._merge_configs({}, local_config, set(), immutable_sections)
        result = checker._merge_configs(result, remote_config, set(), set())

        # Verify: remote settings should be present, local settings ignored
        assert result["prompt_injection"]["enabled"] is True
        assert result["prompt_injection"]["sensitivity"] == "high"

    def test_multiple_immutable_sections(self):
        """Multiple sections can be marked as immutable"""
        remote_config = {
            "prompt_injection": {
                "enabled": True,
                "sensitivity": "high",
                "immutable": True
            },
            "pattern_server": {
                "enabled": True,
                "url": "https://company.com/patterns",
                "immutable": True
            }
        }

        local_config = {
            "prompt_injection": {
                "enabled": False
            },
            "pattern_server": {
                "enabled": False,
                "url": "https://local.com/patterns"
            }
        }

        checker = ToolPolicyChecker()
        immutable_sections = checker._get_immutable_sections([remote_config])

        assert "prompt_injection" in immutable_sections
        assert "pattern_server" in immutable_sections

        result = checker._merge_configs({}, local_config, set(), immutable_sections)
        result = checker._merge_configs(result, remote_config, set(), set())

        # Both sections should use remote settings
        assert result["prompt_injection"]["enabled"] is True
        assert result["pattern_server"]["url"] == "https://company.com/patterns"

    def test_non_immutable_section_allows_local_override(self):
        """Sections without immutable flag can be overridden locally"""
        remote_config = {
            "secret_scanning": {
                "enabled": True
                # No immutable flag
            }
        }

        local_config = {
            "secret_scanning": {
                "enabled": False
            }
        }

        checker = ToolPolicyChecker()
        immutable_sections = checker._get_immutable_sections([remote_config])

        assert "secret_scanning" not in immutable_sections

        result = checker._merge_configs({}, local_config, set(), immutable_sections)
        result = checker._merge_configs(result, remote_config, set(), set())

        # Without immutable flag, later config wins (remote in this case)
        # But the point is local config was not filtered out during merge
        assert "secret_scanning" in result

    # ========================================================================
    # Test: Backward Compatibility
    # ========================================================================

    def test_configs_without_immutable_field_work_unchanged(self):
        """Existing configs without immutable field work as before"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"]
                        # No immutable field
                    }
                ]
            }
        }

        checker = ToolPolicyChecker()
        immutable_matchers = checker._get_immutable_matchers([config])
        immutable_sections = checker._get_immutable_sections([config])

        # Should have no immutable constraints
        assert len(immutable_matchers) == 0
        assert len(immutable_sections) == 0

    def test_immutable_false_treated_as_non_immutable(self):
        """immutable: false is treated the same as missing field"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"],
                        "immutable": False
                    }
                ]
            },
            "prompt_injection": {
                "enabled": True,
                "immutable": False
            }
        }

        checker = ToolPolicyChecker()
        immutable_matchers = checker._get_immutable_matchers([config])
        immutable_sections = checker._get_immutable_sections([config])

        assert "Skill" not in immutable_matchers
        assert "prompt_injection" not in immutable_sections

    # ========================================================================
    # Test: Integration with Config Loading
    # ========================================================================

    def test_get_immutable_matchers_extracts_correct_matchers(self):
        """_get_immutable_matchers correctly identifies immutable matchers"""
        remote_configs = [
            {
                "permissions": {
                    "enabled": True,
                    "rules": [
                        {
                            "matcher": "Skill",
                            "mode": "allow",
                            "patterns": ["daf-*"],
                            "immutable": True
                        },
                        {
                            "matcher": "Bash",
                            "mode": "deny",
                            "patterns": ["*rm -rf*"],
                            "immutable": False
                        }
                    ]
                }
            }
        ]

        checker = ToolPolicyChecker()
        immutable_matchers = checker._get_immutable_matchers(remote_configs)

        assert "Skill" in immutable_matchers
        assert "Bash" not in immutable_matchers

    def test_get_immutable_sections_extracts_correct_sections(self):
        """_get_immutable_sections correctly identifies immutable sections"""
        remote_configs = [
            {
                "prompt_injection": {
                    "enabled": True,
                    "immutable": True
                },
                "pattern_server": {
                    "enabled": True,
                    "immutable": False
                },
                "secret_scanning": {
                    "enabled": True
                    # No immutable field
                }
            }
        ]

        checker = ToolPolicyChecker()
        immutable_sections = checker._get_immutable_sections(remote_configs)

        assert "prompt_injection" in immutable_sections
        assert "pattern_server" not in immutable_sections
        assert "secret_scanning" not in immutable_sections

    # ========================================================================
    # Test: Schema Validation
    # ========================================================================

    def test_immutable_field_validates_in_schema(self):
        """Configs with immutable field pass schema validation"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"],
                        "immutable": True
                    }
                ]
            },
            "prompt_injection": {
                "enabled": True,
                "immutable": True
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            temp_path = f.name

        try:
            checker = ToolPolicyChecker()
            loaded_config = checker._load_json_file(Path(temp_path), "test")

            # Should load successfully with immutable fields
            assert loaded_config is not None
            assert loaded_config["permissions"]["rules"][0]["immutable"] is True
            assert loaded_config["prompt_injection"]["immutable"] is True
        finally:
            Path(temp_path).unlink()

    def test_invalid_immutable_type_rejected(self):
        """Invalid immutable field type is rejected by schema"""
        config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*"],
                        "immutable": "yes"  # Invalid: should be boolean
                    }
                ]
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            temp_path = f.name

        try:
            checker = ToolPolicyChecker()
            loaded_config = checker._load_json_file(Path(temp_path), "test")

            # Should fail validation
            assert loaded_config is None
        finally:
            Path(temp_path).unlink()

    # ========================================================================
    # Test: Enterprise Use Cases
    # ========================================================================

    def test_enterprise_skill_allowlist_enforcement(self):
        """Enterprise can enforce skill allowlist that users cannot extend"""
        # Enterprise remote config
        enterprise_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["daf-*", "gh-cli"],
                        "immutable": True
                    }
                ]
            }
        }

        # User tries to add custom skill
        user_config = {
            "permissions": {
                "enabled": True,
                "rules": [
                    {
                        "matcher": "Skill",
                        "mode": "allow",
                        "patterns": ["my-custom-skill"]
                    }
                ]
            }
        }

        # Create checker with both configs
        checker = ToolPolicyChecker()
        immutable_matchers = checker._get_immutable_matchers([enterprise_config])

        # Merge user config first, then enterprise config
        result = checker._merge_configs({}, user_config, immutable_matchers, set())
        result = checker._merge_configs(result, enterprise_config, set(), set())

        # Test tool access
        hook_data_allowed = {
            "tool_use": {
                "name": "Skill",
                "input": {"skill": "daf-jira"}
            }
        }

        hook_data_blocked = {
            "tool_use": {
                "name": "Skill",
                "input": {"skill": "my-custom-skill"}
            }
        }

        checker_with_config = ToolPolicyChecker(config=result)

        # Enterprise-allowed skill should work
        is_allowed, error_msg, _ = checker_with_config.check_tool_allowed(hook_data_allowed)
        assert is_allowed

        # User-added skill should be blocked
        is_allowed, error_msg, _ = checker_with_config.check_tool_allowed(hook_data_blocked)
        assert not is_allowed

    def test_enterprise_prompt_injection_enforcement(self):
        """Enterprise can enforce prompt injection settings that cannot be weakened"""
        # Enterprise enforces high sensitivity
        enterprise_config = {
            "prompt_injection": {
                "enabled": True,
                "sensitivity": "high",
                "detector": "heuristic",
                "immutable": True
            }
        }

        # User tries to weaken it
        user_config = {
            "prompt_injection": {
                "enabled": False,
                "sensitivity": "low"
            }
        }

        checker = ToolPolicyChecker()
        immutable_sections = checker._get_immutable_sections([enterprise_config])

        # Merge
        result = checker._merge_configs({}, user_config, set(), immutable_sections)
        result = checker._merge_configs(result, enterprise_config, set(), set())

        # Enterprise settings should be enforced
        assert result["prompt_injection"]["enabled"] is True
        assert result["prompt_injection"]["sensitivity"] == "high"

    # ========================================================================
    # Test: Cascading Priority for Remote Config URLs (Issue #255)
    # ========================================================================

    def test_system_config_blocks_user_remote_urls(self):
        """System config prevents users from adding their own remote URLs"""
        import tempfile
        from unittest.mock import patch

        # Create temporary system config
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            system_config = {
                "urls": ["https://enterprise.com/policy.json"]
            }
            json.dump(system_config, f)
            system_config_path = f.name

        try:
            # User tries to add their own remote URL
            user_config = {
                "remote_configs": {
                    "urls": ["https://user.com/bypass.json"]
                }
            }

            checker = ToolPolicyChecker()

            # Mock remote fetching to track which URLs are fetched
            fetched_urls = []
            original_load = checker._load_remote_config

            def mock_load(url, base_path, token_env):
                fetched_urls.append(url)
                return None  # Return None to avoid actual fetching

            # Mock the system config path
            with patch.object(ToolPolicyChecker, '_get_system_config_path', return_value=Path(system_config_path)):
                with patch.object(checker, '_load_remote_config', side_effect=mock_load):
                    checker._load_remote_configs({}, None, user_config, None)

            # Only enterprise URL should be fetched
            assert "https://enterprise.com/policy.json" in fetched_urls
            assert "https://user.com/bypass.json" not in fetched_urls
        finally:
            Path(system_config_path).unlink()

    def test_cascading_priority_env_var_over_user_config(self):
        """Environment variable takes priority over user config"""
        from unittest.mock import patch

        # Set environment variable
        os.environ["AI_GUARDIAN_REMOTE_CONFIG_URLS"] = "https://env.com/policy.json"

        try:
            user_config = {
                "remote_configs": {
                    "urls": ["https://user.com/config.json"]
                }
            }

            checker = ToolPolicyChecker()

            # Mock to track URLs
            fetched_urls = []

            def mock_load(url, base_path, token_env):
                fetched_urls.append(url)
                return None

            with patch.object(checker, '_load_remote_config', side_effect=mock_load):
                # Mock no system config
                with patch.object(checker, '_get_system_config_path', return_value=None):
                    checker._load_remote_configs({}, None, user_config, None)

            # Only env var URL should be fetched
            assert "https://env.com/policy.json" in fetched_urls
            assert "https://user.com/config.json" not in fetched_urls
        finally:
            del os.environ["AI_GUARDIAN_REMOTE_CONFIG_URLS"]

    def test_user_remote_urls_work_without_system_config(self):
        """User remote URLs work when no system config exists"""
        from unittest.mock import patch

        user_config = {
            "remote_configs": {
                "urls": ["https://user.com/patterns.json"]
            }
        }

        checker = ToolPolicyChecker()

        # Mock to track URLs
        fetched_urls = []

        def mock_load(url, base_path, token_env):
            fetched_urls.append(url)
            return None

        with patch.object(checker, '_load_remote_config', side_effect=mock_load):
            # Mock no system config and no env var
            with patch.object(checker, '_get_system_config_path', return_value=None):
                checker._load_remote_configs({}, None, user_config, None)

        # User URL should be fetched
        assert "https://user.com/patterns.json" in fetched_urls

    def test_local_config_lowest_priority(self):
        """Local config has lowest priority - overridden by user config"""
        from unittest.mock import patch

        user_config = {
            "remote_configs": {
                "urls": ["https://user.com/user-config.json"]
            }
        }

        local_config = {
            "remote_configs": {
                "urls": ["https://local.com/local-config.json"]
            }
        }

        checker = ToolPolicyChecker()

        # Mock to track URLs
        fetched_urls = []

        def mock_load(url, base_path, token_env):
            fetched_urls.append(url)
            return None

        with patch.object(checker, '_load_remote_config', side_effect=mock_load):
            # Mock no system config and no env var
            with patch.object(checker, '_get_system_config_path', return_value=None):
                checker._load_remote_configs(local_config, None, user_config, None)

        # Only user config URL should be fetched
        assert "https://user.com/user-config.json" in fetched_urls
        assert "https://local.com/local-config.json" not in fetched_urls

    def test_legacy_format_still_works(self):
        """Old format (direct list) still works with cascading priority"""
        from unittest.mock import patch

        # Old format: direct list instead of dict with "urls" key
        user_config = {
            "remote_configs": ["https://user.com/old-format.json"]
        }

        checker = ToolPolicyChecker()

        # Mock to track URLs
        fetched_urls = []

        def mock_load(url, base_path, token_env):
            fetched_urls.append(url)
            return None

        with patch.object(checker, '_load_remote_config', side_effect=mock_load):
            # Mock no system config and no env var
            with patch.object(checker, '_get_system_config_path', return_value=None):
                checker._load_remote_configs({}, None, user_config, None)

        # Old format URL should be fetched
        assert "https://user.com/old-format.json" in fetched_urls
