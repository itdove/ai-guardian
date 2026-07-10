"""Tests for _load_config_section deep-merge behavior (Issue #1121).

When a user partially overrides a config section, their values should be
merged with defaults — not replace them wholesale.
"""

from unittest.mock import patch


from ai_guardian.config.loaders import (
    _CONTEXT_POISONING_DEFAULTS,
    _IMAGE_SCANNING_DEFAULTS,
    _PII_DEFAULTS,
    _SUPPLY_CHAIN_DEFAULTS,
    _load_config_section,
)


def _mock_config_file(config_dict):
    return patch(
        "ai_guardian.config.loaders._load_config_file",
        return_value=(config_dict, None),
    )


class TestPartialOverrideMerge:
    """User provides a subset of keys — missing keys come from defaults."""

    def test_pii_partial_override_keeps_defaults(self):
        user_config = {"scan_pii": {"pii_types": ["ssn", "credit_card"]}}
        with _mock_config_file(user_config):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err is None
        assert section["pii_types"] == ["ssn", "credit_card"]
        assert section["enabled"] == _PII_DEFAULTS["enabled"]
        assert section["action"] == _PII_DEFAULTS["action"]
        assert section["ignore_files"] == _PII_DEFAULTS["ignore_files"]
        assert section["allowlist_patterns"] == _PII_DEFAULTS["allowlist_patterns"]
        assert section["pattern_server"] == _PII_DEFAULTS["pattern_server"]

    def test_image_scanning_partial_override(self):
        user_config = {
            "image_scanning": {"max_processing_ms": 3000, "qr_scanning": True}
        }
        with _mock_config_file(user_config):
            section, err = _load_config_section(
                "image_scanning", defaults=_IMAGE_SCANNING_DEFAULTS
            )
        assert err is None
        assert section["max_processing_ms"] == 3000
        assert section["qr_scanning"] is True
        assert section["enabled"] == _IMAGE_SCANNING_DEFAULTS["enabled"]
        assert section["action"] == _IMAGE_SCANNING_DEFAULTS["action"]
        assert section["scan_types"] == _IMAGE_SCANNING_DEFAULTS["scan_types"]
        assert (
            section["redaction_method"] == _IMAGE_SCANNING_DEFAULTS["redaction_method"]
        )

    def test_context_poisoning_partial_override(self):
        user_config = {"context_poisoning": {"sensitivity": "high"}}
        with _mock_config_file(user_config):
            section, err = _load_config_section(
                "context_poisoning", defaults=_CONTEXT_POISONING_DEFAULTS
            )
        assert err is None
        assert section["sensitivity"] == "high"
        assert section["enabled"] == _CONTEXT_POISONING_DEFAULTS["enabled"]
        assert section["action"] == _CONTEXT_POISONING_DEFAULTS["action"]

    def test_supply_chain_partial_override(self):
        user_config = {"supply_chain": {"scan_plugins": False}}
        with _mock_config_file(user_config):
            section, err = _load_config_section(
                "supply_chain", defaults=_SUPPLY_CHAIN_DEFAULTS
            )
        assert err is None
        assert section["scan_plugins"] is False
        assert section["enabled"] == _SUPPLY_CHAIN_DEFAULTS["enabled"]
        assert section["action"] == _SUPPLY_CHAIN_DEFAULTS["action"]
        assert section["scan_hooks"] == _SUPPLY_CHAIN_DEFAULTS["scan_hooks"]

    def test_transcript_scanning_partial_override(self):
        defaults = {"enabled": True}
        user_config = {"transcript_scanning": {"enabled": False}}
        with _mock_config_file(user_config):
            section, err = _load_config_section(
                "transcript_scanning", defaults=defaults
            )
        assert err is None
        assert section["enabled"] is False

    def test_annotations_partial_override(self):
        defaults = {"enabled": True}
        user_config = {"annotations": {"enabled": False}}
        with _mock_config_file(user_config):
            section, err = _load_config_section("annotations", defaults=defaults)
        assert err is None
        assert section["enabled"] is False


class TestFullOverride:
    """User provides all keys — all user values win."""

    def test_full_override_uses_all_user_values(self):
        user_pii = {
            "enabled": False,
            "pii_types": ["ssn"],
            "action": "warn",
            "ignore_files": ["test.py"],
            "ignore_tools": ["Read"],
            "allowlist_patterns": ["xxx"],
            "pattern_server": "http://example.com",
        }
        user_config = {"scan_pii": user_pii}
        with _mock_config_file(user_config):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err is None
        for key, val in user_pii.items():
            assert section[key] == val


class TestNoUserSection:
    """Config file exists but has no section key — full defaults returned."""

    def test_missing_section_returns_defaults(self):
        with _mock_config_file({}):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err is None
        assert section == _PII_DEFAULTS

    def test_empty_config_returns_defaults(self):
        with _mock_config_file({}):
            section, err = _load_config_section(
                "image_scanning", defaults=_IMAGE_SCANNING_DEFAULTS
            )
        assert err is None
        assert section == _IMAGE_SCANNING_DEFAULTS


class TestArrayReplacement:
    """Array fields should be replaced wholesale, not appended."""

    def test_pii_types_replaced_not_appended(self):
        user_config = {"scan_pii": {"pii_types": ["ssn"]}}
        with _mock_config_file(user_config):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err is None
        assert section["pii_types"] == ["ssn"]

    def test_scan_types_replaced_not_appended(self):
        user_config = {"image_scanning": {"scan_types": ["pii"]}}
        with _mock_config_file(user_config):
            section, err = _load_config_section(
                "image_scanning", defaults=_IMAGE_SCANNING_DEFAULTS
            )
        assert err is None
        assert section["scan_types"] == ["pii"]


class TestNonDictUserValue:
    """Edge case: user sets section to a non-dict value."""

    def test_false_value_returns_defaults(self):
        user_config = {"scan_pii": False}
        with _mock_config_file(user_config):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err is None
        assert section == _PII_DEFAULTS

    def test_string_value_returns_defaults(self):
        user_config = {"scan_pii": "disabled"}
        with _mock_config_file(user_config):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err is None
        assert section == _PII_DEFAULTS

    def test_none_value_returns_defaults(self):
        user_config = {"scan_pii": None}
        with _mock_config_file(user_config):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err is None
        assert section == _PII_DEFAULTS


class TestNoDefaults:
    """Sections without defaults should work as before."""

    def test_no_defaults_returns_user_section(self):
        user_config = {"secret_scanning": {"enabled": True, "action": "block"}}
        with _mock_config_file(user_config):
            section, err = _load_config_section("secret_scanning")
        assert err is None
        assert section == {"enabled": True, "action": "block"}

    def test_no_defaults_missing_section_returns_none(self):
        with _mock_config_file({}):
            section, err = _load_config_section("secret_scanning")
        assert err is None
        assert section is None


class TestConfigFileErrors:
    """Error and None config cases still work."""

    def test_config_error_returns_defaults(self):
        with patch(
            "ai_guardian.config.loaders._load_config_file",
            return_value=(None, "File not readable"),
        ):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err == "File not readable"
        assert section == _PII_DEFAULTS

    def test_no_config_file_returns_defaults(self):
        with patch(
            "ai_guardian.config.loaders._load_config_file",
            return_value=(None, None),
        ):
            section, err = _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert err is None
        assert section == _PII_DEFAULTS


class TestDefaultsNotMutated:
    """Verify that the original defaults dict is not modified."""

    def test_defaults_unchanged_after_merge(self):
        import copy

        original = copy.deepcopy(_PII_DEFAULTS)
        user_config = {"scan_pii": {"pii_types": ["ssn"], "action": "warn"}}
        with _mock_config_file(user_config):
            _load_config_section("scan_pii", defaults=_PII_DEFAULTS)
        assert _PII_DEFAULTS == original
