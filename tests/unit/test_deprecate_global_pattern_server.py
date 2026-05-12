"""
Test for Issue #530: Deprecate legacy secret_scanning.pattern_server

Verifies:
- Deprecation warning logged when secret_scanning.pattern_server is present
- Doctor check_global_pattern_server() returns WARN for global, PASS for per-engine only
- Migration Stage 2: secret_scanning.pattern_server → first gitleaks engine in engines[]
- Edge cases: string engines, no gitleaks engine, existing per-engine, idempotency
"""

import json
import logging

import pytest

from ai_guardian.doctor import CheckStatus, Doctor
from ai_guardian.setup import IDESetup


# --- Deprecation warning tests ---


class TestDeprecationWarning:
    """Verify deprecation warning is logged for secret_scanning.pattern_server."""

    def test_warning_logged_for_global_pattern_server(self, _isolate_config_dir, caplog):
        config = {
            "secret_scanning": {
                "pattern_server": {
                    "url": "https://example.com/patterns",
                    "patterns_endpoint": "/patterns/gitleaks/8.18.1"
                }
            }
        }
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps(config))

        from ai_guardian import _load_pattern_server_config
        with caplog.at_level(logging.WARNING):
            result = _load_pattern_server_config()

        assert result is not None
        assert result["url"] == "https://example.com/patterns"
        assert any("DEPRECATED" in r.message and "per-engine" in r.message
                    for r in caplog.records)

    def test_no_warning_for_per_engine_only(self, _isolate_config_dir):
        config = {
            "secret_scanning": {
                "engines": [
                    {"type": "gitleaks", "pattern_server": {"url": "https://example.com"}}
                ]
            }
        }
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps(config))

        from ai_guardian import _load_pattern_server_config
        result = _load_pattern_server_config()
        assert result is None

    def test_root_level_still_works(self, _isolate_config_dir):
        config = {
            "pattern_server": {
                "url": "https://example.com/patterns"
            }
        }
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps(config))

        from ai_guardian import _load_pattern_server_config
        result = _load_pattern_server_config()
        assert result is not None
        assert result["url"] == "https://example.com/patterns"


# --- Doctor check tests ---


class TestDoctorGlobalPatternServer:

    def test_warns_for_global_pattern_server(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"}
            }
        }))
        doctor = Doctor()
        result = doctor.check_global_pattern_server()
        assert result.status == CheckStatus.WARN
        assert "Deprecated" in result.message
        assert result.fixable is True

    def test_pass_for_per_engine_only(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {
                "engines": [
                    {"type": "gitleaks", "pattern_server": {"url": "https://example.com"}}
                ]
            }
        }))
        doctor = Doctor()
        result = doctor.check_global_pattern_server()
        assert result.status == CheckStatus.PASS

    def test_pass_for_no_pattern_server(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {"enabled": True}
        }))
        doctor = Doctor()
        result = doctor.check_global_pattern_server()
        assert result.status == CheckStatus.PASS

    def test_pass_for_null_pattern_server(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {"pattern_server": None}
        }))
        doctor = Doctor()
        result = doctor.check_global_pattern_server()
        assert result.status == CheckStatus.PASS

    def test_no_config(self, _isolate_config_dir):
        doctor = Doctor()
        result = doctor.check_global_pattern_server()
        assert result.status == CheckStatus.PASS


# --- Doctor _get_ps_config priority tests ---


class TestDoctorGetPsConfig:

    def test_per_engine_takes_priority(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {
                "pattern_server": {"url": "https://global.example.com"},
                "engines": [
                    {"type": "gitleaks", "pattern_server": {"url": "https://engine.example.com"}}
                ]
            }
        }))
        doctor = Doctor()
        ps = doctor._get_ps_config()
        assert ps is not None
        assert ps["url"] == "https://engine.example.com"

    def test_falls_back_to_global(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {
                "pattern_server": {"url": "https://global.example.com"},
                "engines": ["gitleaks"]
            }
        }))
        doctor = Doctor()
        ps = doctor._get_ps_config()
        assert ps is not None
        assert ps["url"] == "https://global.example.com"

    def test_falls_back_to_root(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "pattern_server": {"url": "https://root.example.com"}
        }))
        doctor = Doctor()
        ps = doctor._get_ps_config()
        assert ps is not None
        assert ps["url"] == "https://root.example.com"

    def test_none_when_no_ps(self, _isolate_config_dir):
        config_path = _isolate_config_dir / "ai-guardian.json"
        config_path.write_text(json.dumps({
            "secret_scanning": {"enabled": True}
        }))
        doctor = Doctor()
        ps = doctor._get_ps_config()
        assert ps is None


# --- Migration Stage 2 tests ---


class TestMigrationStage2:
    """Test migrate_pattern_server_config() Stage 2: global → per-engine."""

    def setup_method(self):
        self.ide_setup = IDESetup()

    def test_global_to_first_gitleaks_string_engine(self):
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com", "patterns_endpoint": "/p"},
                "engines": ["gitleaks", "betterleaks"]
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is True
        assert "pattern_server" not in result["secret_scanning"]
        engine = result["secret_scanning"]["engines"][0]
        assert isinstance(engine, dict)
        assert engine["type"] == "gitleaks"
        assert engine["pattern_server"]["url"] == "https://example.com"
        assert result["secret_scanning"]["engines"][1] == "betterleaks"

    def test_global_to_existing_gitleaks_dict_engine(self):
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"},
                "engines": [
                    {"type": "gitleaks", "extra_flags": ["--verbose"]},
                    "betterleaks"
                ]
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is True
        engine = result["secret_scanning"]["engines"][0]
        assert engine["pattern_server"]["url"] == "https://example.com"
        assert engine["extra_flags"] == ["--verbose"]

    def test_preserves_existing_per_engine(self):
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://global.example.com"},
                "engines": [
                    {
                        "type": "gitleaks",
                        "pattern_server": {"url": "https://per-engine.example.com"}
                    }
                ]
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is True
        assert "pattern_server" not in result["secret_scanning"]
        engine = result["secret_scanning"]["engines"][0]
        assert engine["pattern_server"]["url"] == "https://per-engine.example.com"

    def test_no_gitleaks_engine_inserts_one(self):
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"},
                "engines": ["betterleaks", "leaktk"]
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is True
        assert len(result["secret_scanning"]["engines"]) == 3
        engine = result["secret_scanning"]["engines"][0]
        assert engine["type"] == "gitleaks"
        assert engine["pattern_server"]["url"] == "https://example.com"

    def test_full_chain_root_to_per_engine(self):
        config = {
            "pattern_server": {"url": "https://example.com"},
            "secret_scanning": {
                "engines": ["gitleaks"]
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is True
        assert "pattern_server" not in result
        assert "pattern_server" not in result["secret_scanning"]
        engine = result["secret_scanning"]["engines"][0]
        assert isinstance(engine, dict)
        assert engine["pattern_server"]["url"] == "https://example.com"

    def test_null_global_pattern_server(self):
        config = {
            "secret_scanning": {
                "pattern_server": None,
                "engines": ["gitleaks"]
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is True
        assert "pattern_server" not in result["secret_scanning"]
        assert result["secret_scanning"]["engines"] == ["gitleaks"]

    def test_no_migration_needed(self):
        config = {
            "secret_scanning": {
                "engines": [
                    {"type": "gitleaks", "pattern_server": {"url": "https://example.com"}}
                ]
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is False

    def test_idempotent(self):
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"},
                "engines": ["gitleaks"]
            }
        }
        _, result1 = self.ide_setup.migrate_pattern_server_config(config)
        migrated2, result2 = self.ide_setup.migrate_pattern_server_config(result1)
        assert migrated2 is False
        assert result1 == result2

    def test_default_engines_when_missing(self):
        config = {
            "secret_scanning": {
                "pattern_server": {"url": "https://example.com"}
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is True
        engine = result["secret_scanning"]["engines"][0]
        assert engine["type"] == "gitleaks"
        assert engine["pattern_server"]["url"] == "https://example.com"

    def test_root_and_global_both_present(self):
        """Root + secret_scanning.pattern_server → root discarded, global wins."""
        config = {
            "pattern_server": {"url": "https://root.example.com"},
            "secret_scanning": {
                "pattern_server": {"url": "https://global.example.com"},
                "engines": ["gitleaks"]
            }
        }
        migrated, result = self.ide_setup.migrate_pattern_server_config(config)
        assert migrated is True
        assert "pattern_server" not in result
        assert "pattern_server" not in result["secret_scanning"]
        engine = result["secret_scanning"]["engines"][0]
        assert engine["pattern_server"]["url"] == "https://global.example.com"
