"""
Test for Issue #519: Wire per-engine pattern_server config in scanning flow

Verifies that per-engine pattern_server overrides are respected during scanning:
- pattern_server: null → engine uses built-in rules (no --config flag)
- pattern_server: {url: ...} → engine fetches from per-engine pattern server
- No override (key absent) → engine uses global pattern server config
"""

import unittest
from unittest.mock import patch, MagicMock, call

from ai_guardian.scanners.engine_builder import (
    EngineConfig,
    ENGINE_PRESETS,
    PATTERN_SERVER_UNSET,
    _build_engine_config,
    resolve_engine_config_path,
    select_all_engines,
)
from ai_guardian.scanners.strategies import (
    FirstMatchStrategy,
    AnyMatchStrategy,
    ScanResult,
)


class TestPerEnginePatternServerInStrategy(unittest.TestCase):
    """Verify strategies resolve config_path per-engine."""

    def _mock_scanner(self, engine_config, source_file, report_file, config_path):
        """Mock scanner that records the config_path it received."""
        return ScanResult(
            has_secrets=False,
            secrets=[],
            engine=engine_config.type,
            scan_time_ms=10.0,
            error=None,
        )

    def test_first_match_resolves_per_engine(self):
        """FirstMatch strategy should resolve config_path per engine."""
        calls = []

        def tracking_scanner(engine_config, source_file, report_file, config_path):
            calls.append((engine_config.type, config_path))
            return ScanResult(
                has_secrets=False, secrets=[], engine=engine_config.type,
            )

        gitleaks = _build_engine_config("gitleaks")
        betterleaks = _build_engine_config({
            "type": "betterleaks",
            "pattern_server": None,
        })

        strategy = FirstMatchStrategy()
        strategy.execute(
            engine_configs=[gitleaks, betterleaks],
            scanner_fn=tracking_scanner,
            source_file="/tmp/src.txt",
            report_file_prefix="/tmp/report",
            config_path="/tmp/global.toml",
            context={"filename": "test.py"},
        )

        self.assertEqual(len(calls), 2)
        # gitleaks: UNSET → should use global (compatible engine)
        self.assertIn("global.toml", calls[0][1])
        # betterleaks: explicit null → should get None
        self.assertIsNone(calls[1][1])

    def test_any_match_resolves_per_engine(self):
        """AnyMatch strategy should resolve config_path per engine."""
        calls = []

        def tracking_scanner(engine_config, source_file, report_file, config_path):
            calls.append((engine_config.type, config_path))
            return ScanResult(
                has_secrets=False, secrets=[], engine=engine_config.type,
            )

        gitleaks = _build_engine_config("gitleaks")
        betterleaks = _build_engine_config({
            "type": "betterleaks",
            "pattern_server": None,
        })

        strategy = AnyMatchStrategy()
        strategy.execute(
            engine_configs=[gitleaks, betterleaks],
            scanner_fn=tracking_scanner,
            source_file="/tmp/src.txt",
            report_file_prefix="/tmp/report",
            config_path="/tmp/global.toml",
            context={"filename": "test.py"},
        )

        self.assertEqual(len(calls), 2)
        calls_by_engine = {c[0]: c[1] for c in calls}
        self.assertIn("global.toml", calls_by_engine["gitleaks"])
        self.assertIsNone(calls_by_engine["betterleaks"])


class TestBackwardCompatibility(unittest.TestCase):
    """Verify backward compatibility with string engine specs."""

    def test_string_engine_uses_global_config(self):
        """Engines from string specs (no overrides) use global config_path."""
        config = _build_engine_config("gitleaks")
        self.assertIs(config.pattern_server, PATTERN_SERVER_UNSET)
        result = resolve_engine_config_path(config, "/tmp/global.toml")
        self.assertIn("global.toml", result)

    def test_string_betterleaks_no_global_config(self):
        """Betterleaks string spec should not receive global config (incompatible)."""
        config = _build_engine_config("betterleaks")
        result = resolve_engine_config_path(config, "/tmp/global.toml")
        self.assertIsNone(result)

    def test_mixed_engines_list(self):
        """Mix of string and dict engine specs works correctly."""
        gitleaks = _build_engine_config("gitleaks")
        betterleaks_disabled = _build_engine_config({
            "type": "betterleaks",
            "pattern_server": None,
        })
        leaktk = _build_engine_config("leaktk")

        global_path = "/tmp/global.toml"

        self.assertIn("global.toml", resolve_engine_config_path(gitleaks, global_path))
        self.assertIsNone(resolve_engine_config_path(betterleaks_disabled, global_path))
        self.assertIn("global.toml", resolve_engine_config_path(leaktk, global_path))


class TestPerEnginePatternServerFetch(unittest.TestCase):
    """Test per-engine pattern server URL fetching."""

    @patch('ai_guardian.pattern_server.PatternServerClient')
    def test_per_engine_url_overrides_global(self, mock_client_cls):
        """Per-engine pattern_server URL should override global config_path."""
        mock_client = MagicMock()
        mock_client.get_patterns_path.return_value = "/cache/engine_specific.toml"
        mock_client_cls.return_value = mock_client

        config = _build_engine_config({
            "type": "gitleaks",
            "pattern_server": {
                "url": "https://custom-server.example.com",
                "auth_token_env": "CUSTOM_TOKEN",
            }
        })
        result = resolve_engine_config_path(config, "/tmp/global.toml")

        self.assertIn("engine_specific.toml", result)
        self.assertNotIn("global.toml", result)

    @patch('ai_guardian.pattern_server.PatternServerClient')
    def test_per_engine_url_returns_none_on_failure(self, mock_client_cls):
        """Failed per-engine fetch should return None, not fall back to global."""
        mock_client = MagicMock()
        mock_client.get_patterns_path.return_value = None
        mock_client_cls.return_value = mock_client

        config = _build_engine_config({
            "type": "gitleaks",
            "pattern_server": {"url": "https://down-server.example.com"}
        })
        result = resolve_engine_config_path(config, "/tmp/global.toml")
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
