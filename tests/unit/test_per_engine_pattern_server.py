"""
Test for Issue #519: Wire per-engine pattern_server config in scanning flow

Verifies that per-engine pattern_server overrides are respected during scanning:
- pattern_server: null → engine uses built-in rules (no --config flag)
- pattern_server: {url: ...} → engine fetches from per-engine pattern server
- No override (key absent) → engine uses global pattern server config
"""

import unittest
from unittest.mock import patch, MagicMock

from ai_guardian.scanners.engine_builder import (
    PATTERN_SERVER_UNSET,
    _build_engine_config,
    resolve_engine_config_path,
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
                has_secrets=False,
                secrets=[],
                engine=engine_config.type,
            )

        gitleaks = _build_engine_config("gitleaks")
        betterleaks = _build_engine_config(
            {
                "type": "betterleaks",
                "pattern_server": None,
            }
        )

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
                has_secrets=False,
                secrets=[],
                engine=engine_config.type,
            )

        gitleaks = _build_engine_config("gitleaks")
        betterleaks = _build_engine_config(
            {
                "type": "betterleaks",
                "pattern_server": None,
            }
        )

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
        betterleaks_disabled = _build_engine_config(
            {
                "type": "betterleaks",
                "pattern_server": None,
            }
        )
        leaktk = _build_engine_config("leaktk")

        global_path = "/tmp/global.toml"

        self.assertIn("global.toml", resolve_engine_config_path(gitleaks, global_path))
        self.assertIsNone(resolve_engine_config_path(betterleaks_disabled, global_path))
        # leaktk has no config_flag — legacy pattern server not passed (#529)
        self.assertIsNone(resolve_engine_config_path(leaktk, global_path))


class TestPerEnginePatternServerFetch(unittest.TestCase):
    """Test per-engine pattern server URL fetching."""

    @patch("ai_guardian.patterns.server.PatternServerClient")
    def test_per_engine_url_overrides_global(self, mock_client_cls):
        """Per-engine pattern_server URL should override global config_path."""
        mock_client = MagicMock()
        mock_client.get_patterns_path.return_value = "/cache/engine_specific.toml"
        mock_client_cls.return_value = mock_client

        config = _build_engine_config(
            {
                "type": "gitleaks",
                "pattern_server": {
                    "url": "https://custom-server.example.com",
                    "auth_token_env": "CUSTOM_TOKEN",
                },
            }
        )
        result = resolve_engine_config_path(config, "/tmp/global.toml")

        self.assertIn("engine_specific.toml", result)
        self.assertNotIn("global.toml", result)

    @patch("ai_guardian.patterns.server.PatternServerClient")
    def test_per_engine_url_returns_none_on_failure(self, mock_client_cls):
        """Failed per-engine fetch should return None, not fall back to global."""
        mock_client = MagicMock()
        mock_client.get_patterns_path.return_value = None
        mock_client_cls.return_value = mock_client

        config = _build_engine_config(
            {
                "type": "gitleaks",
                "pattern_server": {"url": "https://down-server.example.com"},
            }
        )
        result = resolve_engine_config_path(config, "/tmp/global.toml")
        self.assertIsNone(result)


class TestConfigFlagGuard(unittest.TestCase):
    """Issue #529: engines without config_flag never receive pattern server config."""

    def test_engines_without_config_flag_get_none(self):
        """Engines with config_flag=None should not receive global config."""
        for engine_type in ("leaktk", "trufflehog", "detect-secrets", "gitguardian"):
            config = _build_engine_config(engine_type)
            if config is None:
                continue
            result = resolve_engine_config_path(config, "/tmp/global.toml")
            self.assertIsNone(
                result,
                f"{engine_type} has config_flag={config.config_flag} "
                f"but received global config",
            )

    def test_gitleaks_receives_global_config(self):
        """Gitleaks (has config_flag) should receive global config."""
        config = _build_engine_config("gitleaks")
        result = resolve_engine_config_path(config, "/tmp/global.toml")
        self.assertIsNotNone(result)
        self.assertIn("global.toml", result)

    def test_betterleaks_without_override_gets_none(self):
        """Betterleaks is not in _CONFIG_COMPATIBLE_ENGINES despite having config_flag."""
        config = _build_engine_config("betterleaks")
        result = resolve_engine_config_path(config, "/tmp/global.toml")
        self.assertIsNone(result)


class TestDescribePatterns(unittest.TestCase):
    """Issue #529: verify _describe_patterns returns correct message per engine."""

    def setUp(self):
        from ai_guardian import _describe_patterns

        self.describe = _describe_patterns

    def test_gitleaks_with_legacy_pattern_server(self):
        """Gitleaks + legacy pattern server → LeakTK Pattern Server message."""
        config = _build_engine_config("gitleaks")
        pattern_config = {"url": "https://patterns.example.com"}
        result = self.describe(
            config, "/tmp/patterns.toml", "pattern server", pattern_config
        )
        self.assertIn("LeakTK Pattern Server", result)
        self.assertIn("patterns.example.com", result)

    def test_betterleaks_with_legacy_pattern_server_loaded(self):
        """Betterleaks should show built-in rules even when legacy PS is loaded."""
        config = _build_engine_config("betterleaks")
        pattern_config = {"url": "https://patterns.example.com"}
        # resolved_config_path is None because betterleaks doesn't use legacy PS
        result = self.describe(config, None, "pattern server", pattern_config)
        self.assertIn("Built-in betterleaks rules", result)
        self.assertNotIn("LeakTK", result)

    def test_leaktk_built_in_rules(self):
        """LeakTK shows built-in rules (no legacy PS compat)."""
        config = _build_engine_config("leaktk")
        result = self.describe(config, None, None, None)
        self.assertIn("Built-in leaktk rules", result)

    def test_trufflehog_built_in_rules(self):
        """TruffleHog shows built-in rules."""
        config = _build_engine_config("trufflehog")
        result = self.describe(config, None, None, None)
        self.assertIn("Built-in trufflehog rules", result)

    def test_gitleaks_project_config(self):
        """Gitleaks + project config → shows config path."""
        config = _build_engine_config("gitleaks")
        result = self.describe(
            config, "/project/.gitleaks.toml", "project config", None
        )
        self.assertIn("/project/.gitleaks.toml", result)

    def test_gitleaks_defaults(self):
        """Gitleaks without any config → built-in rules."""
        config = _build_engine_config("gitleaks")
        result = self.describe(config, None, "gitleaks defaults", None)
        self.assertIn("Built-in gitleaks rules", result)

    def test_per_engine_pattern_server_override(self):
        """Engine with per-engine pattern_server shows engine-specific message."""
        config = _build_engine_config(
            {
                "type": "betterleaks",
                "pattern_server": {"url": "https://bl-patterns.example.com"},
            }
        )
        result = self.describe(config, "/cache/bl.toml", "pattern server", None)
        self.assertIn("betterleaks Pattern Server", result)
        self.assertIn("bl-patterns.example.com", result)

    def test_per_engine_pattern_server_null(self):
        """Engine with pattern_server: null → built-in rules."""
        config = _build_engine_config(
            {
                "type": "gitleaks",
                "pattern_server": None,
            }
        )
        result = self.describe(config, None, "pattern server", {"url": "https://x.com"})
        self.assertIn("Built-in gitleaks rules", result)
        self.assertNotIn("LeakTK", result)

    def test_no_engine_config_fallback(self):
        """None engine_config falls back to gitleaks."""
        result = self.describe(None, None, None, None)
        self.assertIn("Built-in gitleaks rules", result)


if __name__ == "__main__":
    unittest.main()
