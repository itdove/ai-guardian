"""Tests for engine consent mechanism."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ai_guardian.scanners.engine_builder import (
    EngineConfig,
    ENGINE_PRESETS,
    check_engine_consent,
    grant_engine_consent,
    revoke_engine_consent,
)


class TestEngineConsent(unittest.TestCase):

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.config_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    @patch("ai_guardian.config_utils.get_config_dir")
    def test_consent_not_required_for_local_engine(self, mock_dir):
        mock_dir.return_value = self.config_dir
        config = EngineConfig(
            type="gitleaks", binary="gitleaks",
            command_template=["{binary}"], requires_consent=False,
        )
        self.assertTrue(check_engine_consent(config))

    @patch("ai_guardian.config_utils.get_config_dir")
    def test_consent_required_not_granted(self, mock_dir):
        mock_dir.return_value = self.config_dir
        config = EngineConfig(
            type="gitguardian", binary="ggshield",
            command_template=["{binary}"], requires_consent=True,
        )
        self.assertFalse(check_engine_consent(config))

    @patch("ai_guardian.config_utils.get_config_dir")
    def test_consent_granted(self, mock_dir):
        mock_dir.return_value = self.config_dir
        grant_engine_consent("gitguardian")
        config = EngineConfig(
            type="gitguardian", binary="ggshield",
            command_template=["{binary}"], requires_consent=True,
        )
        self.assertTrue(check_engine_consent(config))

    @patch("ai_guardian.config_utils.get_config_dir")
    def test_grant_creates_file(self, mock_dir):
        mock_dir.return_value = self.config_dir
        grant_engine_consent("gitguardian")
        consent_file = self.config_dir / "consent" / "gitguardian.consent"
        self.assertTrue(consent_file.exists())
        content = consent_file.read_text()
        self.assertIn("gitguardian", content)
        self.assertIn("Timestamp:", content)

    @patch("ai_guardian.config_utils.get_config_dir")
    def test_revoke_removes_file(self, mock_dir):
        mock_dir.return_value = self.config_dir
        grant_engine_consent("gitguardian")
        self.assertTrue(revoke_engine_consent("gitguardian"))
        consent_file = self.config_dir / "consent" / "gitguardian.consent"
        self.assertFalse(consent_file.exists())

    @patch("ai_guardian.config_utils.get_config_dir")
    def test_revoke_nonexistent_returns_false(self, mock_dir):
        mock_dir.return_value = self.config_dir
        self.assertFalse(revoke_engine_consent("gitguardian"))

    def test_gitguardian_preset_requires_consent(self):
        preset = ENGINE_PRESETS["gitguardian"]
        self.assertTrue(preset.requires_consent)
        self.assertEqual(preset.api_key_env, "GITGUARDIAN_API_KEY")

    def test_secretlint_preset_no_consent(self):
        preset = ENGINE_PRESETS["secretlint"]
        self.assertFalse(preset.requires_consent)

    def test_gitleaks_preset_no_consent(self):
        preset = ENGINE_PRESETS["gitleaks"]
        self.assertFalse(preset.requires_consent)


if __name__ == "__main__":
    unittest.main()
