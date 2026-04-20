#!/usr/bin/env python3
"""
Tests for scanner engine builder module.

Tests engine selection, command building, and configuration handling.
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_guardian.scanners.engine_builder import (
    EngineConfig,
    ENGINE_PRESETS,
    select_engine,
    build_scanner_command
)


class TestEnginePresets(unittest.TestCase):
    """Tests for built-in engine presets."""

    def test_gitleaks_preset_exists(self):
        """Test that gitleaks preset is defined."""
        self.assertIn("gitleaks", ENGINE_PRESETS)
        config = ENGINE_PRESETS["gitleaks"]
        self.assertEqual(config.type, "gitleaks")
        self.assertEqual(config.binary, "gitleaks")
        self.assertEqual(config.output_parser, "gitleaks")
        self.assertEqual(config.secrets_found_exit_code, 42)

    def test_betterleaks_preset_exists(self):
        """Test that betterleaks preset is defined."""
        self.assertIn("betterleaks", ENGINE_PRESETS)
        config = ENGINE_PRESETS["betterleaks"]
        self.assertEqual(config.type, "betterleaks")
        self.assertEqual(config.binary, "betterleaks")
        self.assertEqual(config.output_parser, "gitleaks")  # Same as gitleaks
        self.assertEqual(config.secrets_found_exit_code, 42)

    def test_leaktk_preset_exists(self):
        """Test that leaktk preset is defined."""
        self.assertIn("leaktk", ENGINE_PRESETS)
        config = ENGINE_PRESETS["leaktk"]
        self.assertEqual(config.type, "leaktk")
        self.assertEqual(config.binary, "leaktk")
        self.assertEqual(config.output_parser, "leaktk")  # Different parser
        self.assertEqual(config.secrets_found_exit_code, 1)

    def test_all_presets_have_required_fields(self):
        """Test that all presets have required fields."""
        for name, config in ENGINE_PRESETS.items():
            self.assertIsInstance(config, EngineConfig)
            self.assertTrue(config.type, f"{name} missing type")
            self.assertTrue(config.binary, f"{name} missing binary")
            self.assertTrue(config.command_template, f"{name} missing command_template")
            self.assertTrue(config.output_parser, f"{name} missing output_parser")


class TestSelectEngine(unittest.TestCase):
    """Tests for engine selection logic."""

    @patch('ai_guardian.scanners.engine_builder.shutil.which')
    def test_select_first_available_engine(self, mock_which):
        """Test that first available engine is selected."""
        # Mock: betterleaks not found, gitleaks found
        def which_side_effect(binary):
            return "/usr/bin/gitleaks" if binary == "gitleaks" else None

        mock_which.side_effect = which_side_effect

        config = select_engine(["betterleaks", "gitleaks"])
        self.assertEqual(config.type, "gitleaks")

    @patch('ai_guardian.scanners.engine_builder.shutil.which')
    def test_select_betterleaks_when_available(self, mock_which):
        """Test that betterleaks is selected when available."""
        # Mock: betterleaks found
        def which_side_effect(binary):
            return f"/usr/bin/{binary}" if binary == "betterleaks" else None

        mock_which.side_effect = which_side_effect

        config = select_engine(["betterleaks", "gitleaks"])
        self.assertEqual(config.type, "betterleaks")

    @patch('ai_guardian.scanners.engine_builder.shutil.which')
    def test_select_engine_no_scanner_found(self, mock_which):
        """Test that RuntimeError is raised when no scanner is found."""
        # Mock: no scanner found
        mock_which.return_value = None

        with self.assertRaises(RuntimeError) as cm:
            select_engine(["betterleaks", "gitleaks", "leaktk"])

        self.assertIn("No secret scanner found", str(cm.exception))
        self.assertIn("Gitleaks", str(cm.exception))
        self.assertIn("BetterLeaks", str(cm.exception))

    @patch('ai_guardian.scanners.engine_builder.shutil.which')
    def test_select_engine_with_custom_binary_path(self, mock_which):
        """Test engine selection with custom binary path override."""
        # Mock: custom path exists
        def which_side_effect(binary):
            return binary if binary == "/custom/path/betterleaks" else None

        mock_which.side_effect = which_side_effect

        engine_spec = {
            "type": "betterleaks",
            "binary": "/custom/path/betterleaks"
        }
        config = select_engine([engine_spec])
        self.assertEqual(config.type, "betterleaks")
        self.assertEqual(config.binary, "/custom/path/betterleaks")

    @patch('ai_guardian.scanners.engine_builder.shutil.which')
    def test_select_engine_with_extra_flags(self, mock_which):
        """Test engine selection with extra flags override."""
        mock_which.return_value = "/usr/bin/betterleaks"

        engine_spec = {
            "type": "betterleaks",
            "extra_flags": ["--regex-engine=re2", "--verbose"]
        }
        config = select_engine([engine_spec])
        self.assertEqual(config.extra_flags, ["--regex-engine=re2", "--verbose"])

    @patch('ai_guardian.scanners.engine_builder.shutil.which')
    def test_select_custom_engine(self, mock_which):
        """Test selection of fully custom engine."""
        mock_which.return_value = "/usr/bin/my-scanner"

        engine_spec = {
            "type": "custom",
            "binary": "my-scanner",
            "command_template": ["{binary}", "scan", "{source_file}"],
            "success_exit_code": 0,
            "secrets_found_exit_code": 2,
            "output_format": "gitleaks-compatible"
        }
        config = select_engine([engine_spec])
        self.assertEqual(config.type, "custom")
        self.assertEqual(config.binary, "my-scanner")
        self.assertEqual(config.secrets_found_exit_code, 2)
        self.assertEqual(config.output_parser, "gitleaks-compatible")

    @patch('ai_guardian.scanners.engine_builder.shutil.which')
    def test_select_engine_unknown_preset(self, mock_which):
        """Test that unknown presets are skipped."""
        mock_which.return_value = "/usr/bin/gitleaks"

        config = select_engine(["nonexistent", "gitleaks"])
        self.assertEqual(config.type, "gitleaks")


class TestBuildScannerCommand(unittest.TestCase):
    """Tests for scanner command building."""

    def test_build_gitleaks_command_without_config(self):
        """Test building gitleaks command without config file."""
        config = ENGINE_PRESETS["gitleaks"]
        cmd = build_scanner_command(
            engine_config=config,
            source_file="/tmp/test.txt",
            report_file="/tmp/report.json"
        )

        self.assertIn("gitleaks", cmd)
        self.assertIn("detect", cmd)
        self.assertIn("/tmp/test.txt", cmd)
        self.assertIn("/tmp/report.json", cmd)
        # Config flag should not be present
        self.assertNotIn("--config", cmd)

    def test_build_gitleaks_command_with_config(self):
        """Test building gitleaks command with config file."""
        config = ENGINE_PRESETS["gitleaks"]
        cmd = build_scanner_command(
            engine_config=config,
            source_file="/tmp/test.txt",
            report_file="/tmp/report.json",
            config_path="/home/user/.gitleaks.toml"
        )

        self.assertIn("--config", cmd)
        self.assertIn("/home/user/.gitleaks.toml", cmd)

    def test_build_betterleaks_command(self):
        """Test building betterleaks command."""
        config = ENGINE_PRESETS["betterleaks"]
        cmd = build_scanner_command(
            engine_config=config,
            source_file="/tmp/test.txt",
            report_file="/tmp/report.json"
        )

        self.assertIn("betterleaks", cmd)
        self.assertIn("detect", cmd)
        self.assertIn("/tmp/test.txt", cmd)

    def test_build_leaktk_command(self):
        """Test building leaktk command."""
        config = ENGINE_PRESETS["leaktk"]
        cmd = build_scanner_command(
            engine_config=config,
            source_file="/tmp/test.txt",
            report_file="/tmp/report.json"
        )

        self.assertIn("leaktk", cmd)
        self.assertIn("scan", cmd)
        self.assertIn("--kind", cmd)
        self.assertIn("File", cmd)
        self.assertIn("/tmp/test.txt", cmd)

    def test_build_command_with_extra_flags(self):
        """Test building command with extra flags."""
        config = ENGINE_PRESETS["betterleaks"]
        config.extra_flags = ["--verbose", "--debug"]

        cmd = build_scanner_command(
            engine_config=config,
            source_file="/tmp/test.txt",
            report_file="/tmp/report.json"
        )

        self.assertIn("--verbose", cmd)
        self.assertIn("--debug", cmd)

    def test_build_custom_command(self):
        """Test building custom scanner command."""
        config = EngineConfig(
            type="custom",
            binary="my-scanner",
            command_template=[
                "{binary}", "analyze",
                "--input", "{source_file}",
                "--output", "{report_file}",
                "--format", "json"
            ],
            output_parser="gitleaks"
        )

        cmd = build_scanner_command(
            engine_config=config,
            source_file="/tmp/test.txt",
            report_file="/tmp/report.json"
        )

        self.assertEqual(cmd[0], "my-scanner")
        self.assertIn("analyze", cmd)
        self.assertIn("--input", cmd)
        self.assertIn("/tmp/test.txt", cmd)
        self.assertIn("--output", cmd)
        self.assertIn("/tmp/report.json", cmd)

    def test_placeholder_replacement(self):
        """Test that all placeholders are replaced correctly."""
        config = EngineConfig(
            type="test",
            binary="test-scanner",
            command_template=[
                "{binary}",
                "scan",
                "{source_file}",
                "{report_file}"
            ],
            config_flag=["--config", "{config_path}"],
            output_parser="gitleaks"
        )

        cmd = build_scanner_command(
            engine_config=config,
            source_file="/tmp/source.txt",
            report_file="/tmp/report.json",
            config_path="/home/user/config.toml"
        )

        # No placeholders should remain
        for arg in cmd:
            self.assertNotIn("{binary}", arg)
            self.assertNotIn("{source_file}", arg)
            self.assertNotIn("{report_file}", arg)
            self.assertNotIn("{config_path}", arg)


if __name__ == '__main__':
    unittest.main()
