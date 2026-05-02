"""
Scanner engine configuration and command building.

Provides flexible support for multiple secret scanner engines:
- Gitleaks (industry standard)
- BetterLeaks (faster, by original Gitleaks maintainers)
- LeakTK (auto-pattern management)
- Custom scanners

Supports automatic fallback and configuration-driven selection.
"""

import copy
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional


@dataclass
class EngineConfig:
    """
    Configuration for a scanner engine.

    Attributes:
        type: Engine type identifier (e.g., 'gitleaks', 'betterleaks', 'leaktk')
        binary: Binary name or path for the scanner
        command_template: Command template with placeholders for building commands
        config_flag: Optional flags for specifying config file
        extra_flags: Optional additional command-line flags
        success_exit_code: Exit code indicating no secrets found
        secrets_found_exit_code: Exit code indicating secrets were detected
        output_parser: Parser type to use for output ('gitleaks' or 'leaktk')
    """
    type: str
    binary: str
    command_template: List[str]
    config_flag: Optional[List[str]] = None
    extra_flags: Optional[List[str]] = None
    success_exit_code: int = 0
    secrets_found_exit_code: int = 42
    output_parser: str = "gitleaks"


# Built-in engine presets
ENGINE_PRESETS = {
    "gitleaks": EngineConfig(
        type="gitleaks",
        binary="gitleaks",
        command_template=[
            "{binary}", "detect", "--no-git", "--verbose", "--redact=100",
            "--report-format", "json", "--report-path", "{report_file}",
            "--exit-code", "42", "--source", "{source_file}"
        ],
        config_flag=["--config", "{config_path}"],
        output_parser="gitleaks",
        success_exit_code=0,
        secrets_found_exit_code=42
    ),

    "betterleaks": EngineConfig(
        type="betterleaks",
        binary="betterleaks",
        command_template=[
            "{binary}", "dir", "--verbose", "--redact=100",
            "--report-format", "json", "--report-path", "{report_file}",
            "--exit-code", "42", "--validation=false", "{source_file}"
        ],
        config_flag=["--config", "{config_path}"],
        output_parser="gitleaks",  # Same format as gitleaks
        success_exit_code=0,
        secrets_found_exit_code=42
    ),

    "leaktk": EngineConfig(
        type="leaktk",
        binary="leaktk",
        command_template=[
            "{binary}", "scan", "--kind", "File",
            "--format", "json", "--output", "{report_file}",
            "{source_file}"
        ],
        config_flag=None,  # LeakTK auto-manages patterns
        output_parser="leaktk",  # Different output format
        success_exit_code=0,
        secrets_found_exit_code=1
    ),

    "trufflehog": EngineConfig(
        type="trufflehog",
        binary="trufflehog",
        command_template=[
            "{binary}", "filesystem", "{source_file}",
            "--json", "--no-verification",
            "--no-update"
        ],
        config_flag=None,  # TruffleHog uses built-in detectors
        output_parser="trufflehog",
        success_exit_code=0,
        secrets_found_exit_code=183  # TruffleHog exits with 183 when secrets found
    ),

    "detect-secrets": EngineConfig(
        type="detect-secrets",
        binary="detect-secrets",
        command_template=[
            "{binary}", "scan", "{source_file}"
        ],
        config_flag=None,
        output_parser="detect-secrets",
        success_exit_code=0,
        secrets_found_exit_code=1
    )
}


def select_engine(engines_config: List[Any]) -> EngineConfig:
    """
    Select first available engine from configuration list.

    Tries engines in order, returning the first one whose binary is found
    in the system PATH.

    Args:
        engines_config: List of engine specifications. Each can be:
            - String: name of built-in preset (e.g., "betterleaks")
            - Dict: preset with overrides or custom engine definition

    Returns:
        EngineConfig: First available engine configuration

    Raises:
        RuntimeError: If no engine is available

    Example:
        >>> config = select_engine(["betterleaks", "gitleaks"])
        >>> print(config.type)
        'betterleaks'  # or 'gitleaks' if betterleaks not installed
    """
    for engine_spec in engines_config:
        # Build engine config from specification
        if isinstance(engine_spec, str):
            # Simple preset name: "betterleaks"
            if engine_spec not in ENGINE_PRESETS:
                logging.warning(f"Unknown engine preset: {engine_spec}")
                continue
            engine_config = ENGINE_PRESETS[engine_spec]
        else:
            # Dictionary: preset with overrides or custom engine
            engine_type = engine_spec.get("type")
            if engine_type in ENGINE_PRESETS:
                # Start with preset, apply overrides
                engine_config = copy.deepcopy(ENGINE_PRESETS[engine_type])
                if "binary" in engine_spec:
                    engine_config.binary = engine_spec["binary"]
                if "extra_flags" in engine_spec:
                    engine_config.extra_flags = engine_spec["extra_flags"]
                if "config_flag" in engine_spec:
                    engine_config.config_flag = engine_spec["config_flag"]
            elif engine_type == "custom":
                # Fully custom engine
                engine_config = EngineConfig(
                    type="custom",
                    binary=engine_spec["binary"],
                    command_template=engine_spec["command_template"],
                    config_flag=engine_spec.get("config_flag"),
                    extra_flags=engine_spec.get("extra_flags"),
                    success_exit_code=engine_spec.get("success_exit_code", 0),
                    secrets_found_exit_code=engine_spec.get("secrets_found_exit_code", 1),
                    output_parser=engine_spec.get("output_format", "gitleaks")
                )
            else:
                logging.warning(f"Unknown engine type: {engine_type}")
                continue

        # Check if binary exists
        if shutil.which(engine_config.binary):
            logging.info(f"Selected scanner engine: {engine_config.type}")
            return engine_config
        else:
            # Log warning when scanner not available (helps users understand fallback chain)
            logging.warning(
                f"Scanner '{engine_config.type}' (binary: {engine_config.binary}) "
                f"not available, trying next scanner in list"
            )

    # No engine found - provide helpful error message
    raise RuntimeError(
        "No secret scanner found. Install one of:\n"
        "  • Gitleaks: brew install gitleaks\n"
        "  • BetterLeaks: brew install betterleaks\n"
        "  • LeakTK: brew install leaktk/tap/leaktk"
    )


def build_scanner_command(
    engine_config: EngineConfig,
    source_file: str,
    report_file: str,
    config_path: Optional[str] = None
) -> List[str]:
    """
    Build scanner command from engine configuration.

    Replaces placeholders in command template:
    - {binary} -> engine_config.binary
    - {source_file} -> source_file
    - {report_file} -> report_file
    - {config_path} -> config_path (if provided)

    Args:
        engine_config: Engine configuration
        source_file: Path to file being scanned
        report_file: Path for output report
        config_path: Optional path to configuration file

    Returns:
        List of command arguments ready for subprocess.run()

    Example:
        >>> config = ENGINE_PRESETS["gitleaks"]
        >>> cmd = build_scanner_command(config, "/tmp/test", "/tmp/report.json")
        >>> print(cmd[0])
        'gitleaks'
    """
    cmd = []

    # Process command template
    for part in engine_config.command_template:
        part = part.replace("{binary}", engine_config.binary)
        part = part.replace("{source_file}", source_file)
        part = part.replace("{report_file}", report_file)
        if "{config_path}" in part and config_path:
            part = part.replace("{config_path}", config_path)
        cmd.append(part)

    # Add config flag if needed
    if config_path and engine_config.config_flag:
        for flag in engine_config.config_flag:
            flag = flag.replace("{config_path}", config_path)
            cmd.append(flag)

    # Add extra flags
    if engine_config.extra_flags:
        cmd.extend(engine_config.extra_flags)

    return cmd
