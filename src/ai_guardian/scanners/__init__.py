"""
Scanner engine modules for flexible secret detection.

This package provides:
- engine_builder: Configuration and command building for different scanner engines
- output_parsers: Parsers for different scanner output formats
- strategies: Execution strategies for running multiple scanners
"""

from ai_guardian.scanners.engine_builder import (
    EngineConfig,
    ENGINE_PRESETS,
    select_engine,
    select_all_engines,
    build_scanner_command,
    check_engine_consent,
    grant_engine_consent,
    revoke_engine_consent,
)
from ai_guardian.scanners.output_parsers import (
    ScannerOutputParser,
    SecretlintOutputParser,
    GitGuardianOutputParser,
    get_parser,
    OUTPUT_PARSERS,
)
from ai_guardian.scanners.strategies import (
    ExecutionStrategy,
    FirstMatchStrategy,
    AnyMatchStrategy,
    ConsensusStrategy,
    SecretMatch,
    ScanResult,
    EXECUTION_STRATEGIES,
    get_strategy,
)
from ai_guardian.scanners.executor import (
    run_single_engine,
    run_python_scanner,
    run_engine,
)
from ai_guardian.scanners.cache import ScanResultCache, FileStateTracker
from ai_guardian.scanners.audit import ScanAuditLogger
from ai_guardian.scanners.compliance import ComplianceReporter
from ai_guardian.scanners.remote_config import (
    fetch_remote_engine_config,
    merge_engine_configs,
)
from ai_guardian.scanners.sdk import Scanner, Finding
from ai_guardian.scanners.python_loader import (
    load_python_scanner,
    load_from_module,
    load_from_file,
    discover_entry_points,
    discover_scanner_directory,
)
from ai_guardian.scanners.secret_validator import (
    SecretValidator,
    ValidationStatus,
    ValidationResult,
)

__all__ = [
    "EngineConfig",
    "ENGINE_PRESETS",
    "select_engine",
    "select_all_engines",
    "build_scanner_command",
    "check_engine_consent",
    "grant_engine_consent",
    "revoke_engine_consent",
    "ScannerOutputParser",
    "SecretlintOutputParser",
    "GitGuardianOutputParser",
    "get_parser",
    "OUTPUT_PARSERS",
    "ExecutionStrategy",
    "FirstMatchStrategy",
    "AnyMatchStrategy",
    "ConsensusStrategy",
    "SecretMatch",
    "ScanResult",
    "EXECUTION_STRATEGIES",
    "get_strategy",
    "run_single_engine",
    "run_python_scanner",
    "run_engine",
    "ScanResultCache",
    "FileStateTracker",
    "ScanAuditLogger",
    "ComplianceReporter",
    "fetch_remote_engine_config",
    "merge_engine_configs",
    "Scanner",
    "Finding",
    "load_python_scanner",
    "load_from_module",
    "load_from_file",
    "discover_entry_points",
    "discover_scanner_directory",
    "SecretValidator",
    "ValidationStatus",
    "ValidationResult",
]
