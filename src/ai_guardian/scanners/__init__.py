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
    build_scanner_command
)
from ai_guardian.scanners.output_parsers import (
    ScannerOutputParser,
    get_parser,
    OUTPUT_PARSERS
)
from ai_guardian.scanners.strategies import (
    ExecutionStrategy,
    FirstMatchStrategy,
    AnyMatchStrategy,
    ConsensusStrategy,
    SecretMatch,
    ScanResult,
    EXECUTION_STRATEGIES,
    get_strategy
)

__all__ = [
    'EngineConfig',
    'ENGINE_PRESETS',
    'select_engine',
    'build_scanner_command',
    'ScannerOutputParser',
    'get_parser',
    'OUTPUT_PARSERS',
    'ExecutionStrategy',
    'FirstMatchStrategy',
    'AnyMatchStrategy',
    'ConsensusStrategy',
    'SecretMatch',
    'ScanResult',
    'EXECUTION_STRATEGIES',
    'get_strategy'
]
