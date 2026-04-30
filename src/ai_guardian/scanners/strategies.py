"""
Execution strategies for running multiple secret scanner engines.

Provides different strategies for combining results from multiple scanners:
- FirstMatchStrategy: Use first available engine (default, backward compatible)
- AnyMatchStrategy: Run all engines, block if ANY finds secrets
- ConsensusStrategy: Block only if multiple engines agree (reduces false positives)
"""

import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple


@dataclass
class SecretMatch:
    """Single secret detection result."""
    rule_id: str
    description: str
    file: str
    line_number: int
    end_line: Optional[int] = None
    commit: Optional[str] = None
    secret: Optional[str] = None  # Redacted or None
    engine: str = ""  # Which engine found it
    confidence: float = 1.0  # 0.0-1.0 confidence score
    verified: bool = False  # For engines that support verification


@dataclass
class ScanResult:
    """Result from a secret scanner."""
    has_secrets: bool
    secrets: List[SecretMatch]
    engine: str
    error: Optional[str] = None
    scan_time_ms: float = 0.0


class ExecutionStrategy(ABC):
    """
    Abstract base class for scanner execution strategies.

    A strategy determines how to execute multiple scanner engines
    and how to combine their results.
    """

    @abstractmethod
    def execute(
        self,
        scanners: List[Any],  # List of configured scanner engines
        content: str,
        filename: str,
        context: Optional[Dict] = None
    ) -> ScanResult:
        """
        Execute scanners and combine results.

        Args:
            scanners: List of scanner engine configurations
            content: Text content to scan
            filename: Filename for context
            context: Optional metadata (ide_type, hook_event, etc.)

        Returns:
            ScanResult with combined findings
        """
        pass


class FirstMatchStrategy(ExecutionStrategy):
    """
    Use first available scanner, fall back if unavailable.

    This is the default strategy, maintaining backward compatibility.
    Tries scanners in order, returning the first one that's available.
    """

    def execute(
        self,
        scanners: List[Any],
        content: str,
        filename: str,
        context: Optional[Dict] = None
    ) -> ScanResult:
        """
        Execute first available scanner.

        Args:
            scanners: List of scanner configurations (ordered by preference)
            content: Content to scan
            filename: File being scanned
            context: Optional metadata

        Returns:
            Result from first available scanner
        """
        for scanner_config in scanners:
            # This would call the actual scanner execution
            # For now, this is a placeholder that would be integrated
            # with the existing check_secrets_with_gitleaks() logic
            logging.info(f"FirstMatchStrategy: Trying scanner {scanner_config.type}")
            # TODO: Integrate with actual scanner execution
            pass

        # If no scanner available, return no secrets found
        return ScanResult(
            has_secrets=False,
            secrets=[],
            engine="none",
            error="No scanners available"
        )


class AnyMatchStrategy(ExecutionStrategy):
    """
    Run all scanners, block if ANY finds secrets.

    Provides maximum security by requiring all scanners to pass.
    Useful for defense-in-depth and compliance requirements.
    """

    def execute(
        self,
        scanners: List[Any],
        content: str,
        filename: str,
        context: Optional[Dict] = None
    ) -> ScanResult:
        """
        Execute all available scanners and combine results.

        Args:
            scanners: List of scanner configurations
            content: Content to scan
            filename: File being scanned
            context: Optional metadata

        Returns:
            Combined result (has_secrets=True if ANY scanner found secrets)
        """
        all_secrets: List[SecretMatch] = []
        engines_run: List[str] = []
        total_time_ms = 0.0

        for scanner_config in scanners:
            logging.info(f"AnyMatchStrategy: Running scanner {scanner_config.type}")
            # TODO: Integrate with actual scanner execution
            # result = run_scanner(scanner_config, content, filename)
            # all_secrets.extend(result.secrets)
            # engines_run.append(scanner_config.type)
            # total_time_ms += result.scan_time_ms
            pass

        # Deduplicate secrets by line number and rule
        unique_secrets = self._deduplicate(all_secrets)

        return ScanResult(
            has_secrets=len(unique_secrets) > 0,
            secrets=unique_secrets,
            engine=f"multiple({','.join(engines_run)})",
            scan_time_ms=total_time_ms
        )

    def _deduplicate(self, secrets: List[SecretMatch]) -> List[SecretMatch]:
        """
        Deduplicate secrets found by multiple engines.

        Strategy: Keep the secret with highest confidence when multiple
        engines find the same secret at the same location.

        Args:
            secrets: List of all secret matches from all engines

        Returns:
            Deduplicated list of secret matches
        """
        if not secrets:
            return []

        # Group by (file, line_number, rule_id)
        grouped: Dict[Tuple[str, int, str], List[SecretMatch]] = defaultdict(list)
        for secret in secrets:
            key = (secret.file, secret.line_number, secret.rule_id)
            grouped[key].append(secret)

        # For each group, keep the one with highest confidence
        # or the verified one if any engine verified it
        unique: List[SecretMatch] = []
        for group_secrets in grouped.values():
            # Prefer verified secrets
            verified = [s for s in group_secrets if s.verified]
            if verified:
                best = max(verified, key=lambda s: s.confidence)
            else:
                best = max(group_secrets, key=lambda s: s.confidence)

            # Add all engine names that found this secret
            engines = {s.engine for s in group_secrets if s.engine}
            best.engine = ",".join(sorted(engines))

            unique.append(best)

        return unique


class ConsensusStrategy(ExecutionStrategy):
    """
    Block only if multiple scanners agree (reduces false positives).

    Requires N engines to find the same secret before blocking.
    Useful for reducing interruptions in development while maintaining security.
    """

    def __init__(self, threshold: int = 2):
        """
        Initialize consensus strategy.

        Args:
            threshold: Minimum number of engines that must agree (default: 2)
        """
        self.threshold = threshold

    def execute(
        self,
        scanners: List[Any],
        content: str,
        filename: str,
        context: Optional[Dict] = None
    ) -> ScanResult:
        """
        Execute all scanners and require consensus.

        Args:
            scanners: List of scanner configurations
            content: Content to scan
            filename: File being scanned
            context: Optional metadata

        Returns:
            Result with only secrets that meet consensus threshold
        """
        all_secrets: List[SecretMatch] = []
        engines_run: List[str] = []
        total_time_ms = 0.0

        for scanner_config in scanners:
            logging.info(f"ConsensusStrategy: Running scanner {scanner_config.type}")
            # TODO: Integrate with actual scanner execution
            # result = run_scanner(scanner_config, content, filename)
            # all_secrets.extend(result.secrets)
            # engines_run.append(scanner_config.type)
            # total_time_ms += result.scan_time_ms
            pass

        # Group by location and find secrets that meet threshold
        consensus_secrets = self._find_consensus(all_secrets)

        return ScanResult(
            has_secrets=len(consensus_secrets) > 0,
            secrets=consensus_secrets,
            engine=f"consensus({','.join(engines_run)})",
            scan_time_ms=total_time_ms
        )

    def _find_consensus(self, secrets: List[SecretMatch]) -> List[SecretMatch]:
        """
        Find secrets that meet consensus threshold.

        Groups secrets by approximate location (file and line number range)
        and returns only those found by at least threshold engines.

        Args:
            secrets: List of all secret matches from all engines

        Returns:
            List of secrets that met consensus threshold
        """
        if not secrets:
            return []

        # Group by (file, line_number with tolerance of ±1)
        # This accounts for slight differences in how engines report line numbers
        grouped: Dict[Tuple[str, int], List[SecretMatch]] = defaultdict(list)

        for secret in secrets:
            # Round to nearest line (handles ±1 tolerance)
            key = (secret.file, secret.line_number)
            grouped[key].append(secret)

        # Find secrets that meet threshold
        consensus: List[SecretMatch] = []
        for location_secrets in grouped.values():
            # Count unique engines that found this secret
            engines = {s.engine for s in location_secrets if s.engine}

            if len(engines) >= self.threshold:
                # Use the highest confidence match
                best = max(location_secrets, key=lambda s: s.confidence)

                # Annotate with all engines that found it
                best.engine = f"{','.join(sorted(engines))} ({len(engines)} engines)"

                consensus.append(best)

        return consensus


# Strategy registry
EXECUTION_STRATEGIES = {
    "first-match": FirstMatchStrategy,
    "any-match": AnyMatchStrategy,
    "consensus": ConsensusStrategy
}


def get_strategy(strategy_name: str, **kwargs) -> ExecutionStrategy:
    """
    Get execution strategy instance by name.

    Args:
        strategy_name: Name of strategy ('first-match', 'any-match', 'consensus')
        **kwargs: Strategy-specific configuration (e.g., threshold for consensus)

    Returns:
        Strategy instance

    Raises:
        ValueError: If strategy name is unknown
    """
    if strategy_name not in EXECUTION_STRATEGIES:
        raise ValueError(
            f"Unknown strategy: {strategy_name}. "
            f"Available strategies: {', '.join(EXECUTION_STRATEGIES.keys())}"
        )

    strategy_class = EXECUTION_STRATEGIES[strategy_name]
    return strategy_class(**kwargs)
