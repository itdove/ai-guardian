"""
Single-engine execution for secret scanning.

Provides run_single_engine() which runs one scanner engine via subprocess,
parses its output, and returns a standardized ScanResult. This function
is the building block that execution strategies use to run scanners.
"""

import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from ai_guardian.scanners.engine_builder import EngineConfig, build_scanner_command
from ai_guardian.scanners.output_parsers import get_parser
from ai_guardian.scanners.strategies import ScanResult, SecretMatch


def run_single_engine(
    engine_config: EngineConfig,
    source_file: str,
    report_file: str,
    config_path: Optional[str] = None,
    timeout: int = 30,
    cache=None,
    content_hash: Optional[str] = None,
) -> ScanResult:
    """
    Run a single scanner engine and return standardized results.

    Builds the scanner command, executes via subprocess, parses the output,
    and returns a ScanResult with SecretMatch objects.

    Args:
        engine_config: Engine configuration (from ENGINE_PRESETS or custom)
        source_file: Path to the file being scanned
        report_file: Path for scanner output report
        config_path: Optional path to scanner configuration file
        timeout: Subprocess timeout in seconds
        cache: Optional ScanResultCache for result caching
        content_hash: Optional content hash for cache lookups

    Returns:
        ScanResult with findings from this engine
    """
    if cache and content_hash:
        from ai_guardian.scanners.cache import ScanResultCache
        cfg_hash = ScanResultCache.config_hash(engine_config)
        cached = cache.get(content_hash, engine_config.type, cfg_hash)
        if cached is not None:
            logging.info(
                f"Cache hit for {engine_config.type} "
                f"(hash={content_hash[:12]})"
            )
            return cached

    if hasattr(engine_config, 'api_key_env') and engine_config.api_key_env:
        if not os.environ.get(engine_config.api_key_env):
            return ScanResult(
                has_secrets=False, secrets=[], engine=engine_config.type,
                error=f"API key not set: ${engine_config.api_key_env}"
            )

    start_time = time.monotonic()

    try:
        cmd = build_scanner_command(
            engine_config=engine_config,
            source_file=source_file,
            report_file=report_file,
            config_path=config_path
        )

        logging.debug(f"Engine {engine_config.type}: running {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        elapsed_ms = (time.monotonic() - start_time) * 1000

        # For engines that write to stdout instead of a report file
        # (TruffleHog, detect-secrets), write stdout to the report file
        if "{report_file}" not in " ".join(engine_config.command_template):
            if result.stdout:
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(result.stdout)

        # Gitleaks/betterleaks exit code 1 special case (Issue #411):
        # when --exit-code flag is not honored, exit 1 means secrets found
        is_gitleaks_like = engine_config.type in ("gitleaks", "betterleaks")
        is_secrets_found = (
            result.returncode == engine_config.secrets_found_exit_code
            or (result.returncode == 1 and is_gitleaks_like)
        )

        if is_secrets_found:
            scan_result = _parse_secrets_result(engine_config, report_file, elapsed_ms)
            if cache and content_hash:
                from ai_guardian.scanners.cache import ScanResultCache
                cfg_hash = ScanResultCache.config_hash(engine_config)
                cache.put(content_hash, engine_config.type, cfg_hash, scan_result)
            return scan_result

        if result.returncode == engine_config.success_exit_code:
            logging.info(
                f"Engine scan complete: engine={engine_config.type} "
                f"duration_ms={elapsed_ms:.1f} findings=0 has_secrets=False"
            )
            clean_result = ScanResult(
                has_secrets=False,
                secrets=[],
                engine=engine_config.type,
                scan_time_ms=elapsed_ms
            )
            if cache and content_hash:
                from ai_guardian.scanners.cache import ScanResultCache
                cfg_hash = ScanResultCache.config_hash(engine_config)
                cache.put(content_hash, engine_config.type, cfg_hash, clean_result)
            return clean_result

        # Unexpected exit code
        stderr_preview = ""
        if result.stderr:
            stderr_lines = [line.strip() for line in result.stderr.split('\n') if line.strip()]
            if stderr_lines:
                stderr_preview = stderr_lines[0][:200]

        logging.warning(
            f"Engine {engine_config.type} returned unexpected exit code "
            f"{result.returncode}: {stderr_preview}"
        )
        return ScanResult(
            has_secrets=False,
            secrets=[],
            engine=engine_config.type,
            error=f"Unexpected exit code {result.returncode}: {stderr_preview}",
            scan_time_ms=elapsed_ms
        )

    except subprocess.TimeoutExpired:
        elapsed_ms = (time.monotonic() - start_time) * 1000
        logging.warning(f"Engine {engine_config.type} timed out after {timeout}s")
        return ScanResult(
            has_secrets=False,
            secrets=[],
            engine=engine_config.type,
            error=f"Timed out after {timeout}s",
            scan_time_ms=elapsed_ms
        )
    except FileNotFoundError:
        elapsed_ms = (time.monotonic() - start_time) * 1000
        logging.warning(f"Engine {engine_config.type} binary not found: {engine_config.binary}")
        return ScanResult(
            has_secrets=False,
            secrets=[],
            engine=engine_config.type,
            error=f"Binary not found: {engine_config.binary}",
            scan_time_ms=elapsed_ms
        )
    except Exception as e:
        elapsed_ms = (time.monotonic() - start_time) * 1000
        logging.error(f"Engine {engine_config.type} failed: {e}")
        return ScanResult(
            has_secrets=False,
            secrets=[],
            engine=engine_config.type,
            error=str(e),
            scan_time_ms=elapsed_ms
        )


def _parse_secrets_result(
    engine_config: EngineConfig,
    report_file: str,
    elapsed_ms: float
) -> ScanResult:
    """Parse scanner output into ScanResult with SecretMatch objects."""
    try:
        parser = get_parser(engine_config.output_parser)
        parsed = parser.parse(report_file)

        if not parsed or not parsed.get("has_secrets"):
            logging.info(
                f"Engine scan complete: engine={engine_config.type} "
                f"duration_ms={elapsed_ms:.1f} findings=0 has_secrets=False "
                f"(exit code indicated secrets but parser found none)"
            )
            return ScanResult(
                has_secrets=False,
                secrets=[],
                engine=engine_config.type,
                scan_time_ms=elapsed_ms
            )

        secrets = []
        for finding in parsed.get("findings", []):
            secrets.append(SecretMatch(
                rule_id=finding.get("rule_id", "unknown"),
                description=finding.get("description", "Secret detected"),
                file=finding.get("file", "unknown"),
                line_number=finding.get("line_number", 0),
                end_line=finding.get("end_line"),
                commit=finding.get("commit"),
                engine=engine_config.type,
                verified=finding.get("verified", False),
            ))

        logging.info(
            f"Engine scan complete: engine={engine_config.type} "
            f"duration_ms={elapsed_ms:.1f} findings={len(secrets)} has_secrets=True"
        )

        return ScanResult(
            has_secrets=True,
            secrets=secrets,
            engine=engine_config.type,
            scan_time_ms=elapsed_ms
        )

    except Exception as e:
        logging.error(f"Failed to parse {engine_config.type} output: {e}")
        return ScanResult(
            has_secrets=True,
            secrets=[SecretMatch(
                rule_id="parse-error",
                description=f"Scanner detected secrets but output parsing failed: {e}",
                file="unknown",
                line_number=0,
                engine=engine_config.type,
            )],
            engine=engine_config.type,
            error=f"Parse error: {e}",
            scan_time_ms=elapsed_ms
        )
