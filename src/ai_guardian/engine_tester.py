"""
Engine Tester — test strings against individual scanner engines.

Provides functions to run a test string through one or all installed
scanner engines and return structured results.  Used by both the CLI
(``ai-guardian engine-test``) and the Console Engine Tester panel.
"""

import json
import logging
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from ai_guardian.scanner_manager import ScannerManager
from ai_guardian.scanners.engine_builder import (
    ENGINE_PRESETS,
    _build_engine_config,
    resolve_engine_config_path,
)
from ai_guardian.scanners.executor import run_single_engine
from ai_guardian.scanners.strategies import SecretMatch


@dataclass
class EngineTestResult:
    """Result of testing a string against one scanner engine."""

    engine: str
    found: bool
    secrets: List[SecretMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0
    error: Optional[str] = None


def get_available_engines() -> List[str]:
    """Return names of all installed scanner engines."""
    manager = ScannerManager()
    return [s.name for s in manager.list_installed()]


def test_engine(
    engine_name: str,
    text: str,
    use_pattern_server: bool = False,
) -> EngineTestResult:
    """Test *text* against a single scanner engine.

    Args:
        engine_name: Engine preset name (e.g. ``"gitleaks"``).
        text: The string to scan for secrets.
        use_pattern_server: When ``True``, resolve the pattern-server
            config path for engines that support it.

    Returns:
        An :class:`EngineTestResult` with findings.
    """
    if engine_name not in ENGINE_PRESETS:
        return EngineTestResult(
            engine=engine_name,
            found=False,
            error=f"Unknown engine: {engine_name}",
        )

    engine_config = _build_engine_config(engine_name)
    if engine_config is None:
        return EngineTestResult(
            engine=engine_name,
            found=False,
            error=f"Failed to build config for engine: {engine_name}",
        )

    config_path: Optional[str] = None
    if use_pattern_server:
        try:
            from ai_guardian import _load_pattern_server_config

            pattern_config = _load_pattern_server_config()
            if pattern_config and isinstance(pattern_config, dict):
                from ai_guardian.pattern_server import PatternServerClient

                client = PatternServerClient(pattern_config)
                global_path = client.get_patterns_path()
            else:
                global_path = None
            config_path = resolve_engine_config_path(
                engine_config, global_path
            )
        except Exception as exc:
            logging.warning("Pattern server resolution failed: %s", exc)

    with tempfile.TemporaryDirectory(prefix="aiguardian_engtest_") as tmpdir:
        source_file = str(Path(tmpdir) / "test_input.txt")
        report_file = str(Path(tmpdir) / "report.json")

        Path(source_file).write_text(text, encoding="utf-8")
        Path(report_file).write_text("", encoding="utf-8")

        scan_result = run_single_engine(
            engine_config=engine_config,
            source_file=source_file,
            report_file=report_file,
            config_path=config_path,
            timeout=30,
        )

    return EngineTestResult(
        engine=engine_name,
        found=scan_result.has_secrets,
        secrets=list(scan_result.secrets),
        scan_time_ms=scan_result.scan_time_ms,
        error=scan_result.error,
    )


def test_all_engines(
    text: str,
    use_pattern_server: bool = False,
) -> List[EngineTestResult]:
    """Test *text* against every installed scanner engine."""
    engines = get_available_engines()
    if not engines:
        return []
    return [
        test_engine(name, text, use_pattern_server=use_pattern_server)
        for name in engines
    ]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def format_result(result: EngineTestResult) -> str:
    """Human-readable output for a single engine result."""
    if result.error and not result.found:
        return f"  {result.engine}: ERROR — {result.error}"

    status = (
        f"\033[31mFOUND ({len(result.secrets)} secret"
        f"{'s' if len(result.secrets) != 1 else ''})\033[0m"
        if result.found
        else "\033[32mNOT FOUND\033[0m"
    )
    lines = [f"  {result.engine}: {status}  ({result.scan_time_ms:.0f}ms)"]

    for secret in result.secrets:
        parts = []
        if secret.rule_id:
            parts.append(f"Rule: {secret.rule_id}")
        parts.append(f"Line: {secret.line_number}")
        if secret.description:
            parts.append(secret.description)
        lines.append(f"    {', '.join(parts)}")

    return "\n".join(lines)


def format_comparison(results: List[EngineTestResult]) -> str:
    """Tabular comparison across multiple engines."""
    if not results:
        return "  No engines available."

    name_w = max(len(r.engine) for r in results)
    name_w = max(name_w, 6)  # minimum "Engine" header width

    header = f"  {'Engine':<{name_w}}  {'Result':<12}  {'Secrets':>7}  {'Time':>8}"
    sep = "  " + "─" * (name_w + 12 + 7 + 8 + 6)
    lines = [header, sep]

    for r in results:
        if r.error and not r.found:
            status = "ERROR"
        elif r.found:
            status = "FOUND"
        else:
            status = "NOT FOUND"
        lines.append(
            f"  {r.engine:<{name_w}}  {status:<12}  "
            f"{len(r.secrets):>7}  {r.scan_time_ms:>6.0f}ms"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def engine_test_command(args) -> int:
    """CLI handler for ``ai-guardian engine-test``."""
    has_engine = getattr(args, "engine", None)
    has_all = getattr(args, "all_engines", False)
    has_compare = getattr(args, "compare", False)
    use_ps = getattr(args, "pattern_server", False)
    use_json = getattr(args, "json", False)

    if not has_engine and not has_all and not has_compare:
        print(
            "Error: specify --engine NAME, --all, or --compare",
            file=sys.stderr,
        )
        return 2

    if sys.stdin.isatty():
        print(
            "Error: pipe text via stdin, e.g.:\n"
            '  echo "AWS_KEY=AKIAIOSFODNN7EXAMPLE" '
            "| ai-guardian engine-test --engine gitleaks",
            file=sys.stderr,
        )
        return 2

    text = sys.stdin.read()
    if not text.strip():
        print("Error: empty input", file=sys.stderr)
        return 2

    if has_engine:
        result = test_engine(has_engine, text, use_pattern_server=use_ps)
        if use_json:
            print(json.dumps(_result_to_dict(result), indent=2))
        else:
            print(format_result(result))
        return 1 if result.found else 0

    # --all or --compare
    results = test_all_engines(text, use_pattern_server=use_ps)
    if use_json:
        print(json.dumps([_result_to_dict(r) for r in results], indent=2))
    elif has_compare:
        print(format_comparison(results))
    else:
        for r in results:
            print(format_result(r))
    return 1 if any(r.found for r in results) else 0


def _result_to_dict(result: EngineTestResult) -> dict:
    """Serialize an :class:`EngineTestResult` to a plain dict."""
    d = asdict(result)
    for s in d.get("secrets", []):
        s.pop("secret", None)
    return d
