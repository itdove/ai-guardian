#!/usr/bin/env python3
"""
Performance benchmarks for AI Guardian Phase 1-4 features.

Ensures all security features meet performance targets:
- SSRF check: <1ms per URL
- Unicode detection: <5ms per check
- Config file scanning: <10ms per file
- Secret redaction: <5ms per 10KB
- Total overhead: <20ms combined

Run with: pytest tests/benchmark_phases.py -v
"""

import time
import pytest

# Import gc for memory test
try:
    import gc
    HAS_GC = True
except ImportError:
    HAS_GC = False

# Import Phase 1-4 modules
try:
    from ai_guardian.ssrf_protector import SSRFProtector
    HAS_SSRF = True
except ImportError:
    HAS_SSRF = False
    pytestmark = pytest.mark.skip(reason="SSRF protector not available")

try:
    from ai_guardian.prompt_injection import UnicodeAttackDetector
    HAS_UNICODE = True
except ImportError:
    HAS_UNICODE = False

try:
    from ai_guardian.config_scanner import check_config_file_threats
    HAS_CONFIG_SCANNER = True
except ImportError:
    HAS_CONFIG_SCANNER = False

try:
    from ai_guardian.secret_redactor import SecretRedactor
    HAS_SECRET_REDACTOR = True
except ImportError:
    HAS_SECRET_REDACTOR = False


# Performance targets (in milliseconds)
SSRF_TARGET_MS = 1.0
UNICODE_TARGET_MS = 5.0
CONFIG_SCANNER_TARGET_MS = 10.0
SECRET_REDACTOR_TARGET_MS = 5.0
TOTAL_OVERHEAD_TARGET_MS = 20.0

# Number of iterations for averaging
ITERATIONS = 100


@pytest.mark.benchmark
@pytest.mark.skipif(not HAS_SSRF, reason="SSRF protector not available")
class TestSSRFPerformance:
    """Benchmark SSRF detection performance."""

    def test_benchmark_ssrf_check(self):
        """Benchmark SSRF URL checking."""
        protector = SSRFProtector()
        test_commands = [
            "curl https://example.com/api/data",
            "wget http://192.168.1.1/admin",
            "fetch http://10.0.0.1/config",
            "curl https://github.com/user/repo",
        ]

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            for cmd in test_commands:
                protector.check("Bash", {"command": cmd})
        end = time.perf_counter()

        total_checks = ITERATIONS * len(test_commands)
        avg_time_ms = ((end - start) / total_checks) * 1000

        print(f"\n✓ SSRF check: {avg_time_ms:.4f}ms per URL (target: <{SSRF_TARGET_MS}ms)")
        assert avg_time_ms < SSRF_TARGET_MS, f"SSRF check too slow: {avg_time_ms:.4f}ms > {SSRF_TARGET_MS}ms"

    def test_benchmark_ssrf_metadata_endpoint(self):
        """Benchmark SSRF metadata endpoint detection."""
        protector = SSRFProtector()
        metadata_commands = [
            "curl http://169.254.169.254/latest/meta-data/",
            "wget http://metadata.google.internal/computeMetadata/v1/",
        ]

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            for cmd in metadata_commands:
                protector.check("Bash", {"command": cmd})
        end = time.perf_counter()

        total_checks = ITERATIONS * len(metadata_commands)
        avg_time_ms = ((end - start) / total_checks) * 1000

        print(f"\n✓ SSRF metadata check: {avg_time_ms:.4f}ms per URL")
        assert avg_time_ms < SSRF_TARGET_MS


@pytest.mark.benchmark
@pytest.mark.skipif(not HAS_UNICODE, reason="Unicode detector not available")
class TestUnicodePerformance:
    """Benchmark Unicode attack detection performance."""

    def test_benchmark_unicode_zero_width(self):
        """Benchmark zero-width character detection."""
        detector = UnicodeAttackDetector()
        # Text with zero-width characters
        test_text = "normal text with​​​hidden​​​zero-width chars"

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            detector.detect_zero_width(test_text)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Unicode zero-width: {avg_time_ms:.4f}ms per check (target: <{UNICODE_TARGET_MS}ms)")
        assert avg_time_ms < UNICODE_TARGET_MS

    def test_benchmark_unicode_bidi(self):
        """Benchmark bidirectional override detection."""
        detector = UnicodeAttackDetector()
        test_text = "normal text with potential override"

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            detector.detect_bidi_override(test_text)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Unicode bidi: {avg_time_ms:.4f}ms per check")
        assert avg_time_ms < UNICODE_TARGET_MS

    def test_benchmark_unicode_homoglyphs(self):
        """Benchmark homoglyph detection."""
        detector = UnicodeAttackDetector()
        test_text = "normal text without homoglyphs"

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            detector.detect_homoglyphs(test_text)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Unicode homoglyphs: {avg_time_ms:.4f}ms per check")
        assert avg_time_ms < UNICODE_TARGET_MS

    def test_benchmark_unicode_combined(self):
        """Benchmark all Unicode checks combined."""
        detector = UnicodeAttackDetector()
        test_text = "normal text for comprehensive check"

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            detector.detect_zero_width(test_text)
            detector.detect_bidi_override(test_text)
            detector.detect_homoglyphs(test_text)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Unicode combined: {avg_time_ms:.4f}ms per check (target: <{UNICODE_TARGET_MS}ms)")
        assert avg_time_ms < UNICODE_TARGET_MS


@pytest.mark.benchmark
@pytest.mark.skipif(not HAS_CONFIG_SCANNER, reason="Config scanner not available")
class TestConfigScannerPerformance:
    """Benchmark config file scanner performance."""

    def test_benchmark_config_scan(self):
        """Benchmark config file scanning."""
        test_content = """
# CLAUDE.md

Instructions for AI assistant.

Use these commands to help:
- npm install
- npm test
- npm run build

Remember to check all edge cases.
        """.strip()

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            check_config_file_threats("CLAUDE.md", test_content)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Config scan: {avg_time_ms:.4f}ms per file (target: <{CONFIG_SCANNER_TARGET_MS}ms)")
        assert avg_time_ms < CONFIG_SCANNER_TARGET_MS

    def test_benchmark_config_scan_large(self):
        """Benchmark config file scanning with larger content."""
        # Generate larger config file (simulate real-world CLAUDE.md)
        test_content = "\n".join([
            "# Project Instructions",
            "",
            "## Overview",
            "This is a comprehensive guide for the AI assistant.",
            "",
            "## Commands",
        ] + [f"- Command {i}: Do something useful" for i in range(100)])

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            check_config_file_threats("CLAUDE.md", test_content)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Config scan (large): {avg_time_ms:.4f}ms per file")
        assert avg_time_ms < CONFIG_SCANNER_TARGET_MS


@pytest.mark.benchmark
@pytest.mark.skipif(not HAS_SECRET_REDACTOR, reason="Secret redactor not available")
class TestSecretRedactorPerformance:
    """Benchmark secret redaction performance."""

    def test_benchmark_secret_redaction(self):
        """Benchmark secret redaction."""
        redactor = SecretRedactor()
        test_output = """
Command output:
Environment variables:
PATH=/usr/bin:/usr/local/bin
HOME=/home/user
API_KEY=not-a-real-key-1234567890
DATABASE_URL=postgresql://user:pass@localhost/db
        """.strip()

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            redactor.redact(test_output)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Secret redaction: {avg_time_ms:.4f}ms per 10KB (target: <{SECRET_REDACTOR_TARGET_MS}ms)")
        assert avg_time_ms < SECRET_REDACTOR_TARGET_MS

    def test_benchmark_secret_redaction_large(self):
        """Benchmark secret redaction with larger output."""
        redactor = SecretRedactor()
        # Generate ~10KB of output
        test_output = "\n".join([
            f"Line {i}: Some output with potential secrets API_KEY_{i}=fake-key-{i}"
            for i in range(200)
        ])

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            redactor.redact(test_output)
        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Secret redaction (large): {avg_time_ms:.4f}ms per 10KB")
        assert avg_time_ms < SECRET_REDACTOR_TARGET_MS


@pytest.mark.benchmark
@pytest.mark.skipif(
    not all([HAS_SSRF, HAS_UNICODE, HAS_CONFIG_SCANNER, HAS_SECRET_REDACTOR]),
    reason="Not all modules available"
)
class TestTotalOverhead:
    """Benchmark total overhead of all features combined."""

    def test_benchmark_total_overhead(self):
        """
        Benchmark total overhead of running all Phase 1-4 checks.

        This simulates the overhead added to a typical AI interaction.
        """
        # Initialize all scanners
        ssrf_protector = SSRFProtector()
        unicode_detector = UnicodeAttackDetector()
        secret_redactor = SecretRedactor()

        # Sample inputs
        test_command = "curl https://example.com/api"
        test_text = "normal text for checking"
        test_config_content = "# CLAUDE.md\nInstructions here"
        test_output = "Command output with potential secrets"

        start = time.perf_counter()
        for _ in range(ITERATIONS):
            # Phase 1: SSRF check
            ssrf_protector.check("Bash", {"command": test_command})

            # Phase 2: Unicode checks
            unicode_detector.detect_zero_width(test_text)
            unicode_detector.detect_bidi_override(test_text)
            unicode_detector.detect_homoglyphs(test_text)

            # Phase 3: Config scan
            check_config_file_threats("CLAUDE.md", test_config_content)

            # Phase 4: Secret redaction
            secret_redactor.redact(test_output)

        end = time.perf_counter()

        avg_time_ms = ((end - start) / ITERATIONS) * 1000

        print(f"\n✓ Total overhead: {avg_time_ms:.4f}ms (target: <{TOTAL_OVERHEAD_TARGET_MS}ms)")
        print(f"\n  Target overhead: <{TOTAL_OVERHEAD_TARGET_MS}ms")
        print(f"  Actual overhead: {avg_time_ms:.4f}ms")
        print(f"  Performance: {(TOTAL_OVERHEAD_TARGET_MS / avg_time_ms * 100):.1f}% of target")

        assert avg_time_ms < TOTAL_OVERHEAD_TARGET_MS, (
            f"Total overhead too high: {avg_time_ms:.4f}ms > {TOTAL_OVERHEAD_TARGET_MS}ms"
        )

    def test_memory_usage(self):
        """Test memory usage of all modules."""
        import sys

        # Get initial memory usage
        initial_objects = len(gc.get_objects()) if HAS_GC else 0

        # Initialize all scanners
        ssrf_protector = SSRFProtector()
        unicode_detector = UnicodeAttackDetector()
        secret_redactor = SecretRedactor()

        # Rough memory estimate
        final_objects = len(gc.get_objects()) if HAS_GC else 0
        objects_created = final_objects - initial_objects

        print(f"\n✓ Objects created: {objects_created}")

        # This is a rough check - actual memory profiling would need memory_profiler
        # For now, just ensure scanners can be created without errors
        assert ssrf_protector is not None
        assert unicode_detector is not None
        assert secret_redactor is not None


if __name__ == "__main__":
    # Run benchmarks with pytest
    pytest.main([__file__, "-v", "-m", "benchmark"])
