"""
Tests for Custom Scanner SDK (Issue #474).

Tests the Scanner base class, Finding dataclass, Python scanner loader,
in-process execution, and integration with the engine framework.
"""

import os
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from ai_guardian.scanners.sdk import Scanner, Finding
from ai_guardian.scanners.python_loader import (
    load_from_file,
    load_from_module,
    load_python_scanner,
    discover_entry_points,
    discover_scanner_directory,
    _validate_path,
    _validate_scanner_class,
)
from ai_guardian.scanners.engine_builder import (
    EngineConfig,
    _build_engine_config,
    select_engine,
    select_all_engines,
)
from ai_guardian.scanners.executor import (
    run_python_scanner,
    run_engine,
)
from ai_guardian.scanners.strategies import ScanResult

# ---------------------------------------------------------------------------
# Sample scanner for testing
# ---------------------------------------------------------------------------


class SampleScanner(Scanner):
    """Test scanner that detects 'LEAK' in content."""

    name = "sample-scanner"
    version = "1.0.0"

    def scan(self, content: str, file_path: str = None) -> List[Finding]:
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            if "LEAK" in line:
                findings.append(
                    Finding(
                        rule_id="test-leak",
                        line_number=i,
                        matched_text=line.strip(),
                        description="Test leak detected",
                    )
                )
        return findings


class ConfigurableScanner(Scanner):
    """Scanner that accepts configuration."""

    name = "configurable-scanner"
    version = "2.0.0"

    def __init__(self):
        self.patterns = []

    def configure(self, config: dict) -> None:
        self.patterns = config.get("patterns", [])

    def scan(self, content: str, file_path: str = None) -> List[Finding]:
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            for pattern in self.patterns:
                if pattern in line:
                    findings.append(
                        Finding(
                            rule_id=f"custom-{pattern}",
                            line_number=i,
                            matched_text=line.strip(),
                            description=f"Pattern '{pattern}' detected",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# Finding dataclass tests
# ---------------------------------------------------------------------------


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_creation(self):
        f = Finding(
            rule_id="test-rule",
            line_number=42,
            matched_text="secret = 'abc123'",
            description="Test secret found",
        )
        assert f.rule_id == "test-rule"
        assert f.line_number == 42
        assert f.matched_text == "secret = 'abc123'"
        assert f.description == "Test secret found"

    def test_finding_defaults(self):
        f = Finding(
            rule_id="r",
            line_number=1,
            matched_text="x",
            description="d",
        )
        assert f.severity == "warning"
        assert f.end_line is None
        assert f.commit is None

    def test_finding_with_all_fields(self):
        f = Finding(
            rule_id="r",
            line_number=1,
            matched_text="x",
            description="d",
            severity="critical",
            end_line=5,
            commit="abc123",
        )
        assert f.severity == "critical"
        assert f.end_line == 5
        assert f.commit == "abc123"


# ---------------------------------------------------------------------------
# Scanner ABC tests
# ---------------------------------------------------------------------------


class TestScannerABC:
    """Tests for the Scanner abstract base class."""

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            Scanner()

    def test_subclass_must_implement_scan(self):
        class BadScanner(Scanner):
            name = "bad"

        with pytest.raises(TypeError):
            BadScanner()

    def test_subclass_works(self):
        scanner = SampleScanner()
        assert scanner.name == "sample-scanner"
        assert scanner.version == "1.0.0"

    def test_scan_finds_matches(self):
        scanner = SampleScanner()
        content = "line 1\nLEAK here\nline 3"
        findings = scanner.scan(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "test-leak"
        assert findings[0].line_number == 2

    def test_scan_no_matches(self):
        scanner = SampleScanner()
        findings = scanner.scan("safe content\nno issues here")
        assert findings == []

    def test_configure_method(self):
        scanner = ConfigurableScanner()
        scanner.configure({"patterns": ["SECRET", "TOKEN"]})
        content = "my SECRET value\nmy TOKEN here\nsafe line"
        findings = scanner.scan(content)
        assert len(findings) == 2

    def test_default_configure_is_noop(self):
        scanner = SampleScanner()
        scanner.configure({"anything": "goes"})

    def test_default_class_attributes(self):
        class MinimalScanner(Scanner):
            def scan(self, content, file_path=None):
                return []

        s = MinimalScanner()
        assert s.name == "custom"
        assert s.version == "0.0.0"


# ---------------------------------------------------------------------------
# Python loader tests
# ---------------------------------------------------------------------------


class TestValidation:
    """Tests for security validation helpers."""

    def test_validate_path_rejects_traversal(self):
        with pytest.raises(ValueError, match="Path traversal"):
            _validate_path("../../etc/passwd")

    def test_validate_path_accepts_normal(self):
        _validate_path("my_scanner.py")
        _validate_path("/home/user/scanners/test.py")

    def test_validate_scanner_class_rejects_non_scanner(self):
        with pytest.raises(TypeError, match="not a Scanner subclass"):
            _validate_scanner_class(str, "test")

    def test_validate_scanner_class_rejects_base_class(self):
        with pytest.raises(TypeError, match="Cannot use Scanner base class"):
            _validate_scanner_class(Scanner, "test")

    def test_validate_scanner_class_accepts_subclass(self):
        result = _validate_scanner_class(SampleScanner, "test")
        assert result is SampleScanner


class TestLoadFromFile:
    """Tests for loading scanners from .py files."""

    def test_load_from_file(self):
        scanner_code = textwrap.dedent("""\
            from ai_guardian.scanners.sdk import Scanner, Finding

            class FileScanner(Scanner):
                name = "file-scanner"
                version = "1.0.0"

                def scan(self, content, file_path=None):
                    return []
        """)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(scanner_code)
            f.flush()
            tmp_path = f.name

        try:
            cls = load_from_file(tmp_path, "FileScanner")
            assert issubclass(cls, Scanner)
            assert cls.name == "file-scanner"

            instance = cls()
            assert instance.scan("test") == []
        finally:
            os.unlink(tmp_path)

    def test_load_from_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_from_file("/nonexistent/scanner.py", "X")

    def test_load_from_file_not_py(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            tmp_path = f.name
        try:
            with pytest.raises(ValueError, match="must be a .py file"):
                load_from_file(tmp_path, "X")
        finally:
            os.unlink(tmp_path)

    def test_load_from_file_path_traversal(self):
        with pytest.raises(ValueError, match="Path traversal"):
            load_from_file("../../../etc/scanner.py", "X")


class TestLoadFromModule:
    """Tests for loading scanners from Python modules."""

    def test_load_from_module(self):
        cls = load_from_module("tests.unit.test_scanner_sdk", "SampleScanner")
        assert cls is SampleScanner

    def test_load_from_module_not_found(self):
        with pytest.raises(ImportError):
            load_from_module("nonexistent.module", "X")

    def test_load_from_module_class_not_found(self):
        with pytest.raises(AttributeError):
            load_from_module("tests.unit.test_scanner_sdk", "NonexistentClass")


class TestLoadPythonScanner:
    """Tests for the unified load_python_scanner function."""

    def test_load_via_module(self):
        spec = {
            "type": "python",
            "module": "tests.unit.test_scanner_sdk",
            "class": "SampleScanner",
        }
        scanner = load_python_scanner(spec)
        assert isinstance(scanner, Scanner)
        assert scanner.name == "sample-scanner"

    def test_load_via_file(self):
        scanner_code = textwrap.dedent("""\
            from ai_guardian.scanners.sdk import Scanner, Finding

            class TmpScanner(Scanner):
                name = "tmp-scanner"
                version = "0.1.0"
                def scan(self, content, file_path=None):
                    return []
        """)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(scanner_code)
            f.flush()
            tmp_path = f.name

        try:
            spec = {
                "type": "python",
                "path": tmp_path,
                "class": "TmpScanner",
            }
            scanner = load_python_scanner(spec)
            assert scanner.name == "tmp-scanner"
        finally:
            os.unlink(tmp_path)

    def test_load_with_config(self):
        spec = {
            "type": "python",
            "module": "tests.unit.test_scanner_sdk",
            "class": "ConfigurableScanner",
            "scanner_config": {"patterns": ["FOO"]},
        }
        scanner = load_python_scanner(spec)
        assert scanner.patterns == ["FOO"]

    def test_load_invalid_spec(self):
        with pytest.raises(ValueError, match="must include"):
            load_python_scanner({"type": "python"})


class TestDiscoverEntryPoints:
    """Tests for entry point discovery."""

    def test_discover_entry_points_empty(self):
        with patch(
            "ai_guardian.scanners.python_loader.importlib.metadata"
        ) as mock_meta:
            if sys.version_info >= (3, 12):
                mock_meta.entry_points.return_value = []
            else:
                mock_meta.entry_points.return_value = {}
            result = discover_entry_points()
            assert result == {}


class TestDiscoverScannerDirectory:
    """Tests for scanner directory auto-discovery."""

    def test_discover_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_dir = Path(tmpdir) / "scanners"
            scanner_dir.mkdir()
            with patch(
                "ai_guardian.config.utils.get_config_dir", return_value=Path(tmpdir)
            ):
                result = discover_scanner_directory()
                assert result == {}

    def test_discover_dir_not_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(
                "ai_guardian.config.utils.get_config_dir", return_value=Path(tmpdir)
            ):
                result = discover_scanner_directory()
                assert result == {}

    def test_discover_scanner_file(self):
        scanner_code = textwrap.dedent("""\
            from ai_guardian.scanners.sdk import Scanner, Finding

            class DirScanner(Scanner):
                name = "dir-scanner"
                version = "1.0.0"
                def scan(self, content, file_path=None):
                    return []
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_dir = Path(tmpdir) / "scanners"
            scanner_dir.mkdir()
            (scanner_dir / "my_scanner.py").write_text(scanner_code)

            with patch(
                "ai_guardian.config.utils.get_config_dir", return_value=Path(tmpdir)
            ):
                result = discover_scanner_directory()
                assert "dir-scanner" in result
                assert issubclass(result["dir-scanner"], Scanner)

    def test_discover_skips_underscored_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_dir = Path(tmpdir) / "scanners"
            scanner_dir.mkdir()
            (scanner_dir / "_helper.py").write_text("# not a scanner")

            with patch(
                "ai_guardian.config.utils.get_config_dir", return_value=Path(tmpdir)
            ):
                result = discover_scanner_directory()
                assert result == {}


# ---------------------------------------------------------------------------
# Engine builder integration tests
# ---------------------------------------------------------------------------


class TestEngineBuilderPython:
    """Tests for Python scanner integration in engine builder."""

    def test_build_engine_config_python(self):
        spec = {
            "type": "python",
            "module": "tests.unit.test_scanner_sdk",
            "class": "SampleScanner",
        }
        config = _build_engine_config(spec)
        assert config is not None
        assert config.type == "python"
        assert config.binary == "__python__"
        assert config.python_scanner is not None
        assert config.python_scanner.name == "sample-scanner"

    def test_build_engine_config_python_with_config(self):
        spec = {
            "type": "python",
            "module": "tests.unit.test_scanner_sdk",
            "class": "ConfigurableScanner",
            "scanner_config": {"patterns": ["TEST"]},
        }
        config = _build_engine_config(spec)
        assert config is not None
        assert config.python_scanner.patterns == ["TEST"]

    def test_build_engine_config_python_load_failure(self):
        spec = {
            "type": "python",
            "module": "nonexistent.module",
            "class": "X",
        }
        config = _build_engine_config(spec)
        assert config is None

    @patch("shutil.which", return_value=None)
    def test_select_engine_python_no_binary_needed(self, mock_which):
        """Python scanners don't need shutil.which — they're always available."""
        engines = [
            {
                "type": "python",
                "module": "tests.unit.test_scanner_sdk",
                "class": "SampleScanner",
            }
        ]
        config = select_engine(engines)
        assert config.type == "python"
        assert config.python_scanner is not None

    @patch("shutil.which", return_value=None)
    def test_select_all_engines_python(self, mock_which):
        """Python scanners appear in select_all_engines without binary check."""
        engines = [
            {
                "type": "python",
                "module": "tests.unit.test_scanner_sdk",
                "class": "SampleScanner",
            }
        ]
        configs = select_all_engines(engines)
        assert len(configs) == 1
        assert configs[0].type == "python"

    @patch("shutil.which", return_value="/usr/bin/gitleaks")
    def test_select_engine_mixed_python_and_subprocess(self, mock_which):
        """Python scanners work alongside subprocess engines."""
        engines = [
            "gitleaks",
            {
                "type": "python",
                "module": "tests.unit.test_scanner_sdk",
                "class": "SampleScanner",
            },
        ]
        configs = select_all_engines(engines)
        assert len(configs) == 2
        types = [c.type for c in configs]
        assert "gitleaks" in types
        assert "python" in types


# ---------------------------------------------------------------------------
# Executor tests
# ---------------------------------------------------------------------------


class TestRunPythonScanner:
    """Tests for the run_python_scanner function."""

    def test_run_python_scanner_no_findings(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("safe content\nno issues here\n")
            f.flush()
            tmp_path = f.name

        try:
            config = EngineConfig(
                type="python",
                binary="__python__",
                command_template=[],
                python_scanner=SampleScanner(),
            )
            result = run_python_scanner(config, tmp_path, "/dev/null")
            assert isinstance(result, ScanResult)
            assert result.has_secrets is False
            assert result.secrets == []
            assert result.engine == "sample-scanner"
            assert result.scan_time_ms >= 0
        finally:
            os.unlink(tmp_path)

    def test_run_python_scanner_with_findings(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("line 1\nLEAK secret here\nline 3\n")
            f.flush()
            tmp_path = f.name

        try:
            config = EngineConfig(
                type="python",
                binary="__python__",
                command_template=[],
                python_scanner=SampleScanner(),
            )
            result = run_python_scanner(config, tmp_path, "/dev/null")
            assert result.has_secrets is True
            assert len(result.secrets) == 1
            assert result.secrets[0].rule_id == "test-leak"
            assert result.secrets[0].line_number == 2
            assert result.secrets[0].engine == "sample-scanner"
        finally:
            os.unlink(tmp_path)

    def test_run_python_scanner_error_handling(self):
        class FailingScanner(Scanner):
            name = "failing"
            version = "0.0.0"

            def scan(self, content, file_path=None):
                raise RuntimeError("Scan failed")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("content\n")
            f.flush()
            tmp_path = f.name

        try:
            config = EngineConfig(
                type="python",
                binary="__python__",
                command_template=[],
                python_scanner=FailingScanner(),
            )
            result = run_python_scanner(config, tmp_path, "/dev/null")
            assert result.has_secrets is False
            assert result.error is not None
            assert "Scan failed" in result.error
        finally:
            os.unlink(tmp_path)

    def test_run_python_scanner_multiple_findings(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("LEAK one\nclean\nLEAK two\n")
            f.flush()
            tmp_path = f.name

        try:
            config = EngineConfig(
                type="python",
                binary="__python__",
                command_template=[],
                python_scanner=SampleScanner(),
            )
            result = run_python_scanner(config, tmp_path, "/dev/null")
            assert result.has_secrets is True
            assert len(result.secrets) == 2
            assert result.secrets[0].line_number == 1
            assert result.secrets[1].line_number == 3
        finally:
            os.unlink(tmp_path)

    @pytest.mark.parametrize(
        "original_file_path, expect_original",
        [("/real/path.txt", True), (None, False)],
        ids=["with-original-path", "without-original-path"],
    )
    def test_run_python_scanner_file_path_in_result(
        self, original_file_path, expect_original
    ):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("LEAK secret here\n")
            f.flush()
            tmp_path = f.name

        try:
            config = EngineConfig(
                type="python",
                binary="__python__",
                command_template=[],
                python_scanner=SampleScanner(),
            )
            kwargs = {}
            if original_file_path is not None:
                kwargs["original_file_path"] = original_file_path
            result = run_python_scanner(config, tmp_path, "/dev/null", **kwargs)
            assert result.has_secrets is True
            expected = original_file_path if expect_original else tmp_path
            assert result.secrets[0].file == expected
        finally:
            os.unlink(tmp_path)


class TestRunEngine:
    """Tests for the run_engine dispatcher."""

    def test_dispatches_to_python_scanner(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("LEAK\n")
            f.flush()
            tmp_path = f.name

        try:
            config = EngineConfig(
                type="python",
                binary="__python__",
                command_template=[],
                python_scanner=SampleScanner(),
            )
            result = run_engine(config, tmp_path, "/dev/null")
            assert result.has_secrets is True
            assert result.engine == "sample-scanner"
        finally:
            os.unlink(tmp_path)

    @patch("ai_guardian.scanners.executor.run_single_engine")
    def test_dispatches_to_subprocess_engine(self, mock_run):
        mock_run.return_value = ScanResult(
            has_secrets=False, secrets=[], engine="gitleaks"
        )
        config = EngineConfig(
            type="gitleaks",
            binary="gitleaks",
            command_template=["gitleaks"],
        )
        result = run_engine(config, "/tmp/test", "/tmp/report.json")
        assert result.engine == "gitleaks"
        mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# Strategy integration tests
# ---------------------------------------------------------------------------


class TestStrategyIntegration:
    """Test Python scanners work with all execution strategies."""

    def _make_python_config(self):
        return EngineConfig(
            type="python",
            binary="__python__",
            command_template=[],
            python_scanner=SampleScanner(),
        )

    def _write_temp_file(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        f.write(content)
        f.flush()
        f.close()
        return f.name

    def test_first_match_strategy(self):
        from ai_guardian.scanners.strategies import FirstMatchStrategy

        tmp_path = self._write_temp_file("LEAK secret\n")
        try:
            strategy = FirstMatchStrategy()
            result = strategy.execute(
                engine_configs=[self._make_python_config()],
                scanner_fn=run_engine,
                source_file=tmp_path,
                report_file_prefix="/tmp/test_report",
            )
            assert result.has_secrets is True
        finally:
            os.unlink(tmp_path)

    def test_any_match_strategy(self):
        from ai_guardian.scanners.strategies import AnyMatchStrategy

        tmp_path = self._write_temp_file("LEAK secret\n")
        try:
            strategy = AnyMatchStrategy()
            result = strategy.execute(
                engine_configs=[self._make_python_config()],
                scanner_fn=run_engine,
                source_file=tmp_path,
                report_file_prefix="/tmp/test_report",
            )
            assert result.has_secrets is True
        finally:
            os.unlink(tmp_path)

    def test_consensus_strategy(self):
        from ai_guardian.scanners.strategies import ConsensusStrategy

        tmp_path = self._write_temp_file("LEAK secret\n")
        try:
            strategy = ConsensusStrategy(threshold=1)
            result = strategy.execute(
                engine_configs=[self._make_python_config()],
                scanner_fn=run_engine,
                source_file=tmp_path,
                report_file_prefix="/tmp/test_report",
            )
            assert result.has_secrets is True
        finally:
            os.unlink(tmp_path)

    def test_first_match_no_findings(self):
        from ai_guardian.scanners.strategies import FirstMatchStrategy

        tmp_path = self._write_temp_file("clean content\n")
        try:
            strategy = FirstMatchStrategy()
            result = strategy.execute(
                engine_configs=[self._make_python_config()],
                scanner_fn=run_engine,
                source_file=tmp_path,
                report_file_prefix="/tmp/test_report",
            )
            assert result.has_secrets is False
        finally:
            os.unlink(tmp_path)
