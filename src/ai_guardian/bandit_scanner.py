"""Bandit Python code security scanner for AI Guardian.

Scans Python source code for insecure patterns:
eval/exec, subprocess shell injection, weak crypto, SQL injection, etc.
"""

import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


@dataclass
class CodeSecurityFinding:
    rule_id: str
    description: str
    line_number: int
    severity: str
    confidence: str
    file_path: str
    end_line: Optional[int] = None
    start_column: Optional[int] = None
    snippet: Optional[str] = None


class BanditScanner:
    """Python code security scanner using Bandit."""

    name = "bandit"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        raw_threshold = self.config.get("severity_threshold", "MEDIUM")
        self._threshold = _SEVERITY_ORDER.get(raw_threshold.upper(), 1)
        self._allowlist: List[Dict[str, Any]] = self.config.get("allowlist", []) or []

    def scan(
        self, content: str, file_path: str = "unknown.py"
    ) -> List[CodeSecurityFinding]:
        """Scan Python source code for security issues.

        Writes content to a temp file, runs Bandit in-process, then applies
        severity threshold and allowlist filters.

        # nosec / # nosec B101 inline comments in source are honored natively
        by Bandit and those findings never surface.

        Args:
            content: Python source code to scan
            file_path: Original file path for finding attribution

        Returns:
            List of CodeSecurityFinding at or above the severity threshold,
            minus allowlist-suppressed entries.
        """
        if not content.strip():
            return []

        try:
            findings = self._run_bandit(content, file_path)
        except Exception as e:
            logger.warning("Bandit scan failed for %s: %s", file_path, e)
            return []

        return [f for f in findings if not self._is_allowlisted(f, file_path)]

    def _run_bandit(self, content: str, file_path: str) -> List[CodeSecurityFinding]:
        from bandit.core import config as b_config
        from bandit.core import manager as b_manager

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".py", prefix="ai-guardian-bandit-")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.write(content)

            conf = b_config.BanditConfig()
            mgr = b_manager.BanditManager(
                conf,
                agg_type="file",
                debug=False,
                verbose=False,
                profile=None,
                ignore_nosec=False,
            )
            mgr.discover_files([tmp_path], False)
            mgr.run_tests()

            lines = content.splitlines()
            findings = []
            for issue in mgr.results:
                sev = (issue.severity or "MEDIUM").upper()
                if _SEVERITY_ORDER.get(sev, 0) < self._threshold:
                    continue

                test_id = getattr(issue, "test_id", "") or ""
                if test_id and not test_id.startswith("B"):
                    test_id = f"B{test_id}"
                rule_id = test_id or "BANDIT"

                lineno = getattr(issue, "lineno", 0) or 0
                col = getattr(issue, "col_offset", None)
                confidence = (getattr(issue, "confidence", None) or "MEDIUM").upper()

                snippet = None
                if lineno and 1 <= lineno <= len(lines):
                    line_text = lines[lineno - 1]
                    # Honor inline ai-guardian:allow annotation
                    if "ai-guardian:allow" in line_text:
                        continue
                    snippet = line_text.strip()[:120]

                findings.append(
                    CodeSecurityFinding(
                        rule_id=rule_id,
                        description=issue.text or "Insecure code pattern detected",
                        line_number=lineno,
                        end_line=None,
                        start_column=col,
                        severity=sev,
                        confidence=confidence,
                        file_path=file_path,
                        snippet=snippet,
                    )
                )
            return findings
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _is_allowlisted(self, finding: CodeSecurityFinding, file_path: str) -> bool:
        """Check if finding matches any allowlist entry.

        Allowlist entry format:
            {"test_id": "B101", "file": "tests/", "reason": "..."}

        `test_id` is required; `file` is an optional path prefix filter.
        """
        for entry in self._allowlist:
            entry_test_id = entry.get("test_id", "")
            if entry_test_id and entry_test_id != finding.rule_id:
                continue
            entry_file = entry.get("file", "")
            if entry_file and not file_path.startswith(entry_file):
                continue
            return True
        return False
