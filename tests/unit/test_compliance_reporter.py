"""Tests for compliance reporting."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ai_guardian.scanners.audit import ScanAuditLogger
from ai_guardian.scanners.compliance import ComplianceReporter
from ai_guardian.scanners.strategies import ScanResult


class TestComplianceReporter(unittest.TestCase):

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.log_path = Path(self.tmp.name) / "audit.jsonl"
        self.audit = ScanAuditLogger(log_path=self.log_path)
        self.reporter = ComplianceReporter(audit_logger=self.audit)

    def tearDown(self):
        self.tmp.cleanup()

    def _log_scans(self, count=5, engine="gitleaks", has_secrets=False):
        for i in range(count):
            result = ScanResult(
                has_secrets=has_secrets, secrets=[],
                engine=engine, scan_time_ms=50.0,
            )
            self.audit.log_scan(result, f"file{i}.py", strategy="first-match")

    def test_generate_hipaa_report(self):
        self._log_scans(3, engine="gitleaks")
        self._log_scans(2, engine="trufflehog")
        report = self.reporter.generate_report("hipaa", days=30)
        self.assertEqual(report["framework"], "hipaa")
        self.assertEqual(report["framework_name"], "HIPAA")
        self.assertEqual(report["summary"]["total_scans"], 5)
        checks = {c["check"]: c for c in report["compliance_checks"]}
        self.assertEqual(checks["Multi-engine scanning"]["status"], "pass")

    def test_generate_pci_report(self):
        self._log_scans(3)
        report = self.reporter.generate_report("pci-dss", days=30)
        self.assertEqual(report["framework"], "pci-dss")
        checks = {c["check"]: c for c in report["compliance_checks"]}
        self.assertEqual(checks["Secret scanning active"]["status"], "pass")

    def test_single_engine_multi_engine_warn(self):
        self._log_scans(3, engine="gitleaks")
        report = self.reporter.generate_report("hipaa")
        checks = {c["check"]: c for c in report["compliance_checks"]}
        self.assertEqual(checks["Multi-engine scanning"]["status"], "warn")

    def test_empty_entries(self):
        report = self.reporter.generate_report("soc2")
        self.assertEqual(report["summary"]["total_scans"], 0)
        checks = {c["check"]: c for c in report["compliance_checks"]}
        self.assertEqual(checks["Secret scanning active"]["status"], "fail")

    def test_export_for_audit(self):
        self._log_scans(3)
        export_path = Path(self.tmp.name) / "export.json"
        self.reporter.export_for_audit(export_path, days=90)
        self.assertTrue(export_path.exists())
        data = json.loads(export_path.read_text())
        self.assertEqual(data["entry_count"], 3)
        self.assertEqual(len(data["entries"]), 3)


if __name__ == "__main__":
    unittest.main()
