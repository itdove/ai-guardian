"""
Compliance report generation for secret scanning.

Generates reports for compliance frameworks (HIPAA, PCI-DSS, SOC2)
using audit log data.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from ai_guardian.scanners.audit import ScanAuditLogger


COMPLIANCE_FRAMEWORKS = {
    "hipaa": {
        "name": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act",
        "requires": ["multi_engine", "audit_logging"],
    },
    "pci-dss": {
        "name": "PCI-DSS",
        "description": "Payment Card Industry Data Security Standard",
        "requires": ["secret_scanning", "audit_logging"],
    },
    "soc2": {
        "name": "SOC 2",
        "description": "Service Organization Control 2",
        "requires": ["secret_scanning"],
    },
}


class ComplianceReporter:
    """Generate compliance reports from audit logs."""

    def __init__(self, audit_logger: Optional[ScanAuditLogger] = None):
        self.audit = audit_logger or ScanAuditLogger()

    def generate_report(
        self,
        framework: str,
        days: int = 30,
    ) -> Dict[str, Any]:
        entries = self.audit.get_recent_entries(limit=100000)

        cutoff = time.time() - (days * 86400)
        filtered = []
        for e in entries:
            ts = e.get("timestamp", "")
            try:
                entry_time = datetime.fromisoformat(ts).timestamp()
                if entry_time >= cutoff:
                    filtered.append(e)
            except (ValueError, TypeError):
                filtered.append(e)

        scan_entries = [e for e in filtered if e.get("event") == "scan_completed"]
        failure_entries = [e for e in filtered if e.get("event") == "engine_failure"]

        engines_used = list(set(e.get("engine", "") for e in scan_entries if e.get("engine")))
        strategies_used = list(set(e.get("strategy", "") for e in scan_entries if e.get("strategy")))

        report = {
            "framework": framework,
            "framework_name": COMPLIANCE_FRAMEWORKS.get(framework, {}).get("name", framework),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period_days": days,
            "summary": {
                "total_scans": len(scan_entries),
                "secrets_detected": sum(1 for e in scan_entries if e.get("has_secrets")),
                "engine_failures": len(failure_entries),
                "engines_used": engines_used,
                "strategies_used": strategies_used,
            },
            "compliance_checks": self._check_compliance(framework, scan_entries),
        }

        return report

    def _check_compliance(
        self, framework: str, entries: List[Dict]
    ) -> List[Dict]:
        checks = []

        fw = COMPLIANCE_FRAMEWORKS.get(framework, {})
        requirements = fw.get("requires", [])

        if "secret_scanning" in requirements:
            checks.append({
                "check": "Secret scanning active",
                "status": "pass" if entries else "fail",
                "details": f"{len(entries)} scans performed",
            })

        if "multi_engine" in requirements:
            engines = set(e.get("engine", "") for e in entries)
            multi = len(engines) > 1
            checks.append({
                "check": "Multi-engine scanning",
                "status": "pass" if multi else "warn",
                "details": f"{len(engines)} engine(s): {', '.join(sorted(engines))}",
            })

        if "audit_logging" in requirements:
            checks.append({
                "check": "Audit logging enabled",
                "status": "pass" if entries else "fail",
                "details": f"{len(entries)} audit entries",
            })

        return checks

    def export_for_audit(
        self,
        output_path: Path,
        days: int = 90,
    ) -> None:
        entries = self.audit.get_recent_entries(limit=100000)
        export = {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "period_days": days,
            "entry_count": len(entries),
            "entries": entries,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2)
