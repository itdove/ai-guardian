"""
Scan finding analyzer for init-project --scan.

Clusters FileScanner findings by (rule_id, sub_type), identifies
high-frequency patterns as likely false positives, and generates
config recommendations for ai-guardian.json and .aiguardignore.toml.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any, Dict, List, Optional, Set, Tuple

RULE_ID_TO_SCANNER = {
    "SECRET-001": "secret_scanning",
    "PII-001": "scan_pii",
    "PROMPT-INJECTION-001": "prompt_injection",
    "CONFIG-001": "config_file_scanning",
    "SUPPLY-CHAIN-001": "supply_chain",
    "EXFIL-DETECTION-001": "exfil_detection",
}

NEVER_SUPPRESS = frozenset({"SSRF-001", "UNICODE-001", "canary_detected"})

MAX_SAMPLE_FILES = 5


@dataclass
class FindingCluster:
    """A group of findings sharing the same fingerprint."""

    rule_id: str
    sub_type: str
    file_count: int = 0
    total_count: int = 0
    sample_files: List[str] = field(default_factory=list)


@dataclass
class DirectoryAnalysis:
    """Analysis of a first-level directory's findings."""

    directory: str
    total_findings: int = 0
    high_frequency_findings: int = 0

    @property
    def all_high_frequency(self) -> bool:
        return (
            self.total_findings > 0
            and self.total_findings == self.high_frequency_findings
        )


@dataclass
class ScanAnalysisResult:
    """Complete analysis output."""

    total_findings: int = 0
    total_files_scanned: int = 0
    clusters: List[FindingCluster] = field(default_factory=list)
    high_frequency_clusters: List[FindingCluster] = field(default_factory=list)
    directories_to_ignore: List[DirectoryAnalysis] = field(default_factory=list)
    recommended_config: Dict[str, Any] = field(default_factory=dict)
    recommended_ignore_paths: Dict[str, List[str]] = field(default_factory=dict)
    suppressed_count: int = 0


def fingerprint_finding(finding: Dict[str, Any]) -> Tuple[str, str]:
    """Extract (rule_id, sub_type) from a finding dict."""
    rule_id = finding.get("rule_id", "")
    details = finding.get("details", {})

    if rule_id == "SECRET-001":
        return (rule_id, details.get("secret_type", "unknown"))
    if rule_id == "PII-001":
        return (rule_id, details.get("pii_type", "unknown"))
    if rule_id == "PROMPT-INJECTION-001":
        desc = details.get("description", "")
        return (rule_id, _normalize_pi_description(desc))
    if rule_id == "SUPPLY-CHAIN-001":
        return (rule_id, details.get("category", "unknown"))
    if rule_id == "CONFIG-001":
        return (rule_id, details.get("pattern", details.get("category", "unknown")))
    if rule_id == "EXFIL-DETECTION-001":
        return (rule_id, details.get("category", "unknown"))

    return (rule_id, "")


def _normalize_pi_description(desc: str) -> str:
    """Normalize a PI description to a canonical pattern key.

    Strips varying parts (file names, line numbers) and keeps the
    detection category.
    """
    first_line = desc.split("\n")[0].strip() if desc else ""
    first_line = re.sub(r"\s+at line \d+", "", first_line)
    first_line = re.sub(r"\s+in .+$", "", first_line)
    return first_line


def cluster_findings(findings: List[Dict[str, Any]]) -> List[FindingCluster]:
    """Group findings by fingerprint."""
    groups: Dict[Tuple[str, str], Dict] = defaultdict(
        lambda: {"files": set(), "count": 0, "sample_files": []}
    )

    for finding in findings:
        fp = fingerprint_finding(finding)
        g = groups[fp]
        g["count"] += 1
        file_path = finding.get("file_path") or ""
        if file_path and file_path not in g["files"]:
            g["files"].add(file_path)
            if len(g["sample_files"]) < MAX_SAMPLE_FILES:
                g["sample_files"].append(file_path)

    clusters = []
    for (rule_id, sub_type), g in sorted(groups.items()):
        clusters.append(
            FindingCluster(
                rule_id=rule_id,
                sub_type=sub_type,
                file_count=len(g["files"]),
                total_count=g["count"],
                sample_files=g["sample_files"],
            )
        )

    return clusters


def analyze_directories(
    findings: List[Dict[str, Any]],
    high_freq_fingerprints: Set[Tuple[str, str]],
) -> List[DirectoryAnalysis]:
    """Analyze first-level directories for ignore recommendations."""
    dir_stats: Dict[str, Dict] = defaultdict(lambda: {"total": 0, "high_freq": 0})

    for finding in findings:
        file_path = finding.get("file_path") or ""
        if not file_path:
            continue

        parts = PurePath(file_path).parts
        if not parts:
            continue
        top_dir = parts[0] if len(parts) > 1 else ""
        if not top_dir:
            continue

        fp = fingerprint_finding(finding)
        stats = dir_stats[top_dir]
        stats["total"] += 1
        if fp in high_freq_fingerprints:
            stats["high_freq"] += 1

    analyses = []
    for directory, stats in sorted(dir_stats.items()):
        analyses.append(
            DirectoryAnalysis(
                directory=directory,
                total_findings=stats["total"],
                high_frequency_findings=stats["high_freq"],
            )
        )

    return analyses


_NO_CONFIG_SCANNERS = frozenset({"scan_pii", "code_scanning"})


def _scanner_for_rule_id(rule_id: str) -> Optional[str]:
    """Map a rule_id to its scanner type. Returns None for never-suppress rules."""
    if rule_id in NEVER_SUPPRESS:
        return None
    scanner = RULE_ID_TO_SCANNER.get(rule_id)
    if scanner:
        return scanner
    if re.match(r"^B\d+", rule_id):
        return "code_scanning"
    return None


def build_recommendations(
    findings: List[Dict[str, Any]],
    threshold: int = 10,
) -> ScanAnalysisResult:
    """Analyze findings and build suppression recommendations."""
    clusters = cluster_findings(findings)

    high_freq = [
        c
        for c in clusters
        if c.file_count >= threshold
        and c.rule_id not in NEVER_SUPPRESS
        and _scanner_for_rule_id(c.rule_id) not in _NO_CONFIG_SCANNERS
    ]

    high_freq_fps: Set[Tuple[str, str]] = {(c.rule_id, c.sub_type) for c in high_freq}

    dir_analyses = analyze_directories(findings, high_freq_fps)
    dirs_to_ignore = [d for d in dir_analyses if d.all_high_frequency]

    dir_scanner_map: Dict[str, Set[str]] = defaultdict(set)
    for finding in findings:
        fp = finding.get("file_path") or ""
        parts = PurePath(fp).parts
        if parts and len(parts) > 1:
            scanner = _scanner_for_rule_id(finding.get("rule_id", ""))
            if scanner:
                dir_scanner_map[parts[0]].add(scanner)

    config = _build_config(high_freq)
    ignore_paths = _build_ignore_paths(dirs_to_ignore, dir_scanner_map)

    suppressed = sum(c.total_count for c in high_freq)

    all_files = {f.get("file_path") for f in findings if f.get("file_path")}

    return ScanAnalysisResult(
        total_findings=len(findings),
        total_files_scanned=len(all_files),
        clusters=clusters,
        high_frequency_clusters=high_freq,
        directories_to_ignore=dirs_to_ignore,
        recommended_config=config,
        recommended_ignore_paths=ignore_paths,
        suppressed_count=suppressed,
    )


def _build_config(high_freq_clusters: List[FindingCluster]) -> Dict[str, Any]:
    """Build ai-guardian.json config sections from high-frequency clusters."""
    config: Dict[str, Any] = {}

    by_scanner: Dict[str, List[FindingCluster]] = defaultdict(list)
    for cluster in high_freq_clusters:
        scanner = _scanner_for_rule_id(cluster.rule_id)
        if scanner:
            by_scanner[scanner].append(cluster)

    for scanner, clusters_list in sorted(by_scanner.items()):
        section = config.setdefault(scanner, {})

        if scanner == "secret_scanning":
            patterns = section.setdefault("allowlist_patterns", [])
            for c in clusters_list:
                pattern = re.escape(c.sub_type)
                if pattern not in patterns:
                    patterns.append(pattern)

        elif scanner == "prompt_injection":
            patterns = section.setdefault("allowlist_patterns", [])
            for c in clusters_list:
                pattern = re.escape(c.sub_type)
                if pattern not in patterns:
                    patterns.append(pattern)

    return config


def _build_ignore_paths(
    dirs_to_ignore: List[DirectoryAnalysis],
    dir_scanner_map: Dict[str, Set[str]],
) -> Dict[str, List[str]]:
    """Build .aiguardignore.toml paths from directory analysis."""
    ignore_paths: Dict[str, List[str]] = defaultdict(list)

    for dir_analysis in dirs_to_ignore:
        dir_name = dir_analysis.directory
        pattern = f"{dir_name}/**"

        for scanner in sorted(dir_scanner_map.get(dir_name, set())):
            if pattern not in ignore_paths[scanner]:
                ignore_paths[scanner].append(pattern)

    return dict(ignore_paths)
