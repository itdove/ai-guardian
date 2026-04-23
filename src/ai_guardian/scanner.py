#!/usr/bin/env python3
"""
Static file scanner for AI Guardian.

Scans repository files for security issues using all Phase 1-4 detectors:
- SSRF Protection (Phase 1)
- Unicode Attack Detection (Phase 2)
- Config File Scanner (Phase 3)
- Secret Redaction/Detection (Phase 4)
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import fnmatch


# Import Phase 1-4 scanners
try:
    from ai_guardian.ssrf_protector import SSRFProtector
    HAS_SSRF = True
except ImportError:
    HAS_SSRF = False

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
    from ai_guardian.sarif_formatter import (
        SARIFFormatter,
        create_ssrf_finding,
        create_unicode_finding,
        create_config_finding,
        create_secret_finding,
    )
    HAS_SARIF = True
except ImportError:
    HAS_SARIF = False


logger = logging.getLogger(__name__)


# Config file patterns (from Phase 3)
CONFIG_FILE_PATTERNS = [
    "CLAUDE.md",
    "AGENTS.md",
    ".cursorrules",
    "*.aider*",
    ".github/copilot-instructions.md",
    "ai-guardian.json",
    ".ai-guardian.json",
]


class FileScanner:
    """Static file scanner for security issues."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        verbose: bool = False
    ):
        """
        Initialize file scanner.

        Args:
            config: AI Guardian configuration dict
            verbose: Enable verbose output
        """
        self.config = config or {}
        self.verbose = verbose
        self.findings: List[Dict[str, Any]] = []

        # Initialize scanners with feature-specific sub-configs
        self.ssrf_protector = SSRFProtector(config.get("ssrf_protection", {})) if HAS_SSRF else None
        self.unicode_detector = UnicodeAttackDetector(config.get("prompt_injection", {})) if HAS_UNICODE else None

    def scan_directory(
        self,
        path: str,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        config_only: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Scan directory for security issues.

        Args:
            path: Directory path to scan
            include_patterns: File patterns to include (glob style)
            exclude_patterns: File patterns to exclude (glob style)
            config_only: Only scan AI config files

        Returns:
            List of findings
        """
        self.findings = []
        scan_path = Path(path).resolve()

        if not scan_path.exists():
            logger.error(f"Path does not exist: {path}")
            return self.findings

        if scan_path.is_file():
            # Scan single file
            self._scan_file(scan_path, scan_path.parent)
        else:
            # Scan directory
            files_to_scan = self._discover_files(
                scan_path,
                include_patterns,
                exclude_patterns,
                config_only
            )

            if self.verbose:
                print(f"Scanning {len(files_to_scan)} files...")

            for file_path in files_to_scan:
                self._scan_file(file_path, scan_path)

        return self.findings

    def _discover_files(
        self,
        base_path: Path,
        include_patterns: Optional[List[str]],
        exclude_patterns: Optional[List[str]],
        config_only: bool
    ) -> List[Path]:
        """
        Discover files to scan.

        Args:
            base_path: Base directory to search
            include_patterns: File patterns to include
            exclude_patterns: File patterns to exclude
            config_only: Only include config files

        Returns:
            List of file paths to scan
        """
        files: Set[Path] = set()

        # Default exclude patterns
        default_excludes = [
            ".git/*",
            ".git/**/*",
            "__pycache__/*",
            "__pycache__/**/*",
            "*.pyc",
            "node_modules/*",
            "node_modules/**/*",
            ".venv/*",
            ".venv/**/*",
            "venv/*",
            "venv/**/*",
            "*.min.js",
            "*.map",
        ]

        exclude_patterns = (exclude_patterns or []) + default_excludes

        if config_only:
            # Only scan config files
            for pattern in CONFIG_FILE_PATTERNS:
                for file_path in base_path.rglob(pattern):
                    if file_path.is_file() and not self._is_excluded(file_path, base_path, exclude_patterns):
                        files.add(file_path)
        elif include_patterns:
            # Scan files matching include patterns
            for pattern in include_patterns:
                for file_path in base_path.rglob(pattern):
                    if file_path.is_file() and not self._is_excluded(file_path, base_path, exclude_patterns):
                        files.add(file_path)
        else:
            # Scan all text files
            for file_path in base_path.rglob("*"):
                if (
                    file_path.is_file()
                    and not self._is_excluded(file_path, base_path, exclude_patterns)
                    and self._is_text_file(file_path)
                ):
                    files.add(file_path)

        return sorted(files)

    def _is_excluded(self, file_path: Path, base_path: Path, exclude_patterns: List[str]) -> bool:
        """
        Check if file should be excluded.

        Args:
            file_path: File to check
            base_path: Base scan directory
            exclude_patterns: Exclusion patterns

        Returns:
            True if file should be excluded
        """
        try:
            relative_path = file_path.relative_to(base_path)
        except ValueError:
            return True

        for pattern in exclude_patterns:
            if fnmatch.fnmatch(str(relative_path), pattern):
                return True
            if fnmatch.fnmatch(file_path.name, pattern):
                return True

        return False

    def _is_text_file(self, file_path: Path) -> bool:
        """
        Check if file is likely a text file.

        Args:
            file_path: File to check

        Returns:
            True if likely a text file
        """
        # Check extension
        text_extensions = {
            ".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml",
            ".sh", ".bash", ".zsh", ".fish", ".js", ".ts", ".jsx", ".tsx",
            ".html", ".css", ".xml", ".sql", ".go", ".rs", ".c", ".cpp",
            ".h", ".hpp", ".java", ".rb", ".php", ".pl", ".swift", ".kt",
            ".scala", ".r", ".m", ".mm", ".vim", ".el", ".lua", ".tcl",
            ".awk", ".sed", ".gradle", ".properties", ".conf", ".cfg",
            ".ini", ".env", ".gitignore", ".dockerignore", ".editorconfig",
        }

        if file_path.suffix.lower() in text_extensions:
            return True

        # Check for files without extensions that are likely text
        if not file_path.suffix and file_path.name in [
            "Dockerfile", "Makefile", "Rakefile", "Gemfile",
            "LICENSE", "README", "CHANGELOG", "AUTHORS"
        ]:
            return True

        return False

    def _scan_file(self, file_path: Path, base_path: Path) -> None:
        """
        Scan a single file for security issues.

        Args:
            file_path: File to scan
            base_path: Base scan directory (for relative paths)
        """
        try:
            # Get relative path for reporting
            try:
                relative_path = str(file_path.relative_to(base_path))
            except ValueError:
                relative_path = str(file_path)

            # Read file content
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Could not read {relative_path}: {e}")
                return

            # Skip empty files
            if not content.strip():
                return

            if self.verbose:
                print(f"Scanning: {relative_path}")

            # Check for config file threats (Phase 3)
            if self._is_config_file(file_path) and HAS_CONFIG_SCANNER:
                self._check_config_threats(relative_path, content)

            # Check for SSRF patterns (Phase 1)
            if self.ssrf_protector:
                self._check_ssrf(relative_path, content)

            # Check for Unicode attacks (Phase 2)
            if self.unicode_detector:
                self._check_unicode_attacks(relative_path, content)

            # Note: Secret scanning (Phase 4) is typically done via gitleaks
            # which runs as a separate process. We could integrate it here
            # in the future if needed.

        except Exception as e:
            if self.verbose:
                logger.error(f"Error scanning {file_path}: {e}")

    def _is_config_file(self, file_path: Path) -> bool:
        """Check if file is an AI config file."""
        file_name = file_path.name
        for pattern in CONFIG_FILE_PATTERNS:
            if fnmatch.fnmatch(file_name, pattern):
                return True
        return False

    def _check_config_threats(self, file_path: str, content: str) -> None:
        """Check config file for exfiltration threats."""
        try:
            is_malicious, reason, details = check_config_file_threats(file_path, content, self.config)
            if is_malicious:
                finding = create_config_finding(
                    pattern=details.get("pattern", "unknown"),
                    reason=reason,
                    file_path=file_path,
                    line_number=details.get("line_number"),
                    snippet=details.get("snippet")
                )
                self.findings.append(finding)
                if self.verbose:
                    print(f"  [CONFIG] {reason}")
        except Exception as e:
            logger.debug(f"Error checking config threats: {e}")

    def _check_ssrf(self, file_path: str, content: str) -> None:
        """Check for SSRF patterns in file content."""
        try:
            # Check content as if it were a Bash command
            # This allows us to detect URLs in any context
            should_block, reason = self.ssrf_protector.check("Bash", {"command": content})

            if should_block:
                # Extract the problematic URL from the reason or content
                import re
                url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                urls = re.findall(url_pattern, content)

                # Find which URL triggered the block
                for url in urls:
                    # Test each URL individually
                    url_should_block, url_reason = self.ssrf_protector.check("Bash", {"command": f"curl {url}"})
                    if url_should_block:
                        # Find line number
                        line_number = None
                        snippet = None
                        for i, line in enumerate(content.split('\n'), 1):
                            if url in line:
                                line_number = i
                                snippet = line.strip()
                                break

                        finding = create_ssrf_finding(
                            url=url,
                            reason=url_reason or reason,
                            file_path=file_path,
                            line_number=line_number,
                            snippet=snippet
                        )
                        self.findings.append(finding)
                        if self.verbose:
                            print(f"  [SSRF] {url_reason or reason}: {url}")
        except Exception as e:
            logger.debug(f"Error checking SSRF: {e}")

    def _check_unicode_attacks(self, file_path: str, content: str) -> None:
        """Check for Unicode attacks in file content."""
        try:
            # Check zero-width characters
            is_attack, details = self.unicode_detector.detect_zero_width(content)
            if is_attack:
                finding = create_unicode_finding(
                    attack_type="zero-width characters",
                    details=f"Zero-width characters detected: {details}",
                    file_path=file_path
                )
                self.findings.append(finding)
                if self.verbose:
                    print(f"  [UNICODE] Zero-width characters detected")

            # Check bidirectional override
            is_attack, details = self.unicode_detector.detect_bidi_override(content)
            if is_attack:
                finding = create_unicode_finding(
                    attack_type="bidirectional override",
                    details="Bidirectional override characters detected",
                    file_path=file_path
                )
                self.findings.append(finding)
                if self.verbose:
                    print(f"  [UNICODE] Bidirectional override detected")

            # Check homoglyphs
            is_attack, details = self.unicode_detector.detect_homoglyphs(content)
            if is_attack:
                finding = create_unicode_finding(
                    attack_type="homoglyphs",
                    details=f"Homoglyph characters detected: {details}",
                    file_path=file_path
                )
                self.findings.append(finding)
                if self.verbose:
                    print(f"  [UNICODE] Homoglyphs detected")

            # Check tag characters
            is_attack, details = self.unicode_detector.detect_tag_chars(content)
            if is_attack:
                finding = create_unicode_finding(
                    attack_type="tag characters",
                    details=f"Tag characters detected: {details}",
                    file_path=file_path
                )
                self.findings.append(finding)
                if self.verbose:
                    print(f"  [UNICODE] Tag characters detected")

        except Exception as e:
            logger.debug(f"Error checking Unicode attacks: {e}")


def scan_command(args) -> int:
    """
    Handle the scan command.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, 1 for issues found)
    """
    # Load configuration
    config = {}
    if hasattr(args, 'config') and args.config:
        try:
            with open(args.config, encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}", file=sys.stderr)

    # Initialize scanner
    scanner = FileScanner(config=config, verbose=args.verbose)

    # Scan files
    findings = scanner.scan_directory(
        path=args.path,
        include_patterns=args.include if hasattr(args, 'include') else None,
        exclude_patterns=args.exclude if hasattr(args, 'exclude') else None,
        config_only=args.config_only if hasattr(args, 'config_only') else False
    )

    # Output results
    if args.sarif_output and HAS_SARIF:
        # SARIF output
        from ai_guardian import __version__
        formatter = SARIFFormatter(version=__version__)
        formatter.write_sarif_file(findings, args.sarif_output, scan_path=args.path)
        if args.verbose or not args.json_output:
            print(f"SARIF output written to: {args.sarif_output}")

    if args.json_output:
        # JSON output
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
        if args.verbose or not args.sarif_output:
            print(f"JSON output written to: {args.json_output}")

    # Text output (default)
    if not args.sarif_output and not args.json_output:
        if findings:
            print(f"\n🛡️ AI Guardian Scan Results\n")
            print(f"Found {len(findings)} security issue(s):\n")
            for i, finding in enumerate(findings, 1):
                print(f"{i}. [{finding['rule_id']}] {finding['message']}")
                if finding.get('file_path'):
                    print(f"   File: {finding['file_path']}", end="")
                    if finding.get('line_number'):
                        print(f":{finding['line_number']}")
                    else:
                        print()
                if finding.get('snippet'):
                    print(f"   Code: {finding['snippet']}")
                print()
        else:
            print("✅ No security issues detected")

    # Exit code
    if args.exit_code and findings:
        return 1
    return 0
