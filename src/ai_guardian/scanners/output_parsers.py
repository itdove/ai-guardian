"""
Output parsers for different scanner engines.

Provides a unified interface for parsing output from different secret scanners,
normalizing their output into a common format.
"""

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, List


class ScannerOutputParser(ABC):
    """Abstract base class for scanner output parsers."""

    @abstractmethod
    def parse(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        Parse scanner output file into standardized format.

        Args:
            output_file: Path to scanner output file

        Returns:
            Standardized result dictionary with format:
            {
                "has_secrets": bool,
                "findings": [
                    {
                        "rule_id": str,
                        "file": str,
                        "line_number": int,
                        "description": str
                    },
                    ...
                ],
                "total_findings": int
            }
            Returns None if parsing fails.
        """
        pass


class GitleaksOutputParser(ScannerOutputParser):
    """
    Parser for Gitleaks and BetterLeaks output.

    Both tools use the same JSON format:
    [
        {
            "RuleID": "aws-access-token",
            "File": "test.txt",
            "StartLine": 5,
            "EndLine": 5,
            "Description": "AWS Access Key"
        },
        ...
    ]
    """

    def parse(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        Parse Gitleaks JSON output.

        Args:
            output_file: Path to Gitleaks JSON report

        Returns:
            Standardized result dict or None on error
        """
        try:
            output_path = Path(output_file)
            if not output_path.exists():
                logging.error(f"Gitleaks output file not found: {output_file}")
                return None

            with open(output_file, 'r', encoding='utf-8') as f:
                findings = json.load(f)

            # Empty list means no secrets
            if not findings:
                return {
                    "has_secrets": False,
                    "findings": [],
                    "total_findings": 0
                }

            # Convert to standardized format
            standardized_findings = []
            for finding in findings:
                standardized_findings.append({
                    "rule_id": finding.get("RuleID", "unknown"),
                    "file": finding.get("File", "unknown"),
                    "line_number": finding.get("StartLine", 0),
                    "end_line": finding.get("EndLine", 0),
                    "description": finding.get("Description", "Secret detected"),
                    "commit": finding.get("Commit", "N/A")
                })

            return {
                "has_secrets": True,
                "findings": standardized_findings,
                "total_findings": len(standardized_findings)
            }

        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse Gitleaks JSON output: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error parsing Gitleaks output: {e}")
            return None


class LeakTKOutputParser(ScannerOutputParser):
    """
    Parser for LeakTK output.

    LeakTK uses a different JSON format:
    {
        "findings": [
            {
                "RuleID": "aws-access-key",
                "File": "test.txt",
                "StartLine": 5,
                "Description": "AWS Access Key"
            }
        ],
        "errors": []
    }
    """

    def parse(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        Parse LeakTK JSON output.

        Args:
            output_file: Path to LeakTK JSON report

        Returns:
            Standardized result dict or None on error
        """
        try:
            output_path = Path(output_file)
            if not output_path.exists():
                logging.error(f"LeakTK output file not found: {output_file}")
                return None

            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Check for errors
            errors = data.get("errors", [])
            if errors:
                for error in errors:
                    logging.warning(f"LeakTK scanner error: {error}")

            # Get findings
            findings = data.get("findings", [])

            # Empty findings means no secrets
            if not findings:
                return {
                    "has_secrets": False,
                    "findings": [],
                    "total_findings": 0
                }

            # Convert to standardized format
            standardized_findings = []
            for finding in findings:
                standardized_findings.append({
                    "rule_id": finding.get("RuleID", "unknown"),
                    "file": finding.get("File", "unknown"),
                    "line_number": finding.get("StartLine", 0),
                    "end_line": finding.get("EndLine", 0),
                    "description": finding.get("Description", "Secret detected"),
                    "commit": finding.get("Commit", "N/A")
                })

            return {
                "has_secrets": True,
                "findings": standardized_findings,
                "total_findings": len(standardized_findings)
            }

        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse LeakTK JSON output: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error parsing LeakTK output: {e}")
            return None


class TruffleHogOutputParser(ScannerOutputParser):
    """
    Parser for TruffleHog v3 output.

    TruffleHog outputs newline-delimited JSON with format:
    {"SourceMetadata":{"Data":{"Filesystem":{"file":"test.txt","line":5}}},"DetectorName":"AWS","DetectorType":2,"Verified":false}
    {"SourceMetadata":{"Data":{"Filesystem":{"file":"test.txt","line":10}}},"DetectorName":"GitHub","DetectorType":13,"Verified":false}
    """

    def parse(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        Parse TruffleHog newline-delimited JSON output.

        Args:
            output_file: Path to TruffleHog output file (newline-delimited JSON)

        Returns:
            Standardized result dict or None on error
        """
        try:
            output_path = Path(output_file)
            if not output_path.exists():
                logging.error(f"TruffleHog output file not found: {output_file}")
                return None

            standardized_findings = []

            with open(output_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        finding = json.loads(line)

                        # Extract file and line information from SourceMetadata
                        source_meta = finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                        file_path = source_meta.get("file", "unknown")
                        line_number = source_meta.get("line", 0)

                        # Get detector information
                        detector_name = finding.get("DetectorName", "unknown")
                        verified = finding.get("Verified", False)

                        # Build description
                        description = f"{detector_name} secret detected"
                        if verified:
                            description += " (verified)"

                        standardized_findings.append({
                            "rule_id": detector_name.lower().replace(" ", "-"),
                            "file": file_path,
                            "line_number": line_number,
                            "end_line": line_number,
                            "description": description,
                            "commit": "N/A",
                            "verified": verified
                        })

                    except json.JSONDecodeError as e:
                        logging.warning(f"Failed to parse TruffleHog line {line_num}: {e}")
                        continue

            # No findings means no secrets
            if not standardized_findings:
                return {
                    "has_secrets": False,
                    "findings": [],
                    "total_findings": 0
                }

            return {
                "has_secrets": True,
                "findings": standardized_findings,
                "total_findings": len(standardized_findings)
            }

        except Exception as e:
            logging.error(f"Unexpected error parsing TruffleHog output: {e}")
            return None


class DetectSecretsOutputParser(ScannerOutputParser):
    """
    Parser for detect-secrets output.

    detect-secrets outputs a baseline JSON file with format:
    {
        "results": {
            "test.txt": [
                {
                    "type": "AWS Access Key",
                    "line_number": 5,
                    "hashed_secret": "abc123..."
                }
            ]
        },
        "version": "1.0.0"
    }
    """

    def parse(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        Parse detect-secrets baseline JSON output.

        Args:
            output_file: Path to detect-secrets baseline file

        Returns:
            Standardized result dict or None on error
        """
        try:
            output_path = Path(output_file)
            if not output_path.exists():
                logging.error(f"detect-secrets output file not found: {output_file}")
                return None

            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Get results
            results = data.get("results", {})

            # No results means no secrets
            if not results:
                return {
                    "has_secrets": False,
                    "findings": [],
                    "total_findings": 0
                }

            # Convert to standardized format
            standardized_findings = []
            for file_path, file_findings in results.items():
                for finding in file_findings:
                    secret_type = finding.get("type", "unknown")
                    line_number = finding.get("line_number", 0)

                    standardized_findings.append({
                        "rule_id": secret_type.lower().replace(" ", "-"),
                        "file": file_path,
                        "line_number": line_number,
                        "end_line": line_number,
                        "description": f"{secret_type} detected",
                        "commit": "N/A"
                    })

            return {
                "has_secrets": True,
                "findings": standardized_findings,
                "total_findings": len(standardized_findings)
            }

        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse detect-secrets JSON output: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error parsing detect-secrets output: {e}")
            return None


# Parser registry
OUTPUT_PARSERS = {
    "gitleaks": GitleaksOutputParser(),
    "leaktk": LeakTKOutputParser(),
    "trufflehog": TruffleHogOutputParser(),
    "detect-secrets": DetectSecretsOutputParser()
}


def get_parser(parser_name: str) -> ScannerOutputParser:
    """
    Get parser instance by name.

    Args:
        parser_name: Name of parser ('gitleaks' or 'leaktk')

    Returns:
        Parser instance

    Raises:
        ValueError: If parser name is unknown
    """
    if parser_name not in OUTPUT_PARSERS:
        raise ValueError(
            f"Unknown parser: {parser_name}. "
            f"Available parsers: {', '.join(OUTPUT_PARSERS.keys())}"
        )
    return OUTPUT_PARSERS[parser_name]
