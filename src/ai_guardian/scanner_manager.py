#!/usr/bin/env python3
"""
Scanner Manager for ai-guardian.

Manages and lists installed scanner engines.
"""

import json
import logging
import shutil
import subprocess
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


@dataclass
class InstalledScanner:
    """Information about an installed scanner."""

    name: str
    version: str
    path: str
    is_default: bool


class ScannerManager:
    """Manages installed scanner engines."""

    SUPPORTED_SCANNERS = ["gitleaks", "betterleaks", "leaktk", "trufflehog", "detect-secrets", "secretlint", "gitguardian"]

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize scanner manager.

        Args:
            config: AI Guardian configuration dict
        """
        self.config = config or {}

    def _get_version(self, scanner_name: str) -> str:
        """
        Get version of installed scanner.

        Args:
            scanner_name: Scanner name

        Returns:
            Version string or "unknown" if cannot be determined
        """
        try:
            # Try running scanner with version command
            result = subprocess.run(
                [scanner_name, "version"],
                capture_output=True,
                timeout=5,
                text=True,
            )

            if result.returncode != 0:
                return "unknown"

            # Parse version from output
            # Different scanners have different version output formats
            output = result.stdout + result.stderr

            # Common patterns: "v1.2.3", "version 1.2.3", "1.2.3"
            version_patterns = [
                r"v?(\d+\.\d+\.\d+)",  # Semantic version with optional 'v'
                r"version\s+v?(\d+\.\d+\.\d+)",  # "version X.Y.Z"
            ]

            for pattern in version_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    return match.group(1)

            # If no pattern matched, return first line (often contains version)
            first_line = output.strip().split("\n")[0]
            if first_line:
                return first_line.strip()

            return "unknown"

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"Failed to get version for {scanner_name}: {e}")
            return "unknown"

    def _is_default_scanner(self, scanner_name: str) -> bool:
        """
        Check if scanner is the default scanner in config.

        Args:
            scanner_name: Scanner name

        Returns:
            True if this is the default scanner
        """
        # Check secret_scanning.engines config
        secret_config = self.config.get("secret_scanning", {})
        engines = secret_config.get("engines", [])

        if not engines:
            # No engines configured, gitleaks is default
            return scanner_name == "gitleaks"

        # First engine in list is default
        first_engine = engines[0]
        if isinstance(first_engine, str):
            return first_engine == scanner_name
        elif isinstance(first_engine, dict):
            return first_engine.get("type") == scanner_name

        return False

    def list_installed(self) -> List[InstalledScanner]:
        """
        List all installed scanners.

        Returns:
            List of InstalledScanner objects
        """
        installed = []

        for scanner_name in self.SUPPORTED_SCANNERS:
            path = shutil.which(scanner_name)
            if path:
                version = self._get_version(scanner_name)
                is_default = self._is_default_scanner(scanner_name)
                installed.append(
                    InstalledScanner(
                        name=scanner_name,
                        version=version,
                        path=path,
                        is_default=is_default,
                    )
                )

        return installed

    def print_scanner_list(self, verbose: bool = False):
        """
        Print formatted list of installed scanners.

        Args:
            verbose: Include extra details
        """
        scanners = self.list_installed()

        if not scanners:
            print("\nNo scanners installed.\n")
            print("Install a scanner:")
            print("  ai-guardian scanner install gitleaks")
            print("  ai-guardian scanner install betterleaks")
            print("  ai-guardian scanner install leaktk")
            return

        print("\nInstalled scanners:\n")
        for scanner in scanners:
            default_marker = " (default)" if scanner.is_default else ""
            print(f"  • {scanner.name} {scanner.version}{default_marker}")
            if verbose:
                print(f"    Path: {scanner.path}")

        if not verbose:
            print("\nUse --verbose to show installation paths")

    def get_scanner_info(self, scanner_name: str) -> Optional[InstalledScanner]:
        """
        Get detailed information about a specific scanner.

        Args:
            scanner_name: Scanner name

        Returns:
            InstalledScanner object or None if not installed
        """
        for scanner in self.list_installed():
            if scanner.name == scanner_name:
                return scanner
        return None

    def print_scanner_info(self, scanner_name: str):
        """
        Print detailed information about a scanner.

        Args:
            scanner_name: Scanner name
        """
        scanner = self.get_scanner_info(scanner_name)

        if not scanner:
            print(f"\n{scanner_name} is not installed.\n")
            print(f"Install with: ai-guardian scanner install {scanner_name}")
            return

        print(f"\nScanner: {scanner.name}")
        print(f"Version: {scanner.version}")
        print(f"Path:    {scanner.path}")
        print(f"Default: {'Yes' if scanner.is_default else 'No'}")

        # Get GitHub repo
        from ai_guardian.scanner_installer import ScannerInstaller

        installer = ScannerInstaller()
        repo = installer.get_github_repo(scanner_name)
        print(f"GitHub:  https://github.com/{repo}")

    def get_scanner_list_json(self) -> str:
        """Return installed scanners as JSON string."""
        scanners = self.list_installed()
        data = {
            "scanners": [
                {
                    "name": s.name,
                    "version": s.version,
                    "path": s.path,
                    "is_default": s.is_default,
                }
                for s in scanners
            ]
        }
        return json.dumps(data, indent=2)

    def get_scanner_info_json(self, scanner_name: str) -> str:
        """Return scanner info as JSON string."""
        scanner = self.get_scanner_info(scanner_name)

        if not scanner:
            data = {"error": f"{scanner_name} is not installed"}
            return json.dumps(data, indent=2)

        from ai_guardian.scanner_installer import ScannerInstaller

        installer = ScannerInstaller()
        repo = installer.get_github_repo(scanner_name)

        data = {
            "name": scanner.name,
            "version": scanner.version,
            "path": scanner.path,
            "is_default": scanner.is_default,
            "github": f"https://github.com/{repo}",
        }
        return json.dumps(data, indent=2)

    def print_supported_scanners(self):
        """Print all supported scanners with versions and repos."""
        from ai_guardian.scanner_installer import ScannerInstaller

        installer = ScannerInstaller()
        repos = installer.scanner_config.get("repos", {})

        print("\nSupported scanners:\n")
        for name in installer.SUPPORTED_SCANNERS:
            version = installer.get_pinned_version(name)
            repo = repos.get(name, "N/A")
            license_info = installer.SCANNER_LICENSES.get(name, "Unknown")
            print(f"  {name}")
            print(f"    Version: {version}")
            print(f"    Repo:    {repo}")
            print(f"    License: {license_info}")
            print()

    def get_supported_scanners_json(self) -> str:
        """Return all supported scanners as JSON string."""
        from ai_guardian.scanner_installer import ScannerInstaller

        installer = ScannerInstaller()
        repos = installer.scanner_config.get("repos", {})

        scanners: Dict[str, Any] = {}
        for name in installer.SUPPORTED_SCANNERS:
            version = installer.get_pinned_version(name)
            repo = repos.get(name, None)
            scanners[name] = {
                "version": version,
                "repo": repo,
                "license": installer.SCANNER_LICENSES.get(name, "Unknown"),
            }

        return json.dumps({"scanners": scanners}, indent=2)

    def get_pattern_servers_json(self) -> str:
        """Return pattern server configuration as JSON string."""
        from ai_guardian.scanner_installer import ScannerInstaller

        installer = ScannerInstaller()
        servers = installer.get_pattern_servers()

        result: Dict[str, Any] = {}
        for name, config in servers.items():
            if isinstance(config, dict):
                result[name] = config
            else:
                result[name] = str(config)

        return json.dumps({"pattern_servers": result}, indent=2)

    def print_pattern_servers(self):
        """Print all supported pattern servers."""
        from ai_guardian.scanner_installer import ScannerInstaller

        installer = ScannerInstaller()
        servers = installer.get_pattern_servers()

        if not servers:
            print("\nNo pattern servers configured.\n")
            return

        print("\nSupported pattern servers:\n")
        for name, config in servers.items():
            print(f"  {name}")
            if isinstance(config, dict):
                url = config.get("url", "N/A")
                endpoint = config.get("patterns_endpoint", "N/A")
                print(f"    URL:      {url}")
                print(f"    Endpoint: {endpoint}")
            print()
