#!/usr/bin/env python3
"""
Scanner Installer for ai-guardian.

Handles automated installation and upgrade of scanner engines:
- Gitleaks
- BetterLeaks
- LeakTK
"""

import logging
import platform
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any
import sys

# Handle tomllib import for Python 3.11+ and fallback to tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        # If tomli not available, provide helpful error
        logging.error(
            "tomli package required for Python < 3.11. Install with: pip install tomli"
        )
        tomllib = None

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


logger = logging.getLogger(__name__)


class InstallMethod(Enum):
    """Installation method types."""
    PACKAGE_MANAGER = "package_manager"
    DIRECT_DOWNLOAD = "direct_download"
    FROM_FILE = "from_file"


class ScannerInstaller:
    """Handles installation of scanner engines."""

    # Supported scanners
    SUPPORTED_SCANNERS = ["gitleaks", "betterleaks", "leaktk"]

    def __init__(self, install_dir: Optional[Path] = None):
        """
        Initialize scanner installer.

        Args:
            install_dir: Directory to install scanners (default: ~/.local/bin)
        """
        self.install_dir = install_dir or Path.home() / ".local" / "bin"
        self.install_dir.mkdir(parents=True, exist_ok=True)
        self.scanner_config = self._load_scanner_config()

    def _load_scanner_config(self) -> Dict[str, Any]:
        """
        Load scanner configuration from pyproject.toml.

        Returns:
            Scanner configuration dict with versions and repos
        """
        if tomllib is None:
            logger.warning("tomllib not available, using fallback configuration")
            return {
                "gitleaks": "8.30.1",
                "betterleaks": "1.1.2",
                "leaktk": "0.2.10",
                "repos": {
                    "gitleaks": "gitleaks/gitleaks",
                    "betterleaks": "betterleaks/betterleaks",
                    "leaktk": "leaktk/leaktk",
                },
            }

        try:
            # Find pyproject.toml (relative to this module)
            pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"

            if not pyproject_path.exists():
                logger.warning(f"pyproject.toml not found at {pyproject_path}")
                return {}

            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)

            config = data.get("tool", {}).get("ai-guardian", {}).get("scanners", {})
            return config
        except Exception as e:
            logger.warning(f"Failed to load scanner config from pyproject.toml: {e}")
            return {}

    def get_github_repo(self, scanner_name: str) -> str:
        """
        Get GitHub repository from pyproject.toml.

        Args:
            scanner_name: Scanner name (gitleaks, betterleaks, leaktk)

        Returns:
            GitHub repository in format "owner/repo"
        """
        repos = self.scanner_config.get("repos", {})
        return repos.get(scanner_name, f"{scanner_name}/{scanner_name}")

    def get_pinned_version(self, scanner_name: str) -> str:
        """
        Get pinned version from pyproject.toml.

        Args:
            scanner_name: Scanner name

        Returns:
            Version string (without 'v' prefix)
        """
        version = self.scanner_config.get(scanner_name, "unknown")
        # Remove 'v' prefix if present
        if version.startswith("v"):
            version = version[1:]
        return version

    def detect_platform(self) -> str:
        """
        Detect platform architecture (e.g., darwin_arm64).

        Returns:
            Platform string in format "system_arch"
        """
        system = platform.system().lower()
        machine = platform.machine().lower()

        # Architecture normalization
        arch_map = {
            "x86_64": "x64",
            "amd64": "x64",
            "aarch64": "arm64",
            "arm64": "arm64",
            "armv7l": "armv7",
            "armv6l": "armv6",
            "i686": "x32",
            "i386": "x32",
        }

        arch = arch_map.get(machine, machine)
        return f"{system}_{arch}"

    def get_latest_version(self, scanner_name: str) -> str:
        """
        Fetch latest version from GitHub releases API.

        Args:
            scanner_name: Scanner name

        Returns:
            Latest version string (without 'v' prefix)
        """
        if not HAS_REQUESTS:
            logger.warning(
                "requests library not available, using pinned version from pyproject.toml"
            )
            return self.get_pinned_version(scanner_name)

        repo = self.get_github_repo(scanner_name)
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"

        try:
            response = requests.get(api_url, timeout=5)
            response.raise_for_status()
            version = response.json()["tag_name"]
            # Remove 'v' prefix if present
            if version.startswith("v"):
                version = version[1:]
            logger.info(f"Latest version of {scanner_name} from GitHub: {version}")
            return version
        except Exception as e:
            logger.warning(f"Failed to fetch latest version from GitHub: {e}")
            logger.info("Falling back to pinned version from pyproject.toml")
            return self.get_pinned_version(scanner_name)

    def install_via_package_manager(self, scanner_name: str) -> bool:
        """
        Try to install via system package manager.

        Args:
            scanner_name: Scanner to install

        Returns:
            True if installation succeeded, False otherwise
        """
        system = platform.system().lower()

        try:
            if system == "darwin" and shutil.which("brew"):
                logger.info(f"Installing {scanner_name} via Homebrew...")
                result = subprocess.run(
                    ["brew", "install", scanner_name],
                    capture_output=True,
                    timeout=300,
                )
                return result.returncode == 0
            elif system == "linux":
                if shutil.which("apt-get"):
                    logger.info(f"Installing {scanner_name} via apt-get...")
                    result = subprocess.run(
                        ["sudo", "apt-get", "install", "-y", scanner_name],
                        capture_output=True,
                        timeout=300,
                    )
                    return result.returncode == 0
                elif shutil.which("yum"):
                    logger.info(f"Installing {scanner_name} via yum...")
                    result = subprocess.run(
                        ["sudo", "yum", "install", "-y", scanner_name],
                        capture_output=True,
                        timeout=300,
                    )
                    return result.returncode == 0
            elif system == "windows" and shutil.which("choco"):
                logger.info(f"Installing {scanner_name} via Chocolatey...")
                result = subprocess.run(
                    ["choco", "install", "-y", scanner_name],
                    capture_output=True,
                    timeout=300,
                )
                return result.returncode == 0
        except subprocess.TimeoutExpired:
            logger.warning("Package manager installation timed out")
            return False
        except Exception as e:
            logger.debug(f"Package manager installation failed: {e}")
            return False

        logger.debug(f"No package manager available for {system}")
        return False

    def install_from_download(
        self, scanner_name: str, version: Optional[str] = None
    ) -> Path:
        """
        Download and install scanner binary from GitHub releases.

        Args:
            scanner_name: Scanner to install
            version: Specific version to install (optional, uses latest if not provided)

        Returns:
            Path to installed binary

        Raises:
            RuntimeError: If installation fails
        """
        if not HAS_REQUESTS:
            raise RuntimeError(
                "requests library required for downloading scanners. "
                "Install with: pip install requests"
            )

        # Determine version to install
        version = version or self.get_latest_version(scanner_name)

        # Detect platform
        platform_arch = self.detect_platform()
        logger.info(f"Detected platform: {platform_arch}")

        # Build download URL
        repo = self.get_github_repo(scanner_name)
        system = platform_arch.split("_")[0]

        # Determine file extension and binary name
        if system == "windows":
            ext = "zip"
            binary_name = f"{scanner_name}.exe"
        else:
            ext = "tar.gz"
            binary_name = scanner_name

        # Build filename - different scanners have different naming conventions
        filename = f"{scanner_name}_{version}_{platform_arch}.{ext}"
        download_url = (
            f"https://github.com/{repo}/releases/download/v{version}/{filename}"
        )

        logger.info(f"Downloading {scanner_name} {version} from {download_url}")

        # Download to temporary file
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            archive_path = temp_path / filename

            try:
                response = requests.get(download_url, timeout=60)
                response.raise_for_status()

                with open(archive_path, "wb") as f:
                    f.write(response.content)

                logger.info(f"Downloaded {archive_path.stat().st_size} bytes")

                # Extract archive
                extract_dir = temp_path / "extract"
                extract_dir.mkdir()

                if ext == "zip":
                    with zipfile.ZipFile(archive_path, "r") as zip_ref:
                        zip_ref.extractall(extract_dir)
                else:
                    with tarfile.open(archive_path, "r:gz") as tar_ref:
                        tar_ref.extractall(extract_dir)

                # Find the binary in extracted files
                binary_path = None
                for path in extract_dir.rglob(binary_name):
                    if path.is_file():
                        binary_path = path
                        break

                if not binary_path:
                    raise RuntimeError(
                        f"Binary '{binary_name}' not found in archive. "
                        f"Archive contents: {list(extract_dir.rglob('*'))}"
                    )

                # Install to install_dir
                target_path = self.install_dir / binary_name
                shutil.copy2(binary_path, target_path)

                # Make executable (Unix)
                if system != "windows":
                    target_path.chmod(0o755)

                logger.info(f"Installed {scanner_name} to {target_path}")
                print(f"✓ Installed {scanner_name} {version} to {target_path}")

                return target_path

            except (tarfile.TarError, zipfile.BadZipFile) as e:
                raise RuntimeError(f"Failed to extract archive: {e}") from e
            except Exception as e:
                # Catch all download/network errors
                raise RuntimeError(
                    f"Failed to download {scanner_name} from {download_url}: {e}"
                ) from e

    def install(
        self,
        scanner_name: str,
        version: Optional[str] = None,
        use_pinned: bool = False,
        method: Optional[InstallMethod] = None,
    ) -> bool:
        """
        Install scanner using best available method.

        Args:
            scanner_name: Scanner to install (gitleaks, betterleaks, leaktk)
            version: Specific version to install (optional)
            use_pinned: Use version from pyproject.toml (fallback)
            method: Installation method (optional)

        Returns:
            True if installation succeeded

        Version selection priority:
            1. --version flag (explicit)
            2. GitHub API latest (default)
            3. pyproject.toml pinned version (fallback)
        """
        if scanner_name not in self.SUPPORTED_SCANNERS:
            raise ValueError(
                f"Unsupported scanner: {scanner_name}. "
                f"Supported: {', '.join(self.SUPPORTED_SCANNERS)}"
            )

        # Determine target version
        if version:
            # Explicit version specified
            target_version = version
            logger.info(
                f"Installing {scanner_name} {version} (explicitly specified)"
            )
        elif use_pinned:
            # Use pinned version from pyproject.toml
            target_version = self.get_pinned_version(scanner_name)
            logger.info(
                f"Installing {scanner_name} {target_version} (pinned version)"
            )
        else:
            # Try to fetch latest from GitHub (with fallback to pinned)
            target_version = self.get_latest_version(scanner_name)
            logger.info(f"Installing {scanner_name} {target_version}")

        # Try package manager first (unless method specified)
        if method is None or method == InstallMethod.PACKAGE_MANAGER:
            if self.install_via_package_manager(scanner_name):
                print(f"✓ Installed {scanner_name} via package manager")
                return True

        # Fallback to direct download with determined version
        if method is None or method == InstallMethod.DIRECT_DOWNLOAD:
            try:
                self.install_from_download(scanner_name, target_version)
                return True
            except Exception as e:
                logger.error(f"Failed to install {scanner_name}: {e}")
                return False

        return False

    def verify_installation(self, scanner_name: str) -> bool:
        """
        Verify scanner is installed and working.

        Args:
            scanner_name: Scanner to verify

        Returns:
            True if scanner is installed and working
        """
        if not shutil.which(scanner_name):
            # Check in install_dir
            binary_path = self.install_dir / scanner_name
            if not binary_path.exists():
                return False

            # Try to run version command
            try:
                result = subprocess.run(
                    [str(binary_path), "version"],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False
        else:
            # Binary in PATH, verify it works
            try:
                result = subprocess.run(
                    [scanner_name, "version"],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False
