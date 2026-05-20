"""
PATH augmentation for GUI-launched processes.

When the tray or daemon is launched from a desktop shortcut (.app bundle)
or launchd/autostart, the process inherits a minimal system PATH that
doesn't include Homebrew or user bin directories.  This module augments
os.environ["PATH"] so that shutil.which() can find scanner binaries.
"""

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_WELL_KNOWN_DIRS = [
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    str(Path.home() / ".local" / "bin"),
]

_SCANNER_BINARIES = [
    "betterleaks",
    "gitleaks",
    "leaktk",
    "trufflehog",
    "detect-secrets",
    "secretlint",
    "ggshield",
]

_augmented = False


def ensure_scanner_path():
    """Augment PATH with directories where scanner binaries are installed.

    Safe to call multiple times — only augments once per process.

    Strategy:
      1. Probe well-known directories for configured scanner binaries
      2. Read the user's login shell PATH for additional directories
      3. Add any well-known directory that exists (even without a scanner)
    """
    global _augmented
    if _augmented:
        return
    _augmented = True

    current = os.environ.get("PATH", "")
    current_dirs = set(current.split(os.pathsep))
    added = []

    for d in _well_known_dirs_with_scanners():
        if d not in current_dirs and os.path.isdir(d):
            added.append(d)
            current_dirs.add(d)

    try:
        shell_dirs = _read_shell_path()
    except Exception as e:
        logger.debug("Shell PATH read failed: %s", e)
        shell_dirs = []
    for d in shell_dirs:
        if d and d not in current_dirs and os.path.isdir(d):
            added.append(d)
            current_dirs.add(d)

    for d in _WELL_KNOWN_DIRS:
        if d not in current_dirs and os.path.isdir(d):
            added.append(d)
            current_dirs.add(d)

    if added:
        os.environ["PATH"] = os.pathsep.join(added) + os.pathsep + current
        logger.info("Augmented PATH with: %s", ", ".join(added))


def _well_known_dirs_with_scanners():
    """Return well-known directories that contain at least one scanner binary."""
    dirs = []
    for d in _WELL_KNOWN_DIRS:
        for binary in _SCANNER_BINARIES:
            candidate = os.path.join(d, binary)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                if d not in dirs:
                    dirs.append(d)
                break
    return dirs


def _read_shell_path():
    """Read PATH from the user's login shell.

    Returns a list of directory strings, or empty list on failure.
    """
    shell = os.environ.get("SHELL")
    if not shell:
        return []
    try:
        result = subprocess.run(
            [shell, "-l", "-c", "echo $PATH"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split(os.pathsep)
    except (subprocess.TimeoutExpired, OSError, ValueError) as e:
        logger.debug("Failed to read shell PATH: %s", e)
    return []
