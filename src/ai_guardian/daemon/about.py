"""Shared About info for daemon, tray, and REST API."""

import platform
import sys

PROJECT_URL = "https://github.com/itdove/ai-guardian"


def get_about_info() -> dict:
    """Gather about info for the current process."""
    try:
        from ai_guardian import __version__
    except ImportError:
        __version__ = "unknown"

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    system = platform.system()
    if system == "Darwin":
        mac_ver = platform.mac_ver()[0]
        plat_str = f"macOS {mac_ver} {platform.machine()}" if mac_ver else f"macOS {platform.machine()}"
    else:
        plat_str = f"{system} {platform.release()} {platform.machine()}"

    config_path = None
    try:
        from ai_guardian.config_utils import get_config_dir
        config_path = str(get_config_dir() / "ai-guardian.json")
    except Exception:
        pass

    scanners = []
    try:
        from ai_guardian.scanner_manager import ScannerManager
        sm = ScannerManager()
        for s in sm.list_installed():
            scanners.append({"name": s.name, "version": s.version})
    except Exception:
        pass

    return {
        "version": __version__,
        "python": py_ver,
        "platform": plat_str,
        "config_path": config_path,
        "scanners": scanners,
        "url": PROJECT_URL,
    }


def format_about_text(info: dict) -> str:
    """Format an about info dict into display text."""
    lines = [f"AI Guardian v{info.get('version', 'unknown')}"]
    lines.append(f"Python: {info.get('python', 'unknown')}")
    lines.append(f"Platform: {info.get('platform', 'unknown')}")

    config_path = info.get("config_path")
    if config_path:
        lines.append(f"Config: {config_path}")

    scanners = info.get("scanners", [])
    if scanners:
        parts = [f"{s['name']} {s['version']}" for s in scanners]
        lines.append(f"Scanners: {', '.join(parts)}")
    else:
        lines.append("Scanners: none installed")

    lines.append("")
    lines.append(info.get("url", PROJECT_URL))

    return "\n".join(lines)
