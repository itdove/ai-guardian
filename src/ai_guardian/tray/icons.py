"""
Tray icon creation and image manipulation functions.

Split from tray.py (Issue #1492) to separate pure icon image operations
from tray lifecycle, menu construction, and animation state.

All functions are stateless — they take inputs and return images.
Animation state remains on DaemonTray since tests mock animation
methods on the tray instance.
"""

import logging

logger = logging.getLogger(__name__)

try:
    from PIL import Image, ImageDraw

    _HAS_PIL = True
except Exception:
    _HAS_PIL = False


def needs_dark_icon():
    """Check if the panel has a light background requiring a dark icon."""
    import platform

    if platform.system() != "Linux":
        return False
    import os

    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
    if "GNOME" not in desktop.upper():
        return False
    try:
        import subprocess

        result = subprocess.run(
            ["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        scheme = result.stdout.strip().strip("'\"")
        return scheme != "prefer-dark"
    except Exception:
        return False


def invert_icon(img):
    """Invert a white monochrome icon to dark, preserving alpha."""
    img = img.copy()
    r, g, b, a = img.split()
    from PIL import ImageOps

    r = ImageOps.invert(r)
    g = ImageOps.invert(g)
    b = ImageOps.invert(b)
    return Image.merge("RGBA", (r, g, b, a))


def apply_paused_dimming(img):
    """Reduce alpha to ~50% to indicate paused state."""
    img = img.copy()
    alpha = img.split()[3]
    alpha = alpha.point(lambda a: a // 2)
    img.putalpha(alpha)
    return img


def apply_stale_overlay(img):
    """Draw a small orange dot in the bottom-right corner to indicate stale daemon."""
    img = img.copy()
    draw = ImageDraw.Draw(img)
    w, h = img.size
    r = max(3, w // 5)
    x0, y0 = w - r - 1, h - r - 1
    draw.ellipse([x0, y0, x0 + r, y0 + r], fill=(255, 140, 0, 255))
    return img


def get_tray_icon_size():
    """Return the preferred tray icon size for the current platform."""
    import platform

    system = platform.system()
    if system == "Darwin":
        return None
    if system == "Windows":
        return 16
    return 22


def find_tray_icon_path():
    """Find the monochrome tray icon for the current platform.

    Uses three strategies to ensure the returned path remains valid
    after this method returns (important for AppIndicator on GNOME/KDE
    which reads the icon asynchronously).
    """
    from pathlib import Path
    import platform
    import importlib.resources

    system = platform.system()

    if system == "Darwin":
        names = ["tray-iconTemplate@2x.png", "tray-iconTemplate.png"]
    elif system == "Windows":
        names = ["tray-icon-16.png"]
    else:
        names = ["tray-icon-22.png", "tray-icon-32.png"]

    for name in names:
        try:
            ref = importlib.resources.files("ai_guardian") / "images" / name
            if isinstance(ref, Path) and ref.exists():
                return str(ref)
        except Exception:
            pass

    for name in names:
        try:
            ref = importlib.resources.files("ai_guardian") / "images" / name
            with importlib.resources.as_file(ref) as p:
                if p.exists():
                    import shutil
                    import tempfile

                    persistent_dir = Path(tempfile.gettempdir()) / "ai-guardian-icons"
                    persistent_dir.mkdir(parents=True, exist_ok=True)
                    dest = persistent_dir / name
                    if not dest.exists():
                        shutil.copy2(str(p), str(dest))
                    return str(dest)
        except Exception:
            pass

    src_dir = Path(__file__).resolve().parent.parent
    candidates_dirs = [
        src_dir / "images",
        src_dir.parent.parent / "images",
    ]
    for d in candidates_dirs:
        for name in names:
            path = d / name
            if path.exists():
                return str(path)

    return None


def create_fallback_icon(size):
    """Create a simple fallback icon if the tray icon files are not found."""
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse([4, 4, size - 4, size - 4], fill=(0, 160, 220, 255))
    try:
        draw.text((size // 4, size // 6), "G", fill=(255, 255, 255, 255))
    except Exception:
        pass
    return image
