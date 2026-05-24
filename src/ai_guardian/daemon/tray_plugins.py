"""
Tray menu plugin loader and command utilities.

Loads plugin definitions from JSON files in the tray-plugins directory.
Each daemon reads its own plugins and serves them via the REST API.
"""

import json
import logging
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class PluginParam:
    """Parameter definition for a plugin menu item."""
    name: str
    hint: str = ""
    default: str = ""
    options: Optional[List[str]] = None


@dataclass
class PluginItem:
    """Menu item within a plugin."""
    label: str
    command: Union[str, Dict[str, str]]
    type: str = "terminal"
    params: List[PluginParam] = field(default_factory=list)


@dataclass
class Plugin:
    """Plugin definition with name and menu items."""
    name: str
    items: List[PluginItem] = field(default_factory=list)


def load_plugins(plugins_dir: Optional[Path] = None) -> List[Plugin]:
    """Load all plugin JSON files from the plugins directory.

    Args:
        plugins_dir: Directory to scan. Defaults to get_tray_plugins_dir().

    Returns:
        List of validated Plugin objects. Malformed files are skipped.
    """
    if plugins_dir is None:
        from ai_guardian.daemon import get_tray_plugins_dir
        plugins_dir = get_tray_plugins_dir()

    if not plugins_dir.is_dir():
        return []

    plugins = []
    for path in sorted(plugins_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Skipping malformed plugin file %s: %s", path.name, e)
            continue

        plugin = _parse_plugin(data, path.name)
        if plugin is not None:
            plugins.append(plugin)

    return plugins


def _parse_plugin(data: dict, filename: str) -> Optional[Plugin]:
    """Parse and validate a plugin dict from a JSON file."""
    if not isinstance(data, dict):
        logger.warning("Skipping %s: expected JSON object", filename)
        return None

    name = data.get("name")
    if not name or not isinstance(name, str):
        logger.warning("Skipping %s: missing or invalid 'name'", filename)
        return None

    raw_items = data.get("items")
    if not isinstance(raw_items, list):
        logger.warning("Skipping %s: missing or invalid 'items'", filename)
        return None

    items = []
    for i, raw_item in enumerate(raw_items):
        item = _parse_item(raw_item, filename, i)
        if item is not None:
            items.append(item)

    if not items:
        logger.warning("Skipping %s: no valid items", filename)
        return None

    return Plugin(name=name, items=items)


def _parse_item(raw: dict, filename: str, index: int) -> Optional[PluginItem]:
    """Parse and validate a single plugin item."""
    if not isinstance(raw, dict):
        logger.warning("Skipping item %d in %s: not a dict", index, filename)
        return None

    label = raw.get("label")
    command = raw.get("command")
    if not label or not isinstance(label, str):
        logger.warning("Skipping item %d in %s: missing 'label'", index, filename)
        return None
    if command is None:
        logger.warning("Skipping item %d in %s: missing 'command'", index, filename)
        return None
    if not isinstance(command, (str, dict)):
        logger.warning("Skipping item %d in %s: 'command' must be string or object", index, filename)
        return None

    item_type = raw.get("type", "terminal")
    if item_type not in ("terminal", "background", "notification", "clipboard"):
        item_type = "terminal"

    params = []
    for raw_param in raw.get("params", []):
        param = _parse_param(raw_param)
        if param is not None:
            params.append(param)

    return PluginItem(label=label, command=command, type=item_type, params=params)


def _parse_param(raw: dict) -> Optional[PluginParam]:
    """Parse a single parameter definition."""
    if not isinstance(raw, dict):
        return None
    name = raw.get("name")
    if not name or not isinstance(name, str):
        return None
    return PluginParam(
        name=name,
        hint=raw.get("hint", ""),
        default=str(raw.get("default", "")),
        options=raw.get("options") if isinstance(raw.get("options"), list) else None,
    )


def resolve_command(command: Union[str, Dict[str, str]]) -> Optional[str]:
    """Resolve a command spec to a platform-specific string.

    Args:
        command: Either a plain command string or a platform map dict
            with keys like "darwin", "linux", "windows", "default".

    Returns:
        Resolved command string, or None if no match for this platform.
    """
    if isinstance(command, str):
        return command
    if not isinstance(command, dict):
        return None
    system = platform.system().lower()
    if system in command:
        return command[system]
    return command.get("default")


PARAM_PREFIX = "tray."


def substitute_params(template: str, values: Dict[str, str]) -> str:
    """Substitute {tray.param} placeholders in a command template.

    Uses the ``{tray.name}`` namespace to avoid collisions with shell
    variables (``$name``/``${name}``) and other brace patterns in commands.

    Args:
        template: Command string with {tray.name} placeholders.
        values: Mapping of parameter names to values.

    Returns:
        Command with placeholders replaced. Unmatched {tray.*} become empty.
        Non-tray braces like {json} are left untouched.
    """
    result = template
    for key, val in values.items():
        result = result.replace("{" + PARAM_PREFIX + key + "}", val)
    result = re.sub(r"\{" + re.escape(PARAM_PREFIX) + r"(\w+)\}", "", result)
    return result


def plugins_to_dict(plugins: List[Plugin]) -> dict:
    """Serialize a list of plugins to a JSON-serializable dict.

    Returns:
        Dict with "plugins" key containing list of plugin dicts.
    """
    return {
        "plugins": [
            {
                "name": p.name,
                "items": [
                    _item_to_dict(item)
                    for item in p.items
                ],
            }
            for p in plugins
        ]
    }


def _item_to_dict(item: PluginItem) -> dict:
    """Serialize a PluginItem to a dict."""
    d = {"label": item.label, "command": item.command, "type": item.type}
    if item.params:
        d["params"] = [
            _param_to_dict(p)
            for p in item.params
        ]
    return d


def _param_to_dict(param: PluginParam) -> dict:
    """Serialize a PluginParam to a dict."""
    d = {"name": param.name}
    if param.hint:
        d["hint"] = param.hint
    if param.default:
        d["default"] = param.default
    if param.options:
        d["options"] = param.options
    return d


def dict_to_plugins(data: dict) -> List[Plugin]:
    """Deserialize a dict (from REST API) back to Plugin objects.

    Args:
        data: Dict with "plugins" key, as returned by plugins_to_dict().

    Returns:
        List of Plugin objects.
    """
    plugins = []
    for raw in data.get("plugins", []):
        plugin = _parse_plugin(raw, "<api>")
        if plugin is not None:
            plugins.append(plugin)
    return plugins


def _find_icon(filename: str) -> str:
    """Find an icon file in the images directory."""
    from pathlib import Path
    candidates = [
        Path(__file__).resolve().parent.parent / "images" / filename,
        Path(__file__).resolve().parent.parent.parent.parent / "images" / filename,
    ]
    try:
        from importlib.resources import files
        candidates.insert(0, Path(str(files("ai_guardian") / "images" / filename)))
    except Exception:
        pass
    for p in candidates:
        if p.exists():
            return str(p)
    return ""


def show_dialog(title: str, message: str) -> bool:
    """Show a modal dialog box. Returns True on success.

    Uses platform-native dialogs: AppleScript on macOS, zenity/kdialog
    on Linux, PowerShell on Windows.
    """
    import subprocess
    system = platform.system()
    try:
        if system == "Darwin":
            msg = message.replace("\\", "\\\\").replace('"', '\\"')
            ttl = title.replace("\\", "\\\\").replace('"', '\\"')
            icon_clause = ""
            icns_path = _find_icon("ai-guardian.icns")
            if icns_path:
                icon_clause = f' with icon file (POSIX file "{icns_path}" as alias)'
            script = (
                f'display dialog "{msg}" with title "{ttl}" '
                f'buttons {{"OK"}} default button "OK"{icon_clause}'
            )
            subprocess.run(["osascript", "-e", script], timeout=30)
        elif system == "Linux":
            icon_args = []
            png_path = _find_icon("ai-guardian-320.png")
            if png_path:
                icon_args = ["--icon-name", png_path]
            subprocess.run(
                ["zenity", "--info", "--title", title, "--text", message] + icon_args,
                timeout=30,
            )
        elif system == "Windows":
            ttl = title.replace("'", "''")
            msg = message.replace("'", "''")
            ps = (
                "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; "
                f"[System.Windows.Forms.MessageBox]::Show('{msg}', '{ttl}', 'OK', 'Information')"
            )
            subprocess.run(["powershell", "-Command", ps], timeout=30)
        else:
            return False
        return True
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return False


def send_notification(title: str, message: str) -> bool:
    """Show a system notification with the AI Guardian icon.

    On macOS the icon comes from the app-level NSApplication icon set at
    tray startup.  On Linux ``--icon`` is passed to ``notify-send``.
    On Windows a custom icon is loaded from PNG for the balloon tip.
    Returns True on success.
    """
    import subprocess
    system = platform.system()
    try:
        if system == "Darwin":
            msg = message.replace("\\", "\\\\").replace('"', '\\"')
            msg = msg.replace("\n", '" & return & "')
            ttl = title.replace("\\", "\\\\").replace('"', '\\"')
            script = f'display notification ("{msg}") with title "{ttl}"'
            subprocess.run(["osascript", "-e", script], timeout=5)
        elif system == "Linux":
            icon_args: list[str] = []
            png_path = _find_icon("ai-guardian-320.png")
            if png_path:
                icon_args = ["--icon", png_path]
            subprocess.run(
                ["notify-send"] + icon_args + [title, message], timeout=5,
            )
        elif system == "Windows":
            ttl = title.replace("'", "''")
            msg = message.replace("'", "''")
            png_path = _find_icon("ai-guardian-320.png")
            if png_path:
                ps_icon_path = png_path.replace("\\", "\\\\")
                icon_line = (
                    "try { "
                    f"$bmp = [System.Drawing.Bitmap]::new('{ps_icon_path}'); "
                    "$n.Icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon()) "
                    "} catch { "
                    "$n.Icon = [System.Drawing.SystemIcons]::Information "
                    "}; "
                )
            else:
                icon_line = "$n.Icon = [System.Drawing.SystemIcons]::Information; "
            ps = (
                "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; "
                "[System.Reflection.Assembly]::LoadWithPartialName('System.Drawing') | Out-Null; "
                "$n = New-Object System.Windows.Forms.NotifyIcon; "
                f"{icon_line}"
                "$n.Visible = $true; "
                f"$n.ShowBalloonTip(5000, '{ttl}', '{msg}', 'Info')"
            )
            subprocess.run(["powershell", "-Command", ps], timeout=10)
        else:
            return False
        return True
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return False


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard. Returns True on success."""
    import shutil
    import subprocess
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(["pbcopy"], input=text.encode(), timeout=5)
        elif system == "Linux":
            for cmd in (["xclip", "-selection", "clipboard"],
                        ["xsel", "--clipboard", "--input"]):
                if shutil.which(cmd[0]):
                    subprocess.run(cmd, input=text.encode(), timeout=5)
                    break
            else:
                return False
        elif system == "Windows":
            subprocess.run(["clip"], input=text.encode(), timeout=5)
        else:
            return False
        return True
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return False
