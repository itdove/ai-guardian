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
    run_on_target: bool = False
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
    if item_type not in ("terminal", "background", "notification", "clipboard", "modal"):
        item_type = "terminal"

    params = []
    for raw_param in raw.get("params", []):
        param = _parse_param(raw_param)
        if param is not None:
            params.append(param)

    run_on_target = bool(raw.get("run_on_target", False))

    return PluginItem(
        label=label, command=command, type=item_type,
        run_on_target=run_on_target, params=params,
    )


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


_TARGET_VARS = frozenset({
    "container_id", "container_engine", "host", "port", "name",
    "pod_name", "namespace",
})


def substitute_target_vars(template: str, target) -> str:
    """Substitute built-in ``{variable}`` placeholders from a DaemonTarget.

    Target variables use bare names (e.g., ``{container_id}``) without a
    namespace prefix.  They cannot collide with the ``{tray.*}`` user-param
    namespace.

    Args:
        template: Command string with ``{variable}`` placeholders.
        target: A ``DaemonTarget`` instance, or ``None`` for no substitution.

    Returns:
        Command with known target placeholders replaced.  Unknown bare
        ``{name}`` patterns are left untouched.
    """
    if target is None:
        return template
    result = template
    for var_name in _TARGET_VARS:
        placeholder = "{" + var_name + "}"
        if placeholder in result:
            value = getattr(target, var_name, None)
            result = result.replace(
                placeholder, str(value) if value is not None else "",
            )
    return result


_SHELL_OPERATORS = ("&&", "||", "|", ";", ">>", "<<", ">", "<")


def _needs_shell(command_str: str) -> bool:
    """Return True if *command_str* contains shell operators."""
    return any(op in command_str for op in _SHELL_OPERATORS)


def wrap_for_target(cmd_parts: list, target, interactive: bool = True) -> list:
    """Wrap command parts for execution on a DaemonTarget's runtime.

    Args:
        cmd_parts: The command as a list of strings (already shlex-split).
        target: A ``DaemonTarget`` instance.
        interactive: Whether to include ``-it`` flags (True for terminal type).

    Returns:
        Wrapped command parts.  For local runtime, returns *cmd_parts*
        unchanged.
    """
    import shutil
    runtime = target.runtime if target else "local"

    if runtime == "container":
        engine = target.container_engine or "podman"
        cid = target.container_id or ""
        if not cid or not re.match(r"^[a-fA-F0-9]{12,64}$", cid):
            logger.warning("run_on_target: invalid container_id, running locally")
            return cmd_parts
        flags = ["-it"] if interactive else []
        return [engine, "exec"] + flags + [cid] + cmd_parts

    if runtime == "kubernetes":
        pod = target.pod_name or ""
        ns = target.namespace or "default"
        if not pod:
            logger.warning("run_on_target: no pod_name, running locally")
            return cmd_parts
        kube_cli = "oc" if shutil.which("oc") else "kubectl"
        flags = ["-it"] if interactive else []
        return [kube_cli, "exec"] + flags + [pod, "-n", ns, "--"] + cmd_parts

    return cmd_parts


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
    if item.run_on_target:
        d["run_on_target"] = True
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
            msg = message.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", '" & return & "')
            ttl = title.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", " ")
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
    """Show a system notification.

    On macOS, osascript ``display notification`` always shows the Script
    Editor icon — custom icons require running from a signed .app bundle.
    NSUserNotification (which respected setApplicationIconImage_) was
    removed in macOS 26. A timestamp subtitle is added to prevent
    Notification Center from deduplicating identical messages.
    On Linux ``--icon`` is passed to ``notify-send``.
    On Windows a custom icon is loaded from PNG for the balloon tip.
    Returns True on success.
    """
    import subprocess
    system = platform.system()
    try:
        if system == "Darwin":
            from datetime import datetime
            ts = datetime.now().strftime("%H:%M:%S")
            msg = message.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", '" & return & "')
            ttl = title.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "").replace("\n", " ")
            script = f'display notification ("{msg}") with title "{ttl}" subtitle "{ts}"'
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
                ps_icon_path = png_path.replace("\\", "\\\\").replace("'", "''")
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
