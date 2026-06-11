"""Config Editor page — JSON config editor with scope toggle."""

import json
import shutil
from pathlib import Path

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar


def _validate_json(text):
    """Validate JSON text. Returns (parsed_dict, error_string)."""
    if not text or not text.strip():
        return None, "Empty content"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"
    if not isinstance(parsed, dict):
        return None, "Config must be a JSON object (not array or scalar)"
    return parsed, None


def _get_config_path(scope):
    """Get the config file path for the given scope."""
    if scope == "project":
        from ai_guardian.config_utils import get_project_config_path
        return get_project_config_path()
    from ai_guardian.config_utils import get_config_dir
    return get_config_dir() / "ai-guardian.json"


def _load_config_by_scope(scope):
    """Load config from the specified scope. Returns (content_str, path_str)."""
    path = _get_config_path(scope)
    if path is None:
        return "", None
    path_str = str(path)
    if not path.exists():
        return "", path_str
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return json.dumps(data, indent=2), path_str
    except Exception as e:
        return f"// Error: {e}", path_str


def _save_config_with_backup(content_str, path_str):
    """Save config with .json.bak backup. Returns error string or None."""
    if not path_str:
        return "No config path available"
    parsed, err = _validate_json(content_str)
    if err:
        return err
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, str(path) + ".bak")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2)
        f.write("\n")
    return None


def create_config_editor_page(service, daemon_name: str):
    """Create the Config Editor page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/config-editor")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Config Editor").classes("text-2xl font-bold")
            ui.label(
                "Edit configuration files with JSON validation."
            ).classes("text-xs text-grey-6")

            state = {"scope": "global", "path": None}

            with ui.card().classes("w-full"):
                ui.label("Scope").classes("text-lg font-bold")
                scope_sel = ui.select(
                    options={"global": "Global", "project": "Project"},
                    value="global",
                ).classes("w-48")
                path_label = ui.label("").classes(
                    "text-sm text-grey-4"
                ).style("font-family: monospace")

            with ui.card().classes("w-full"):
                ui.label("Editor").classes("text-lg font-bold")
                status_label = ui.label("").classes("text-sm")
                # Defer codemirror initialization to avoid duplicate ESM module
                # warnings when navigating between config pages (issue #1102)
                editor_container = ui.column().classes("w-full")
                editor = None

                async def init_editor():
                    nonlocal editor
                    with editor_container:
                        editor = ui.codemirror(
                            "", language="JSON", theme="dracula",
                            line_wrapping=True,
                        ).classes("w-full").style("min-height: 500px")
                        editor.on_value_change(on_editor_change)
                    return editor

            with ui.row().classes("gap-2"):
                async def do_save():
                    nonlocal editor
                    if editor is None:
                        await init_editor()

                    with ui.dialog() as dlg, ui.card():
                        ui.label("Save Configuration?").classes("font-bold")
                        ui.label(
                            "This will create a backup (.json.bak) and "
                            "overwrite the config file."
                        ).classes("text-sm")
                        ui.label(
                            f"File: {state['path']}"
                        ).classes("text-xs text-grey-6").style(
                            "font-family: monospace"
                        )

                        with ui.row().classes("gap-2 mt-2"):
                            async def confirm_save():
                                err = await run.io_bound(
                                    _save_config_with_backup,
                                    editor.value,
                                    state["path"],
                                )
                                dlg.close()
                                if err:
                                    ui.notify(f"Error: {err}",
                                              type="negative")
                                else:
                                    ui.notify("Saved", type="positive")

                            ui.button(
                                "Save", on_click=confirm_save, color="green"
                            ).props("dense")
                            ui.button(
                                "Cancel", on_click=dlg.close
                            ).props("dense flat")

                    dlg.open()

                ui.button("Save", icon="save", on_click=do_save).props(
                    "dense"
                )

                async def do_reload():
                    nonlocal editor
                    if editor is None:
                        await init_editor()

                    text, path_str = await run.io_bound(
                        _load_config_by_scope, state["scope"]
                    )
                    state["path"] = path_str
                    path_label.text = f"File: {path_str or 'N/A'}"
                    editor.value = text
                    _update_validation(text)
                    ui.notify("Reloaded from disk", type="positive")

                ui.button(
                    "Reload", icon="refresh", on_click=do_reload
                ).props("dense")

            def _update_validation(text):
                _, err = _validate_json(text)
                if err:
                    status_label.text = f"Invalid: {err}"
                    status_label.classes(replace="text-sm text-red")
                else:
                    status_label.text = "Valid JSON"
                    status_label.classes(replace="text-sm text-green")

            def on_editor_change(e):
                _update_validation(e.value)

            async def load_scope(scope_val=None):
                nonlocal editor
                if editor is None:
                    await init_editor()

                sc = scope_val if scope_val else scope_sel.value
                state["scope"] = sc
                text, path_str = await run.io_bound(
                    _load_config_by_scope, sc
                )
                state["path"] = path_str
                path_label.text = f"File: {path_str or 'N/A'}"
                editor.value = text
                _update_validation(text)

            async def on_scope_change(e):
                await load_scope(e.value)

            scope_sel.on_value_change(on_scope_change)

            ui.timer(0.1, load_scope, once=True)
