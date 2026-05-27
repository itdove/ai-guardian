"""Config File page — read-only view of configuration files."""

import json
from pathlib import Path

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar


def _load_config_files():
    """Load both global and project config file info."""
    from ai_guardian.config_utils import get_config_dir, get_project_config_path

    global_path = get_config_dir() / "ai-guardian.json"
    project_path = get_project_config_path()

    result = {
        "global_path": str(global_path),
        "global_exists": global_path.exists(),
        "global_content": None,
        "project_path": str(project_path) if project_path else None,
        "project_exists": bool(project_path and project_path.exists()),
        "project_content": None,
    }

    if result["global_exists"]:
        try:
            with open(global_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            result["global_content"] = json.dumps(data, indent=2)
        except Exception as e:
            result["global_content"] = f"Error reading file: {e}"

    if result["project_exists"] and project_path:
        try:
            with open(project_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            result["project_content"] = json.dumps(data, indent=2)
        except Exception as e:
            result["project_content"] = f"Error reading file: {e}"

    return result


def create_config_file_page(service, daemon_name: str):
    """Create the Config File page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/config-file")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Config File Viewer").classes("text-2xl font-bold")
            ui.label(
                "Read-only view of current configuration files."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                info = await run.io_bound(_load_config_files)

                with content:
                    with ui.card().classes("w-full"):
                        ui.label("Config Sources").classes(
                            "text-lg font-bold"
                        )
                        with ui.column().classes("gap-2"):
                            with ui.row().classes("items-center gap-2"):
                                ui.icon(
                                    "check_circle"
                                    if info["global_exists"]
                                    else "cancel"
                                ).classes(
                                    "text-green"
                                    if info["global_exists"]
                                    else "text-red"
                                )
                                ui.label("Global:").classes(
                                    "font-bold text-sm"
                                )
                                ui.label(info["global_path"]).classes(
                                    "text-sm text-grey-4"
                                ).style("font-family: monospace")

                            with ui.row().classes("items-center gap-2"):
                                ui.icon(
                                    "check_circle"
                                    if info["project_exists"]
                                    else "cancel"
                                ).classes(
                                    "text-green"
                                    if info["project_exists"]
                                    else "text-red"
                                )
                                ui.label("Project:").classes(
                                    "font-bold text-sm"
                                )
                                ui.label(
                                    info["project_path"] or "Not found"
                                ).classes("text-sm text-grey-4").style(
                                    "font-family: monospace"
                                )

                    if info["global_exists"] and info["global_content"]:
                        with ui.card().classes("w-full"):
                            ui.label("Global Configuration").classes(
                                "text-lg font-bold"
                            )
                            with ui.scroll_area().classes("w-full").style(
                                "max-height: 500px"
                            ):
                                ui.code(
                                    info["global_content"], language="json"
                                ).classes("w-full")

                    if info["project_exists"] and info["project_content"]:
                        with ui.card().classes("w-full"):
                            ui.label("Project Configuration").classes(
                                "text-lg font-bold"
                            )
                            with ui.scroll_area().classes("w-full").style(
                                "max-height: 500px"
                            ):
                                ui.code(
                                    info["project_content"], language="json"
                                ).classes("w-full")
                    elif not info["project_exists"]:
                        with ui.card().classes("w-full"):
                            ui.label("Project Configuration").classes(
                                "text-lg font-bold"
                            )
                            ui.label(
                                "No project configuration file found."
                            ).classes("text-grey-6 text-sm")

                    ui.button(
                        "Refresh", icon="refresh", on_click=refresh
                    ).props("dense")

            ui.timer(0.1, refresh, once=True)
