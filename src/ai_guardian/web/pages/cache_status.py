"""Config Cache Status page — per-project config cache diagnostics."""

from datetime import datetime, timezone

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar


def _format_mtime(mtime):
    if mtime is None:
        return "—"
    try:
        dt = datetime.fromtimestamp(mtime, tz=timezone.utc).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(mtime)


def _format_seconds_ago(seconds):
    if seconds is None:
        return "—"
    seconds = round(seconds)
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s ago"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours}h {minutes}m ago"


def _short_path(path):
    if not path:
        return "—"
    parts = path.replace("\\", "/").split("/")
    if len(parts) > 3:
        return ".../" + "/".join(parts[-3:])
    return path


def create_cache_status_page(service, daemon_name: str):
    """Create the Config Cache Status page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(
            daemon_name, current=f"/{daemon_name}/cache-status"
        )

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Config Cache Status").classes("text-2xl font-bold")
            ui.label(
                "Per-project config cache state tracked by the daemon. "
                "Helps debug cross-project config issues."
            ).classes("text-xs text-grey-6")

            summary_row = ui.row().classes("gap-4")
            content = ui.column().classes("w-full gap-4")

            async def refresh():
                target = service.get_target_by_name(daemon_name)
                if not target:
                    content.clear()
                    with content:
                        ui.label("Daemon not found").classes(
                            "text-red text-lg"
                        )
                    return

                data = await run.io_bound(
                    service.get_cache_status, target
                )

                summary_row.clear()
                content.clear()

                if not data:
                    with content:
                        ui.label(
                            "Could not fetch cache status from daemon"
                        ).classes("text-orange text-lg")
                    return

                projects = data.get("projects", [])
                total = data.get("total_tracked", 0)
                last_reload = data.get(
                    "last_project_config_reload_at"
                )

                with summary_row:
                    with ui.card().classes("p-3"):
                        ui.label("Projects Tracked").classes(
                            "text-xs text-grey-6"
                        )
                        ui.label(str(total)).classes(
                            "text-2xl font-bold"
                        )

                    with ui.card().classes("p-3"):
                        overrides = sum(
                            1 for p in projects
                            if p.get("has_project_override")
                        )
                        ui.label("With Project Override").classes(
                            "text-xs text-grey-6"
                        )
                        ui.label(str(overrides)).classes(
                            "text-2xl font-bold"
                        )

                    with ui.card().classes("p-3"):
                        ui.label("Last Config Reload").classes(
                            "text-xs text-grey-6"
                        )
                        if last_reload:
                            dt = datetime.fromtimestamp(
                                last_reload, tz=timezone.utc
                            ).astimezone()
                            ui.label(
                                dt.strftime("%H:%M:%S")
                            ).classes("text-2xl font-bold")
                        else:
                            ui.label("—").classes(
                                "text-2xl font-bold text-grey-6"
                            )

                with content:
                    if not projects:
                        ui.label(
                            "No projects tracked yet. Projects appear "
                            "when the daemon processes hook requests."
                        ).classes("text-grey-6 mt-4")
                        return

                    for proj in projects:
                        project_dir = proj.get("project_dir", "?")
                        has_override = proj.get(
                            "has_project_override", False
                        )

                        with ui.card().classes("w-full"):
                            with ui.row().classes(
                                "items-center gap-2"
                            ):
                                ui.label(
                                    project_dir.rsplit("/", 1)[-1]
                                    if "/" in project_dir
                                    else project_dir
                                ).classes("text-lg font-bold")

                                if has_override:
                                    ui.badge(
                                        "project override",
                                        color="blue",
                                    )
                                else:
                                    ui.badge(
                                        "global only",
                                        color="grey",
                                    )

                            ui.label(project_dir).classes(
                                "text-xs text-grey-6 font-mono"
                            )

                            ui.separator()

                            with ui.grid(columns=2).classes(
                                "w-full gap-x-8 gap-y-2"
                            ):
                                ui.label("Project Config").classes(
                                    "text-xs text-grey-6"
                                )
                                ui.label(
                                    _short_path(
                                        proj.get("config_path")
                                    )
                                ).classes("text-sm font-mono")

                                ui.label("Config Modified").classes(
                                    "text-xs text-grey-6"
                                )
                                ui.label(
                                    _format_mtime(
                                        proj.get("config_mtime")
                                    )
                                ).classes("text-sm")

                                ui.label("Last Seen").classes(
                                    "text-xs text-grey-6"
                                )
                                ui.label(
                                    _format_seconds_ago(
                                        proj.get(
                                            "last_seen_seconds_ago"
                                        )
                                    )
                                ).classes("text-sm")

                                gp = proj.get("global_config_path")
                                if gp:
                                    ui.label(
                                        "Global Config"
                                    ).classes(
                                        "text-xs text-grey-6"
                                    )
                                    ui.label(
                                        _short_path(gp)
                                    ).classes(
                                        "text-sm font-mono"
                                    )

                                    ui.label(
                                        "Global Modified"
                                    ).classes(
                                        "text-xs text-grey-6"
                                    )
                                    ui.label(
                                        _format_mtime(
                                            proj.get(
                                                "global_config_mtime"
                                            )
                                        )
                                    ).classes("text-sm")

                                cache_ago = proj.get(
                                    "cache_last_accessed_seconds_ago"
                                )
                                if cache_ago is not None:
                                    ui.label(
                                        "Cache Accessed"
                                    ).classes(
                                        "text-xs text-grey-6"
                                    )
                                    ui.label(
                                        _format_seconds_ago(
                                            cache_ago
                                        )
                                    ).classes("text-sm")

            with ui.row().classes("gap-2 mt-2"):
                ui.button(
                    "Refresh", on_click=refresh, icon="refresh"
                ).props("outline")

            ui.timer(0.1, refresh, once=True)
