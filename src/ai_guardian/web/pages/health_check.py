"""Health Check page — system health diagnostics and auto-fix."""

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar

_STATUS_ICONS = {
    "pass": ("check_circle", "green"),
    "warn": ("warning", "amber"),
    "fail": ("error", "red"),
    "skip": ("skip_next", "grey"),
}


def create_health_check_page(service, daemon_name: str):
    """Create the Health Check page."""
    sidebar = create_sidebar(daemon_name, current=f"/{daemon_name}/health-check")
    create_header(daemon_name, drawer=sidebar)

    with ui.column().classes("flex-grow p-6 gap-4"):
        ui.label("Health Check").classes("text-2xl font-bold")
        ui.label("Run system diagnostics and auto-fix issues.").classes(
            "text-xs text-grey-6"
        )

        from ai_guardian.web.config_helpers import is_remote_daemon

        _is_remote = is_remote_daemon()

        content = ui.column().classes("w-full gap-4")

        async def refresh(fix=False):
            content.clear()

            with content:
                ui.label("Running checks...").classes("text-sm text-grey-6")

            from ai_guardian.web.config_helpers import load_web_health_check

            report = await run.io_bound(load_web_health_check, fix)

            content.clear()
            with content:
                if not report:
                    ui.label("Failed to run health checks.").classes("text-grey-6")
                    return

                checks = report.get("checks", [])

                counts = {"pass": 0, "warn": 0, "fail": 0, "skip": 0, "fixed": 0}
                for check in checks:
                    status = check.get("status", "skip")
                    counts[status] = counts.get(status, 0) + 1
                    if check.get("fixed"):
                        counts["fixed"] += 1

                with ui.card().classes("w-full"):
                    ui.label("Summary").classes("text-lg font-bold")
                    with ui.row().classes("items-center gap-3"):
                        ui.badge(
                            f"Pass: {counts['pass']}",
                            color="green",
                        )
                        ui.badge(
                            f"Warn: {counts['warn']}",
                            color="amber",
                        )
                        ui.badge(
                            f"Fail: {counts['fail']}",
                            color="red",
                        )
                        ui.badge(
                            f"Skip: {counts['skip']}",
                            color="grey",
                        )
                        if counts["fixed"]:
                            ui.badge(
                                f"Fixed: {counts['fixed']}",
                                color="blue",
                            )

                with ui.card().classes("w-full"):
                    ui.label("Check Results").classes("text-lg font-bold")

                    for check in checks:
                        status = check.get("status", "skip")
                        icon_name, color = _STATUS_ICONS.get(
                            status,
                            ("help", "grey"),
                        )
                        with ui.row().classes("items-center gap-2 w-full"):
                            ui.icon(icon_name).classes(f"text-{color}")
                            ui.label(check.get("name", "")).classes("font-bold text-sm")
                            ui.label(check.get("message", "")).classes(
                                "text-sm text-grey-4 flex-grow"
                            )
                            if check.get("fixed"):
                                ui.badge("FIXED", color="blue").classes("text-xs")

                        detail = check.get("detail")
                        fix_hint = check.get("fix_hint")
                        if detail or fix_hint:
                            with ui.expansion("Details").classes("w-full ml-8"):
                                if detail:
                                    ui.label(detail).classes("text-xs text-grey-6")
                                if fix_hint:
                                    ui.label(f"Fix: {fix_hint}").classes(
                                        "text-xs text-blue-4"
                                    )

                with ui.row().classes("gap-2"):
                    ui.button(
                        "Refresh",
                        icon="refresh",
                        on_click=lambda: refresh(fix=False),
                    ).props("dense")

                    async def do_fix():
                        with ui.dialog() as dlg, ui.card():
                            ui.label("Fix Issues?").classes("font-bold")
                            ui.label(
                                "This will attempt to auto-fix fixable issues."
                            ).classes("text-sm")

                            with ui.row().classes("gap-2 mt-2"):

                                async def confirm():
                                    dlg.close()
                                    await refresh(fix=True)
                                    ui.notify(
                                        "Fix complete",
                                        type="positive",
                                    )

                                ui.button(
                                    "Fix",
                                    on_click=confirm,
                                    color="green",
                                ).props("dense")
                                ui.button(
                                    "Cancel",
                                    on_click=dlg.close,
                                ).props("dense flat")

                        dlg.open()

                    if not _is_remote:
                        has_fixable = any(c.get("fixable") for c in checks)
                        ui.button(
                            "Fix Issues",
                            icon="build",
                            on_click=do_fix,
                            color="green",
                        ).props("dense" + (" disable" if not has_fixable else ""))

        ui.timer(0.1, refresh, once=True)
