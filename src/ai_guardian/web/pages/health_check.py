"""Health Check page — system health diagnostics and auto-fix."""

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar


def _get_status_icons():
    """Build the status icon mapping (lazy import to avoid circular deps)."""
    from ai_guardian.doctor import CheckStatus

    return {
        CheckStatus.PASS: ("check_circle", "green"),
        CheckStatus.WARN: ("warning", "amber"),
        CheckStatus.FAIL: ("error", "red"),
        CheckStatus.SKIP: ("skip_next", "grey"),
    }


def _run_doctor(fix=False):
    """Run all health checks. Returns DoctorReport."""
    from ai_guardian.doctor import Doctor

    doctor = Doctor(fix=fix)
    return doctor.run_all()


def create_health_check_page(service, daemon_name: str):
    """Create the Health Check page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/health-check")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Health Check").classes("text-2xl font-bold")
            ui.label("Run system diagnostics and auto-fix issues.").classes(
                "text-xs text-grey-6"
            )

            content = ui.column().classes("w-full gap-4")

            async def refresh(fix=False):
                content.clear()

                with content:
                    ui.label("Running checks...").classes("text-sm text-grey-6")

                report = await run.io_bound(_run_doctor, fix)

                content.clear()
                with content:
                    status_icons = _get_status_icons()

                    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0, "FIXED": 0}
                    for check in report.checks:
                        counts[check.status.name] += 1
                        if check.fixed:
                            counts["FIXED"] += 1

                    with ui.card().classes("w-full"):
                        ui.label("Summary").classes("text-lg font-bold")
                        with ui.row().classes("items-center gap-3"):
                            ui.badge(
                                f"Pass: {counts['PASS']}",
                                color="green",
                            )
                            ui.badge(
                                f"Warn: {counts['WARN']}",
                                color="amber",
                            )
                            ui.badge(
                                f"Fail: {counts['FAIL']}",
                                color="red",
                            )
                            ui.badge(
                                f"Skip: {counts['SKIP']}",
                                color="grey",
                            )
                            if counts["FIXED"]:
                                ui.badge(
                                    f"Fixed: {counts['FIXED']}",
                                    color="blue",
                                )

                    with ui.card().classes("w-full"):
                        ui.label("Check Results").classes("text-lg font-bold")

                        for check in report.checks:
                            icon_name, color = status_icons.get(
                                check.status,
                                ("help", "grey"),
                            )
                            with ui.row().classes("items-center gap-2 w-full"):
                                ui.icon(icon_name).classes(f"text-{color}")
                                ui.label(check.name).classes("font-bold text-sm")
                                ui.label(check.message).classes(
                                    "text-sm text-grey-4 flex-grow"
                                )
                                if check.fixed:
                                    ui.badge("FIXED", color="blue").classes("text-xs")

                            if check.detail or check.fix_hint:
                                with ui.expansion("Details").classes("w-full ml-8"):
                                    if check.detail:
                                        ui.label(check.detail).classes(
                                            "text-xs text-grey-6"
                                        )
                                    if check.fix_hint:
                                        ui.label(f"Fix: {check.fix_hint}").classes(
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
                                    "This will attempt to auto-fix " "fixable issues."
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

                        has_fixable = any(c.fixable for c in report.checks)
                        ui.button(
                            "Fix Issues",
                            icon="build",
                            on_click=do_fix,
                            color="green",
                        ).props("dense" + (" disable" if not has_fixable else ""))

            ui.timer(0.1, refresh, once=True)
