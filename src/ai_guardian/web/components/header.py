"""Shared header and navigation components for the web console."""

from nicegui import ui


def create_header(daemon_name: str = ""):
    """Create the shared header bar showing current daemon."""
    with ui.header().classes("items-center justify-between bg-blue-grey-10"):
        with ui.row().classes("items-center gap-4"):
            ui.icon("shield").classes("text-2xl text-blue-4")
            ui.link("AI Guardian", "/").classes(
                "text-xl font-bold text-white no-underline"
            )
            if daemon_name:
                ui.label("|").classes("text-grey-6")
                ui.label(daemon_name).classes("text-white font-bold")
        with ui.row().classes("gap-2"):
            if daemon_name:
                prefix = f"/{daemon_name}"
                ui.link("Dashboard", prefix).classes(
                    "text-white no-underline"
                )
                ui.link("Violations", f"{prefix}/violations").classes(
                    "text-white no-underline"
                )
                ui.link("Metrics", f"{prefix}/metrics").classes(
                    "text-white no-underline"
                )
            else:
                ui.link("Select Daemon", "/").classes(
                    "text-white no-underline"
                )


def create_sidebar(daemon_name: str, current: str = ""):
    """Create the navigation sidebar for a specific daemon."""
    prefix = f"/{daemon_name}"
    nav_groups = [
        ("Security Overview", [
            ("Security Dashboard", prefix),
            ("Global Settings", f"{prefix}/settings"),
        ]),
        ("Monitoring", [
            ("Violations", f"{prefix}/violations"),
            ("Violation Logging", f"{prefix}/violation-logging"),
            ("Metrics", f"{prefix}/metrics"),
            ("Logs", f"{prefix}/logs"),
        ]),
        ("Configuration", [
            ("Daemon", f"{prefix}/daemon"),
        ]),
    ]
    with ui.column().classes("w-56 bg-blue-grey-10 min-h-screen p-2 gap-0"):
        for group_name, items in nav_groups:
            ui.label(group_name).classes(
                "text-xs text-grey-6 font-bold uppercase mt-4 mb-1 px-2"
            )
            for label, path in items:
                classes = "w-full no-underline rounded px-2 py-1 text-sm "
                if current == path:
                    classes += "bg-blue-grey-8 text-white font-bold"
                else:
                    classes += "text-grey-4 hover:bg-blue-grey-9"
                ui.link(label, path).classes(classes)
