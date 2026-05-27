"""Directory Scan page — scan directories for security issues."""

import json
import time

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar

SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "amber",
    "low": "blue",
    "info": "grey",
}

MAX_FINDINGS_DISPLAY = 200


def _format_severity(severity):
    """Return a NiceGUI badge color for the given severity level."""
    return SEVERITY_COLORS.get(
        (severity or "").lower(), "grey"
    )


def _load_config():
    from ai_guardian.config_utils import get_config_dir
    path = get_config_dir() / "ai-guardian.json"
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _run_scan(path, recursive, config_only, config):
    """Run a directory scan. Returns (findings, elapsed_seconds)."""
    from pathlib import Path as P
    from ai_guardian.scanner import FileScanner

    scanner = FileScanner(config)
    start = time.monotonic()
    if not recursive and P(path).is_dir():
        findings = []
        for f in sorted(P(path).resolve().iterdir()):
            if f.is_file():
                findings.extend(
                    scanner.scan_directory(
                        str(f), config_only=config_only
                    )
                )
    else:
        findings = scanner.scan_directory(path, config_only=config_only)
    elapsed = time.monotonic() - start
    return findings, elapsed


def create_directory_scan_page(service, daemon_name: str):
    """Create the Directory Scan page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(
            daemon_name, current=f"/{daemon_name}/directory-scan"
        )

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Directory Scan").classes("text-2xl font-bold")
            ui.label(
                "Scan directories for secrets, PII, and security issues."
            ).classes("text-xs text-grey-6")

            with ui.card().classes("w-full"):
                ui.label("Scan Configuration").classes("text-lg font-bold")
                path_input = ui.input(
                    label="Directory Path",
                    value=".",
                ).props("dense outlined").classes("w-full").style(
                    "font-family: monospace"
                )

                with ui.row().classes("items-center gap-4"):
                    recursive_check = ui.checkbox(
                        "Recursive", value=True
                    )
                    config_only_check = ui.checkbox(
                        "Config files only", value=False
                    )

            results_container = ui.column().classes("w-full gap-4")

            async def do_scan():
                path = path_input.value.strip()
                if not path:
                    ui.notify("Enter a directory path", type="negative")
                    return

                ui.notify("Scanning...", type="info")
                config = await run.io_bound(_load_config)
                findings, elapsed = await run.io_bound(
                    _run_scan, path,
                    recursive_check.value,
                    config_only_check.value, config,
                )

                results_container.clear()
                with results_container:
                    with ui.card().classes("w-full"):
                        ui.label("Results").classes("text-lg font-bold")

                        count = len(findings) if findings else 0
                        with ui.row().classes("items-center gap-4"):
                            ui.label(
                                f"Findings: {count}"
                            ).classes("text-sm font-bold")
                            ui.label(
                                f"Elapsed: {elapsed:.1f}s"
                            ).classes("text-xs text-grey-6")

                        if findings:
                            truncated = count > MAX_FINDINGS_DISPLAY
                            display = findings[:MAX_FINDINGS_DISPLAY]

                            with ui.scroll_area().classes(
                                "w-full"
                            ).style("max-height: 500px"):
                                for f in display:
                                    sev = f.get("severity", "info")
                                    with ui.row().classes(
                                        "items-center gap-2 w-full"
                                    ):
                                        ui.badge(
                                            sev.upper(),
                                            color=_format_severity(sev),
                                        ).classes("text-xs")
                                        rule = f.get("rule_id", "")
                                        ui.label(rule).classes(
                                            "text-xs font-bold"
                                        ).style("font-family: monospace")
                                        fp = f.get("file_path", "")
                                        ln = f.get("line_number", "")
                                        ui.label(
                                            f"{fp}:{ln}"
                                        ).classes(
                                            "text-xs text-grey-4"
                                        ).style("font-family: monospace")
                                    msg = f.get("message", "")
                                    if msg:
                                        ui.label(msg).classes(
                                            "text-xs text-grey-6 ml-8"
                                        )

                            if truncated:
                                ui.label(
                                    f"Showing {MAX_FINDINGS_DISPLAY} "
                                    f"of {count} findings."
                                ).classes("text-xs text-amber mt-2")
                        else:
                            ui.label(
                                "No issues found."
                            ).classes("text-grey-6 text-sm")

            ui.button(
                "Scan", icon="search", on_click=do_scan
            ).props("dense")
