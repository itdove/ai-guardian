"""Effective Config page — read-only merged configuration view."""

import json
import subprocess
import sys

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar


def _run_config_show():
    """Run `ai-guardian config show --all --json` and return output.

    Returns (output_text, error_text).
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "ai_guardian", "config", "show",
             "--all", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                return json.dumps(data, indent=2), None
            except json.JSONDecodeError:
                return result.stdout, None
        return None, result.stderr or f"Exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return None, "Command timed out (15s)"
    except Exception as e:
        return None, str(e)


def create_config_effective_page(service, daemon_name: str):
    """Create the Effective Config page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(
            daemon_name, current=f"/{daemon_name}/config-effective"
        )

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Effective Configuration").classes("text-2xl font-bold")
            ui.label(
                "Merged configuration from all sources "
                "(global + project + defaults)."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                output, error = await run.io_bound(_run_config_show)

                with content:
                    if error:
                        with ui.card().classes("w-full"):
                            ui.label("Error").classes(
                                "text-lg font-bold text-red"
                            )
                            ui.label(error).classes("text-sm text-red")
                    elif output:
                        with ui.card().classes("w-full"):
                            cm = ui.codemirror(
                                output,
                                language="JSON",
                                theme="dracula",
                                line_wrapping=True,
                            ).classes("w-full").style(
                                "min-height: 70vh"
                            )
                            cm.disable()

                    ui.button(
                        "Refresh", icon="refresh", on_click=refresh
                    ).props("dense")

            ui.timer(0.1, refresh, once=True)
