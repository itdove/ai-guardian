"""Console Settings page — editor theme and display preferences."""

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config

EDITOR_THEMES = {
    "monokai": "Monokai (dark)",
    "vscode_dark": "VS Code Dark",
    "dracula": "Dracula",
    "github_light": "GitHub Light",
}

THEME_DESCRIPTIONS = {
    "monokai": "Classic dark theme with warm accent colors — popular default for many editors.",
    "vscode_dark": "Dark theme matching Visual Studio Code's default dark color scheme.",
    "dracula": "Dark theme with vibrant purple, pink, and cyan highlights.",
    "github_light": "Light theme matching GitHub's code viewing style — good for bright environments.",
}



def create_console_settings_page(service, daemon_name: str):
    """Create the Console Settings page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(
            daemon_name, current=f"/{daemon_name}/console-settings"
        )

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Console Settings").classes("text-2xl font-bold")
            ui.label(
                "Configure console display preferences."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    with ui.card().classes("w-full"):
                        ui.label("Editor Theme").classes("text-lg font-bold")
                        ui.label(
                            "Theme used for JSON editors in the console."
                        ).classes("text-xs text-grey-6")

                        current = (
                            config.get("console", {})
                            .get("editor_theme", "monokai")
                        )
                        theme_sel = ui.select(
                            options=EDITOR_THEMES,
                            value=current,
                        ).classes("w-64")

                        desc_label = ui.label(
                            THEME_DESCRIPTIONS.get(current, "")
                        ).classes("text-sm text-grey-4 mt-1")

                        async def save_theme(e):
                            desc_label.text = THEME_DESCRIPTIONS.get(
                                e.value, ""
                            )
                            cfg = await run.io_bound(load_web_config)
                            console = cfg.get("console", {})
                            if not isinstance(console, dict):
                                console = {}
                            console["editor_theme"] = e.value
                            cfg["console"] = console
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(
                                f"Theme: {EDITOR_THEMES.get(e.value, e.value)}",
                                type="positive",
                            )

                        theme_sel.on_value_change(save_theme)

            ui.timer(0.1, refresh, once=True)
