"""Reusable help panel component for web console scanner pages."""

from nicegui import ui


def add_help_button(scanner_key: str) -> None:
    """Render a '?' icon button that opens a help dialog for the given scanner.

    Call this inside a ui.row() alongside the page title label.
    """
    from ai_guardian.help_content import SCANNER_HELP

    info = SCANNER_HELP.get(scanner_key)
    if not info:
        return

    doc_url = info.get("doc_url")

    with ui.dialog() as dialog, ui.card().classes("w-full max-w-xl"):
        with ui.row().classes("w-full items-center justify-between mb-2"):
            ui.label(info["title"]).classes("text-xl font-bold")
            ui.button(icon="close", on_click=dialog.close).props("flat round dense")

        ui.separator()

        ui.label(info["summary"]).classes("text-sm mt-2")

        catches = info.get("catches", [])
        if catches:
            ui.label("What it catches:").classes("font-bold text-sm mt-3")
            with ui.column().classes("gap-0.5"):
                for item in catches:
                    with ui.row().classes("items-start gap-1"):
                        ui.icon("check_circle", size="xs").classes(
                            "text-green-600 mt-0.5"
                        )
                        ui.label(item).classes("text-sm")

        does_not_catch = info.get("does_not_catch", [])
        if does_not_catch:
            ui.label("What it does NOT catch:").classes(
                "font-bold text-sm mt-3 text-orange-700"
            )
            with ui.column().classes("gap-0.5"):
                for item in does_not_catch:
                    with ui.row().classes("items-start gap-1"):
                        ui.icon("cancel", size="xs").classes("text-orange-500 mt-0.5")
                        ui.label(item).classes("text-sm")

        config_summary = info.get("config_summary", "")
        if config_summary:
            ui.label("Key configuration:").classes("font-bold text-sm mt-3")
            ui.code(config_summary, language="yaml").classes("text-xs w-full")

        ui.separator().classes("mt-3")

        with ui.row().classes("gap-2 mt-1"):
            if doc_url:
                ui.button(
                    "Full documentation →",
                    on_click=lambda url=doc_url: ui.navigate.to(url, new_tab=True),
                ).props("flat color=primary").classes("text-sm")
            ui.button("Close", on_click=dialog.close).props("flat")

    ui.button(
        icon="help_outline",
        on_click=dialog.open,
    ).props(
        "flat round dense color=primary"
    ).tooltip("Learn more about this scanner")
