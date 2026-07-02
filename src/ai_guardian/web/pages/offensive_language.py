"""Offensive Language Scanner page — configuration and statistics."""

from nicegui import ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config

_CATEGORIES = ["profanity", "slurs", "inclusive_language"]
_CATEGORY_LABELS = {
    "profanity": "Profanity",
    "slurs": "Slurs (racial, ethnic, gender, ableist)",
    "inclusive_language": "Non-inclusive language (master/slave, blacklist, dummy…)",
}


def _load_ol_violations():
    from ai_guardian.web.config_helpers import load_web_violations

    result = load_web_violations(violation_type="offensive_language")
    if result and result.get("violations"):
        return len(result["violations"])
    return 0


def create_offensive_language_page(service, daemon_name: str):
    """Render the Offensive Language Scanner configuration page."""

    def _load():
        cfg = load_web_config()
        return (cfg or {}).get("scan_offensive", {})

    def _save(section):
        cfg = load_web_config()
        if cfg is None:
            cfg = {}
        cfg["scan_offensive"] = section
        save_web_config(cfg)

    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/offensive-language")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Offensive Language Scanner").classes("text-2xl font-bold")
            ui.label(
                "Detect profanity, slurs, and non-inclusive terminology in code, "
                "comments, and variable names. Disabled by default."
            ).classes("text-xs text-grey-6")

            ol = _load()
            enabled = ol.get("enabled", False)
            action = ol.get("action", "log")
            categories = ol.get("categories", ["profanity", "slurs"])
            ignore_files = ol.get("ignore_files", [])

            # Status card
            with ui.card().classes("w-full"):
                ui.label("Status").classes("text-lg font-bold mb-2")
                status_color = "green" if enabled else "grey"
                ui.badge(
                    "Enabled" if enabled else "Disabled (default)",
                    color=status_color,
                ).classes("mb-2")
                ui.label(f"Action: {action}").classes("text-sm text-gray-600")
                cats_str = ", ".join(categories) if categories else "(none)"
                ui.label(f"Categories: {cats_str}").classes("text-sm text-gray-600")
                violation_count = _load_ol_violations()
                ui.label(f"Violations logged: {violation_count}").classes(
                    "text-sm text-gray-600"
                )

            # Configuration
            with ui.card().classes("w-full"):
                ui.label("Configuration").classes("text-lg font-bold mb-2")

                enable_toggle = ui.switch(
                    "Enable offensive language scanning", value=enabled
                )
                ui.label(
                    "Disabled by default. Unlike secrets/PII, offensive language is "
                    "context-dependent — enable only when your org requires it."
                ).classes("text-xs text-gray-500 mb-2")

                action_select = ui.select(
                    [
                        "block",
                        "warn",
                        "log",
                        "log-only",
                        "ask",
                        "ask:warn",
                        "ask:log-only",
                    ],
                    label="Action",
                    value=action,
                ).classes("w-48")

            # Categories
            with ui.card().classes("w-full"):
                ui.label("Categories").classes("text-lg font-bold mb-2")
                ui.label(
                    "Select which pattern sets to load. inclusive_language has a high "
                    "false positive rate in legacy codebases (git master, DNS blacklist, etc.)."
                ).classes("text-xs text-gray-500 mb-2")

                cat_checkboxes = {}
                for cat in _CATEGORIES:
                    cb = ui.checkbox(
                        _CATEGORY_LABELS[cat],
                        value=cat in categories,
                    )
                    cat_checkboxes[cat] = cb

            # Ignore files
            with ui.card().classes("w-full"):
                ui.label("Ignore Files").classes("text-lg font-bold mb-2")
                ui.label("Glob patterns for files to skip (one per line).").classes(
                    "text-xs text-gray-500"
                )
                ignore_files_area = ui.textarea(
                    label="Ignore Files",
                    value="\n".join(ignore_files),
                ).classes("w-full font-mono text-sm")

            # Save
            def on_save():
                selected_cats = [c for c, cb in cat_checkboxes.items() if cb.value]
                ign = [
                    ln.strip()
                    for ln in ignore_files_area.value.splitlines()
                    if ln.strip()
                ]
                existing = _load()
                existing.update(
                    {
                        "enabled": enable_toggle.value,
                        "action": action_select.value,
                        "categories": selected_cats,
                        "ignore_files": ign,
                    }
                )
                _save(existing)
                ui.notify("Offensive language settings saved.", type="positive")

            ui.button("Save", on_click=on_save).classes("mt-2")

            # Help
            with ui.card().classes("w-full"):
                ui.label("False Positive Handling").classes("text-lg font-bold mb-2")
                ui.markdown(
                    "- Add `# ai-guardian:allow` inline to suppress a specific line\n"
                    "- Add glob patterns to **ignore_files** above\n"
                    "- Add regexes to `scan_offensive.allowlist_patterns` in `ai-guardian.json`\n"
                    "- Deselect categories you don't need\n"
                    "- Add pattern files (`src/ai_guardian/patterns/offensive-*.toml`) to "
                    "`.aiguardignore.toml` to prevent self-scanning"
                )
