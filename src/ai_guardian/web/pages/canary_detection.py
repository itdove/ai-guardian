"""Canary Token Detection page — configuration and statistics."""

from nicegui import ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config


def _load_canary_violations():
    from ai_guardian.web.config_helpers import load_web_violations

    result = load_web_violations(violation_type="canary_detected")
    if result and result.get("violations"):
        return len(result["violations"])
    return 0


def create_canary_detection_page(service, daemon_name: str):
    """Render the Canary Token Detection configuration page."""

    def _load():
        cfg = load_web_config()
        return (cfg or {}).get("canary_detection", {})

    def _save(section):
        cfg = load_web_config()
        if cfg is None:
            cfg = {}
        cfg["canary_detection"] = section
        save_web_config(cfg)

    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/canary-detection")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Canary Token Detection").classes("text-2xl font-bold")
            ui.label(
                "Register tripwire values in sensitive files. If the AI ever outputs "
                "those values (e.g. in a curl command), data exfiltration is detected. "
                "Disabled by default — add at least one token to make this useful."
            ).classes("text-xs text-grey-6")

            cd = _load()
            enabled = cd.get("enabled", False)
            action = cd.get("action", "block")
            tokens = cd.get("tokens", [])

            # Status card
            with ui.card().classes("w-full"):
                ui.label("Status").classes("text-lg font-bold mb-2")
                status_color = "green" if enabled else "grey"
                ui.badge(
                    "Enabled" if enabled else "Disabled (default)",
                    color=status_color,
                ).classes("mb-2")
                ui.label(f"Action: {action}").classes("text-sm text-gray-600")
                ui.label(f"Tokens registered: {len(tokens)}").classes(
                    "text-sm text-gray-600"
                )
                violation_count = _load_canary_violations()
                ui.label(f"Violations logged: {violation_count}").classes(
                    "text-sm text-gray-600"
                )

            # Configuration
            with ui.card().classes("w-full"):
                ui.label("Configuration").classes("text-lg font-bold mb-2")

                enable_toggle = ui.switch(
                    "Enable canary token detection", value=enabled
                )
                ui.label(
                    "Disabled by default. Enable after registering at least one token."
                ).classes("text-xs text-gray-500 mb-2")

                action_select = ui.select(
                    [
                        "block",
                        "warn",
                        "log-only",
                        "ask",
                        "ask:warn",
                        "ask:log-only",
                    ],
                    label="Action",
                    value=action,
                ).classes("w-48")
                ui.label(
                    "block (recommended) — prevents the operation when a canary is detected"
                ).classes("text-xs text-gray-500")

            # Tokens editor
            with ui.card().classes("w-full"):
                ui.label("Tokens").classes("text-lg font-bold mb-2")
                ui.label(
                    "One token per line. Format: value=<exact_string> or pattern=<regex>. "
                    "Optionally append :description=<label>.\n"
                    "Example: value=CANARYTOK_my-db-pass:description=DB canary"
                ).classes("text-xs text-gray-500 mb-2")

                def _tokens_to_text(tokens_list):
                    lines = []
                    for t in tokens_list:
                        desc = t.get("description", "")
                        desc_part = f":description={desc}" if desc else ""
                        if "value" in t:
                            lines.append(f"value={t['value']}{desc_part}")
                        elif "pattern" in t:
                            lines.append(f"pattern={t['pattern']}{desc_part}")
                    return "\n".join(lines)

                tokens_area = ui.textarea(
                    label="Tokens (one per line)",
                    value=_tokens_to_text(tokens),
                ).classes("w-full font-mono text-sm")

            def on_save():
                token_list = []
                for raw in tokens_area.value.splitlines():
                    raw = raw.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    desc = ""
                    if ":description=" in raw:
                        raw, desc = raw.rsplit(":description=", 1)
                    if raw.startswith("value="):
                        entry = {"value": raw[6:]}
                    elif raw.startswith("pattern="):
                        entry = {"pattern": raw[8:]}
                    else:
                        continue
                    if desc:
                        entry["description"] = desc
                    token_list.append(entry)

                existing = _load()
                existing.update(
                    {
                        "enabled": enable_toggle.value,
                        "action": action_select.value,
                        "tokens": token_list,
                    }
                )
                _save(existing)
                ui.notify("Canary detection settings saved.", type="positive")

            ui.button("Save", on_click=on_save).classes("mt-2")

            # Help
            with ui.card().classes("w-full"):
                ui.label("How It Works").classes("text-lg font-bold mb-2")
                ui.markdown(
                    "**Threat model**: Plant a secret value (canary token) in a sensitive "
                    "config file. Register it here. If the AI outputs that value in a "
                    "`curl` command, file write, or any tool output — exfiltration is "
                    "caught before it leaves.\n\n"
                    "**Why not just secret scanning?**\n"
                    "Secret scanner uses entropy + pattern matching and filters OUT "
                    "low-entropy strings to reduce false positives. "
                    "Canary detection uses exact user-registered values, bypassing entropy "
                    "checks. Works for any string you deliberately plant, including plain "
                    "text phrases like `SENTINEL_PROD_DB_2026`.\n\n"
                    "**Token types**:\n"
                    "- `value=...` — exact string match (case-sensitive)\n"
                    "- `pattern=...` — regex match (e.g. `CANARY_[A-Z0-9]{8}`)"
                )
