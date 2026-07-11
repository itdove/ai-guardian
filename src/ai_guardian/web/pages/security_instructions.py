"""Security Instructions page — editor for agent context injection rules."""

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.components.help_panel import field_help_icon
from ai_guardian.web.config_helpers import load_web_config, save_web_config


def _get_builtin_rules() -> str:
    try:
        from ai_guardian.response_format import _SECURITY_SYSTEM_MESSAGE

        return _SECURITY_SYSTEM_MESSAGE
    except Exception:
        return "(could not load built-in rules)"


def create_security_instructions_page(service, daemon_name: str):
    """Render the Security Instructions configuration page."""

    def _load():
        cfg = load_web_config()
        return (cfg or {}).get("security_instructions", {})

    def _save(section):
        cfg = load_web_config()
        if cfg is None:
            cfg = {}
        cfg["security_instructions"] = section
        save_web_config(cfg)

    sidebar = create_sidebar(
        daemon_name, current=f"/{daemon_name}/security-instructions"
    )
    create_header(daemon_name, drawer=sidebar)

    with ui.column().classes("flex-grow p-6 gap-4"):
        with ui.row().classes("items-center gap-2"):
            ui.label("Security Instructions").classes("text-2xl font-bold")
            field_help_icon("security_instructions")
        ui.label(
            "Configure the security rules injected into the AI agent's context "
            "via systemMessage on UserPromptSubmit. These rules instruct the agent "
            "to never attempt to bypass, disable, or work around security protections."
        ).classes("text-xs text-grey-6")

        content = ui.column().classes("w-full gap-4")

        async def refresh():
            content.clear()
            si = await run.io_bound(_load)
            if not isinstance(si, dict):
                si = {}

            inject_on_prompt = si.get("inject_on_prompt", True)
            inject_trigger = si.get("inject_trigger", "first_per_session")
            custom_rules = si.get("custom_rules", [])
            replace_defaults = si.get("replace_defaults", False)

            with content:
                # Enable / disable
                with ui.card().classes("w-full"):
                    ui.label("Injection Control").classes("text-lg font-bold mb-1")
                    ui.label(
                        "When disabled, no security rules are injected into agent context."
                    ).classes("text-xs text-grey-6 mb-2")

                    enabled_sw = ui.switch(
                        "Enable security instructions injection",
                        value=bool(inject_on_prompt),
                    )
                    ui.label(
                        "Disable only for ai-guardian development or testing."
                    ).classes("text-xs text-grey-7")

                # Inject trigger
                with ui.card().classes("w-full"):
                    ui.label("Injection Trigger").classes("text-lg font-bold mb-1")
                    ui.label(
                        "Controls when security rules are injected into the agent's context."
                    ).classes("text-xs text-grey-6 mb-2")

                    trigger_sel = ui.select(
                        options={
                            "first_per_session": "First prompt per session + after blocks (default)",
                            "every_prompt": "Every UserPromptSubmit",
                            "after_block_only": "After a block event only",
                        },
                        value=inject_trigger,
                        label="Trigger",
                    ).classes("w-96")

                # Custom rules
                with ui.card().classes("w-full"):
                    ui.label("Custom Rules").classes("text-lg font-bold mb-1")
                    ui.label(
                        "Additional rules to include in the injected security instructions. "
                        "One rule per line. These are appended to (or replace) the built-in rules."
                    ).classes("text-xs text-grey-6 mb-2")

                    custom_text = "\n".join(custom_rules)
                    rules_area = ui.textarea(
                        label="Custom rules (one per line)",
                        value=custom_text,
                    ).classes("w-full font-mono text-sm")

                    replace_sw = ui.switch(
                        "Replace built-in rules (use custom rules only)",
                        value=bool(replace_defaults),
                    )
                    ui.label(
                        "If enabled, only your custom rules are injected — the built-in rules are omitted. "
                        "Leave disabled to append custom rules to built-in rules."
                    ).classes("text-xs text-grey-7")

                def on_save():
                    raw_rules = [
                        line.strip()
                        for line in rules_area.value.splitlines()
                        if line.strip()
                    ]
                    existing = _load()
                    existing.update(
                        {
                            "inject_on_prompt": enabled_sw.value,
                            "inject_trigger": trigger_sel.value,
                            "custom_rules": raw_rules,
                            "replace_defaults": replace_sw.value,
                        }
                    )
                    _save(existing)
                    ui.notify("Security instructions settings saved.", type="positive")

                ui.button("Save", on_click=on_save).classes("mt-2")

                # Built-in rules preview
                with ui.card().classes("w-full"):
                    ui.label("Built-in Rules (read-only)").classes(
                        "text-lg font-bold mb-1"
                    )
                    ui.label(
                        "The default rules injected by ai-guardian. "
                        "These cannot be edited here — use custom_rules above to extend or "
                        "replace them."
                    ).classes("text-xs text-grey-6 mb-2")
                    builtin = _get_builtin_rules()
                    ui.code(builtin, language="text").classes("w-full text-xs")

                # How it works
                with ui.card().classes("w-full"):
                    ui.label("How It Works").classes("text-lg font-bold mb-1")
                    ui.markdown(
                        "**Security rules are injected via `systemMessage`** on `UserPromptSubmit` "
                        "hooks. The agent receives the rules in its context before processing "
                        "the user's request.\n\n"
                        "**Trigger options:**\n"
                        "- `first_per_session` — Inject once per session, then again after any "
                        "block event (recommended)\n"
                        "- `every_prompt` — Inject on every `UserPromptSubmit` (highest security, "
                        "slight overhead)\n"
                        "- `after_block_only` — Only inject after a violation block (minimal "
                        "injection frequency)\n\n"
                        "**Custom rules:**\n"
                        "Add organization-specific policies, compliance rules, or behavioral "
                        "constraints. Each line becomes one rule in the injected context.\n\n"
                        "**Replace defaults:**\n"
                        "Enable to use *only* your custom rules. Useful when the built-in rules "
                        "conflict with your workflow. Leave disabled to combine both."
                    )

        ui.timer(0.1, refresh, once=True)
