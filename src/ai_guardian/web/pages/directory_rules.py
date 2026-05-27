"""Directory Rules page — manage file path access rules with JSON editor."""

import json

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar


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


def _save_config(config):
    from ai_guardian.config_utils import get_config_dir
    path = get_config_dir() / "ai-guardian.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")


def _get_editable_rules(config):
    """Get rules without _generated/_immutable flags for editing."""
    dr = config.get("directory_rules", {})
    if not isinstance(dr, dict):
        return []
    rules = dr.get("rules", [])
    return [r for r in rules if not r.get("_generated") and not r.get("_immutable")]


def _get_preserved_rules(config):
    """Get _generated and _immutable rules to preserve on save."""
    dr = config.get("directory_rules", {})
    if not isinstance(dr, dict):
        return []
    rules = dr.get("rules", [])
    return [r for r in rules if r.get("_generated") or r.get("_immutable")]


def _validate_rules_json(text):
    """Validate rules JSON, returning (parsed_list, error_string)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"
    if not isinstance(data, list):
        return None, "Rules must be a JSON array"
    for i, rule in enumerate(data):
        if not isinstance(rule, dict):
            return None, f"Rule {i} must be an object"
        mode = rule.get("mode")
        if mode not in ("allow", "deny"):
            return None, f"Rule {i}: mode must be 'allow' or 'deny'"
        paths = rule.get("paths")
        if not isinstance(paths, list) or not paths:
            return None, f"Rule {i}: paths must be a non-empty array"
    return data, None


def create_directory_rules_page(service, daemon_name: str):
    """Create the Directory Rules page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(
            daemon_name, current=f"/{daemon_name}/directory-rules"
        )

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Directory Rules").classes("text-2xl font-bold")
            ui.label(
                "Control which file paths AI agents can access."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(_load_config)

                with content:
                    dr = config.get("directory_rules", {})
                    action = dr.get("action", "block") if isinstance(dr, dict) else "block"

                    # Action dropdown
                    with ui.card().classes("w-full"):
                        ui.label("Violation Action").classes("text-lg font-bold")
                        ui.label(
                            "What happens when a directory rule denies access."
                        ).classes("text-xs text-grey-6")
                        act_sel = ui.select(
                            options={
                                "block": "Block",
                                "warn": "Warn",
                                "log-only": "Log Only",
                            },
                            value=action,
                        ).classes("w-48")

                        async def save_action(e):
                            cfg = await run.io_bound(_load_config)
                            if "directory_rules" not in cfg or not isinstance(cfg["directory_rules"], dict):
                                cfg["directory_rules"] = {}
                            cfg["directory_rules"]["action"] = e.value
                            await run.io_bound(_save_config, cfg)
                            ui.notify(f"Action: {e.value}", type="positive")

                        act_sel.on_value_change(save_action)

                    # Rules editor
                    with ui.card().classes("w-full"):
                        ui.label("Rules Editor").classes("text-lg font-bold")
                        ui.label(
                            "Edit directory access rules as JSON. Last matching rule wins."
                        ).classes("text-xs text-grey-6")

                        editable = _get_editable_rules(config)
                        rules_text = json.dumps(editable, indent=2)

                        editor = ui.textarea(
                            value=rules_text,
                        ).props("outlined autogrow").classes("w-full").style(
                            "font-family: monospace; min-height: 200px"
                        )

                        status_label = ui.label(
                            f"Valid JSON — {len(editable)} rule(s)"
                        ).classes("text-xs text-green")

                        def on_edit(e):
                            parsed, err = _validate_rules_json(e.value)
                            if err:
                                status_label.text = err
                                status_label.classes(replace="text-xs text-red")
                            else:
                                status_label.text = f"Valid JSON — {len(parsed)} rule(s)"
                                status_label.classes(replace="text-xs text-green")

                        editor.on("update:model-value", on_edit)

                        with ui.row().classes("gap-2 mt-2"):

                            async def save_rules():
                                parsed, err = _validate_rules_json(editor.value)
                                if err:
                                    ui.notify(err, type="negative")
                                    return
                                cfg = await run.io_bound(_load_config)
                                preserved = _get_preserved_rules(cfg)
                                if "directory_rules" not in cfg or not isinstance(cfg["directory_rules"], dict):
                                    cfg["directory_rules"] = {}
                                cfg["directory_rules"]["rules"] = preserved + parsed
                                await run.io_bound(_save_config, cfg)
                                ui.notify(
                                    f"Saved {len(parsed)} rule(s)",
                                    type="positive",
                                )

                            async def reload_rules():
                                await refresh()
                                ui.notify("Rules reloaded", type="positive")

                            ui.button(
                                "Save", icon="save", on_click=save_rules
                            ).props("dense")
                            ui.button(
                                "Reload", icon="refresh", on_click=reload_rules
                            ).props("dense flat")

                    # Reference
                    with ui.card().classes("w-full"):
                        ui.label("Pattern Syntax Reference").classes(
                            "text-sm font-bold"
                        )
                        for line in [
                            "~ — expands to user home directory",
                            "* — matches one directory level",
                            "** — matches any depth recursively",
                            "Evaluation order: last matching rule wins",
                        ]:
                            ui.label(f"  {line}").classes("text-xs text-grey-6")
                        ui.label("Example:").classes("text-xs text-grey-6 mt-1")
                        ui.code(
                            '[\n'
                            '  {"mode": "deny", "paths": ["~/.ssh/**"]},\n'
                            '  {"mode": "allow", "paths": ["~/projects/**"]}\n'
                            ']',
                            language="json",
                        ).classes("text-xs")

            ui.timer(0.1, refresh, once=True)
