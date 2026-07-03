"""Code Security (Bandit) page — configuration and statistics."""

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.components.help_panel import add_help_button
from ai_guardian.web.config_helpers import load_web_config, save_web_config

_SEVERITY_OPTS = {
    "LOW": "LOW — surface all findings (low, medium, high)",
    "MEDIUM": "MEDIUM — surface medium and high findings (recommended)",
    "HIGH": "HIGH — surface high-severity findings only",
}

_ACTION_OPTS = {
    "block": "Block — fail the scan",
    "ask": "Ask — interactive prompt (block if headless)",
    "ask:warn": "Ask — interactive prompt (warn if headless)",
    "ask:log-only": "Ask — interactive prompt (log-only if headless)",
    "warn": "Warn — allow with warning (recommended)",
    "log-only": "Log Only — silent logging",
}


def _load_cs_stats():
    from ai_guardian.web.config_helpers import load_web_violations

    result = load_web_violations(violation_type="code_security")
    if result and result.get("violations"):
        return len(result["violations"])
    return 0


def create_code_security_page(service, daemon_name: str):
    """Create the Code Security (Bandit) page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/code-security")

        with ui.column().classes("flex-grow p-6 gap-4"):
            with ui.row().classes("items-center gap-2"):
                ui.label("Code Security Scanning").classes("text-2xl font-bold")
                add_help_button("code_scanning")
            ui.label(
                "Python code security scanning using Bandit — detects insecure patterns "
                "including eval/exec, subprocess shell injection, weak crypto, and SQL injection."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    cs = config.get("code_scanning", {})
                    if not isinstance(cs, dict):
                        cs = {}

                    # Enable/disable toggle
                    with ui.card().classes("w-full"):
                        ui.label("Enable Code Security Scanning").classes(
                            "text-lg font-bold"
                        )
                        is_enabled = cs.get("enabled", True)
                        sw = ui.switch("Enabled", value=bool(is_enabled))
                        ui.label(
                            "Scan all .py files in the project for insecure code patterns."
                        ).classes("text-xs text-grey-6")

                        async def on_enable_toggle(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("code_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["enabled"] = e.value
                            cfg["code_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(
                                f"Code Security {'enabled' if e.value else 'disabled'}",
                                type="positive",
                            )

                        sw.on_value_change(on_enable_toggle)

                    # Action mode
                    with ui.card().classes("w-full"):
                        ui.label("Action Mode").classes("text-lg font-bold")
                        ui.label(
                            "What happens when a code security issue is detected during scan."
                        ).classes("text-xs text-grey-6")
                        action = cs.get("action", "warn")
                        act_sel = ui.select(options=_ACTION_OPTS, value=action).classes(
                            "w-80"
                        )

                        async def save_action(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("code_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["action"] = e.value
                            cfg["code_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Action: {e.value}", type="positive")

                        act_sel.on_value_change(save_action)

                    # Severity threshold
                    with ui.card().classes("w-full"):
                        ui.label("Severity Threshold").classes("text-lg font-bold")
                        ui.label(
                            "Minimum severity level to report. Findings below the threshold are silently ignored."
                        ).classes("text-xs text-grey-6")
                        threshold = cs.get("severity_threshold", "MEDIUM").upper()
                        thr_sel = ui.select(
                            options=_SEVERITY_OPTS,
                            value=(
                                threshold if threshold in _SEVERITY_OPTS else "MEDIUM"
                            ),
                        ).classes("w-80")

                        async def save_threshold(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("code_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["severity_threshold"] = e.value
                            cfg["code_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Severity threshold: {e.value}", type="positive")

                        thr_sel.on_value_change(save_threshold)

                    # Allowlist
                    with ui.card().classes("w-full"):
                        ui.label("Allowlist").classes("text-lg font-bold")
                        ui.label(
                            "Suppress specific Bandit findings by test ID, optionally scoped to a path prefix. "
                            "The # nosec annotation in source code is also honored by Bandit natively."
                        ).classes("text-xs text-grey-6")

                        allowlist = cs.get("allowlist", [])
                        if allowlist:
                            for idx, entry in enumerate(allowlist):
                                test_id = entry.get("test_id", "?")
                                file_scope = entry.get("file", "")
                                reason = entry.get("reason", "")
                                scope_str = (
                                    f"  {file_scope}" if file_scope else "  (all files)"
                                )
                                reason_str = f"  — {reason}" if reason else ""
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("block").classes("text-orange-4")
                                    ui.label(
                                        f"{test_id}{scope_str}{reason_str}"
                                    ).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_entry(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("code_scanning", {})
                                        if not isinstance(sect, dict):
                                            return
                                        items = sect.get("allowlist", [])
                                        if i < len(items):
                                            items.pop(i)
                                            sect["allowlist"] = items
                                            cfg["code_scanning"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify(
                                                "Allowlist entry removed",
                                                type="positive",
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_entry,
                                        color="red",
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No allowlist entries.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2 flex-wrap"):
                            tid_input = (
                                ui.input(placeholder="Test ID (e.g. B101)")
                                .props("dense outlined")
                                .classes("w-32")
                            )
                            file_input = (
                                ui.input(
                                    placeholder="File prefix (optional, e.g. tests/)"
                                )
                                .props("dense outlined")
                                .classes("w-48")
                            )
                            reason_input = (
                                ui.input(placeholder="Reason (optional)")
                                .props("dense outlined")
                                .classes("w-48")
                            )

                            async def add_entry():
                                tid = tid_input.value.strip()
                                if not tid:
                                    ui.notify(
                                        "Enter a Bandit test ID (e.g. B101)",
                                        type="negative",
                                    )
                                    return
                                new_entry = {"test_id": tid}
                                fp = file_input.value.strip()
                                if fp:
                                    new_entry["file"] = fp
                                rsn = reason_input.value.strip()
                                if rsn:
                                    new_entry["reason"] = rsn
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("code_scanning", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                items = sect.get("allowlist", [])
                                items.append(new_entry)
                                sect["allowlist"] = items
                                cfg["code_scanning"] = sect
                                await run.io_bound(save_web_config, cfg)
                                tid_input.value = ""
                                file_input.value = ""
                                reason_input.value = ""
                                ui.notify(
                                    f"Allowlist entry added: {tid}", type="positive"
                                )
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_entry).props(
                                "dense"
                            )

                    # Ignore files
                    with ui.card().classes("w-full"):
                        ui.label("Ignore Files").classes("text-lg font-bold")
                        ui.label(
                            "Glob patterns for Python files to skip during code security scanning."
                        ).classes("text-xs text-grey-6")

                        ignore_files = cs.get("ignore_files", [])
                        if ignore_files:
                            for idx, pattern in enumerate(ignore_files):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("visibility_off").classes("text-grey-5")
                                    ui.label(pattern).classes(
                                        "flex-grow text-sm"
                                    ).style("font-family: monospace")

                                    async def remove_ignore(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("code_scanning", {})
                                        if not isinstance(sect, dict):
                                            return
                                        items = sect.get("ignore_files", [])
                                        if i < len(items):
                                            items.pop(i)
                                            sect["ignore_files"] = items
                                            cfg["code_scanning"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify(
                                                "Pattern removed", type="positive"
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_ignore,
                                        color="red",
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No ignore patterns.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            pattern_input = (
                                ui.input(
                                    placeholder="e.g. tests/**/*.py or migrations/"
                                )
                                .props("dense outlined")
                                .classes("flex-grow")
                            )

                            async def add_ignore():
                                val = pattern_input.value.strip()
                                if not val:
                                    ui.notify("Enter a glob pattern", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("code_scanning", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                items = sect.get("ignore_files", [])
                                if val in items:
                                    ui.notify("Pattern already exists", type="warning")
                                    return
                                items.append(val)
                                sect["ignore_files"] = items
                                cfg["code_scanning"] = sect
                                await run.io_bound(save_web_config, cfg)
                                pattern_input.value = ""
                                ui.notify(f"Added: {val}", type="positive")
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_ignore).props(
                                "dense"
                            )

                    # Statistics
                    with ui.card().classes("w-full"):
                        ui.label("Detection Statistics").classes("text-lg font-bold")
                        total = await run.io_bound(_load_cs_stats)
                        if total == 0:
                            ui.label(
                                "No code security violations recorded yet."
                            ).classes("text-grey-6 text-sm")
                        else:
                            ui.label(
                                f"Total code security violations recorded: {total}"
                            ).classes("text-sm")

                        ui.label(
                            "Run  ai-guardian scan .  to detect code security issues."
                        ).classes("text-xs text-grey-6 mt-2")

            ui.timer(0.1, refresh, once=True)
