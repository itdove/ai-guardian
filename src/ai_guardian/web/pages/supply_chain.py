"""Supply Chain Scanning page — configuration, allowlist paths, and statistics."""

import re as re_mod
from datetime import datetime, timedelta, timezone

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config

DURATION_RE = re_mod.compile(r"^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?$", re_mod.IGNORECASE)


def _parse_duration(text):
    text = text.strip()
    m = DURATION_RE.match(text)
    if not m:
        try:
            return timedelta(minutes=int(text))
        except ValueError:
            return None
    d, h, mi = int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0)
    if d == 0 and h == 0 and mi == 0:
        return None
    return timedelta(days=d, hours=h, minutes=mi)


def _format_remaining(dt):
    remaining = dt - datetime.now(timezone.utc)
    total = max(0, int(remaining.total_seconds()))
    if total == 0:
        return "expired"
    d = total // 86400
    h = (total % 86400) // 3600
    m = (total % 3600) // 60
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    return " ".join(parts) if parts else "<1m"


def _parse_enabled(raw):
    if isinstance(raw, dict):
        disabled_until = raw.get("disabled_until")
        if disabled_until:
            try:
                until_dt = datetime.fromisoformat(disabled_until.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) < until_dt:
                    return True, until_dt, raw.get("reason", ""), False
            except (ValueError, TypeError):
                pass  # intentionally silent — invalid value uses default
        return False, None, "", bool(raw.get("value", True))
    return False, None, "", bool(raw)


def _load_sc_stats():
    from ai_guardian.web.config_helpers import load_web_violations

    result = load_web_violations(violation_type="supply_chain")
    if result and result.get("violations"):
        return len(result["violations"])
    return 0


def _render_toggle(
    label, desc, is_temp, until_dt, reason, is_enabled, save_fn, refresh_fn
):
    with ui.card().classes("w-full"):
        if is_temp and until_dt:
            remaining = _format_remaining(until_dt)
            with ui.row().classes("items-center gap-2 w-full"):
                ui.icon("timer").classes("text-amber")
                ui.label(label).classes("font-bold text-sm flex-grow")
                ui.badge(f"TEMP DISABLED — {remaining}", color="amber").classes(
                    "text-xs"
                )
            ui.label(desc).classes("text-xs text-grey-6 ml-8")
            if reason:
                ui.label(f"Reason: {reason}").classes("text-xs text-grey-7 ml-8")

            async def do_reenable():
                await run.io_bound(save_fn, True)
                ui.notify(f"{label} re-enabled", type="positive")
                await refresh_fn()

            ui.button(
                "Re-enable Now", icon="play_arrow", color="green", on_click=do_reenable
            ).props("dense size=sm").classes("ml-8")
        else:
            with ui.row().classes("items-center gap-2 w-full"):
                sw = ui.switch(label, value=bool(is_enabled)).classes("flex-grow")
                ui.label(desc).classes("text-xs text-grey-6")

                async def on_toggle(e):
                    await run.io_bound(save_fn, e.value)
                    ui.notify(
                        f"{label} {'enabled' if e.value else 'disabled'}",
                        type="positive",
                    )

                sw.on_value_change(on_toggle)

            with ui.row().classes("items-center gap-2 ml-8"):
                dur = (
                    ui.input(placeholder="e.g. 30m, 2h, 1d")
                    .props("dense outlined")
                    .classes("w-32")
                )
                rsn = (
                    ui.input(placeholder="Reason")
                    .props("dense outlined")
                    .classes("w-40")
                )

                async def do_temp(d=dur, r=rsn):
                    delta = _parse_duration(d.value or "30m")
                    if not delta:
                        ui.notify(
                            "Invalid duration (e.g. 30m, 2h, 1d)", type="negative"
                        )
                        return
                    until_ts = (datetime.now(timezone.utc) + delta).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    entry = {"value": False, "disabled_until": until_ts}
                    rv = r.value.strip()
                    if rv:
                        entry["reason"] = rv
                    await run.io_bound(save_fn, entry)
                    ui.notify(
                        f"{label} temp disabled for {d.value or '30m'}", type="warning"
                    )
                    await refresh_fn()

                ui.button("Temp Disable", icon="timer", on_click=do_temp).props(
                    "dense size=sm"
                )


def create_supply_chain_page(service, daemon_name: str):
    """Create the Supply Chain Scanning page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/supply-chain")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Supply Chain Scanning").classes("text-2xl font-bold")
            ui.label(
                "Detect malicious patterns in agent hooks, MCP server configs, and plugin files."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    sc = config.get("supply_chain", {})
                    if not isinstance(sc, dict):
                        sc = {}

                    is_temp, until_dt, reason, is_enabled = _parse_enabled(
                        sc.get("enabled", True)
                    )

                    def save_enabled(value):
                        cfg = load_web_config()
                        sect = cfg.get("supply_chain", {})
                        if not isinstance(sect, dict):
                            sect = {}
                        sect["enabled"] = value
                        cfg["supply_chain"] = sect
                        save_web_config(cfg)

                    _render_toggle(
                        "Supply Chain Scanning",
                        "Scan agent configuration files for malicious commands and supply chain attacks.",
                        is_temp,
                        until_dt,
                        reason,
                        is_enabled,
                        save_enabled,
                        refresh,
                    )

                    # Action mode
                    with ui.card().classes("w-full"):
                        ui.label("Action Mode").classes("text-lg font-bold")
                        ui.label(
                            "What happens when a supply chain threat is detected."
                        ).classes("text-xs text-grey-6")
                        action = sc.get("action", "block")
                        act_sel = ui.select(
                            options={
                                "block": "Block — reject the operation (recommended)",
                                "ask": "Ask — interactive prompt (block if headless)",
                                "ask:warn": "Ask — interactive prompt (warn if headless)",
                                "ask:log-only": "Ask — interactive prompt (log-only if headless)",
                                "warn": "Warn — allow with warning",
                                "log-only": "Log Only — silent logging",
                            },
                            value=action,
                        ).classes("w-64")

                        async def save_action(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("supply_chain", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["action"] = e.value
                            cfg["supply_chain"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Action: {e.value}", type="positive")

                        act_sel.on_value_change(save_action)

                    # Scan targets
                    with ui.card().classes("w-full"):
                        ui.label("Scan Targets").classes("text-lg font-bold")
                        ui.label(
                            "Choose which types of agent configuration files to scan."
                        ).classes("text-xs text-grey-6")

                        scan_fields = [
                            (
                                "scan_hooks",
                                "Scan Hooks",
                                "Scan hook configuration files (hooks.json, settings.json)",
                            ),
                            (
                                "scan_mcp_configs",
                                "Scan MCP Configs",
                                "Scan MCP server command configurations for suspicious patterns",
                            ),
                            (
                                "scan_plugins",
                                "Scan Plugins",
                                "Scan plugin files (OpenCode .ts, AiderDesk extensions) for dangerous APIs",
                            ),
                        ]

                        for key, label, desc in scan_fields:
                            with ui.row().classes("items-center gap-2 w-full"):
                                sw = ui.switch(label, value=sc.get(key, True)).classes(
                                    "flex-grow"
                                )
                                ui.label(desc).classes("text-xs text-grey-6")

                                async def on_scan_toggle(e, k=key):
                                    cfg = await run.io_bound(load_web_config)
                                    sect = cfg.get("supply_chain", {})
                                    if not isinstance(sect, dict):
                                        sect = {}
                                    sect[k] = e.value
                                    cfg["supply_chain"] = sect
                                    await run.io_bound(save_web_config, cfg)
                                    ui.notify(
                                        f"{k}: {'enabled' if e.value else 'disabled'}",
                                        type="positive",
                                    )

                                sw.on_value_change(on_scan_toggle)

                    # Allowlist paths
                    with ui.card().classes("w-full"):
                        ui.label("Allowlist Paths").classes("text-lg font-bold")
                        ui.label(
                            "File paths to skip during supply chain scanning. "
                            "Supports ~ expansion and glob patterns."
                        ).classes("text-xs text-grey-6")

                        paths = sc.get("allowlist_paths", [])
                        if paths:
                            for idx, path in enumerate(paths):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("folder_open").classes("text-blue-4")
                                    ui.label(path).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_path(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("supply_chain", {})
                                        if not isinstance(sect, dict):
                                            return
                                        items = sect.get("allowlist_paths", [])
                                        if i < len(items):
                                            items.pop(i)
                                            sect["allowlist_paths"] = items
                                            cfg["supply_chain"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify("Path removed", type="positive")
                                            await refresh()

                                    ui.button(
                                        icon="delete", on_click=remove_path, color="red"
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No allowlisted paths.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            path_input = (
                                ui.input(
                                    placeholder="e.g. ~/.cursor/hooks.json or ~/dev/**/*.ts"
                                )
                                .props("dense outlined")
                                .classes("flex-grow")
                            )

                            async def add_path():
                                val = path_input.value.strip()
                                if not val:
                                    ui.notify("Enter a file path", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("supply_chain", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                items = sect.get("allowlist_paths", [])
                                if val in items:
                                    ui.notify("Path already exists", type="warning")
                                    return
                                items.append(val)
                                sect["allowlist_paths"] = items
                                cfg["supply_chain"] = sect
                                await run.io_bound(save_web_config, cfg)
                                path_input.value = ""
                                ui.notify(f"Added: {val}", type="positive")
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_path).props(
                                "dense"
                            )

                    # Detection statistics
                    with ui.card().classes("w-full"):
                        ui.label("Detection Statistics").classes("text-lg font-bold")
                        total = await run.io_bound(_load_sc_stats)
                        if total is None:
                            ui.label("Violation logging not available.").classes(
                                "text-grey-6 text-sm"
                            )
                        elif total == 0:
                            ui.label("No supply chain threats detected yet.").classes(
                                "text-grey-6 text-sm"
                            )
                        else:
                            ui.label(
                                f"Total supply chain threats detected: {total}"
                            ).classes("text-sm")

            ui.timer(0.1, refresh, once=True)
