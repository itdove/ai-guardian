"""MCP Servers page — manage MCP server permissions and support bundle."""

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config


def _get_mcp_rules(config):
    """Extract permission rules where matcher starts with mcp__."""
    permissions = config.get("permissions", {})
    if not isinstance(permissions, dict):
        return []
    rules = permissions.get("rules", [])
    return [r for r in rules if r.get("matcher", "").startswith("mcp__")]


def create_mcp_servers_page(service, daemon_name: str):
    """Create the MCP Servers permissions page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/mcp-servers")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("MCP Server Permissions").classes("text-2xl font-bold")
            ui.label(
                "Manage MCP server tool permissions and support bundle configuration."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    # Proactive Level
                    with ui.card().classes("w-full"):
                        ui.label("Proactive Check Level").classes(
                            "text-lg font-bold"
                        )
                        ui.label(
                            "Controls how aggressively MCP tools perform security checks."
                        ).classes("text-xs text-grey-6")
                        mcp_cfg = config.get("mcp_server", {})
                        level = mcp_cfg.get("proactive_level", "low") if isinstance(mcp_cfg, dict) else "low"
                        sel = ui.select(
                            options={
                                "low": "Low — check only when asked",
                                "medium": "Medium — check unfamiliar paths/commands",
                                "high": "High — check everything",
                            },
                            value=level,
                        ).classes("w-96")

                        async def save_level(e):
                            cfg = await run.io_bound(load_web_config)
                            if "mcp_server" not in cfg or not isinstance(cfg["mcp_server"], dict):
                                cfg["mcp_server"] = {}
                            cfg["mcp_server"]["proactive_level"] = e.value
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Proactive level: {e.value}", type="positive")

                        sel.on_value_change(save_level)

                    # Support Bundle
                    with ui.card().classes("w-full"):
                        ui.label("Support Bundle Export").classes(
                            "text-lg font-bold"
                        )
                        support = config.get("support", {})
                        dest_val = support.get("export_destination", "") if isinstance(support, dict) else ""
                        ttl_val = support.get("bundle_ttl_minutes", 30) if isinstance(support, dict) else 30

                        dest = ui.input(
                            label="Destination",
                            value=dest_val,
                            placeholder="~/support-bundles or s3://bucket/prefix/",
                        ).props("outlined dense").classes("w-full")
                        ttl = ui.input(
                            label="Bundle TTL (minutes)",
                            value=str(ttl_val),
                            placeholder="30",
                        ).props("outlined dense").classes("w-48")

                        async def save_support():
                            cfg = await run.io_bound(load_web_config)
                            if "support" not in cfg or not isinstance(cfg["support"], dict):
                                cfg["support"] = {}
                            cfg["support"]["export_destination"] = dest.value.strip()
                            try:
                                cfg["support"]["bundle_ttl_minutes"] = int(ttl.value)
                            except (ValueError, TypeError):
                                cfg["support"]["bundle_ttl_minutes"] = 30
                            await run.io_bound(save_web_config, cfg)
                            ui.notify("Support config saved", type="positive")

                        ui.button("Save", icon="save", on_click=save_support).props(
                            "dense"
                        )

                    # MCP Permission Rules
                    with ui.card().classes("w-full"):
                        ui.label("MCP Permission Rules").classes(
                            "text-lg font-bold"
                        )
                        mcp_rules = _get_mcp_rules(config)

                        if mcp_rules:
                            for idx, rule in enumerate(mcp_rules):
                                matcher = rule.get("matcher", "")
                                mode = rule.get("mode", "allow")
                                patterns = rule.get("patterns", [])
                                mode_color = "green" if mode == "allow" else "red"

                                with ui.card().classes("w-full").style(
                                    f"border-left: 3px solid {'#4caf50' if mode == 'allow' else '#f44336'}"
                                ):
                                    with ui.row().classes(
                                        "items-center gap-2 w-full"
                                    ):
                                        ui.badge(
                                            mode.upper(), color=mode_color
                                        ).classes("text-xs")
                                        ui.label(matcher).classes(
                                            "font-bold text-sm flex-grow"
                                        )

                                        async def do_edit(
                                            i=idx,
                                            r_matcher=matcher,
                                            r_mode=mode,
                                            r_patterns=patterns,
                                        ):
                                            with ui.dialog() as dlg, ui.card().classes(
                                                "w-[500px]"
                                            ):
                                                ui.label(
                                                    "Edit MCP Permission"
                                                ).classes("text-lg font-bold")
                                                e_matcher = ui.input(
                                                    label="Server Matcher",
                                                    value=r_matcher,
                                                ).props(
                                                    "outlined dense"
                                                ).classes("w-full")
                                                e_mode = ui.select(
                                                    label="Mode",
                                                    options={
                                                        "allow": "Allow",
                                                        "deny": "Deny",
                                                    },
                                                    value=r_mode,
                                                ).classes("w-48")
                                                e_pats = ui.input(
                                                    label="Tool Patterns (comma-separated)",
                                                    value=", ".join(
                                                        str(p) for p in r_patterns
                                                    ),
                                                ).props(
                                                    "outlined dense"
                                                ).classes("w-full")

                                                with ui.row().classes(
                                                    "gap-2 mt-2"
                                                ):

                                                    async def do_save_edit(
                                                        ii=i,
                                                    ):
                                                        m_val = e_matcher.value.strip()
                                                        if not m_val.startswith(
                                                            "mcp__"
                                                        ):
                                                            ui.notify(
                                                                "Matcher must start with mcp__",
                                                                type="negative",
                                                            )
                                                            return
                                                        new_pats = [
                                                            p.strip()
                                                            for p in e_pats.value.split(
                                                                ","
                                                            )
                                                            if p.strip()
                                                        ]
                                                        if not new_pats:
                                                            new_pats = ["*"]
                                                        cfg = await run.io_bound(
                                                            load_web_config
                                                        )
                                                        perms = cfg.get(
                                                            "permissions", {}
                                                        )
                                                        rules = (
                                                            perms.get("rules", [])
                                                            if isinstance(perms, dict)
                                                            else []
                                                        )
                                                        mcp_idx = 0
                                                        for ri, rr in enumerate(
                                                            rules
                                                        ):
                                                            if rr.get(
                                                                "matcher", ""
                                                            ).startswith("mcp__"):
                                                                if mcp_idx == ii:
                                                                    rules[ri] = {
                                                                        "matcher": m_val,
                                                                        "mode": e_mode.value,
                                                                        "patterns": new_pats,
                                                                    }
                                                                    break
                                                                mcp_idx += 1
                                                        if isinstance(
                                                            cfg.get("permissions"),
                                                            dict,
                                                        ):
                                                            cfg["permissions"][
                                                                "rules"
                                                            ] = rules
                                                        await run.io_bound(
                                                            save_web_config, cfg
                                                        )
                                                        dlg.close()
                                                        ui.notify(
                                                            "Rule updated",
                                                            type="positive",
                                                        )
                                                        await refresh()

                                                    ui.button(
                                                        "Save",
                                                        icon="save",
                                                        on_click=do_save_edit,
                                                    ).props("dense")
                                                    ui.button(
                                                        "Cancel",
                                                        on_click=dlg.close,
                                                    ).props("dense flat")
                                            dlg.open()

                                        ui.button(
                                            icon="edit",
                                            on_click=do_edit,
                                        ).props("flat dense size=sm")

                                        async def do_delete(i=idx):
                                            cfg = await run.io_bound(load_web_config)
                                            perms = cfg.get("permissions", {})
                                            rules = perms.get("rules", []) if isinstance(perms, dict) else []
                                            mcp_idx = 0
                                            for ri, r in enumerate(rules):
                                                if r.get("matcher", "").startswith("mcp__"):
                                                    if mcp_idx == i:
                                                        rules.pop(ri)
                                                        if isinstance(cfg.get("permissions"), dict):
                                                            cfg["permissions"]["rules"] = rules
                                                        await run.io_bound(
                                                            save_web_config, cfg
                                                        )
                                                        ui.notify(
                                                            "Rule deleted",
                                                            type="positive",
                                                        )
                                                        await refresh()
                                                        return
                                                    mcp_idx += 1

                                        ui.button(
                                            icon="delete",
                                            on_click=do_delete,
                                            color="red",
                                        ).props("flat dense size=sm")
                                    if patterns:
                                        ui.label(
                                            f"Patterns: {', '.join(str(p) for p in patterns)}"
                                        ).classes("text-xs text-grey-6")
                        else:
                            ui.label(
                                "No MCP server permissions defined."
                            ).classes("text-grey-6 text-sm")

                        # Add permission button + dialog
                        async def show_add_dialog():
                            with ui.dialog() as dialog, ui.card().classes(
                                "w-[500px]"
                            ):
                                ui.label("Add MCP Permission").classes(
                                    "text-lg font-bold"
                                )
                                m_input = ui.input(
                                    label="Server Matcher",
                                    placeholder="mcp__server-name__*",
                                ).props("outlined dense").classes("w-full")
                                m_mode = ui.select(
                                    label="Mode",
                                    options={"allow": "Allow", "deny": "Deny"},
                                    value="allow",
                                ).classes("w-48")
                                m_patterns = ui.input(
                                    label="Tool Patterns (comma-separated)",
                                    placeholder="*, notebook_*, chat_*",
                                ).props("outlined dense").classes("w-full")

                                with ui.row().classes("gap-2 mt-2"):

                                    async def do_save():
                                        matcher = m_input.value.strip()
                                        if not matcher.startswith("mcp__"):
                                            ui.notify(
                                                "Matcher must start with mcp__",
                                                type="negative",
                                            )
                                            return
                                        pats = [
                                            p.strip()
                                            for p in m_patterns.value.split(",")
                                            if p.strip()
                                        ]
                                        if not pats:
                                            pats = ["*"]
                                        cfg = await run.io_bound(load_web_config)
                                        perms = cfg.get("permissions", {})
                                        if not isinstance(perms, dict):
                                            perms = {"enabled": True, "rules": []}
                                        rules = perms.get("rules", [])
                                        rules.append(
                                            {
                                                "matcher": matcher,
                                                "mode": m_mode.value,
                                                "patterns": pats,
                                            }
                                        )
                                        perms["rules"] = rules
                                        cfg["permissions"] = perms
                                        await run.io_bound(save_web_config, cfg)
                                        dialog.close()
                                        ui.notify(
                                            "Permission added", type="positive"
                                        )
                                        await refresh()

                                    ui.button(
                                        "Save", icon="save", on_click=do_save
                                    ).props("dense")
                                    ui.button(
                                        "Cancel", on_click=dialog.close
                                    ).props("dense flat")
                            dialog.open()

                        ui.button(
                            "Add Permission",
                            icon="add",
                            on_click=show_add_dialog,
                        ).props("dense").classes("mt-2")

            ui.timer(0.1, refresh, once=True)
