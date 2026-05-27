"""Permissions Discovery page — manage auto-discovery directories."""

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


def create_permissions_discovery_page(service, daemon_name: str):
    """Create the Permissions Discovery page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(
            daemon_name, current=f"/{daemon_name}/permissions-discovery"
        )

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Permissions Auto-Discovery").classes("text-2xl font-bold")
            ui.label(
                "Configure directories for scanning Skill and MCP definitions."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(_load_config)

                with content:
                    pd = config.get("permissions_directories", {})
                    allow_dirs = pd.get("allow", []) if isinstance(pd, dict) else []
                    deny_dirs = pd.get("deny", []) if isinstance(pd, dict) else []
                    total = len(allow_dirs) + len(deny_dirs)

                    # Status card
                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-2"):
                            if total > 0:
                                ui.icon("check_circle").classes("text-green")
                                ui.label(
                                    f"ENABLED — Scanning {total} director{'y' if total == 1 else 'ies'}"
                                ).classes("font-bold")
                            else:
                                ui.icon("cancel").classes("text-red")
                                ui.label(
                                    "DISABLED — No directories configured"
                                ).classes("font-bold")
                        if total > 0:
                            ui.label(
                                f"{len(allow_dirs)} allow, {len(deny_dirs)} deny"
                            ).classes("text-xs text-grey-6 ml-8")

                    # Info card
                    with ui.card().classes("w-full"):
                        ui.label("How Auto-Discovery Works").classes(
                            "text-sm font-bold"
                        )
                        ui.label(
                            "Auto-discovery scans configured directories for Skill and MCP "
                            "definition files. Discovered permissions are merged with manually "
                            "configured rules. Allow directories add permissions; deny directories "
                            "block specific matchers."
                        ).classes("text-xs text-grey-6")

                    # Allow directories
                    with ui.card().classes("w-full"):
                        ui.label("Allow Directories").classes(
                            "text-lg font-bold text-green"
                        )
                        if allow_dirs:
                            for idx, entry in enumerate(allow_dirs):
                                with ui.row().classes(
                                    "items-center gap-2 w-full"
                                ):
                                    ui.badge("ALLOW", color="green").classes(
                                        "text-xs"
                                    )
                                    ui.label(
                                        entry.get("matcher", "")
                                    ).classes("font-bold text-sm")
                                    ui.label(
                                        entry.get("url", "")
                                    ).classes("flex-grow text-sm text-grey-4")
                                    if entry.get("token_env"):
                                        ui.badge(
                                            f"token: {entry['token_env']}",
                                            color="blue-grey",
                                        ).classes("text-xs")

                                    async def remove_allow(i=idx):
                                        cfg = await run.io_bound(_load_config)
                                        dirs = cfg.get(
                                            "permissions_directories", {}
                                        )
                                        a = dirs.get("allow", [])
                                        if i < len(a):
                                            a.pop(i)
                                            dirs["allow"] = a
                                            cfg["permissions_directories"] = dirs
                                            await run.io_bound(_save_config, cfg)
                                            ui.notify(
                                                "Directory removed",
                                                type="positive",
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_allow,
                                        color="red",
                                    ).props("flat dense size=sm")
                                ui.separator().classes("my-1")
                        else:
                            ui.label("No allow directories configured.").classes(
                                "text-grey-6 text-sm"
                            )

                    # Deny directories
                    with ui.card().classes("w-full"):
                        ui.label("Deny Directories").classes(
                            "text-lg font-bold text-red"
                        )
                        if deny_dirs:
                            for idx, entry in enumerate(deny_dirs):
                                with ui.row().classes(
                                    "items-center gap-2 w-full"
                                ):
                                    ui.badge("DENY", color="red").classes(
                                        "text-xs"
                                    )
                                    ui.label(
                                        entry.get("matcher", "")
                                    ).classes("font-bold text-sm")
                                    ui.label(
                                        entry.get("url", "")
                                    ).classes("flex-grow text-sm text-grey-4")
                                    if entry.get("token_env"):
                                        ui.badge(
                                            f"token: {entry['token_env']}",
                                            color="blue-grey",
                                        ).classes("text-xs")

                                    async def remove_deny(i=idx):
                                        cfg = await run.io_bound(_load_config)
                                        dirs = cfg.get(
                                            "permissions_directories", {}
                                        )
                                        d = dirs.get("deny", [])
                                        if i < len(d):
                                            d.pop(i)
                                            dirs["deny"] = d
                                            cfg["permissions_directories"] = dirs
                                            await run.io_bound(_save_config, cfg)
                                            ui.notify(
                                                "Directory removed",
                                                type="positive",
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_deny,
                                        color="red",
                                    ).props("flat dense size=sm")
                                ui.separator().classes("my-1")
                        else:
                            ui.label("No deny directories configured.").classes(
                                "text-grey-6 text-sm"
                            )

                    # Add new directory
                    with ui.card().classes("w-full"):
                        ui.label("Add Directory").classes("text-lg font-bold")
                        with ui.column().classes("gap-2 w-full"):
                            list_type = ui.select(
                                label="List Type",
                                options={"allow": "Allow", "deny": "Deny"},
                                value="allow",
                            ).classes("w-48")
                            matcher_input = ui.input(
                                label="Matcher",
                                placeholder='e.g., Skill, mcp__*',
                            ).props("outlined dense").classes("w-full")
                            mode_input = ui.select(
                                label="Mode",
                                options={"allow": "Allow", "deny": "Deny"},
                                value="allow",
                            ).classes("w-48")
                            url_input = ui.input(
                                label="URL / Path",
                                placeholder="/path/to/dir or https://github.com/...",
                            ).props("outlined dense").classes("w-full")
                            token_input = ui.input(
                                label="Token Env Var (optional)",
                                placeholder="GITHUB_TOKEN",
                            ).props("outlined dense").classes("w-64")

                            async def add_directory():
                                matcher = matcher_input.value.strip()
                                url = url_input.value.strip()
                                if not matcher or not url:
                                    ui.notify(
                                        "Matcher and URL are required",
                                        type="negative",
                                    )
                                    return
                                cfg = await run.io_bound(_load_config)
                                dirs = cfg.get("permissions_directories", {})
                                if not isinstance(dirs, dict):
                                    dirs = {"allow": [], "deny": []}
                                lt = list_type.value
                                entries = dirs.get(lt, [])
                                entry = {
                                    "matcher": matcher,
                                    "mode": mode_input.value,
                                    "url": url,
                                }
                                token = token_input.value.strip()
                                if token:
                                    entry["token_env"] = token
                                entries.append(entry)
                                dirs[lt] = entries
                                cfg["permissions_directories"] = dirs
                                await run.io_bound(_save_config, cfg)
                                matcher_input.value = ""
                                url_input.value = ""
                                token_input.value = ""
                                ui.notify("Directory added", type="positive")
                                await refresh()

                            ui.button(
                                "Add Directory",
                                icon="add",
                                on_click=add_directory,
                            ).props("dense")

            ui.timer(0.1, refresh, once=True)
