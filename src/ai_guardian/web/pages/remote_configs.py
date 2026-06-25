"""Remote Configs page — manage remote configuration URLs."""

import os
import urllib.request
import urllib.error

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config


def _normalize_url_entry(entry):
    """Normalize a URL entry to dict format.

    Accepts either a plain URL string or a dict with
    {url, enabled, token_env} keys.
    """
    if isinstance(entry, str):
        return {"url": entry, "enabled": True, "token_env": None}
    if isinstance(entry, dict):
        return {
            "url": entry.get("url", ""),
            "enabled": entry.get("enabled", True),
            "token_env": entry.get("token_env") or None,
        }
    return {"url": str(entry), "enabled": True, "token_env": None}


def _test_url_connectivity(url, token_env=None):
    """Test URL connectivity with a 5-second timeout.

    Returns (success, message).
    """
    try:
        req = urllib.request.Request(url, method="GET")
        if token_env:
            token = os.environ.get(token_env, "")
            if token:
                req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return True, f"OK ({resp.status})"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, str(e.reason)
    except Exception as e:
        return False, str(e)


def create_remote_configs_page(service, daemon_name: str):
    """Create the Remote Configs page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/remote-configs")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Remote Configs").classes("text-2xl font-bold")
            ui.label(
                "Manage remote configuration URLs that supplement local config."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    rc = config.get("remote_configs", {})
                    if not isinstance(rc, dict):
                        rc = {}
                    urls_raw = rc.get("urls", [])
                    if not isinstance(urls_raw, list):
                        urls_raw = []
                    urls = [_normalize_url_entry(e) for e in urls_raw]

                    with ui.card().classes("w-full"):
                        ui.label("Remote URLs").classes("text-lg font-bold")
                        ui.label("Configuration sources fetched periodically.").classes(
                            "text-xs text-grey-6"
                        )

                        if urls:
                            for idx, entry in enumerate(urls):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon(
                                        "link" if entry["enabled"] else "link_off"
                                    ).classes(
                                        "text-green"
                                        if entry["enabled"]
                                        else "text-grey-6"
                                    )
                                    ui.label(entry["url"]).classes(
                                        "flex-grow text-sm"
                                    ).style("font-family: monospace")
                                    if entry["token_env"]:
                                        ui.badge(
                                            entry["token_env"],
                                            color="blue-grey",
                                        ).classes("text-xs")

                                    sw = ui.switch("", value=entry["enabled"]).props(
                                        "dense"
                                    )

                                    async def toggle_enabled(e, i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("remote_configs", {})
                                        items = sect.get("urls", [])
                                        if i < len(items):
                                            norm = _normalize_url_entry(items[i])
                                            norm["enabled"] = e.value
                                            items[i] = norm
                                            sect["urls"] = items
                                            cfg["remote_configs"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify("Updated", type="positive")

                                    sw.on_value_change(toggle_enabled)

                                    async def test_url(
                                        u=entry["url"],
                                        t=entry["token_env"],
                                    ):
                                        ok, msg = await run.io_bound(
                                            _test_url_connectivity, u, t
                                        )
                                        ui.notify(
                                            f"{msg}",
                                            type=("positive" if ok else "negative"),
                                        )

                                    ui.button(
                                        icon="speed",
                                        on_click=test_url,
                                    ).props(
                                        "flat dense size=sm"
                                    ).tooltip("Test connectivity")

                                    async def remove_url(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("remote_configs", {})
                                        items = sect.get("urls", [])
                                        if i < len(items):
                                            items.pop(i)
                                            sect["urls"] = items
                                            cfg["remote_configs"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify("Removed", type="positive")
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_url,
                                        color="red",
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No remote config URLs.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            url_input = (
                                ui.input(placeholder="https://example.com/config.json")
                                .props("dense outlined")
                                .classes("flex-grow")
                            )
                            token_input = (
                                ui.input(placeholder="Token env var (optional)")
                                .props("dense outlined")
                                .classes("w-48")
                            )

                            async def add_url():
                                val = url_input.value.strip()
                                if not val:
                                    ui.notify("Enter a URL", type="negative")
                                    return
                                if not (
                                    val.startswith("http://")
                                    or val.startswith("https://")
                                    or val.startswith("/")
                                ):
                                    ui.notify(
                                        "URL must start with http://, "
                                        "https://, or /",
                                        type="negative",
                                    )
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("remote_configs", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                items = sect.get("urls", [])
                                entry = {"url": val, "enabled": True}
                                tv = token_input.value.strip()
                                if tv:
                                    entry["token_env"] = tv
                                items.append(entry)
                                sect["urls"] = items
                                cfg["remote_configs"] = sect
                                await run.io_bound(save_web_config, cfg)
                                url_input.value = ""
                                token_input.value = ""
                                ui.notify(f"Added: {val}", type="positive")
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_url).props(
                                "dense"
                            )

                    with ui.card().classes("w-full"):
                        ui.label("Cache Settings").classes("text-lg font-bold")
                        ui.label(
                            "How often to refresh remote configs and "
                            "when to expire cached data."
                        ).classes("text-xs text-grey-6")

                        with ui.row().classes("items-center gap-4"):
                            refresh_input = (
                                ui.number(
                                    label="Refresh interval (hours)",
                                    value=rc.get("refresh_interval_hours", 12),
                                    min=1,
                                    max=168,
                                )
                                .props("dense outlined")
                                .classes("w-48")
                            )

                            expire_input = (
                                ui.number(
                                    label="Expire after (hours)",
                                    value=rc.get("expire_after_hours", 168),
                                    min=1,
                                    max=720,
                                )
                                .props("dense outlined")
                                .classes("w-48")
                            )

                            async def save_cache():
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("remote_configs", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                sect["refresh_interval_hours"] = int(
                                    refresh_input.value or 12
                                )
                                sect["expire_after_hours"] = int(
                                    expire_input.value or 168
                                )
                                cfg["remote_configs"] = sect
                                await run.io_bound(save_web_config, cfg)
                                ui.notify("Cache settings saved", type="positive")

                            ui.button("Save", icon="save", on_click=save_cache).props(
                                "dense"
                            )

            ui.timer(0.1, refresh, once=True)
