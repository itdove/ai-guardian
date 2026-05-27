"""Prompt Injection Patterns page — allowlist and custom detection patterns."""

import json
import re as re_mod
from datetime import datetime, timedelta, timezone

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar

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
                pass
        return False, None, "", bool(raw.get("value", True))
    return False, None, "", bool(raw)


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


def _format_expiration(valid_until):
    if not valid_until:
        return None
    try:
        dt = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if datetime.now(timezone.utc) >= dt:
        return "EXPIRED", "red"
    remaining = _format_remaining(dt)
    return f"expires {remaining}", "amber"


def _get_pattern_text(entry):
    if isinstance(entry, dict):
        return entry.get("pattern", str(entry))
    return str(entry)


def _render_toggle(label, desc, is_temp, until_dt, reason, is_enabled,
                   save_fn, refresh_fn):
    with ui.card().classes("w-full"):
        if is_temp and until_dt:
            remaining = _format_remaining(until_dt)
            with ui.row().classes("items-center gap-2 w-full"):
                ui.icon("timer").classes("text-amber")
                ui.label(label).classes("font-bold text-sm flex-grow")
                ui.badge(f"TEMP DISABLED — {remaining}", color="amber").classes("text-xs")
            ui.label(desc).classes("text-xs text-grey-6 ml-8")
            if reason:
                ui.label(f"Reason: {reason}").classes("text-xs text-grey-7 ml-8")

            async def do_reenable():
                await run.io_bound(save_fn, True)
                ui.notify(f"{label} re-enabled", type="positive")
                await refresh_fn()

            ui.button("Re-enable Now", icon="play_arrow", color="green",
                      on_click=do_reenable).props("dense size=sm").classes("ml-8")
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
                dur = ui.input(placeholder="e.g. 30m, 2h, 1d").props("dense outlined").classes("w-32")
                rsn = ui.input(placeholder="Reason").props("dense outlined").classes("w-40")

                async def do_temp(d=dur, r=rsn):
                    delta = _parse_duration(d.value or "30m")
                    if not delta:
                        ui.notify("Invalid duration (e.g. 30m, 2h, 1d)", type="negative")
                        return
                    until_ts = (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")
                    entry = {"value": False, "disabled_until": until_ts}
                    rv = r.value.strip()
                    if rv:
                        entry["reason"] = rv
                    await run.io_bound(save_fn, entry)
                    ui.notify(f"{label} temp disabled for {d.value or '30m'}", type="warning")
                    await refresh_fn()

                ui.button("Temp Disable", icon="timer", on_click=do_temp).props("dense size=sm")


def create_pi_patterns_page(service, daemon_name: str):
    """Create the Prompt Injection Patterns page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/pi-patterns")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Prompt Injection Patterns").classes("text-2xl font-bold")
            ui.label(
                "Manage allowlist and custom detection patterns for prompt injection."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(_load_config)

                with content:
                    pi = config.get("prompt_injection", {})
                    if not isinstance(pi, dict):
                        pi = {}

                    with ui.card().classes("w-full"):
                        ui.label("Allowlist Patterns").classes("text-lg font-bold")
                        ui.label(
                            "Patterns that bypass injection detection. "
                            "Each entry can be a plain regex or include an expiration date."
                        ).classes("text-xs text-grey-6")

                        allowlist = pi.get("allowlist_patterns", [])
                        if allowlist:
                            for idx, entry in enumerate(allowlist):
                                pat_text = _get_pattern_text(entry)
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("code").classes("text-blue-4")
                                    ui.label(pat_text).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )
                                    if isinstance(entry, dict):
                                        exp_info = _format_expiration(entry.get("valid_until"))
                                        if exp_info:
                                            badge_text, badge_color = exp_info
                                            ui.badge(f"[{badge_text}]", color=badge_color).classes("text-xs")
                                        elif entry.get("valid_until"):
                                            vu = entry["valid_until"][:10]
                                            ui.badge(f"[until {vu}]", color="blue").classes("text-xs")

                                    async def remove_allow(i=idx):
                                        cfg = await run.io_bound(_load_config)
                                        sect = cfg.get("prompt_injection", {})
                                        if not isinstance(sect, dict):
                                            return
                                        pats = sect.get("allowlist_patterns", [])
                                        if i < len(pats):
                                            pats.pop(i)
                                            sect["allowlist_patterns"] = pats
                                            cfg["prompt_injection"] = sect
                                            await run.io_bound(_save_config, cfg)
                                            ui.notify("Pattern removed", type="positive")
                                            await refresh()

                                    ui.button(
                                        icon="delete", on_click=remove_allow, color="red"
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No allowlist patterns.").classes("text-grey-6 text-sm")

                        with ui.row().classes("items-center gap-2 mt-2"):
                            allow_input = ui.input(
                                placeholder="Enter allowlist regex pattern"
                            ).props("dense outlined").classes("flex-grow")

                            async def add_allow():
                                pattern = allow_input.value.strip()
                                if not pattern:
                                    ui.notify("Enter a pattern", type="negative")
                                    return
                                try:
                                    re_mod.compile(pattern)
                                except re_mod.error as e:
                                    ui.notify(f"Invalid regex: {e}", type="negative")
                                    return
                                cfg = await run.io_bound(_load_config)
                                sect = cfg.get("prompt_injection", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                pats = sect.get("allowlist_patterns", [])
                                existing = [_get_pattern_text(p) for p in pats]
                                if pattern in existing:
                                    ui.notify("Pattern already exists", type="warning")
                                    return
                                pats.append(pattern)
                                sect["allowlist_patterns"] = pats
                                cfg["prompt_injection"] = sect
                                await run.io_bound(_save_config, cfg)
                                allow_input.value = ""
                                ui.notify(f"Added: {pattern}", type="positive")
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_allow).props("dense")

                    with ui.card().classes("w-full"):
                        ui.label("Custom Detection Patterns").classes("text-lg font-bold")
                        ui.label(
                            "Custom regex patterns to detect additional injection attempts."
                        ).classes("text-xs text-grey-6")

                        custom = pi.get("custom_patterns", [])
                        if custom:
                            for idx, pat in enumerate(custom):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("code").classes("text-blue-4")
                                    ui.label(pat).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_custom(i=idx):
                                        cfg = await run.io_bound(_load_config)
                                        sect = cfg.get("prompt_injection", {})
                                        if not isinstance(sect, dict):
                                            return
                                        pats = sect.get("custom_patterns", [])
                                        if i < len(pats):
                                            pats.pop(i)
                                            sect["custom_patterns"] = pats
                                            cfg["prompt_injection"] = sect
                                            await run.io_bound(_save_config, cfg)
                                            ui.notify("Pattern removed", type="positive")
                                            await refresh()

                                    ui.button(
                                        icon="delete", on_click=remove_custom, color="red"
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No custom patterns.").classes("text-grey-6 text-sm")

                        with ui.row().classes("items-center gap-2 mt-2"):
                            custom_input = ui.input(
                                placeholder="Enter custom regex pattern"
                            ).props("dense outlined").classes("flex-grow")

                            async def add_custom():
                                pattern = custom_input.value.strip()
                                if not pattern:
                                    ui.notify("Enter a pattern", type="negative")
                                    return
                                try:
                                    re_mod.compile(pattern)
                                except re_mod.error as e:
                                    ui.notify(f"Invalid regex: {e}", type="negative")
                                    return
                                cfg = await run.io_bound(_load_config)
                                sect = cfg.get("prompt_injection", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                pats = sect.get("custom_patterns", [])
                                if pattern in pats:
                                    ui.notify("Pattern already exists", type="warning")
                                    return
                                pats.append(pattern)
                                sect["custom_patterns"] = pats
                                cfg["prompt_injection"] = sect
                                await run.io_bound(_save_config, cfg)
                                custom_input.value = ""
                                ui.notify(f"Added: {pattern}", type="positive")
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_custom).props("dense")

            ui.timer(0.1, refresh, once=True)
