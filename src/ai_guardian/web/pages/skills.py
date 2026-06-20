"""Skills page — manage Skill tool allow/deny permission patterns."""

import re
from datetime import datetime, timedelta, timezone

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config


def _get_skill_patterns(config):
    """Extract allow and deny pattern lists for Skill matcher."""
    permissions = config.get("permissions", {})
    if not isinstance(permissions, dict):
        return [], []
    rules = permissions.get("rules", [])
    allow = []
    deny = []
    for rule in rules:
        if rule.get("matcher") == "Skill":
            mode = rule.get("mode", "allow")
            patterns = rule.get("patterns", [])
            if mode == "allow":
                allow = patterns
            elif mode == "deny":
                deny = patterns
    return allow, deny


DURATION_RE = re.compile(r"^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?$", re.IGNORECASE)


def _parse_duration(text):
    """Parse a duration string like '30m', '2h', '1d' into timedelta."""
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
    """Format remaining time until a datetime as a human-readable string."""
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


def _format_expiration(valid_until):
    """Format a valid_until timestamp for display."""
    if not valid_until:
        return None
    try:
        dt = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if dt <= now:
            return "EXPIRED", "red"
        remaining = dt - now
        total = int(remaining.total_seconds())
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
        label = " ".join(parts) if parts else "<1m"
        color = "amber" if total < 86400 else "blue-grey"
        return f"expires {label}", color
    except (ValueError, TypeError):
        return None


def create_skills_page(service, daemon_name: str):
    """Create the Skills permissions page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/skills")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Skill Permissions").classes("text-2xl font-bold")
            ui.label(
                "Manage allow/deny patterns for Skill tools."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    permissions = config.get("permissions", {})
                    raw_enabled = permissions.get("enabled", True) if isinstance(permissions, dict) else True

                    is_temp = False
                    until_dt = None
                    reason = ""
                    if isinstance(raw_enabled, dict):
                        disabled_until = raw_enabled.get("disabled_until")
                        if disabled_until:
                            try:
                                until_dt = datetime.fromisoformat(
                                    disabled_until.replace("Z", "+00:00")
                                )
                                if datetime.now(timezone.utc) < until_dt:
                                    is_temp = True
                                    reason = raw_enabled.get("reason", "")
                            except (ValueError, TypeError):
                                pass  # intentionally silent — invalid value uses default
                        is_enabled = raw_enabled.get("value", True) if not is_temp else False
                    else:
                        is_enabled = bool(raw_enabled)

                    # Enforcement toggle
                    with ui.card().classes("w-full"):
                        if is_temp and until_dt:
                            remaining = _format_remaining(until_dt)
                            with ui.row().classes("items-center gap-2 w-full"):
                                ui.icon("timer").classes("text-amber")
                                ui.label("Tool Permissions Enforcement").classes(
                                    "font-bold text-sm flex-grow"
                                )
                                ui.badge(
                                    f"TEMP DISABLED — {remaining}",
                                    color="amber",
                                ).classes("text-xs")
                            ui.label(
                                "Controls whether AI Guardian enforces tool permission rules."
                            ).classes("text-xs text-grey-6 ml-8")
                            if reason:
                                ui.label(f"Reason: {reason}").classes(
                                    "text-xs text-grey-7 ml-8"
                                )

                            async def do_reenable():
                                cfg = await run.io_bound(load_web_config)
                                if "permissions" not in cfg or not isinstance(cfg["permissions"], dict):
                                    cfg["permissions"] = {"enabled": True, "rules": []}
                                cfg["permissions"]["enabled"] = True
                                await run.io_bound(save_web_config, cfg)
                                ui.notify("Permissions re-enabled", type="positive")
                                await refresh()

                            ui.button(
                                "Re-enable Now",
                                icon="play_arrow",
                                color="green",
                                on_click=do_reenable,
                            ).props("dense size=sm").classes("ml-8")
                        else:
                            with ui.row().classes("items-center gap-2 w-full"):
                                sw = ui.switch(
                                    "Tool Permissions Enforcement",
                                    value=bool(is_enabled),
                                ).classes("flex-grow")
                                ui.label(
                                    "Controls whether AI Guardian enforces tool permission rules."
                                ).classes("text-xs text-grey-6")

                                async def on_toggle(e):
                                    cfg = await run.io_bound(load_web_config)
                                    if "permissions" not in cfg or not isinstance(cfg["permissions"], dict):
                                        cfg["permissions"] = {"enabled": True, "rules": []}
                                    cfg["permissions"]["enabled"] = e.value
                                    await run.io_bound(save_web_config, cfg)
                                    ui.notify(
                                        f"Permissions {'enabled' if e.value else 'disabled'}",
                                        type="positive",
                                    )

                                sw.on_value_change(on_toggle)

                            with ui.row().classes("items-center gap-2 ml-8"):
                                dur = ui.input(
                                    placeholder="e.g. 30m, 2h, 1d"
                                ).props("dense outlined").classes("w-32")
                                rsn = ui.input(placeholder="Reason").props(
                                    "dense outlined"
                                ).classes("w-40")

                                async def do_temp(d=dur, r=rsn):
                                    delta = _parse_duration(d.value or "30m")
                                    if not delta:
                                        ui.notify(
                                            "Invalid duration (e.g. 30m, 2h, 1d)",
                                            type="negative",
                                        )
                                        return
                                    until_ts = (
                                        datetime.now(timezone.utc) + delta
                                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                                    entry = {"value": False, "disabled_until": until_ts}
                                    rv = r.value.strip()
                                    if rv:
                                        entry["reason"] = rv
                                    cfg = await run.io_bound(load_web_config)
                                    if "permissions" not in cfg or not isinstance(cfg["permissions"], dict):
                                        cfg["permissions"] = {"enabled": True, "rules": []}
                                    cfg["permissions"]["enabled"] = entry
                                    await run.io_bound(save_web_config, cfg)
                                    ui.notify(
                                        f"Permissions temp disabled for {d.value or '30m'}",
                                        type="warning",
                                    )
                                    await refresh()

                                ui.button(
                                    "Temp Disable",
                                    icon="timer",
                                    on_click=do_temp,
                                ).props("dense size=sm")

                    allow_patterns, deny_patterns = _get_skill_patterns(config)

                    # Allow list
                    with ui.card().classes("w-full"):
                        ui.label("Allow List").classes("text-lg font-bold text-green")
                        ui.label(
                            "Skills matching these patterns will be allowed."
                        ).classes("text-xs text-grey-6")

                        if allow_patterns:
                            for idx, pat in enumerate(allow_patterns):
                                pat_str = pat.get("pattern", pat) if isinstance(pat, dict) else pat
                                valid_until = pat.get("valid_until") if isinstance(pat, dict) else None
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("check_circle").classes("text-green")
                                    ui.label(pat_str).classes("flex-grow text-sm")
                                    exp = _format_expiration(valid_until)
                                    if exp:
                                        ui.badge(exp[0], color=exp[1]).classes("text-xs")

                                    async def do_remove(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        perms = cfg.get("permissions", {})
                                        rules = perms.get("rules", []) if isinstance(perms, dict) else []
                                        for rule in rules:
                                            if rule.get("matcher") == "Skill" and rule.get("mode") == "allow":
                                                pats = rule.get("patterns", [])
                                                if i < len(pats):
                                                    removed = pats.pop(i)
                                                    if not pats:
                                                        rules.remove(rule)
                                                    if isinstance(cfg.get("permissions"), dict):
                                                        cfg["permissions"]["rules"] = rules
                                                    await run.io_bound(save_web_config, cfg)
                                                    ui.notify(f"Removed: {removed}", type="positive")
                                                    await refresh()
                                                break

                                    ui.button(
                                        icon="delete", on_click=do_remove, color="red"
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No allow patterns configured.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            allow_input = ui.input(
                                placeholder="Enter pattern (e.g., daf-*, hello)"
                            ).props("dense outlined").classes("flex-grow")

                            async def add_allow():
                                pattern = allow_input.value.strip()
                                if not pattern:
                                    ui.notify("Enter a pattern", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                perms = cfg.get("permissions", {})
                                if not isinstance(perms, dict):
                                    perms = {"enabled": True, "rules": []}
                                rules = perms.get("rules", [])
                                existing = None
                                for rule in rules:
                                    if rule.get("matcher") == "Skill" and rule.get("mode") == "allow":
                                        existing = rule
                                        break
                                if existing:
                                    if pattern in existing.get("patterns", []):
                                        ui.notify("Pattern already exists", type="warning")
                                        return
                                    existing.setdefault("patterns", []).append(pattern)
                                else:
                                    rules.append({"matcher": "Skill", "mode": "allow", "patterns": [pattern]})
                                perms["rules"] = rules
                                cfg["permissions"] = perms
                                await run.io_bound(save_web_config, cfg)
                                ui.notify(f"Added allow: {pattern}", type="positive")
                                allow_input.value = ""
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_allow).props(
                                "dense"
                            )

                    # Deny list
                    with ui.card().classes("w-full"):
                        ui.label("Deny List").classes("text-lg font-bold text-red")
                        ui.label(
                            "Skills matching these patterns will be blocked."
                        ).classes("text-xs text-grey-6")

                        if deny_patterns:
                            for idx, pat in enumerate(deny_patterns):
                                pat_str = pat.get("pattern", pat) if isinstance(pat, dict) else pat
                                valid_until = pat.get("valid_until") if isinstance(pat, dict) else None
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("block").classes("text-red")
                                    ui.label(pat_str).classes("flex-grow text-sm")
                                    exp = _format_expiration(valid_until)
                                    if exp:
                                        ui.badge(exp[0], color=exp[1]).classes("text-xs")

                                    async def do_remove_deny(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        perms = cfg.get("permissions", {})
                                        rules = perms.get("rules", []) if isinstance(perms, dict) else []
                                        for rule in rules:
                                            if rule.get("matcher") == "Skill" and rule.get("mode") == "deny":
                                                pats = rule.get("patterns", [])
                                                if i < len(pats):
                                                    removed = pats.pop(i)
                                                    if not pats:
                                                        rules.remove(rule)
                                                    if isinstance(cfg.get("permissions"), dict):
                                                        cfg["permissions"]["rules"] = rules
                                                    await run.io_bound(save_web_config, cfg)
                                                    ui.notify(f"Removed: {removed}", type="positive")
                                                    await refresh()
                                                break

                                    ui.button(
                                        icon="delete", on_click=do_remove_deny, color="red"
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No deny patterns configured.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            deny_input = ui.input(
                                placeholder="Enter pattern (e.g., dangerous-*)"
                            ).props("dense outlined").classes("flex-grow")

                            async def add_deny():
                                pattern = deny_input.value.strip()
                                if not pattern:
                                    ui.notify("Enter a pattern", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                perms = cfg.get("permissions", {})
                                if not isinstance(perms, dict):
                                    perms = {"enabled": True, "rules": []}
                                rules = perms.get("rules", [])
                                existing = None
                                for rule in rules:
                                    if rule.get("matcher") == "Skill" and rule.get("mode") == "deny":
                                        existing = rule
                                        break
                                if existing:
                                    if pattern in existing.get("patterns", []):
                                        ui.notify("Pattern already exists", type="warning")
                                        return
                                    existing.setdefault("patterns", []).append(pattern)
                                else:
                                    rules.append({"matcher": "Skill", "mode": "deny", "patterns": [pattern]})
                                perms["rules"] = rules
                                cfg["permissions"] = perms
                                await run.io_bound(save_web_config, cfg)
                                ui.notify(f"Added deny: {pattern}", type="positive")
                                deny_input.value = ""
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_deny).props(
                                "dense"
                            )

            ui.timer(0.1, refresh, once=True)
