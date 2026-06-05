"""Permission Rules page — unified view of all permissions.rules[] entries.

Replaces the separate Skills and MCP Servers rule panels with a single
ordered list. Rule order matters: last-match-wins across all rules.
"""

import re
from datetime import datetime, timedelta, timezone

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    """Format remaining time until *dt* as a human-readable string."""
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
    """Format a valid_until timestamp for display badge."""
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


def _classify_matcher(matcher: str) -> tuple:
    """Return (type_label, icon, color) for a matcher string."""
    if matcher.startswith("mcp__"):
        return "MCP", "dns", "purple"
    if matcher == "Skill":
        return "Skill", "extension", "blue"
    if matcher in ("Bash", "Write", "Read", "Edit", "Glob", "Grep", "WebFetch"):
        return "Tool", "build", "orange"
    if matcher == "*":
        return "Global", "public", "grey"
    return "Custom", "tune", "teal"


def _get_all_rules(config):
    """Return the full permissions.rules[] list."""
    permissions = config.get("permissions", {})
    if not isinstance(permissions, dict):
        return []
    return list(permissions.get("rules", []))


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

def create_permission_rules_page(service, daemon_name: str):
    """Create the unified Permission Rules page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/permission-rules")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Permission Rules").classes("text-2xl font-bold")
            ui.label(
                "All tool permission rules in evaluation order. "
                "Last matching rule wins."
            ).classes("text-xs text-grey-6")

            # State for filter
            filter_state = {"type": "all"}

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    permissions = config.get("permissions", {})
                    raw_enabled = (
                        permissions.get("enabled", True)
                        if isinstance(permissions, dict)
                        else True
                    )

                    # --- Enforcement toggle ---
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
                                pass
                        is_enabled = (
                            raw_enabled.get("value", True) if not is_temp else False
                        )
                    else:
                        is_enabled = bool(raw_enabled)

                    with ui.card().classes("w-full"):
                        if is_temp and until_dt:
                            remaining = _format_remaining(until_dt)
                            with ui.row().classes("items-center gap-2 w-full"):
                                ui.icon("timer").classes("text-amber")
                                ui.label("Tool Permissions Enforcement").classes(
                                    "font-bold text-sm flex-grow"
                                )
                                ui.badge(
                                    f"TEMP DISABLED \u2014 {remaining}",
                                    color="amber",
                                ).classes("text-xs")
                            ui.label(
                                "Controls whether AI Guardian enforces "
                                "tool permission rules."
                            ).classes("text-xs text-grey-6 ml-8")
                            if reason:
                                ui.label(f"Reason: {reason}").classes(
                                    "text-xs text-grey-7 ml-8"
                                )

                            async def do_reenable():
                                cfg = await run.io_bound(load_web_config)
                                if "permissions" not in cfg or not isinstance(
                                    cfg["permissions"], dict
                                ):
                                    cfg["permissions"] = {
                                        "enabled": True,
                                        "rules": [],
                                    }
                                cfg["permissions"]["enabled"] = True
                                await run.io_bound(save_web_config, cfg)
                                ui.notify(
                                    "Permissions re-enabled", type="positive"
                                )
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
                                    "Controls whether AI Guardian enforces "
                                    "tool permission rules."
                                ).classes("text-xs text-grey-6")

                                async def on_toggle(e):
                                    cfg = await run.io_bound(load_web_config)
                                    if "permissions" not in cfg or not isinstance(
                                        cfg["permissions"], dict
                                    ):
                                        cfg["permissions"] = {
                                            "enabled": True,
                                            "rules": [],
                                        }
                                    cfg["permissions"]["enabled"] = e.value
                                    await run.io_bound(save_web_config, cfg)
                                    ui.notify(
                                        "Permissions "
                                        f"{'enabled' if e.value else 'disabled'}",
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
                                            "Invalid duration (e.g. 30m, 2h, 1d)",
                                            type="negative",
                                        )
                                        return
                                    until_ts = (
                                        datetime.now(timezone.utc) + delta
                                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                                    entry = {
                                        "value": False,
                                        "disabled_until": until_ts,
                                    }
                                    rv = r.value.strip()
                                    if rv:
                                        entry["reason"] = rv
                                    cfg = await run.io_bound(load_web_config)
                                    if "permissions" not in cfg or not isinstance(
                                        cfg["permissions"], dict
                                    ):
                                        cfg["permissions"] = {
                                            "enabled": True,
                                            "rules": [],
                                        }
                                    cfg["permissions"]["enabled"] = entry
                                    await run.io_bound(save_web_config, cfg)
                                    ui.notify(
                                        f"Permissions temp disabled "
                                        f"for {d.value or '30m'}",
                                        type="warning",
                                    )
                                    await refresh()

                                ui.button(
                                    "Temp Disable",
                                    icon="timer",
                                    on_click=do_temp,
                                ).props("dense size=sm")

                    # --- Filter bar ---
                    all_rules = _get_all_rules(config)
                    type_counts = {}
                    for rule in all_rules:
                        t_label, _, _ = _classify_matcher(
                            rule.get("matcher", "")
                        )
                        type_counts[t_label] = type_counts.get(t_label, 0) + 1

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-2"):
                            ui.label("Filter:").classes("text-sm font-bold")

                            async def set_filter(t):
                                filter_state["type"] = t
                                await refresh()

                            btn_all = ui.button(
                                f"All ({len(all_rules)})",
                                on_click=lambda: set_filter("all"),
                            ).props("dense size=sm flat" if filter_state["type"] != "all" else "dense size=sm")
                            if filter_state["type"] == "all":
                                btn_all.classes("bg-blue-grey-8")

                            for t_label, count in sorted(type_counts.items()):
                                _, _, color = _classify_matcher(
                                    {"MCP": "mcp__x", "Skill": "Skill", "Tool": "Bash", "Global": "*", "Custom": "x"}.get(t_label, "x")
                                )

                                async def _click(t=t_label):
                                    await set_filter(t)

                                btn = ui.button(
                                    f"{t_label} ({count})",
                                    on_click=_click,
                                ).props(
                                    "dense size=sm flat"
                                    if filter_state["type"] != t_label
                                    else "dense size=sm"
                                )
                                if filter_state["type"] == t_label:
                                    btn.classes("bg-blue-grey-8")

                    # --- Rules list ---
                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-2 w-full"):
                            ui.label("Rules").classes("text-lg font-bold flex-grow")
                            ui.label(
                                f"{len(all_rules)} rule{'s' if len(all_rules) != 1 else ''}"
                            ).classes("text-xs text-grey-6")

                        if not all_rules:
                            ui.label(
                                "No permission rules configured."
                            ).classes("text-grey-6 text-sm")
                        else:
                            for idx, rule in enumerate(all_rules):
                                matcher = rule.get("matcher", "")
                                mode = rule.get("mode", "allow")
                                patterns = rule.get("patterns", [])
                                action = rule.get("action", "")
                                immutable = rule.get("immutable", False)
                                t_label, t_icon, t_color = _classify_matcher(
                                    matcher
                                )

                                # Apply filter
                                if (
                                    filter_state["type"] != "all"
                                    and filter_state["type"] != t_label
                                ):
                                    continue

                                mode_color = (
                                    "green" if mode == "allow" else "red"
                                )
                                border_hex = (
                                    "#4caf50" if mode == "allow" else "#f44336"
                                )

                                with ui.card().classes("w-full").style(
                                    f"border-left: 3px solid {border_hex}"
                                ):
                                    with ui.row().classes(
                                        "items-center gap-2 w-full"
                                    ):
                                        # Index badge
                                        ui.badge(
                                            str(idx), color="blue-grey"
                                        ).classes("text-xs").props("outline")

                                        # Type icon + label
                                        ui.icon(t_icon).classes(
                                            f"text-{t_color}"
                                        )
                                        ui.badge(
                                            t_label, color=t_color
                                        ).classes("text-xs")

                                        # Mode badge
                                        ui.badge(
                                            mode.upper(), color=mode_color
                                        ).classes("text-xs")

                                        # Matcher
                                        ui.label(matcher).classes(
                                            "font-bold text-sm"
                                        )

                                        # Action badge (deny only)
                                        if action and mode == "deny":
                                            action_color = {
                                                "block": "red",
                                                "warn": "amber",
                                                "log-only": "blue-grey",
                                            }.get(action, "grey")
                                            ui.badge(
                                                action, color=action_color
                                            ).classes("text-xs")

                                        # Immutable badge
                                        if immutable:
                                            ui.badge(
                                                "immutable", color="blue-grey"
                                            ).classes("text-xs").props(
                                                "outline"
                                            )

                                        # Spacer
                                        ui.element("div").classes("flex-grow")

                                        if not immutable:
                                            # Move up
                                            async def do_move_up(i=idx):
                                                if i == 0:
                                                    return
                                                cfg = await run.io_bound(
                                                    load_web_config
                                                )
                                                perms = cfg.get(
                                                    "permissions", {}
                                                )
                                                rules = (
                                                    perms.get("rules", [])
                                                    if isinstance(
                                                        perms, dict
                                                    )
                                                    else []
                                                )
                                                if i < len(rules):
                                                    rules[i], rules[i - 1] = (
                                                        rules[i - 1],
                                                        rules[i],
                                                    )
                                                    if isinstance(
                                                        cfg.get(
                                                            "permissions"
                                                        ),
                                                        dict,
                                                    ):
                                                        cfg["permissions"][
                                                            "rules"
                                                        ] = rules
                                                    await run.io_bound(
                                                        save_web_config, cfg
                                                    )
                                                    await refresh()

                                            ui.button(
                                                icon="arrow_upward",
                                                on_click=do_move_up,
                                            ).props(
                                                "flat dense size=sm"
                                                + (
                                                    " disable"
                                                    if idx == 0
                                                    else ""
                                                )
                                            )

                                            # Move down
                                            async def do_move_down(i=idx):
                                                cfg = await run.io_bound(
                                                    load_web_config
                                                )
                                                perms = cfg.get(
                                                    "permissions", {}
                                                )
                                                rules = (
                                                    perms.get("rules", [])
                                                    if isinstance(
                                                        perms, dict
                                                    )
                                                    else []
                                                )
                                                if i < len(rules) - 1:
                                                    rules[i], rules[i + 1] = (
                                                        rules[i + 1],
                                                        rules[i],
                                                    )
                                                    if isinstance(
                                                        cfg.get(
                                                            "permissions"
                                                        ),
                                                        dict,
                                                    ):
                                                        cfg["permissions"][
                                                            "rules"
                                                        ] = rules
                                                    await run.io_bound(
                                                        save_web_config, cfg
                                                    )
                                                    await refresh()

                                            is_last = idx == len(all_rules) - 1
                                            ui.button(
                                                icon="arrow_downward",
                                                on_click=do_move_down,
                                            ).props(
                                                "flat dense size=sm"
                                                + (
                                                    " disable"
                                                    if is_last
                                                    else ""
                                                )
                                            )

                                            # Edit
                                            async def do_edit(
                                                i=idx,
                                                r_matcher=matcher,
                                                r_mode=mode,
                                                r_patterns=patterns,
                                                r_action=action,
                                            ):
                                                with ui.dialog() as dlg, ui.card().classes(
                                                    "w-[500px]"
                                                ):
                                                    ui.label(
                                                        "Edit Rule"
                                                    ).classes(
                                                        "text-lg font-bold"
                                                    )
                                                    e_matcher = ui.input(
                                                        label="Matcher",
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
                                                    # Format patterns for display
                                                    pat_strs = []
                                                    for p in r_patterns:
                                                        if isinstance(p, dict):
                                                            pat_strs.append(
                                                                p.get(
                                                                    "pattern",
                                                                    str(p),
                                                                )
                                                            )
                                                        else:
                                                            pat_strs.append(
                                                                str(p)
                                                            )
                                                    e_pats = ui.input(
                                                        label="Patterns (comma-separated)",
                                                        value=", ".join(
                                                            pat_strs
                                                        ),
                                                    ).props(
                                                        "outlined dense"
                                                    ).classes("w-full")
                                                    e_action = ui.select(
                                                        label="Action (deny only)",
                                                        options={
                                                            "": "Default",
                                                            "block": "Block",
                                                            "warn": "Warn",
                                                            "log-only": "Log only",
                                                        },
                                                        value=r_action or "",
                                                    ).classes("w-48")

                                                    with ui.row().classes(
                                                        "gap-2 mt-2"
                                                    ):

                                                        async def do_save(
                                                            ii=i,
                                                        ):
                                                            m_val = e_matcher.value.strip()
                                                            if not m_val:
                                                                ui.notify(
                                                                    "Matcher is required",
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
                                                                new_pats = [
                                                                    "*"
                                                                ]
                                                            cfg = await run.io_bound(
                                                                load_web_config
                                                            )
                                                            perms = cfg.get(
                                                                "permissions",
                                                                {},
                                                            )
                                                            rules = (
                                                                perms.get(
                                                                    "rules",
                                                                    [],
                                                                )
                                                                if isinstance(
                                                                    perms,
                                                                    dict,
                                                                )
                                                                else []
                                                            )
                                                            if ii < len(
                                                                rules
                                                            ):
                                                                new_rule = {
                                                                    "matcher": m_val,
                                                                    "mode": e_mode.value,
                                                                    "patterns": new_pats,
                                                                }
                                                                act = e_action.value
                                                                if (
                                                                    act
                                                                    and e_mode.value
                                                                    == "deny"
                                                                ):
                                                                    new_rule[
                                                                        "action"
                                                                    ] = act
                                                                rules[
                                                                    ii
                                                                ] = new_rule
                                                                if isinstance(
                                                                    cfg.get(
                                                                        "permissions"
                                                                    ),
                                                                    dict,
                                                                ):
                                                                    cfg[
                                                                        "permissions"
                                                                    ][
                                                                        "rules"
                                                                    ] = rules
                                                                await run.io_bound(
                                                                    save_web_config,
                                                                    cfg,
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
                                                            on_click=do_save,
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

                                            # Delete
                                            async def do_delete(i=idx):
                                                cfg = await run.io_bound(
                                                    load_web_config
                                                )
                                                perms = cfg.get(
                                                    "permissions", {}
                                                )
                                                rules = (
                                                    perms.get("rules", [])
                                                    if isinstance(
                                                        perms, dict
                                                    )
                                                    else []
                                                )
                                                if i < len(rules):
                                                    rules.pop(i)
                                                    if isinstance(
                                                        cfg.get(
                                                            "permissions"
                                                        ),
                                                        dict,
                                                    ):
                                                        cfg["permissions"][
                                                            "rules"
                                                        ] = rules
                                                    await run.io_bound(
                                                        save_web_config, cfg
                                                    )
                                                    ui.notify(
                                                        "Rule deleted",
                                                        type="positive",
                                                    )
                                                    await refresh()

                                            ui.button(
                                                icon="delete",
                                                on_click=do_delete,
                                                color="red",
                                            ).props("flat dense size=sm")

                                    # Pattern list
                                    if patterns:
                                        with ui.row().classes(
                                            "items-center gap-1 flex-wrap ml-8"
                                        ):
                                            ui.label("Patterns:").classes(
                                                "text-xs text-grey-6"
                                            )
                                            for p in patterns:
                                                if isinstance(p, dict):
                                                    pat_str = p.get(
                                                        "pattern", str(p)
                                                    )
                                                    valid_until = p.get(
                                                        "valid_until"
                                                    )
                                                    ui.badge(
                                                        pat_str,
                                                        color="blue-grey",
                                                    ).classes(
                                                        "text-xs"
                                                    ).props("outline")
                                                    exp = _format_expiration(
                                                        valid_until
                                                    )
                                                    if exp:
                                                        ui.badge(
                                                            exp[0],
                                                            color=exp[1],
                                                        ).classes("text-xs")
                                                else:
                                                    ui.badge(
                                                        str(p),
                                                        color="blue-grey",
                                                    ).classes(
                                                        "text-xs"
                                                    ).props("outline")

                        # --- Add rule button + dialog ---
                        async def show_add_dialog():
                            with ui.dialog() as dialog, ui.card().classes(
                                "w-[500px]"
                            ):
                                ui.label("Add Permission Rule").classes(
                                    "text-lg font-bold"
                                )
                                ui.label(
                                    "Common matchers: Skill, mcp__server-name__*, "
                                    "Bash, Write, Read, Edit, *"
                                ).classes("text-xs text-grey-6")
                                a_matcher = ui.input(
                                    label="Matcher",
                                    placeholder="e.g. Skill, mcp__my-server__*, Bash, *",
                                ).props("outlined dense").classes("w-full")
                                a_mode = ui.select(
                                    label="Mode",
                                    options={
                                        "allow": "Allow",
                                        "deny": "Deny",
                                    },
                                    value="allow",
                                ).classes("w-48")
                                a_patterns = ui.input(
                                    label="Patterns (comma-separated)",
                                    placeholder="*, daf-*, notebook_*",
                                ).props("outlined dense").classes("w-full")
                                a_action = ui.select(
                                    label="Action (deny only)",
                                    options={
                                        "": "Default",
                                        "block": "Block",
                                        "warn": "Warn",
                                        "log-only": "Log only",
                                    },
                                    value="",
                                ).classes("w-48")

                                with ui.row().classes("gap-2 mt-2"):

                                    async def do_add():
                                        m_val = a_matcher.value.strip()
                                        if not m_val:
                                            ui.notify(
                                                "Matcher is required",
                                                type="negative",
                                            )
                                            return
                                        pats = [
                                            p.strip()
                                            for p in a_patterns.value.split(
                                                ","
                                            )
                                            if p.strip()
                                        ]
                                        if not pats:
                                            pats = ["*"]
                                        cfg = await run.io_bound(
                                            load_web_config
                                        )
                                        perms = cfg.get("permissions", {})
                                        if not isinstance(perms, dict):
                                            perms = {
                                                "enabled": True,
                                                "rules": [],
                                            }
                                        rules = perms.get("rules", [])
                                        new_rule = {
                                            "matcher": m_val,
                                            "mode": a_mode.value,
                                            "patterns": pats,
                                        }
                                        act = a_action.value
                                        if act and a_mode.value == "deny":
                                            new_rule["action"] = act
                                        rules.append(new_rule)
                                        perms["rules"] = rules
                                        cfg["permissions"] = perms
                                        await run.io_bound(
                                            save_web_config, cfg
                                        )
                                        dialog.close()
                                        ui.notify(
                                            "Rule added", type="positive"
                                        )
                                        await refresh()

                                    ui.button(
                                        "Add",
                                        icon="add",
                                        on_click=do_add,
                                    ).props("dense")
                                    ui.button(
                                        "Cancel",
                                        on_click=dialog.close,
                                    ).props("dense flat")
                            dialog.open()

                        ui.button(
                            "Add Rule",
                            icon="add",
                            on_click=show_add_dialog,
                        ).props("dense").classes("mt-2")

                    # --- Info card ---
                    with ui.card().classes("w-full"):
                        ui.label("How Rule Evaluation Works").classes(
                            "text-sm font-bold"
                        )
                        ui.label(
                            "Rules are evaluated in order from first to last. "
                            "The last matching rule determines the outcome "
                            "(last-match-wins). Use the arrow buttons to "
                            "reorder rules. Lower index = evaluated first."
                        ).classes("text-xs text-grey-6")

            ui.timer(0.1, refresh, once=True)
