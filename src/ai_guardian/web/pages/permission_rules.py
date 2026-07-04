"""Permission Rules page — unified view of all permissions.rules[] entries.

Replaces the separate Skills and MCP Servers rule panels with a single
ordered list. Rule order matters: last-match-wins across all rules.
"""

import re
from datetime import datetime, timedelta, timezone

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.components.help_panel import field_help_icon
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


def _pattern_to_str(p) -> str:
    """Extract the display string from a pattern (str or dict)."""
    if isinstance(p, dict):
        return p.get("pattern", str(p))
    return str(p)


def _matches_search(rule, matcher_query: str, pattern_query: str) -> bool:
    """Return True if *rule* matches the search queries (case-insensitive).

    Both queries must match (AND logic). An empty query matches everything.
    """
    if matcher_query:
        if matcher_query.lower() not in rule.get("matcher", "").lower():
            return False
    if pattern_query:
        q = pattern_query.lower()
        if not any(q in _pattern_to_str(p).lower() for p in rule.get("patterns", [])):
            return False
    return True


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
            with ui.row().classes("items-center gap-2"):
                ui.label("Permission Rules").classes("text-2xl font-bold")
                field_help_icon("permissions")
            ui.label(
                "All tool permission rules in evaluation order. "
                "Last matching rule wins."
            ).classes("text-xs text-grey-6")

            # State for filter and search
            filter_state = {
                "type": "all",
                "matcher_q": "",
                "pattern_q": "",
            }

            # --- Search bar (outside refreshable content) ---
            with ui.card().classes("w-full"):
                with ui.row().classes("items-center gap-2 w-full"):
                    ui.icon("search").classes("text-grey-6")
                    matcher_search_input = (
                        ui.input(
                            label="Matcher",
                            placeholder="e.g. Skill, mcp__...",
                        )
                        .props("dense outlined clearable")
                        .classes("w-56")
                    )
                    pattern_search_input = (
                        ui.input(
                            label="Pattern",
                            placeholder="e.g. daf-*, notebook...",
                        )
                        .props("dense outlined clearable")
                        .classes("w-56")
                    )

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
                                pass  # intentionally silent — invalid value uses default
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

                    # --- Filter + search bar ---
                    all_rules = _get_all_rules(config)
                    type_counts = {}
                    for rule in all_rules:
                        t_label, _, _ = _classify_matcher(rule.get("matcher", ""))
                        type_counts[t_label] = type_counts.get(t_label, 0) + 1

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-2 w-full"):
                            ui.label("Filter:").classes("text-sm font-bold")

                            async def set_filter(t):
                                filter_state["type"] = t
                                await refresh()

                            btn_all = ui.button(
                                f"All ({len(all_rules)})",
                                on_click=lambda: set_filter("all"),
                            ).props(
                                "dense size=sm flat"
                                if filter_state["type"] != "all"
                                else "dense size=sm"
                            )
                            if filter_state["type"] == "all":
                                btn_all.classes("bg-blue-grey-8")

                            for t_label, count in sorted(type_counts.items()):
                                _, _, color = _classify_matcher(
                                    {
                                        "MCP": "mcp__x",
                                        "Skill": "Skill",
                                        "Tool": "Bash",
                                        "Global": "*",
                                        "Custom": "x",
                                    }.get(t_label, "x")
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
                    pat_q = filter_state["pattern_q"].lower()

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-2 w-full"):
                            ui.label("Rules").classes("text-lg font-bold flex-grow")
                            ui.label(
                                f"{len(all_rules)} rule"
                                f"{'s' if len(all_rules) != 1 else ''}"
                            ).classes("text-xs text-grey-6")

                        if not all_rules:
                            ui.label("No permission rules configured.").classes(
                                "text-grey-6 text-sm"
                            )
                        else:
                            for idx, rule in enumerate(all_rules):
                                matcher = rule.get("matcher", "")
                                mode = rule.get("mode", "allow")
                                patterns = rule.get("patterns", [])
                                action = rule.get("action", "")
                                immutable = rule.get("immutable", False)
                                t_label, t_icon, t_color = _classify_matcher(matcher)

                                # Type filter
                                if (
                                    filter_state["type"] != "all"
                                    and filter_state["type"] != t_label
                                ):
                                    continue

                                # Matcher search
                                mq = filter_state["matcher_q"]
                                if mq and mq.lower() not in matcher.lower():
                                    continue

                                # Filter patterns by pattern search
                                if pat_q:
                                    visible_pats = [
                                        (pi, p)
                                        for pi, p in enumerate(patterns)
                                        if pat_q in _pattern_to_str(p).lower()
                                    ]
                                    if not visible_pats:
                                        continue
                                else:
                                    visible_pats = list(enumerate(patterns))

                                mode_color = "green" if mode == "allow" else "red"
                                border_hex = "#4caf50" if mode == "allow" else "#f44336"

                                with (
                                    ui.card()
                                    .classes("w-full")
                                    .style(f"border-left: 3px solid {border_hex}")
                                ):
                                    # --- Rule header row ---
                                    with ui.row().classes("items-center gap-2 w-full"):
                                        ui.badge(str(idx), color="blue-grey").classes(
                                            "text-xs"
                                        ).props("outline")
                                        ui.icon(t_icon).classes(f"text-{t_color}")
                                        ui.badge(t_label, color=t_color).classes(
                                            "text-xs"
                                        )
                                        ui.badge(
                                            mode.upper(), color=mode_color
                                        ).classes("text-xs")
                                        ui.label(matcher).classes("font-bold text-sm")
                                        if action and mode == "deny":
                                            ui.badge(
                                                action,
                                                color={
                                                    "block": "red",
                                                    "warn": "amber",
                                                    "log-only": "blue-grey",
                                                    "ask": "purple",
                                                    "ask:warn": "purple",
                                                    "ask:log-only": "purple",
                                                }.get(action, "grey"),
                                            ).classes("text-xs")
                                        if immutable:
                                            ui.badge(
                                                "immutable",
                                                color="blue-grey",
                                            ).classes("text-xs").props("outline")

                                        ui.element("div").classes("flex-grow")

                                        if not immutable:
                                            # Move up
                                            async def do_move_up(i=idx):
                                                if i == 0:
                                                    return
                                                cfg = await run.io_bound(
                                                    load_web_config
                                                )
                                                p = cfg.get("permissions", {})
                                                rl = (
                                                    p.get("rules", [])
                                                    if isinstance(p, dict)
                                                    else []
                                                )
                                                if i < len(rl):
                                                    rl[i], rl[i - 1] = (
                                                        rl[i - 1],
                                                        rl[i],
                                                    )
                                                    if isinstance(
                                                        cfg.get("permissions"),
                                                        dict,
                                                    ):
                                                        cfg["permissions"]["rules"] = rl
                                                    await run.io_bound(
                                                        save_web_config,
                                                        cfg,
                                                    )
                                                    await refresh()

                                            ui.button(
                                                icon="arrow_upward",
                                                on_click=do_move_up,
                                            ).props(
                                                "flat dense size=sm"
                                                + (" disable" if idx == 0 else "")
                                            )

                                            # Move down
                                            async def do_move_down(i=idx):
                                                cfg = await run.io_bound(
                                                    load_web_config
                                                )
                                                p = cfg.get("permissions", {})
                                                rl = (
                                                    p.get("rules", [])
                                                    if isinstance(p, dict)
                                                    else []
                                                )
                                                if i < len(rl) - 1:
                                                    rl[i], rl[i + 1] = (
                                                        rl[i + 1],
                                                        rl[i],
                                                    )
                                                    if isinstance(
                                                        cfg.get("permissions"),
                                                        dict,
                                                    ):
                                                        cfg["permissions"]["rules"] = rl
                                                    await run.io_bound(
                                                        save_web_config,
                                                        cfg,
                                                    )
                                                    await refresh()

                                            ui.button(
                                                icon="arrow_downward",
                                                on_click=do_move_down,
                                            ).props(
                                                "flat dense size=sm"
                                                + (
                                                    " disable"
                                                    if idx == len(all_rules) - 1
                                                    else ""
                                                )
                                            )

                                            # Edit rule (matcher/mode/action)
                                            async def do_edit_rule(
                                                i=idx,
                                                rm=matcher,
                                                rmo=mode,
                                                ra=action,
                                            ):
                                                with (
                                                    ui.dialog() as dlg,
                                                    ui.card().classes("w-[400px]"),
                                                ):
                                                    ui.label("Edit Rule").classes(
                                                        "text-lg font-bold"
                                                    )
                                                    em = (
                                                        ui.input(
                                                            label="Matcher",
                                                            value=rm,
                                                        )
                                                        .props("outlined dense")
                                                        .classes("w-full")
                                                    )
                                                    emd = ui.select(
                                                        label="Mode",
                                                        options={
                                                            "allow": "Allow",
                                                            "deny": "Deny",
                                                        },
                                                        value=rmo,
                                                    ).classes("w-48")
                                                    ea = ui.select(
                                                        label="Action (deny only)",
                                                        options={
                                                            "": "Default",
                                                            "block": "Block",
                                                            "warn": "Warn",
                                                            "log-only": "Log only",
                                                            "ask": "Ask (default: block)",
                                                            "ask:warn": "Ask (default: warn)",
                                                            "ask:log-only": "Ask (default: log-only)",
                                                        },
                                                        value=ra or "",
                                                    ).classes("w-48")

                                                    async def _save(ii=i):
                                                        mv = em.value.strip()
                                                        if not mv:
                                                            ui.notify(
                                                                "Matcher required",
                                                                type="negative",
                                                            )
                                                            return
                                                        cfg = await run.io_bound(
                                                            load_web_config
                                                        )
                                                        pr = cfg.get(
                                                            "permissions",
                                                            {},
                                                        )
                                                        rl = (
                                                            pr.get("rules", [])
                                                            if isinstance(pr, dict)
                                                            else []
                                                        )
                                                        if ii < len(rl):
                                                            rl[ii]["matcher"] = mv
                                                            rl[ii]["mode"] = emd.value
                                                            av = ea.value
                                                            if (
                                                                av
                                                                and emd.value == "deny"
                                                            ):
                                                                rl[ii]["action"] = av
                                                            else:
                                                                rl[ii].pop(
                                                                    "action",
                                                                    None,
                                                                )
                                                            if isinstance(
                                                                cfg.get("permissions"),
                                                                dict,
                                                            ):
                                                                cfg["permissions"][
                                                                    "rules"
                                                                ] = rl
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

                                                    with ui.row().classes("gap-2 mt-2"):
                                                        ui.button(
                                                            "Save",
                                                            icon="save",
                                                            on_click=_save,
                                                        ).props("dense")
                                                        ui.button(
                                                            "Cancel",
                                                            on_click=dlg.close,
                                                        ).props("dense flat")
                                                dlg.open()

                                            ui.button(
                                                icon="edit",
                                                on_click=do_edit_rule,
                                            ).props("flat dense size=sm")

                                            # Delete rule
                                            async def do_delete_rule(
                                                i=idx,
                                            ):
                                                cfg = await run.io_bound(
                                                    load_web_config
                                                )
                                                p = cfg.get("permissions", {})
                                                rl = (
                                                    p.get("rules", [])
                                                    if isinstance(p, dict)
                                                    else []
                                                )
                                                if i < len(rl):
                                                    rl.pop(i)
                                                    if isinstance(
                                                        cfg.get("permissions"),
                                                        dict,
                                                    ):
                                                        cfg["permissions"]["rules"] = rl
                                                    await run.io_bound(
                                                        save_web_config,
                                                        cfg,
                                                    )
                                                    ui.notify(
                                                        "Rule deleted",
                                                        type="positive",
                                                    )
                                                    await refresh()

                                            ui.button(
                                                icon="delete",
                                                on_click=do_delete_rule,
                                                color="red",
                                            ).props("flat dense size=sm")

                                    # --- Patterns section ---
                                    n_total = len(patterns)
                                    n_shown = len(visible_pats)
                                    label_text = (
                                        f"Patterns ({n_total})"
                                        if not pat_q
                                        else f"Patterns ({n_shown}/{n_total} matching)"
                                    )

                                    with (
                                        ui.expansion(
                                            label_text,
                                            value=n_total <= 10,
                                        )
                                        .classes("ml-6 w-full text-xs")
                                        .props("dense")
                                    ):
                                        for pi, p in visible_pats:
                                            pat_str = _pattern_to_str(p)
                                            with (
                                                ui.row()
                                                .classes(
                                                    "items-center gap-1 " "w-full py-0"
                                                )
                                                .style("min-height: 28px")
                                            ):
                                                ui.label(pat_str).classes(
                                                    "text-xs text-grey-4 "
                                                    "font-mono flex-grow"
                                                )
                                                if isinstance(p, dict):
                                                    exp = _format_expiration(
                                                        p.get("valid_until")
                                                    )
                                                    if exp:
                                                        ui.badge(
                                                            exp[0],
                                                            color=exp[1],
                                                        ).classes("text-xs")

                                                if not immutable:
                                                    # Edit pattern
                                                    async def do_edit_pat(
                                                        ri=idx,
                                                        pii=pi,
                                                        old=pat_str,
                                                    ):
                                                        with (
                                                            ui.dialog() as d,
                                                            ui.card().classes(
                                                                "w-[400px]"
                                                            ),
                                                        ):
                                                            ui.label(
                                                                "Edit Pattern"
                                                            ).classes(
                                                                "text-sm " "font-bold"
                                                            )
                                                            ep = (
                                                                ui.input(
                                                                    label="Pattern",
                                                                    value=old,
                                                                )
                                                                .props(
                                                                    "outlined " "dense"
                                                                )
                                                                .classes("w-full")
                                                            )

                                                            async def _sp(
                                                                rii=ri,
                                                                piii=pii,
                                                            ):
                                                                v = ep.value.strip()
                                                                if not v:
                                                                    ui.notify(
                                                                        "Pattern required",
                                                                        type="negative",
                                                                    )
                                                                    return
                                                                cfg = (
                                                                    await run.io_bound(
                                                                        load_web_config
                                                                    )
                                                                )
                                                                pr = cfg.get(
                                                                    "permissions",
                                                                    {},
                                                                )
                                                                rl = (
                                                                    pr.get(
                                                                        "rules",
                                                                        [],
                                                                    )
                                                                    if isinstance(
                                                                        pr,
                                                                        dict,
                                                                    )
                                                                    else []
                                                                )
                                                                if rii < len(rl):
                                                                    pts = rl[rii].get(
                                                                        "patterns",
                                                                        [],
                                                                    )
                                                                    if piii < len(pts):
                                                                        pts[piii] = v
                                                                        rl[rii][
                                                                            "patterns"
                                                                        ] = pts
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
                                                                            ] = rl
                                                                        await run.io_bound(
                                                                            save_web_config,
                                                                            cfg,
                                                                        )
                                                                d.close()
                                                                ui.notify(
                                                                    "Pattern updated",
                                                                    type="positive",
                                                                )
                                                                await refresh()

                                                            with ui.row().classes(
                                                                "gap-2 mt-1"
                                                            ):
                                                                ui.button(
                                                                    "Save",
                                                                    icon="save",
                                                                    on_click=_sp,
                                                                ).props("dense")
                                                                ui.button(
                                                                    "Cancel",
                                                                    on_click=d.close,
                                                                ).props("dense flat")
                                                        d.open()

                                                    ui.button(
                                                        icon="edit",
                                                        on_click=do_edit_pat,
                                                    ).props("flat dense size=xs")

                                                    # Delete pattern
                                                    async def do_del_pat(
                                                        ri=idx, pii=pi
                                                    ):
                                                        cfg = await run.io_bound(
                                                            load_web_config
                                                        )
                                                        pr = cfg.get(
                                                            "permissions",
                                                            {},
                                                        )
                                                        rl = (
                                                            pr.get("rules", [])
                                                            if isinstance(pr, dict)
                                                            else []
                                                        )
                                                        if ri < len(rl):
                                                            pts = rl[ri].get(
                                                                "patterns",
                                                                [],
                                                            )
                                                            if pii < len(pts):
                                                                pts.pop(pii)
                                                                rl[ri]["patterns"] = pts
                                                                if isinstance(
                                                                    cfg.get(
                                                                        "permissions"
                                                                    ),
                                                                    dict,
                                                                ):
                                                                    cfg["permissions"][
                                                                        "rules"
                                                                    ] = rl
                                                                await run.io_bound(
                                                                    save_web_config,
                                                                    cfg,
                                                                )
                                                                ui.notify(
                                                                    "Pattern removed",
                                                                    type="positive",
                                                                )
                                                                await refresh()

                                                    ui.button(
                                                        icon="delete",
                                                        on_click=do_del_pat,
                                                        color="red",
                                                    ).props("flat dense size=xs")

                                        # Add pattern button
                                        if not immutable:

                                            async def do_add_pat(ri=idx):
                                                with (
                                                    ui.dialog() as d,
                                                    ui.card().classes("w-[400px]"),
                                                ):
                                                    ui.label("Add Pattern").classes(
                                                        "text-sm font-bold"
                                                    )
                                                    np = (
                                                        ui.input(
                                                            label="Pattern",
                                                            placeholder="e.g. daf-*, *",
                                                        )
                                                        .props("outlined dense")
                                                        .classes("w-full")
                                                    )

                                                    async def _ap(rii=ri):
                                                        v = np.value.strip()
                                                        if not v:
                                                            ui.notify(
                                                                "Pattern required",
                                                                type="negative",
                                                            )
                                                            return
                                                        cfg = await run.io_bound(
                                                            load_web_config
                                                        )
                                                        pr = cfg.get(
                                                            "permissions",
                                                            {},
                                                        )
                                                        rl = (
                                                            pr.get("rules", [])
                                                            if isinstance(pr, dict)
                                                            else []
                                                        )
                                                        if rii < len(rl):
                                                            rl[rii].setdefault(
                                                                "patterns",
                                                                [],
                                                            ).append(v)
                                                            if isinstance(
                                                                cfg.get("permissions"),
                                                                dict,
                                                            ):
                                                                cfg["permissions"][
                                                                    "rules"
                                                                ] = rl
                                                            await run.io_bound(
                                                                save_web_config,
                                                                cfg,
                                                            )
                                                        d.close()
                                                        ui.notify(
                                                            "Pattern added",
                                                            type="positive",
                                                        )
                                                        await refresh()

                                                    with ui.row().classes("gap-2 mt-1"):
                                                        ui.button(
                                                            "Add",
                                                            icon="add",
                                                            on_click=_ap,
                                                        ).props("dense")
                                                        ui.button(
                                                            "Cancel",
                                                            on_click=d.close,
                                                        ).props("dense flat")
                                                d.open()

                                            ui.button(
                                                "Add Pattern",
                                                icon="add",
                                                on_click=do_add_pat,
                                            ).props("dense size=sm flat").classes(
                                                "mt-1"
                                            )

                        # --- Add rule button + dialog ---
                        async def show_add_dialog():
                            with ui.dialog() as dialog, ui.card().classes("w-[400px]"):
                                ui.label("Add Permission Rule").classes(
                                    "text-lg font-bold"
                                )
                                ui.label(
                                    "Common matchers: Skill, "
                                    "mcp__server-name__*, Bash, *"
                                ).classes("text-xs text-grey-6")
                                a_matcher = (
                                    ui.input(
                                        label="Matcher",
                                        placeholder="e.g. Skill, mcp__my-server__*, *",
                                    )
                                    .props("outlined dense")
                                    .classes("w-full")
                                )
                                a_mode = ui.select(
                                    label="Mode",
                                    options={
                                        "allow": "Allow",
                                        "deny": "Deny",
                                    },
                                    value="allow",
                                ).classes("w-48")
                                a_action = ui.select(
                                    label="Action (deny only)",
                                    options={
                                        "": "Default",
                                        "block": "Block",
                                        "warn": "Warn",
                                        "log-only": "Log only",
                                        "ask": "Ask (default: block)",
                                        "ask:warn": "Ask (default: warn)",
                                        "ask:log-only": "Ask (default: log-only)",
                                    },
                                    value="",
                                ).classes("w-48")
                                ui.label(
                                    "The rule is created with a single "
                                    '"*" pattern. Add more patterns '
                                    "inline after creation."
                                ).classes("text-xs text-grey-6 mt-2")

                                with ui.row().classes("gap-2 mt-2"):

                                    async def do_add():
                                        m_val = a_matcher.value.strip()
                                        if not m_val:
                                            ui.notify(
                                                "Matcher is required",
                                                type="negative",
                                            )
                                            return
                                        cfg = await run.io_bound(load_web_config)
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
                                            "patterns": ["*"],
                                        }
                                        act = a_action.value
                                        if act and a_mode.value == "deny":
                                            new_rule["action"] = act
                                        rules.append(new_rule)
                                        perms["rules"] = rules
                                        cfg["permissions"] = perms
                                        await run.io_bound(save_web_config, cfg)
                                        dialog.close()
                                        ui.notify("Rule added", type="positive")
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

            # Wire search inputs (defined outside content, so they
            # keep focus across refreshes)
            async def _on_matcher_search(e):
                filter_state["matcher_q"] = e.value if e.value else ""
                await refresh()

            matcher_search_input.on_value_change(_on_matcher_search)

            async def _on_pattern_search(e):
                filter_state["pattern_q"] = e.value if e.value else ""
                await refresh()

            pattern_search_input.on_value_change(_on_pattern_search)

            ui.timer(0.1, refresh, once=True)
