"""Prompt Injection Detection page — detection configuration and statistics."""

import re as re_mod
from datetime import datetime, timedelta, timezone

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.components.help_panel import add_help_button, field_help_icon
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


def _load_pi_stats():
    from ai_guardian.web.config_helpers import load_web_violations

    result = load_web_violations(violation_type="prompt_injection")
    violations = result.get("violations", []) if result else []
    if not violations:
        return 0, {}
    by_detector = {}
    for v in violations:
        blocked = v.get("blocked", {}) or {}
        det = blocked.get("detector", "unknown")
        by_detector[det] = by_detector.get(det, 0) + 1
    return len(violations), by_detector


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


def create_pi_detection_page(service, daemon_name: str):
    """Create the Prompt Injection Detection page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/pi-detection")

        with ui.column().classes("flex-grow p-6 gap-4"):
            with ui.row().classes("items-center gap-2"):
                ui.label("Prompt Injection Detection").classes("text-2xl font-bold")
                add_help_button("prompt_injection")
            ui.label("Configure prompt injection detection settings.").classes(
                "text-xs text-grey-6"
            )

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    pi = config.get("prompt_injection", {})
                    if not isinstance(pi, dict):
                        pi = {}

                    is_temp, until_dt, reason, is_enabled = _parse_enabled(
                        pi.get("enabled", False)
                    )

                    def save_enabled(value):
                        cfg = load_web_config()
                        sect = cfg.get("prompt_injection", {})
                        if not isinstance(sect, dict):
                            sect = {}
                        sect["enabled"] = value
                        cfg["prompt_injection"] = sect
                        save_web_config(cfg)

                    _render_toggle(
                        "Prompt Injection Detection",
                        "Detect and block prompt injection attempts in tool inputs.",
                        is_temp,
                        until_dt,
                        reason,
                        is_enabled,
                        save_enabled,
                        refresh,
                    )

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-1"):
                            ui.label("Action Mode").classes("text-lg font-bold")
                            field_help_icon("prompt_injection")
                        ui.label(
                            "What happens when a prompt injection is detected."
                        ).classes("text-xs text-grey-6")
                        action = pi.get("action", "block")
                        act_sel = ui.select(
                            options={
                                "block": "Block — reject the operation",
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
                            sect = cfg.get("prompt_injection", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["action"] = e.value
                            cfg["prompt_injection"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Action: {e.value}", type="positive")

                        act_sel.on_value_change(save_action)

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-1"):
                            ui.label("Detector Engine").classes("text-lg font-bold")
                            field_help_icon("prompt_injection.detector")
                        ui.label("Choose which detection engine to use.").classes(
                            "text-xs text-grey-6"
                        )
                        detector = pi.get("detector", "heuristic")
                        det_sel = ui.select(
                            options={
                                "heuristic": "Heuristic (built-in)",
                                "ml": "ML (DeBERTa via daemon)",
                                "hybrid": "Hybrid (heuristic + ML)",
                            },
                            value=detector,
                        ).classes("w-64")
                        ml_hint = ui.label(
                            "Requires daemon mode and ai-guardian ml download"
                        ).classes("text-xs text-orange-7 mt-1")
                        ml_hint.visible = detector in ("ml", "hybrid")

                        async def save_detector(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("prompt_injection", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["detector"] = e.value
                            cfg["prompt_injection"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ml_hint.visible = e.value in ("ml", "hybrid")
                            ui.notify(f"Detector: {e.value}", type="positive")

                        det_sel.on_value_change(save_detector)

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-1"):
                            ui.label("Sensitivity").classes("text-lg font-bold")
                            field_help_icon("prompt_injection.sensitivity")
                        ui.label("Set the detection sensitivity level.").classes(
                            "text-xs text-grey-6"
                        )
                        sensitivity = pi.get("sensitivity", "medium")
                        sens_sel = ui.select(
                            options={
                                "low": "Low",
                                "medium": "Medium",
                                "high": "High",
                            },
                            value=sensitivity,
                        ).classes("w-64")

                        async def save_sensitivity(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("prompt_injection", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["sensitivity"] = e.value
                            cfg["prompt_injection"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Sensitivity: {e.value}", type="positive")

                        sens_sel.on_value_change(save_sensitivity)

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-1"):
                            ui.label("Max Score Threshold").classes("text-lg font-bold")
                            field_help_icon("prompt_injection.max_score_threshold")
                        ui.label(
                            "Inputs scoring above this threshold are flagged as injections (0.0-1.0)."
                        ).classes("text-xs text-grey-6")
                        threshold = pi.get("max_score_threshold", 0.75)
                        thr_input = (
                            ui.number(
                                value=threshold,
                                min=0.0,
                                max=1.0,
                                step=0.05,
                            )
                            .props("dense outlined")
                            .classes("w-32")
                        )

                        async def save_threshold(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("prompt_injection", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["max_score_threshold"] = e.value
                            cfg["prompt_injection"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Threshold: {e.value}", type="positive")

                        thr_input.on_value_change(save_threshold)

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-1"):
                            ui.label("Ignore Files").classes("text-lg font-bold")
                            field_help_icon("prompt_injection.ignore_files")
                        ui.label(
                            "Glob patterns for files to skip during prompt injection scanning."
                        ).classes("text-xs text-grey-6")

                        ignore_files = pi.get("ignore_files", [])
                        if ignore_files:
                            for idx, pat in enumerate(ignore_files):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("description").classes("text-blue-4")
                                    ui.label(pat).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_ignore_file(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("prompt_injection", {})
                                        if not isinstance(sect, dict):
                                            return
                                        items = sect.get("ignore_files", [])
                                        if i < len(items):
                                            items.pop(i)
                                            sect["ignore_files"] = items
                                            cfg["prompt_injection"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify(
                                                "Pattern removed", type="positive"
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_ignore_file,
                                        color="red",
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No ignore patterns.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            if_input = (
                                ui.input(placeholder="e.g. *.md, tests/**")
                                .props("dense outlined")
                                .classes("flex-grow")
                            )

                            async def add_ignore_file():
                                val = if_input.value.strip()
                                if not val:
                                    ui.notify("Enter a pattern", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("prompt_injection", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                items = sect.get("ignore_files", [])
                                if val in items:
                                    ui.notify("Pattern already exists", type="warning")
                                    return
                                items.append(val)
                                sect["ignore_files"] = items
                                cfg["prompt_injection"] = sect
                                await run.io_bound(save_web_config, cfg)
                                if_input.value = ""
                                ui.notify(f"Added: {val}", type="positive")
                                await refresh()

                            ui.button(
                                "Add", icon="add", on_click=add_ignore_file
                            ).props("dense")

                    with ui.card().classes("w-full"):
                        with ui.row().classes("items-center gap-1"):
                            ui.label("Ignore Tools").classes("text-lg font-bold")
                            field_help_icon("prompt_injection.ignore_tools")
                        ui.label(
                            "Tool name patterns to skip during prompt injection scanning."
                        ).classes("text-xs text-grey-6")

                        ignore_tools = pi.get("ignore_tools", [])
                        if ignore_tools:
                            for idx, pat in enumerate(ignore_tools):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("build").classes("text-blue-4")
                                    ui.label(pat).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_ignore_tool(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("prompt_injection", {})
                                        if not isinstance(sect, dict):
                                            return
                                        items = sect.get("ignore_tools", [])
                                        if i < len(items):
                                            items.pop(i)
                                            sect["ignore_tools"] = items
                                            cfg["prompt_injection"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify(
                                                "Pattern removed", type="positive"
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_ignore_tool,
                                        color="red",
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No ignore patterns.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            it_input = (
                                ui.input(placeholder="e.g. Read, Bash")
                                .props("dense outlined")
                                .classes("flex-grow")
                            )

                            async def add_ignore_tool():
                                val = it_input.value.strip()
                                if not val:
                                    ui.notify("Enter a tool name", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("prompt_injection", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                items = sect.get("ignore_tools", [])
                                if val in items:
                                    ui.notify("Pattern already exists", type="warning")
                                    return
                                items.append(val)
                                sect["ignore_tools"] = items
                                cfg["prompt_injection"] = sect
                                await run.io_bound(save_web_config, cfg)
                                it_input.value = ""
                                ui.notify(f"Added: {val}", type="positive")
                                await refresh()

                            ui.button(
                                "Add", icon="add", on_click=add_ignore_tool
                            ).props("dense")

                    with ui.card().classes("w-full"):
                        ui.label("Detection Statistics").classes("text-lg font-bold")
                        total, by_detector = await run.io_bound(_load_pi_stats)
                        if total is None:
                            ui.label("Violation logging not available.").classes(
                                "text-grey-6 text-sm"
                            )
                        elif total == 0:
                            ui.label("No prompt injections detected yet.").classes(
                                "text-grey-6 text-sm"
                            )
                        else:
                            ui.label(f"Total injections detected: {total}").classes(
                                "text-sm"
                            )
                            if by_detector:
                                ui.label("By detector:").classes(
                                    "text-sm font-bold mt-2"
                                )
                                sorted_dets = sorted(
                                    by_detector.items(),
                                    key=lambda x: x[1],
                                    reverse=True,
                                )[:5]
                                for det, count in sorted_dets:
                                    with ui.row().classes("items-center gap-2"):
                                        ui.label(f"{det}:").classes(
                                            "text-sm text-grey-6 w-48"
                                        )
                                        ui.label(str(count)).classes(
                                            "text-sm font-bold"
                                        )

            ui.timer(0.1, refresh, once=True)
