"""Metrics page — full statistics with percentages, trend chart matching TUI."""

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar


def _load_local_metrics(since_days):
    from ai_guardian.metrics import MetricsComputer
    mc = MetricsComputer(since_days=since_days)
    report = mc.compute()
    return {
        "total_violations": report.total_violations,
        "resolved": report.resolved_count,
        "unresolved": report.unresolved_count,
        "sessions": report.session_count,
        "by_type": report.by_type,
        "by_severity": report.by_severity,
        "by_action": report.by_action,
        "top_files": report.top_files,
        "top_tools": report.top_tools,
        "time_trend": report.time_trend,
        "cumulative_total": report.cumulative_total,
        "cumulative_by_type": report.cumulative_by_type,
        "cumulative_since": report.cumulative_since,
    }


def _get_retention_days():
    try:
        from ai_guardian.violation_logger import ViolationLogger
        vl = ViolationLogger()
        cfg = getattr(vl, "config", {}) or {}
        return cfg.get("retention_days", 30)
    except Exception:
        return 30


def _reset_counters():
    from ai_guardian.violation_counter import ViolationCounter
    return ViolationCounter().reset_to_current_log()


def create_metrics_page(service, daemon_name: str):
    """Build the metrics page with full statistics."""

    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/metrics")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Metrics").classes("text-2xl font-bold")

            retention = _get_retention_days()

            with ui.row().classes("gap-2 items-center"):
                btn_7d = ui.button("7 Days", on_click=lambda: set_range(7))
                btn_30d = ui.button("30 Days", on_click=lambda: set_range(30))
                if retention < 30:
                    btn_30d.props("disable")
                    btn_30d.tooltip(
                        f"Retention is {retention} days"
                    )
                btn_all = ui.button(
                    f"All ({retention}d)",
                    on_click=lambda: set_range(retention),
                )
                ui.button(
                    "Refresh", icon="refresh",
                    on_click=lambda: load_metrics(),
                ).props("flat")
                ui.button(
                    "Reset Counters", icon="restart_alt",
                    on_click=lambda: handle_reset(),
                    color="orange",
                ).props("flat")

            current_range = {"days": 30}
            content = ui.column().classes("w-full gap-4")

            async def set_range(days):
                current_range["days"] = days
                for btn, d in [(btn_7d, 7), (btn_30d, 30), (btn_all, retention)]:
                    if d == days:
                        btn.props("color=primary")
                    else:
                        btn.props(remove="color=primary")
                await load_metrics()

            async def handle_reset():
                with ui.dialog() as dialog, ui.card():
                    ui.label("Reset Cumulative Counters?").classes(
                        "text-lg font-bold"
                    )
                    ui.label(
                        "This will reset all-time counters to the current "
                        "log file counts and update the tracking start date."
                    ).classes("text-sm text-orange")

                    with ui.row().classes("gap-2 mt-4"):
                        async def confirm():
                            await run.io_bound(_reset_counters)
                            dialog.close()
                            ui.notify(
                                "Counters reset", type="positive"
                            )
                            await load_metrics()

                        ui.button(
                            "Reset", icon="restart_alt",
                            color="orange", on_click=confirm,
                        )
                        ui.button(
                            "Cancel", on_click=dialog.close,
                        )
                dialog.open()

            async def load_metrics():
                content.clear()
                await run.io_bound(service.refresh_targets)
                target = service.get_target_by_name(daemon_name)
                since = current_range["days"]

                agg = {
                    "total": 0, "resolved": 0, "unresolved": 0,
                    "sessions": 0, "by_type": {}, "by_severity": {},
                    "by_action": {}, "top_files": [], "top_tools": [],
                    "time_trend": [],
                    "cumulative_total": 0, "cumulative_since": "",
                    "cumulative_by_type": {},
                }

                if target:
                    if target.runtime == "local":
                        m = await run.io_bound(_load_local_metrics, since)
                    else:
                        m = await run.io_bound(
                            service.get_daemon_metrics, target, since
                        )
                    if m:
                        agg["total"] += m.get("total_violations", 0)
                        agg["resolved"] += m.get("resolved", 0)
                        agg["unresolved"] += m.get("unresolved", 0)
                        agg["sessions"] += m.get("sessions", 0)
                        for k, v in m.get("by_type", {}).items():
                            agg["by_type"][k] = agg["by_type"].get(k, 0) + v
                        for k, v in m.get("by_severity", {}).items():
                            agg["by_severity"][k] = agg["by_severity"].get(k, 0) + v
                        for k, v in m.get("by_action", {}).items():
                            agg["by_action"][k] = agg["by_action"].get(k, 0) + v
                        agg["top_files"].extend(m.get("top_files", []))
                        agg["top_tools"].extend(m.get("top_tools", []))
                        agg["time_trend"].extend(m.get("time_trend", []))
                        agg["cumulative_total"] += m.get("cumulative_total", 0)
                        if m.get("cumulative_since"):
                            agg["cumulative_since"] = m["cumulative_since"]
                        for k, v in m.get("cumulative_by_type", {}).items():
                            agg["cumulative_by_type"][k] = (
                                agg["cumulative_by_type"].get(k, 0) + v
                            )

                with content:
                    if not target:
                        ui.label("No daemons discovered.").classes("text-grey-6")
                        return

                    # Cumulative totals
                    if agg["cumulative_total"] > 0:
                        since_str = agg["cumulative_since"][:10] if agg["cumulative_since"] else ""
                        with ui.row().classes("gap-4 flex-wrap"):
                            with ui.card().classes("items-center p-4"):
                                ui.label(str(agg["cumulative_total"])).classes(
                                    "text-3xl font-bold text-purple"
                                )
                                ui.label("Cumulative Total").classes(
                                    "text-sm text-grey-6"
                                )
                            if since_str:
                                with ui.card().classes("items-center p-4"):
                                    ui.label(since_str).classes(
                                        "text-xl font-bold"
                                    )
                                    ui.label("Tracking Since").classes(
                                        "text-sm text-grey-6"
                                    )

                    with ui.row().classes("gap-4 flex-wrap"):
                        for lbl, val, clr in [
                            ("Total", agg["total"], ""),
                            ("Resolved", agg["resolved"], "text-green"),
                            ("Unresolved", agg["unresolved"], "text-amber"),
                            ("Sessions", agg["sessions"], "text-blue"),
                        ]:
                            with ui.card().classes("items-center p-4"):
                                ui.label(str(val)).classes(f"text-3xl font-bold {clr}")
                                ui.label(lbl).classes("text-sm text-grey-6")

                    _breakdown("By Type", agg["by_type"], "type", agg["total"])
                    _breakdown("By Severity", agg["by_severity"], "severity", agg["total"])
                    _breakdown("By Action", agg["by_action"], "action", agg["total"])
                    _top_list("Top Files", agg["top_files"])
                    _top_list("Top Tools", agg["top_tools"])
                    _trend("Daily Trend (last 14 days)", agg["time_trend"])

            btn_30d.props("color=primary")
            ui.timer(0.1, load_metrics, once=True)


def _breakdown(title, data, key_name, total):
    if not data:
        return
    ui.label(title).classes("text-lg font-bold mt-4")
    rows = []
    for k, v in sorted(data.items(), key=lambda x: x[1], reverse=True):
        pct = f"{v / total * 100:.1f}%" if total else "0%"
        rows.append({key_name: k, "count": v, "pct": pct})
    ui.table(
        columns=[
            {"name": key_name, "label": key_name.title(), "field": key_name, "sortable": True},
            {"name": "count", "label": "Count", "field": "count", "sortable": True},
            {"name": "pct", "label": "%", "field": "pct"},
        ],
        rows=rows, row_key=key_name,
    ).classes("w-full max-w-lg")


def _top_list(title, items):
    if not items:
        return
    merged = {}
    for name, count in items:
        merged[name] = merged.get(name, 0) + count
    top = sorted(merged.items(), key=lambda x: x[1], reverse=True)[:10]
    ui.label(title).classes("text-lg font-bold mt-4")
    rows = [{"name": n, "count": c} for n, c in top]
    ui.table(
        columns=[
            {"name": "name", "label": "Name", "field": "name"},
            {"name": "count", "label": "Count", "field": "count", "sortable": True},
        ],
        rows=rows, row_key="name",
    ).classes("w-full max-w-lg")


def _trend(title, trend_data):
    if not trend_data:
        return
    merged = {}
    for entry in trend_data:
        d = entry.get("date", "")
        merged[d] = merged.get(d, 0) + entry.get("count", 0)
    dates = sorted(merged.keys())[-14:]
    if not dates:
        return

    ui.label(title).classes("text-lg font-bold mt-4")
    max_count = max((merged[d] for d in dates), default=1) or 1
    lines = []
    for d in dates:
        count = merged[d]
        bar_len = int(count / max_count * 20) if max_count else 0
        bar = "█" * bar_len
        lines.append(f"  {d}  {count:>4}  {bar}")
    ui.html(
        '<pre style="font-family:monospace;font-size:13px;color:#e0e0e0;'
        'background:#1a1a2e;padding:12px;border-radius:8px">'
        + "\n".join(lines)
        + "</pre>"
    )
