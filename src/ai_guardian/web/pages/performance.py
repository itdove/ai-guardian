"""Performance page — hook latency statistics and per-check breakdown."""

import logging
import json
import tempfile

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar


def _load_local_latency(since_days):
    from ai_guardian.latency_logger import LatencyComputer

    computer = LatencyComputer(since_days=since_days)
    report = computer.compute()
    return {
        "hook_stats": report.hook_stats,
        "check_stats": report.check_stats,
        "invocation_count": report.invocation_count,
    }


def _load_latency_config():
    from ai_guardian.latency_logger import LatencyLogger

    ll = LatencyLogger()
    return dict(ll.config)


def _save_latency_config(updates):
    from ai_guardian.config_utils import get_config_dir

    path = get_config_dir() / "ai-guardian.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    config = {}
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            logging.warning("Failed to read config: %s", e)
    if "latency_tracking" not in config:
        config["latency_tracking"] = {}
    config["latency_tracking"].update(updates)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")


def _clear_latency_log():
    from ai_guardian.latency_logger import LatencyLogger

    return LatencyLogger().clear_log()


def _export_latency(since_days, fmt):
    import csv as csv_mod
    from ai_guardian.latency_logger import (
        LatencyComputer,
        format_latency_human,
        format_latency_json,
    )

    computer = LatencyComputer(since_days=since_days)
    report = computer.compute()
    suffix = {"json": ".json", "csv": ".csv", "text": ".txt"}[fmt]
    tmp = tempfile.NamedTemporaryFile(
        prefix="ai-guardian-latency-",
        suffix=suffix,
        delete=False,
        mode="w",
        encoding="utf-8",
    )
    if fmt == "json":
        tmp.write(format_latency_json(report))
    elif fmt == "csv":
        writer = csv_mod.writer(tmp)
        writer.writerow(
            [
                "type",
                "name",
                "avg_ms",
                "stddev_ms",
                "p95_ms",
                "min_ms",
                "max_ms",
                "count",
                "hooks",
            ]
        )
        for s in report.hook_stats:
            writer.writerow(
                [
                    "hook",
                    s["hook_event"],
                    s["avg"],
                    s["stddev"],
                    s["p95"],
                    s["min"],
                    s["max"],
                    s["count"],
                    "",
                ]
            )
        for s in report.check_stats:
            writer.writerow(
                [
                    "check",
                    s["check_name"],
                    s["avg"],
                    s["stddev"],
                    s["p95"],
                    s["min"],
                    s["max"],
                    s["count"],
                    s.get("hooks", ""),
                ]
            )
    else:
        tmp.write(format_latency_human(report))
    tmp.close()
    return tmp.name


def _get_clipboard_text(since_days):
    from ai_guardian.latency_logger import LatencyComputer, format_latency_human

    computer = LatencyComputer(since_days=since_days)
    report = computer.compute()
    return format_latency_human(report)


def _get_retention_days():
    try:
        from ai_guardian.violation_logger import ViolationLogger

        vl = ViolationLogger()
        cfg = getattr(vl, "config", {}) or {}
        return cfg.get("retention_days", 30)
    except Exception:
        return 30


def create_performance_page(service, daemon_name: str):
    """Build the performance (hook latency) page."""

    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/performance")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Performance").classes("text-2xl font-bold")

            # --- Config controls ---
            with ui.expansion("Settings", icon="settings").classes("w-full max-w-2xl"):
                cfg = _load_latency_config()

                with ui.row().classes("items-center gap-4"):
                    ui.label("Enabled")
                    enabled_switch = ui.switch(
                        "",
                        value=cfg.get("enabled", False),
                    )

                    async def on_toggle(e):
                        await run.io_bound(_save_latency_config, {"enabled": e.value})
                        ui.notify(
                            (
                                "Latency tracking enabled"
                                if e.value
                                else "Latency tracking disabled"
                            ),
                            type="positive",
                        )

                    enabled_switch.on_value_change(on_toggle)

                with ui.row().classes("items-center gap-4 mt-2"):
                    ui.label("Max Entries")
                    max_input = ui.number(
                        "",
                        value=cfg.get("max_entries", 5000),
                        min=100,
                        max=100000,
                        step=1000,
                    ).classes("w-32")

                    async def save_max(e):
                        val = int(e.value) if e.value else 5000
                        await run.io_bound(_save_latency_config, {"max_entries": val})
                        ui.notify(f"Max entries: {val}", type="positive")

                    max_input.on("blur", save_max)

                with ui.row().classes("items-center gap-4 mt-2"):
                    ui.label("Retention Days")
                    ret_input = ui.number(
                        "",
                        value=cfg.get("retention_days", 30),
                        min=1,
                        max=365,
                        step=1,
                    ).classes("w-32")

                    async def save_ret(e):
                        val = int(e.value) if e.value else 30
                        await run.io_bound(
                            _save_latency_config, {"retention_days": val}
                        )
                        ui.notify(f"Retention: {val} days", type="positive")

                    ret_input.on("blur", save_ret)

                with ui.row().classes("mt-2 gap-2"):

                    async def clear_log():
                        await run.io_bound(_clear_latency_log)
                        ui.notify("Latency log cleared", type="warning")
                        await load_data()

                    ui.button(
                        "Clear Log",
                        icon="delete_sweep",
                        on_click=clear_log,
                        color="orange",
                    ).props("flat")

            current_range = {"days": 30}

            # --- Export / Copy ---
            with ui.row().classes("gap-2 items-center"):

                async def do_export(fmt):
                    since = current_range["days"]
                    try:
                        path = await run.io_bound(_export_latency, since, fmt)
                        export_label.set_text(f"Saved: {path}")
                        export_label.classes(replace="text-sm text-green")
                        ui.download(path)
                    except Exception as e:
                        export_label.set_text(f"Export failed: {e}")
                        export_label.classes(replace="text-sm text-red")

                async def do_copy():
                    since = current_range["days"]
                    try:
                        text = await run.io_bound(_get_clipboard_text, since)
                        await ui.run_javascript(
                            f"navigator.clipboard.writeText({json.dumps(text)})"
                        )
                        ui.notify("Copied to clipboard", type="positive")
                    except Exception as e:
                        ui.notify(f"Copy failed: {e}", type="negative")

                ui.button(
                    "Export Text",
                    icon="description",
                    on_click=lambda: do_export("text"),
                ).props("flat")
                ui.button(
                    "Export JSON",
                    icon="data_object",
                    on_click=lambda: do_export("json"),
                ).props("flat")
                ui.button(
                    "Export CSV",
                    icon="table_chart",
                    on_click=lambda: do_export("csv"),
                ).props("flat")
                ui.button(
                    "Copy to Clipboard",
                    icon="content_copy",
                    on_click=do_copy,
                ).props("flat")
                export_label = ui.label("").classes("text-sm")

            # --- Range selector ---
            retention = _get_retention_days()

            with ui.row().classes("gap-2 items-center"):
                btn_7d = ui.button("7 Days", on_click=lambda: set_range(7))
                btn_30d = ui.button("30 Days", on_click=lambda: set_range(30))
                if retention < 30:
                    btn_30d.props("disable")
                    btn_30d.tooltip(f"Retention is {retention} days")
                btn_all = ui.button(
                    f"All ({retention}d)",
                    on_click=lambda: set_range(retention),
                )
                ui.button(
                    "Refresh",
                    icon="refresh",
                    on_click=lambda: load_data(),
                ).props("flat")

            content = ui.column().classes("w-full gap-4")

            async def set_range(days):
                current_range["days"] = days
                for btn, d in [(btn_7d, 7), (btn_30d, 30), (btn_all, retention)]:
                    if d == days:
                        btn.props("color=primary")
                    else:
                        btn.props(remove="color=primary")
                await load_data()

            async def load_data():
                content.clear()
                await run.io_bound(service.refresh_targets)
                target = service.get_target_by_name(daemon_name)
                since = current_range["days"]

                if not target:
                    with content:
                        ui.label("No daemons discovered.").classes("text-grey-6")
                    return

                data = await run.io_bound(_load_local_latency, since)

                with content:
                    if not data or (
                        not data.get("hook_stats") and not data.get("check_stats")
                    ):
                        ui.label("No latency data found.").classes("text-grey-6")
                        ui.label(
                            "Enable latency tracking in Settings above, "
                            "then hook invocations will record timing data."
                        ).classes("text-sm text-grey-5")
                        return

                    with ui.card().classes("items-center p-4"):
                        ui.label(str(data.get("invocation_count", 0))).classes(
                            "text-3xl font-bold text-blue"
                        )
                        ui.label("Hook Invocations").classes("text-sm text-grey-6")

                    _hook_table(data.get("hook_stats", []))
                    _check_table(data.get("check_stats", []))

            btn_30d.props("color=primary")
            ui.timer(0.1, load_data, once=True)


def _hook_table(stats):
    if not stats:
        return
    ui.label("Hook Latency Overview").classes("text-lg font-bold mt-4")
    columns = [
        {
            "name": "hook_event",
            "label": "Hook Event",
            "field": "hook_event",
            "sortable": True,
        },
        {"name": "avg", "label": "Avg (ms)", "field": "avg", "sortable": True},
        {"name": "stddev", "label": "StdDev", "field": "stddev", "sortable": True},
        {"name": "p95", "label": "P95 (ms)", "field": "p95", "sortable": True},
        {"name": "min", "label": "Min (ms)", "field": "min", "sortable": True},
        {"name": "max", "label": "Max (ms)", "field": "max", "sortable": True},
        {"name": "count", "label": "Count", "field": "count", "sortable": True},
    ]
    rows = []
    for s in stats:
        rows.append(
            {
                "hook_event": s.get("hook_event", ""),
                "avg": s.get("avg", 0),
                "stddev": s.get("stddev", 0),
                "p95": s.get("p95", 0),
                "min": s.get("min", 0),
                "max": s.get("max", 0),
                "count": s.get("count", 0),
            }
        )
    table = ui.table(columns=columns, rows=rows, row_key="hook_event")
    table.classes("w-full max-w-4xl")
    table.add_slot(
        "body-cell-p95",
        """
        <q-td :props="props" :class="props.value > 100 ? 'text-red' : props.value > 50 ? 'text-orange' : ''">
            {{ props.value }}
        </q-td>
    """,
    )


def _check_table(stats):
    if not stats:
        return
    ui.label("Per-Violation-Type Breakdown").classes("text-lg font-bold mt-4")
    columns = [
        {
            "name": "check_name",
            "label": "Check Type",
            "field": "check_name",
            "sortable": True,
        },
        {"name": "avg", "label": "Avg (ms)", "field": "avg", "sortable": True},
        {"name": "stddev", "label": "StdDev", "field": "stddev", "sortable": True},
        {"name": "p95", "label": "P95 (ms)", "field": "p95", "sortable": True},
        {"name": "min", "label": "Min (ms)", "field": "min", "sortable": True},
        {"name": "max", "label": "Max (ms)", "field": "max", "sortable": True},
        {"name": "count", "label": "Count", "field": "count", "sortable": True},
        {"name": "hooks", "label": "Hook(s)", "field": "hooks"},
    ]
    rows = []
    for s in stats:
        rows.append(
            {
                "check_name": s.get("check_name", ""),
                "avg": s.get("avg", 0),
                "stddev": s.get("stddev", 0),
                "p95": s.get("p95", 0),
                "min": s.get("min", 0),
                "max": s.get("max", 0),
                "count": s.get("count", 0),
                "hooks": s.get("hooks", ""),
            }
        )
    table = ui.table(columns=columns, rows=rows, row_key="check_name")
    table.classes("w-full max-w-4xl")
    table.add_slot(
        "body-cell-p95",
        """
        <q-td :props="props" :class="props.value > 100 ? 'text-red' : props.value > 50 ? 'text-orange' : ''">
            {{ props.value }}
        </q-td>
    """,
    )
