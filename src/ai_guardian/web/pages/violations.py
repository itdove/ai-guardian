"""Violations page — tabbed browser with details/correlation matching TUI."""

import json

from nicegui import run, ui

from ai_guardian.web.components.local_time import (
    inject_local_time_js,
    local_time_label,
)

from ai_guardian.violation_guidance import get_resolution_instructions
from ai_guardian.web.components.header import create_header, create_sidebar

FILTER_TABS = [
    ("All", None, "Show all violation types"),
    ("Tool Permission", "tool_permission", "Blocked tool/MCP server execution (permission rules)"),
    ("Secrets", "secret_detected", "Hard-coded secrets detected in files or prompts (API keys, tokens, passwords)"),
    ("Secret Redaction", "secret_redaction", "Secrets found in tool output and redacted before reaching the AI model"),
    ("Directories", "directory_blocking", "File access blocked by directory protection rules"),
    ("Prompt Injection", "prompt_injection", "Attempts to manipulate AI behavior detected in prompts or files"),
    ("Jailbreak", "jailbreak_detected", "Attempts to bypass AI safety constraints"),
    ("SSRF Blocked", "ssrf_blocked", "Blocked access to private networks, metadata endpoints, or dangerous URLs"),
    ("Config Exfil", "config_file_exfil", "Credential exfiltration commands detected in AI config files (CLAUDE.md, AGENTS.md)"),
    ("PII Detected", "pii_detected", "Personal Identifiable Information found in files or prompts (SSN, credit card, phone)"),
    ("Secret in Transcript", "secret_in_transcript", "Secret found in conversation history (possibly from ! shell command)"),
    ("PII in Transcript", "pii_in_transcript", "Personal Identifiable Information found in conversation history"),
    ("Injection in Transcript", "prompt_injection_in_transcript", "Prompt injection pattern found in conversation history"),
    ("Annotation Suppressed", "annotation_suppressed", "Finding suppressed by an inline annotation (ai-guardian:allow, gitleaks:allow)"),
    ("Image Secret", "image_secret_detected", "Secret detected in image via OCR scanning"),
    ("Image PII", "image_pii_detected", "PII detected in image via OCR scanning"),
]

DETAIL_FIELDS = {
    "tool_permission": [
        ("Tool", "tool_name"), ("File", "tool_value"),
        ("File Path", "file_path"), ("Line", "line_number"),
        ("Position", "position"), ("Reason", "reason"),
    ],
    "secret_detected": [
        ("File", "file_path"), ("Source", "source"),
        ("Line", "line_number"), ("End Line", "end_line"),
        ("Position", "position"), ("Type", "secret_type"),
        ("Findings", "total_findings"),
    ],
    "prompt_injection": [
        ("Source", "source"), ("File", "file_path"),
        ("Line", "line_number"), ("Position", "position"),
        ("Pattern", "pattern"), ("Matched", "matched_text"),
        ("Method", "method"), ("Confidence", "confidence"),
    ],
    "secret_redaction": [
        ("Tool", "tool"), ("Command", "command"),
        ("File", "file_path"), ("Line", "line_number"),
        ("Count", "redaction_count"), ("Types", "redacted_types"),
    ],
    "pii_detected": [
        ("Hook", "hook"), ("Tool", "tool"), ("Command", "command"),
        ("File", "file_path"), ("Line", "line_number"),
        ("Count", "pii_count"), ("Types", "pii_types"),
    ],
    "jailbreak_detected": [
        ("File", "file_path"), ("Line", "line_number"),
        ("Tool", "tool"), ("Matched", "matched_text"),
        ("Confidence", "confidence"),
    ],
    "ssrf_blocked": [
        ("Tool", "tool_name"), ("URL", "tool_value"),
        ("File", "file_path"), ("Line", "line_number"),
        ("Reason", "reason"),
    ],
    "config_file_exfil": [
        ("File", "file_path"), ("Reason", "reason"),
        ("Details", "details"),
    ],
    "directory_blocking": [
        ("File", "file_path"), ("Directory", "denied_directory"),
    ],
    "secret_in_transcript": [
        ("File", "file_path"), ("Line", "line_number"),
        ("Type", "secret_type"), ("Source", "source"),
    ],
    "pii_in_transcript": [
        ("File", "file_path"), ("Line", "line_number"),
        ("Count", "pii_count"), ("Types", "pii_types"),
    ],
    "image_secret_detected": [
        ("File", "file_path"), ("Type", "secret_type"),
        ("Source", "source"),
    ],
    "image_pii_detected": [
        ("File", "file_path"), ("Count", "pii_count"),
        ("Types", "pii_types"),
    ],
}


def _get_resolution_instructions(violation: dict):
    return get_resolution_instructions(violation)


def _load_local_violations(limit, violation_type):
    from ai_guardian.violation_logger import ViolationLogger
    vl = ViolationLogger()
    return vl.get_recent_violations(
        limit=limit, violation_type=violation_type, resolved=None
    )


def create_violations_page(service, daemon_name: str):
    """Build the violations page with filter tabs and detail modals."""

    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/violations")

        with ui.column().classes("flex-grow p-6 gap-2"):
            ui.label("Violations").classes("text-2xl font-bold")
            ui.label(
                "Historical log of blocked operations. "
                "Click Details for resolution instructions."
            ).classes("text-xs text-grey-6")

            active_filter = {"vtype": None}
            buttons = {}

            with ui.row().classes("gap-1 flex-wrap"):
                for label, vtype, tooltip in FILTER_TABS:
                    async def on_click(vt=vtype, lbl=label):
                        active_filter["vtype"] = vt
                        for bl, b in buttons.items():
                            if bl == lbl:
                                b.props("color=primary")
                                b.props(remove="outline")
                            else:
                                b.props(remove="color=primary")
                                b.props("outline")
                        await load_violations()

                    is_all = label == "All"
                    btn = ui.button(
                        label, on_click=on_click,
                    ).props(
                        "dense size=sm no-caps"
                        + (" color=primary" if is_all else " outline")
                    ).tooltip(tooltip)
                    buttons[label] = btn

            cards_container = ui.column().classes("w-full gap-1")

            async def load_violations():
                cards_container.clear()
                vtype = active_filter["vtype"]
                await run.io_bound(service.refresh_targets)
                target = service.get_target_by_name(daemon_name)

                all_violations = []
                if target:
                    if target.runtime == "local":
                        raw = await run.io_bound(
                            _load_local_violations, 50, vtype
                        )
                    else:
                        raw = await run.io_bound(
                            service.get_daemon_violations, target, 50, vtype
                        )
                    if raw:
                        vlist = raw if isinstance(raw, list) else raw.get(
                            "violations", []
                        )
                        all_violations.extend(vlist)

                all_violations.sort(
                    key=lambda v: v.get("timestamp", ""), reverse=True
                )

                with cards_container:
                    if not all_violations:
                        ui.label(
                            "No violations found."
                        ).classes("text-grey-6 mt-4")
                        return
                    ui.label(
                        f"{len(all_violations)} violations"
                    ).classes("text-xs text-grey-6")
                    for v in all_violations:
                        _render_violation_card(v)

                inject_local_time_js()

            ui.timer(0.1, load_violations, once=True)


def _render_violation_card(v: dict):
    vtype = v.get("violation_type", v.get("type", "unknown"))
    severity = v.get("severity", "warning")
    timestamp = v.get("timestamp", "")
    daemon = v.get("_daemon", "")
    blocked = v.get("blocked", {})
    if not isinstance(blocked, dict):
        blocked = {}
    suggestion = v.get("suggestion", {})
    if not isinstance(suggestion, dict):
        suggestion = {}
    resolved = v.get("resolved", False)
    context = v.get("context", {})
    if not isinstance(context, dict):
        context = {}

    sev_color = {"critical": "red", "high": "orange", "warning": "amber"}.get(
        severity, "grey"
    )
    sev_icon = {"critical": "error", "high": "warning", "warning": "info"}.get(
        severity, "help"
    )

    with ui.card().classes("w-full"):
        with ui.row().classes("items-center gap-2 w-full"):
            ui.icon(sev_icon).classes(f"text-{sev_color}")
            vtype_display = vtype.upper().replace("_", " ")
            ui.label(vtype_display).classes("font-bold text-sm")
            ui.badge(severity, color=sev_color).classes("text-xs")
            if resolved:
                ui.badge("RESOLVED", color="green").classes("text-xs")
            if daemon:
                ui.badge(daemon, color="blue-grey").classes("text-xs")
            local_time_label(timestamp).classes("ml-auto")

        fields = DETAIL_FIELDS.get(vtype, [])
        if fields:
            with ui.grid(columns=2).classes("gap-1 mt-1"):
                for label, key in fields:
                    val = blocked.get(key)
                    if val is not None:
                        ui.label(f"{label}:").classes("text-xs text-grey-6")
                        display = str(val)
                        if key == "secret_type":
                            from ai_guardian.secret_type_names import get_secret_type_display
                            display = get_secret_type_display(display)
                        if isinstance(val, list):
                            display = ", ".join(str(x) for x in val)
                        if isinstance(val, float):
                            display = f"{val:.2f}"
                        if len(display) > 100:
                            display = display[:97] + "..."
                        ui.label(display).classes("text-xs")

        if vtype == "tool_permission" and suggestion.get("rule"):
            ui.label("Suggested rule:").classes("text-xs text-grey-6 mt-1")
            ui.code(
                json.dumps(suggestion["rule"], indent=2), language="json"
            ).classes("text-xs")

        tool_use_id = context.get("tool_use_id")
        hook_event = context.get("hook_event", "")
        has_pretool = bool(context.get("pretool_context"))
        if tool_use_id and has_pretool:
            hook_label = hook_event.replace(
                "posttooluse", "PostToolUse"
            ).replace("pretooluse", "PreToolUse")
            ui.label(
                f"Correlation: {tool_use_id[:16]}... ({hook_label})"
            ).classes("text-xs text-grey-7 mt-1")

        with ui.row().classes("gap-2 mt-1"):
            def show_details(violation=v):
                with ui.dialog() as dialog, ui.card().classes("w-[600px]"):
                    ui.label("Violation Details").classes("text-lg font-bold")
                    ui.code(
                        json.dumps(violation, indent=2, default=str),
                        language="json",
                    ).classes("max-h-[300px] overflow-auto text-xs")

                    ui.separator()
                    ui.label("How to Resolve").classes("font-bold mt-2")
                    instructions, snippet = _get_resolution_instructions(
                        violation
                    )
                    ui.label(instructions).classes("text-sm")
                    if snippet:
                        ui.code(snippet, language="json").classes(
                            "text-xs mt-1"
                        )
                        ui.button(
                            "Copy Config", icon="content_copy",
                            on_click=lambda s=snippet: ui.run_javascript(
                                f"navigator.clipboard.writeText({json.dumps(s)})"
                            ),
                        ).props("flat dense size=sm")

                    ui.button("Close", on_click=dialog.close).classes("mt-2")
                dialog.open()

            ui.button(
                "Details", icon="info", on_click=show_details,
            ).props("flat dense size=sm")

            if has_pretool:
                def show_correlated(ctx=context, tid=tool_use_id):
                    pretool = ctx.get("pretool_context", {})
                    with ui.dialog() as dialog, ui.card().classes("w-[600px]"):
                        ui.label("Correlated PreToolUse Context").classes(
                            "text-lg font-bold"
                        )
                        ui.label(
                            f"Correlation ID: {tid}"
                        ).classes("text-xs text-grey-6")
                        ui.code(
                            json.dumps(pretool, indent=2, default=str),
                            language="json",
                        ).classes("max-h-[400px] overflow-auto text-xs")
                        ui.button(
                            "Close", on_click=dialog.close
                        ).classes("mt-2")
                    dialog.open()

                ui.button(
                    "Correlated", icon="link", on_click=show_correlated,
                ).props("flat dense size=sm")
