"""MCP Security page — read-only MCP security audit results."""

import logging

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar

logger = logging.getLogger(__name__)


def _run_audit():
    """Run MCP security audit, returning (servers, report) or ([], None)."""
    try:
        from ai_guardian.mcp_audit import MCPAuditor
        auditor = MCPAuditor()
        servers = auditor.discover_servers()
        report = auditor.audit_config(servers)
        return servers, report
    except Exception as e:
        logger.debug("MCP audit failed: %s", e)
        return [], None


def create_mcp_security_page(service, daemon_name: str):
    """Create the MCP Security audit page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/mcp-security")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("MCP Security Audit").classes("text-2xl font-bold")
            ui.label(
                "Scan MCP server configurations for security issues."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def run_audit():
                content.clear()
                with content:
                    ui.label("Running audit...").classes("text-grey-6")

                servers, report = await run.io_bound(_run_audit)

                content.clear()
                with content:
                    if report is None:
                        with ui.card().classes("w-full"):
                            ui.label("Audit Unavailable").classes(
                                "text-lg font-bold"
                            )
                            ui.label(
                                "MCP audit module could not be loaded. "
                                "Ensure ai-guardian is installed with MCP support."
                            ).classes("text-sm text-grey-6")
                        return

                    # Summary
                    with ui.card().classes("w-full"):
                        ui.label("Scan Summary").classes("text-lg font-bold")

                        trusted = sum(
                            1 for s in servers if getattr(s, "is_trusted", False)
                        )
                        untrusted = len(servers) - trusted
                        with ui.row().classes("items-center gap-4"):
                            ui.label(f"Servers: {len(servers)} total").classes(
                                "text-sm"
                            )
                            if trusted:
                                ui.badge(
                                    f"{trusted} trusted", color="green"
                                ).classes("text-xs")
                            if untrusted:
                                ui.badge(
                                    f"{untrusted} untrusted", color="red"
                                ).classes("text-xs")

                        findings = getattr(report, "findings", []) or []
                        if findings:
                            sev_counts = {}
                            for f in findings:
                                s = getattr(f, "severity", "info").lower()
                                sev_counts[s] = sev_counts.get(s, 0) + 1
                            parts = []
                            for s in ["critical", "high", "medium", "low", "info"]:
                                if s in sev_counts:
                                    parts.append(f"{sev_counts[s]} {s}")
                            ui.label(
                                f"Findings: {', '.join(parts)}"
                            ).classes("text-sm")
                        else:
                            ui.label("No issues found.").classes(
                                "text-sm text-green"
                            )

                        scan_ms = getattr(report, "scan_time_ms", None)
                        if scan_ms is not None:
                            ui.label(f"Scan time: {scan_ms}ms").classes(
                                "text-xs text-grey-6"
                            )

                    # Servers
                    with ui.card().classes("w-full"):
                        ui.label("Discovered Servers").classes(
                            "text-lg font-bold"
                        )
                        if servers:
                            with ui.grid(columns="200px 1fr 100px 100px").classes(
                                "w-full gap-y-2 gap-x-4 items-center"
                            ):
                                ui.label("Server").classes(
                                    "text-xs text-grey-6 font-bold"
                                )
                                ui.label("Command").classes(
                                    "text-xs text-grey-6 font-bold"
                                )
                                ui.label("Trust").classes(
                                    "text-xs text-grey-6 font-bold"
                                )
                                ui.label("Env Vars").classes(
                                    "text-xs text-grey-6 font-bold"
                                )

                                for srv in servers:
                                    name = getattr(srv, "name", str(srv))
                                    cmd = getattr(srv, "command", "")
                                    is_trusted = getattr(
                                        srv, "is_trusted", False
                                    )
                                    env_count = len(
                                        getattr(srv, "env_var_names", []) or []
                                    )

                                    ui.label(name).classes("font-bold text-sm")
                                    ui.label(
                                        cmd if len(cmd) <= 40 else cmd[:37] + "..."
                                    ).classes("text-xs text-grey-6")
                                    trust_color = (
                                        "green" if is_trusted else "red"
                                    )
                                    trust_label = (
                                        "trusted" if is_trusted else "untrusted"
                                    )
                                    ui.badge(
                                        trust_label, color=trust_color
                                    ).classes("text-xs")
                                    ui.label(
                                        str(env_count) if env_count else "—"
                                    ).classes("text-xs text-grey-6")
                        else:
                            ui.label(
                                "No MCP servers found in IDE configuration files."
                            ).classes("text-grey-6 text-sm")

                    # Findings
                    if findings:
                        with ui.card().classes("w-full"):
                            ui.label("Findings").classes("text-lg font-bold")
                            sev_colors = {
                                "critical": "red",
                                "high": "orange",
                                "medium": "amber",
                                "low": "blue-grey",
                                "info": "grey",
                            }
                            sev_icons = {
                                "critical": "error",
                                "high": "warning",
                                "medium": "info",
                                "low": "help",
                                "info": "help_outline",
                            }
                            for finding in findings:
                                sev = getattr(
                                    finding, "severity", "info"
                                ).lower()
                                msg = getattr(finding, "message", str(finding))
                                srv_name = getattr(
                                    finding, "server_name", ""
                                )
                                with ui.row().classes(
                                    "items-center gap-2 w-full"
                                ):
                                    ui.icon(
                                        sev_icons.get(sev, "help")
                                    ).classes(
                                        f"text-{sev_colors.get(sev, 'grey')}"
                                    )
                                    ui.badge(
                                        sev.upper(),
                                        color=sev_colors.get(sev, "grey"),
                                    ).classes("text-xs")
                                    if srv_name:
                                        ui.label(srv_name).classes(
                                            "font-bold text-xs"
                                        )
                                    ui.label(msg).classes(
                                        "text-sm flex-grow"
                                    )
                                ui.separator().classes("my-1")

                    # Run audit button
                    ui.button(
                        "Run Audit", icon="refresh", on_click=run_audit
                    ).props("dense").classes("mt-2")

            ui.timer(0.1, run_audit, once=True)
