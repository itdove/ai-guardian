"""Shared header and navigation components for the web console."""

from nicegui import ui


def create_header(daemon_name: str = ""):
    """Create the shared header bar showing current daemon."""
    with ui.header().classes("items-center justify-between bg-blue-grey-10"):
        with ui.row().classes("items-center gap-4"):
            ui.image("/images/ai-guardian-320.png").classes("w-8 h-8")
            ui.link("AI Guardian", "/").classes(
                "text-xl font-bold text-white no-underline"
            )
            if daemon_name:
                ui.label("|").classes("text-grey-6")
                ui.label(daemon_name).classes("text-white font-bold")
        with ui.row().classes("gap-2"):
            if daemon_name:
                prefix = f"/{daemon_name}"
                ui.link("Dashboard", prefix).classes(
                    "text-white no-underline"
                )
                ui.link("Violations", f"{prefix}/violations").classes(
                    "text-white no-underline"
                )
                ui.link("Metrics", f"{prefix}/metrics").classes(
                    "text-white no-underline"
                )
            else:
                ui.link("Select Daemon", "/").classes(
                    "text-white no-underline"
                )


def create_sidebar(daemon_name: str, current: str = ""):
    """Create the navigation sidebar for a specific daemon."""
    prefix = f"/{daemon_name}"
    nav_groups = [
        ("Security Overview", [
            ("Security Dashboard", prefix),
            ("Global Settings", f"{prefix}/settings"),
            ("Health Check", f"{prefix}/health-check"),
        ]),
        ("Monitoring", [
            ("Violations", f"{prefix}/violations"),
            ("Violation Logging", f"{prefix}/violation-logging"),
            ("Metrics & Audit", f"{prefix}/metrics"),
            ("Performance", f"{prefix}/performance"),
            ("Logs", f"{prefix}/logs"),
        ]),
        ("Permissions", [
            ("Permission Rules", f"{prefix}/permission-rules"),
            ("MCP Settings", f"{prefix}/mcp-servers"),
            ("MCP Security", f"{prefix}/mcp-security"),
            ("Permissions Discovery", f"{prefix}/permissions-discovery"),
            ("Auto Directory Rules", f"{prefix}/auto-directory-rules"),
            ("Directory Rules", f"{prefix}/directory-rules"),
        ]),
        ("Secrets", [
            ("Secret Scanning", f"{prefix}/secrets"),
            ("Engine Config", f"{prefix}/secret-engines"),
            ("Secret Redaction", f"{prefix}/secret-redaction"),
        ]),
        ("Prompt Injection", [
            ("Detection", f"{prefix}/pi-detection"),
            ("ML Engines", f"{prefix}/pi-ml-engines"),
            ("Patterns", f"{prefix}/pi-patterns"),
            ("Jailbreak", f"{prefix}/pi-jailbreak"),
            ("Unicode Detection", f"{prefix}/pi-unicode"),
        ]),
        ("Threat Detection", [
            ("SSRF Protection", f"{prefix}/ssrf"),
            ("Context Poisoning", f"{prefix}/context-poisoning"),
            ("Config Scanner", f"{prefix}/config-scanner"),
            ("PII Detection", f"{prefix}/scan-pii"),
            ("Annotations", f"{prefix}/annotations"),
        ]),
        ("Configuration", [
            ("Daemon", f"{prefix}/daemon"),
            ("Remote Configs", f"{prefix}/remote-configs"),
            ("Config File", f"{prefix}/config-file"),
            ("Config Editor", f"{prefix}/config-editor"),
            ("Console Settings", f"{prefix}/console-settings"),
            ("Effective Config", f"{prefix}/config-effective"),
        ]),
        ("Tools", [
            ("Regex Tester", f"{prefix}/regex-tester"),
            ("Hook Simulator", f"{prefix}/hook-simulator"),
            ("Engine Tester", f"{prefix}/engine-tester"),
            ("Directory Scan", f"{prefix}/directory-scan"),
        ]),
    ]
    with ui.column().classes("w-56 bg-blue-grey-10 min-h-screen p-2 gap-0"):
        for group_name, items in nav_groups:
            ui.label(group_name).classes(
                "text-xs text-grey-6 font-bold uppercase mt-4 mb-1 px-2"
            )
            for label, path in items:
                classes = "w-full no-underline rounded px-2 py-1 text-sm "
                if current == path:
                    classes += "bg-blue-grey-8 text-white font-bold"
                else:
                    classes += "text-grey-4 hover:bg-blue-grey-9"
                ui.link(label, path).classes(classes)
