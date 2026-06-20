"""Shared header and navigation components for the web console."""

from nicegui import ui

from ai_guardian import __version__

NAV_GROUPS = [
    ("Security Overview", [
        ("Security Dashboard", ""),
        ("Global Settings", "/settings"),
        ("Health Check", "/health-check"),
    ]),
    ("Monitoring", [
        ("Violations", "/violations"),
        ("Violation Logging", "/violation-logging"),
        ("Metrics & Audit", "/metrics"),
        ("Performance", "/performance"),
        ("Logs", "/logs"),
    ]),
    ("Permissions", [
        ("Permission Rules", "/permission-rules"),
        ("MCP Settings", "/mcp-servers"),
        ("MCP Security", "/mcp-security"),
        ("Permissions Discovery", "/permissions-discovery"),
        ("Auto Directory Rules", "/auto-directory-rules"),
        ("Directory Rules", "/directory-rules"),
    ]),
    ("Secrets", [
        ("Secret Scanning", "/secrets"),
        ("Engine Config", "/secret-engines"),
        ("Secret Redaction", "/secret-redaction"),
    ]),
    ("Prompt Injection", [
        ("Detection", "/pi-detection"),
        ("ML Engines", "/pi-ml-engines"),
        ("Patterns", "/pi-patterns"),
        ("Jailbreak", "/pi-jailbreak"),
        ("Unicode Detection", "/pi-unicode"),
    ]),
    ("Threat Detection", [
        ("SSRF Protection", "/ssrf"),
        ("Context Poisoning", "/context-poisoning"),
        ("Supply Chain", "/supply-chain"),
        ("Config Scanner", "/config-scanner"),
        ("PII Detection", "/scan-pii"),
        ("Annotations", "/annotations"),
    ]),
    ("Configuration", [
        ("Daemon", "/daemon"),
        ("Config Cache", "/cache-status"),
        ("Remote Configs", "/remote-configs"),
        ("Config File", "/config-file"),
        ("Config Editor", "/config-editor"),
        ("Console Settings", "/console-settings"),
        ("Effective Config", "/config-effective"),
    ]),
    ("Tools", [
        ("Detection Patterns", "/detection-patterns"),
        ("Regex Tester", "/regex-tester"),
        ("Hook Simulator", "/hook-simulator"),
        ("Engine Tester", "/engine-tester"),
        ("Directory Scan", "/directory-scan"),
    ]),
]


def _build_search_index(prefix):
    """Build search index from nav groups and feature toggle metadata."""
    entries = []
    for group_name, items in NAV_GROUPS:
        for label, suffix in items:
            path = f"{prefix}{suffix}"
            search_text = f"{group_name} {label}".lower()
            entries.append((search_text, label, group_name, path))

    try:
        from ai_guardian.web.pages.global_settings import FEATURE_GROUPS
        settings_path = f"{prefix}/settings"
        for fg_group, features in FEATURE_GROUPS:
            for config_key, feat_label, feat_desc in features:
                search_text = (
                    f"{fg_group} {feat_label} {feat_desc} {config_key}"
                ).lower()
                feat_path = f"{settings_path}#feature-{config_key}"
                entries.append(
                    (search_text, feat_label,
                     f"Settings › {fg_group}", feat_path)
                )
    except ImportError:
        pass  # intentionally silent — optional dependency

    return entries


def _init_scope_state():
    """Initialize scope session state if not set."""
    try:
        from nicegui import app
        if "config_scope" not in app.storage.user:
            app.storage.user["config_scope"] = "global"
        if "project_dir" not in app.storage.user:
            app.storage.user["project_dir"] = None
    except Exception:
        pass  # intentionally silent — optional dependency


def create_header(daemon_name: str = ""):
    """Create the shared header bar showing current daemon and scope toggle."""
    _init_scope_state()

    with ui.header().classes("items-center justify-between bg-blue-grey-10"):
        with ui.row().classes("items-center gap-4"):
            ui.image("/images/ai-guardian-320.png").classes("w-8 h-8")
            ui.link("AI Guardian", "/").classes(
                "text-xl font-bold text-white no-underline"
            )
            ui.label(f"v{__version__}").classes("text-grey-6 text-xs")
            if daemon_name:
                ui.label("|").classes("text-grey-6")
                ui.label(daemon_name).classes("text-white font-bold")
            _create_scope_toggle()
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
    """Create the navigation sidebar with search for a specific daemon."""
    prefix = f"/{daemon_name}"
    search_index = _build_search_index(prefix)

    with ui.column().classes("w-56 bg-blue-grey-10 p-2 gap-2").style(
        "height: calc(100vh - 64px); position: sticky; top: 64px; display: flex; flex-direction: column;"
    ) as sidebar:
        search_input = ui.input(placeholder="Search settings...").props(
            "dense outlined clearable"
        ).classes("w-full").style(
            "color: white; --q-color-primary: #78909c;"
        )

        # Scrollable container for navigation
        nav_container = ui.column().classes("w-full gap-0 overflow-y-auto").style(
            "flex: 1; min-height: 0;"
        )
        active_link = None
        with nav_container:
            for group_name, items in NAV_GROUPS:
                ui.label(group_name).classes(
                    "text-xs text-grey-6 font-bold uppercase mt-4 mb-1 px-2"
                )
                for label, suffix in items:
                    path = f"{prefix}{suffix}"
                    classes = "w-full no-underline rounded px-2 py-1 text-sm "
                    if current == path:
                        classes += "bg-blue-grey-8 text-white font-bold"
                        link = ui.link(label, path).classes(classes)
                        active_link = link
                    else:
                        classes += "text-grey-4 hover:bg-blue-grey-9"
                        ui.link(label, path).classes(classes)

        # Scroll active item into view after page loads
        if active_link:
            ui.run_javascript(f'''
                setTimeout(() => {{
                    const activeLink = document.querySelector('.bg-blue-grey-8');
                    if (activeLink) {{
                        activeLink.scrollIntoView({{
                            behavior: 'smooth',
                            block: 'center'
                        }});
                    }}
                }}, 100);
            ''')

        results_container = ui.column().classes("w-full gap-0 overflow-y-auto").style(
            "flex: 1; min-height: 0;"
        )
        results_container.set_visibility(False)

        result_elements = []
        with results_container:
            no_results_label = ui.label("No matching settings").classes(
                "text-xs text-grey-6 px-2 mt-4"
            )
            for search_text, label, group_name, path in search_index:
                with ui.column().classes(
                    "w-full gap-0 px-1 py-1 rounded hover:bg-blue-grey-9"
                ) as row:
                    ui.label(group_name).classes("text-xs text-grey-7")
                    link_classes = (
                        "w-full no-underline text-sm "
                    )
                    if current == path:
                        link_classes += "text-white font-bold active-search-result"
                    else:
                        link_classes += "text-grey-4"
                    ui.link(label, path).classes(link_classes)
                result_elements.append((search_text, row))

        def on_search(e):
            query = (e.value or "").strip().lower()
            if not query:
                nav_container.set_visibility(True)
                results_container.set_visibility(False)
                # Re-scroll to active item in nav when clearing search
                if active_link:
                    ui.run_javascript('''
                        setTimeout(() => {
                            const activeLink = document.querySelector('.bg-blue-grey-8');
                            if (activeLink) {
                                activeLink.scrollIntoView({
                                    behavior: 'smooth',
                                    block: 'center'
                                });
                            }
                        }, 100);
                    ''')
                return

            nav_container.set_visibility(False)
            results_container.set_visibility(True)

            any_visible = False
            for search_text, row in result_elements:
                match = query in search_text
                row.set_visibility(match)
                if match:
                    any_visible = True

            no_results_label.set_visibility(not any_visible)

            # Scroll to active item in search results if present
            ui.run_javascript('''
                setTimeout(() => {
                    const activeResult = document.querySelector('.active-search-result');
                    if (activeResult && activeResult.closest('[style*="display: none"]') === null) {
                        activeResult.scrollIntoView({
                            behavior: 'smooth',
                            block: 'center'
                        });
                    }
                }, 100);
            ''')

        search_input.on_value_change(on_search)


def _create_scope_toggle():
    """Create the Global/Project scope toggle in the header."""
    try:
        from nicegui import app
        current = app.storage.user.get("config_scope", "global")
    except Exception:
        current = "global"

    with ui.row().classes("items-center gap-1 ml-4"):
        ui.label("|").classes("text-grey-6")
        ui.label("Scope:").classes("text-grey-4 text-xs")

        scope_toggle = ui.toggle(
            {
                "global": "Global",
                "project": "Project",
            },
            value=current,
        ).props("dense size=sm color=blue-grey-6 text-color=white toggle-color=blue-6").classes(
            "text-xs"
        )

        async def on_scope_change(e):
            try:
                from nicegui import app as _app
                _app.storage.user["config_scope"] = e.value
                await ui.run_javascript('location.reload()')
            except Exception:
                pass  # intentionally silent — optional dependency

        scope_toggle.on_value_change(on_scope_change)
