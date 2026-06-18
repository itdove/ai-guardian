"""
Config Cache Status Panel

Shows per-project config cache state tracked by the daemon.
"""

import logging
import os
from datetime import datetime, timezone

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widgets import Static, Button, DataTable

logger = logging.getLogger(__name__)


def _format_mtime(mtime):
    if mtime is None:
        return "—"
    try:
        dt = datetime.fromtimestamp(mtime, tz=timezone.utc).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(mtime)


def _format_seconds_ago(seconds):
    if seconds is None:
        return "—"
    seconds = round(seconds)
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s ago"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours}h {minutes}m ago"


def _short_dir(path):
    if not path:
        return "—"
    return os.path.basename(path) or path


def _fetch_cache_status():
    try:
        from ai_guardian.daemon.multi_client import MultiDaemonClient
        from ai_guardian.daemon.discovery import DaemonDiscovery
        discovery = DaemonDiscovery()
        targets = discovery.discover_all()
        if targets:
            client = MultiDaemonClient()
            return client.get_cache_status(targets[0])
        return MultiDaemonClient._local_cache_status()
    except Exception:
        pass
    return None


class CacheStatusContent(Static):
    """Content widget for Config Cache Status panel."""

    CSS = """
    CacheStatusContent {
        height: 100%;
    }

    #cache-status-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    #cache-summary {
        margin: 1 2;
        padding: 0 1;
    }

    #cache-table {
        margin: 1 2;
        height: auto;
        max-height: 80%;
    }

    #cache-detail {
        margin: 1 2;
        padding: 1;
    }

    .cache-buttons {
        height: auto;
        margin: 1 2;
        padding: 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Config Cache Status[/bold]", id="cache-status-header"
        )

        yield Static("", id="cache-summary")

        with VerticalScroll():
            yield DataTable(id="cache-table")
            yield Static("", id="cache-detail")

        with Horizontal(classes="cache-buttons"):
            yield Button("Refresh", id="cache-refresh", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#cache-table", DataTable)
        table.add_columns(
            "Project", "Config", "Override", "Last Seen", "Modified"
        )
        table.cursor_type = "row"
        self._load_data()

    def refresh_content(self) -> None:
        self._load_data()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cache-refresh":
            self._load_data()
            self.app.notify("Cache status refreshed", severity="information")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._show_detail(event.row_key)

    def _load_data(self) -> None:
        data = _fetch_cache_status()

        summary = self.query_one("#cache-summary", Static)
        table = self.query_one("#cache-table", DataTable)
        detail = self.query_one("#cache-detail", Static)

        table.clear()
        detail.update("")

        if not data:
            summary.update("[yellow]Could not fetch cache status[/yellow]")
            return

        projects = data.get("projects", [])
        total = data.get("total_tracked", 0)
        last_reload = data.get("last_project_config_reload_at")

        overrides = sum(
            1 for p in projects if p.get("has_project_override")
        )
        reload_str = ""
        if last_reload:
            try:
                dt = datetime.fromtimestamp(
                    last_reload, tz=timezone.utc
                ).astimezone()
                reload_str = f"  Last reload: {dt.strftime('%H:%M:%S')}"
            except Exception:
                pass

        summary.update(
            f"[bold]{total}[/bold] projects tracked  "
            f"[bold]{overrides}[/bold] with override"
            f"{reload_str}"
        )

        self._projects_data = projects

        for proj in projects:
            project_dir = proj.get("project_dir", "?")
            config_path = proj.get("config_path")
            has_override = proj.get("has_project_override", False)
            last_seen = proj.get("last_seen_seconds_ago")
            config_mtime = proj.get("config_mtime")

            table.add_row(
                _short_dir(project_dir),
                _short_dir(config_path) if config_path else "—",
                "Yes" if has_override else "No",
                _format_seconds_ago(last_seen),
                _format_mtime(config_mtime),
                key=project_dir,
            )

    def _show_detail(self, row_key) -> None:
        detail = self.query_one("#cache-detail", Static)
        project_dir = str(row_key.value) if row_key else None
        if not project_dir or not hasattr(self, "_projects_data"):
            return

        proj = None
        for p in self._projects_data:
            if p.get("project_dir") == project_dir:
                proj = p
                break

        if not proj:
            detail.update("")
            return

        lines = [f"[bold]Details: {project_dir}[/bold]\n"]
        lines.append(f"  Project dir:    {proj.get('project_dir', '—')}")
        lines.append(
            f"  Config path:    {proj.get('config_path') or '(none)'}"
        )
        lines.append(
            f"  Config mtime:   {_format_mtime(proj.get('config_mtime'))}"
        )
        lines.append(
            f"  Last seen:      "
            f"{_format_seconds_ago(proj.get('last_seen_seconds_ago'))}"
        )
        override = proj.get("has_project_override", False)
        lines.append(
            f"  Has override:   {'[green]Yes[/green]' if override else '[dim]No[/dim]'}"
        )

        gp = proj.get("global_config_path")
        if gp:
            lines.append(f"  Global config:  {gp}")
            lines.append(
                f"  Global mtime:   "
                f"{_format_mtime(proj.get('global_config_mtime'))}"
            )

        cache_ago = proj.get("cache_last_accessed_seconds_ago")
        if cache_ago is not None:
            lines.append(
                f"  Cache accessed: {_format_seconds_ago(cache_ago)}"
            )

        detail.update("\n".join(lines))

    def action_refresh(self) -> None:
        self._load_data()
        self.app.notify("Cache status refreshed", severity="information")
