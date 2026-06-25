#!/usr/bin/env python3
"""
Configuration Viewer Tab Content

Display the current merged configuration with per-key provenance.
"""

from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Static, Button

from ai_guardian.config_utils import get_config_dir, get_project_config_path


class ConfigContent(Container):
    """Content widget for Config tab."""

    CSS = """
    ConfigContent {
        height: 100%;
    }

    #config-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    #config-sources {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    #config-content {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    #config-actions {
        margin: 1 0;
        height: auto;
        layout: horizontal;
    }

    #config-actions Button {
        margin: 0 1 0 0;
    }
    """

    _show_diff_only: bool = False

    def compose(self) -> ComposeResult:
        """Compose the config viewer tab content."""
        yield Static("[bold]Effective Configuration[/bold]", id="config-header")

        with Container(id="config-actions"):
            yield Button("Show All", id="btn-show-all", variant="primary")
            yield Button("Show Overrides Only", id="btn-show-diff", variant="default")

        with VerticalScroll():
            yield Static("", id="config-sources")
            yield Static("", id="config-content")

    def on_mount(self) -> None:
        """Load configuration when mounted."""
        self.load_config()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle toggle between full view and diff view."""
        if event.button.id == "btn-show-all":
            self._show_diff_only = False
        elif event.button.id == "btn-show-diff":
            self._show_diff_only = True
        self._update_toggle_buttons()
        self.load_config()

    def _update_toggle_buttons(self) -> None:
        """Update button variants to reflect active view."""
        btn_all = self.query_one("#btn-show-all", Button)
        btn_diff = self.query_one("#btn-show-diff", Button)
        if self._show_diff_only:
            btn_all.variant = "default"
            btn_diff.variant = "primary"
        else:
            btn_all.variant = "primary"
            btn_diff.variant = "default"

    def refresh_content(self) -> None:
        """Refresh configuration (called by parent app)."""
        self.load_config()

    def load_config(self) -> None:
        """Load and display the current configuration with provenance."""
        config_dir = get_config_dir()
        global_config_path = config_dir / "ai-guardian.json"
        project_config_path = get_project_config_path()

        sources = ["[bold]Configuration Sources:[/bold]\n"]

        if global_config_path.exists():
            sources.append(f"[green]✓[/green] Global: {global_config_path}")
        else:
            sources.append(f"[dim]✗ Global: {global_config_path} (not found)[/dim]")

        if project_config_path:
            sources.append(f"[green]✓[/green] Project: {project_config_path}")
        else:
            sources.append("[dim]✗ Project: (no project config)[/dim]")

        self.query_one("#config-sources", Static).update("\n".join(sources))

        try:
            from ai_guardian.config_writer import (
                load_scoped_config,
                compute_detailed_provenance,
                format_provenance_text,
                format_diff_text,
            )

            merged_config = load_scoped_config("merged")
            provenance = compute_detailed_provenance()

            if not merged_config:
                self.query_one("#config-content", Static).update(
                    "[dim]No configuration found.\n\nUsing built-in defaults.[/dim]"
                )
                return

            if self._show_diff_only:
                project_cfg = load_scoped_config("project")
                if not project_cfg:
                    text = "[dim]No project overrides — using global config only.[/dim]"
                else:
                    header = "[bold]Project Overrides Only:[/bold]\n\n"
                    diff = format_diff_text(project_cfg, provenance)
                    if diff.strip():
                        text = header + diff
                    else:
                        text = "[dim]No project overrides.[/dim]"
            else:
                header = "[bold]Merged Configuration:[/bold]\n\n"
                text = header + format_provenance_text(merged_config, provenance)

            self.query_one("#config-content", Static).update(text)

        except Exception as e:
            self.query_one("#config-content", Static).update(
                f"[red]Error loading configuration: {e}[/red]"
            )

    def action_refresh(self) -> None:
        """Refresh configuration (triggered by 'r' key)."""
        self.load_config()
        self.app.notify("Configuration refreshed", severity="information")
