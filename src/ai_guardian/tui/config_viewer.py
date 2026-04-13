#!/usr/bin/env python3
"""
Configuration Viewer Tab Content

Display the current merged configuration from all sources.
"""

import json
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Static, Button

from ai_guardian.config_utils import get_config_dir


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
        color: $success;
    }

    #config-actions {
        margin: 1 0;
        height: auto;
    }

    #config-actions Button {
        margin: 0 1 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the config viewer tab content."""
        yield Static("[bold]Current Configuration[/bold]", id="config-header")

        with VerticalScroll():
            yield Static("", id="config-sources")
            yield Static("", id="config-content")

    def on_mount(self) -> None:
        """Load configuration when mounted."""
        self.load_config()

    def refresh_content(self) -> None:
        """Refresh configuration (called by parent app)."""
        self.load_config()

    def load_config(self) -> None:
        """Load and display the current configuration."""
        config_dir = get_config_dir()
        user_config_path = config_dir / "ai-guardian.json"
        project_config_path = Path.cwd() / ".ai-guardian.json"

        # Build sources list with visual indicators
        sources = ["[bold]Configuration Sources:[/bold]\n"]

        # User global config
        if user_config_path.exists():
            sources.append(f"[status-ok]✓[/status-ok] User global: {user_config_path}")
        else:
            sources.append(f"[muted]✗ User global: {user_config_path} (not found)[/muted]")

        # Project local config
        if project_config_path.exists():
            sources.append(f"[status-ok]✓[/status-ok] Project local: {project_config_path}")
        else:
            sources.append(f"[muted]✗ Project local: {project_config_path} (not found)[/muted]")

        sources_text = "\n".join(sources)
        self.query_one("#config-sources", Static).update(sources_text)

        # Load merged config
        merged_config = {}

        # Load user global config
        if user_config_path.exists():
            try:
                with open(user_config_path, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    merged_config.update(user_config)
            except Exception as e:
                self.app.notify(f"Error loading user config: {e}", severity="error")

        # Load project local config (overrides user config)
        if project_config_path.exists():
            try:
                with open(project_config_path, 'r', encoding='utf-8') as f:
                    project_config = json.load(f)
                    merged_config.update(project_config)
            except Exception as e:
                self.app.notify(f"Error loading project config: {e}", severity="error")

        # Display merged config
        if merged_config:
            config_text = "[bold]Merged Configuration:[/bold]\n\n"
            config_text += "[status-ok]"  # Green color for JSON
            config_text += json.dumps(merged_config, indent=2)
            config_text += "[/status-ok]"
        else:
            config_text = "[muted]No configuration found.\n\nUsing built-in defaults.[/muted]"

        self.query_one("#config-content", Static).update(config_text)

    def action_refresh(self) -> None:
        """Refresh configuration (triggered by 'r' key)."""
        self.load_config()
        self.app.notify("Configuration refreshed", severity="information")
