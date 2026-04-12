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

        # Build sources list
        sources = []
        sources.append(f"1. User global: {user_config_path}")
        sources.append(f"   {'✓ Found' if user_config_path.exists() else '✗ Not found'}")
        sources.append(f"2. Project local: {project_config_path}")
        sources.append(f"   {'✓ Found' if project_config_path.exists() else '✗ Not found'}")

        sources_text = "[bold]Configuration Sources:[/bold]\n" + "\n".join(sources)
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
            config_text += json.dumps(merged_config, indent=2)
        else:
            config_text = "[dim]No configuration found. Using defaults.[/dim]"

        self.query_one("#config-content", Static).update(config_text)

    def action_refresh(self) -> None:
        """Refresh configuration (triggered by 'r' key)."""
        self.load_config()
        self.app.notify("Configuration refreshed", severity="information")
