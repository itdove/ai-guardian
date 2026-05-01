#!/usr/bin/env python3
"""
Effective Configuration Viewer

Display the effective runtime configuration, equivalent to
`ai-guardian config show --all --json`.
"""

import json
import subprocess
import sys

from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Static

from ai_guardian.config_utils import get_config_dir


class ConfigEffectiveContent(Container):
    """Content widget for Effective Config panel."""

    CSS = """
    ConfigEffectiveContent {
        height: 100%;
    }

    #effective-header {
        margin: 0 0 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Effective Configuration[/bold]  [dim]r=Refresh[/dim]",
            id="effective-header",
        )
        with VerticalScroll():
            yield Static("Loading...", id="effective-content")

    def on_mount(self) -> None:
        self.load_config()

    def refresh_content(self) -> None:
        self.load_config()

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("Effective config refreshed", severity="information")

    def load_config(self) -> None:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "ai_guardian", "config", "show", "--all", "--json"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout.strip():
                config_data = json.loads(result.stdout)
                formatted = json.dumps(config_data, indent=2)
                self.query_one("#effective-content", Static).update(
                    f"[green]{formatted}[/green]"
                )
            else:
                error = result.stderr.strip() if result.stderr else "Unknown error"
                self.query_one("#effective-content", Static).update(
                    f"[red]Error loading config:[/red]\n{error}"
                )
        except json.JSONDecodeError:
            self.query_one("#effective-content", Static).update(
                f"[dim]{result.stdout}[/dim]"
            )
        except Exception as e:
            self.query_one("#effective-content", Static).update(
                f"[red]Error: {e}[/red]"
            )
