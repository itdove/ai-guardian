#!/usr/bin/env python3
"""
Secrets Tab Content

View secret detection settings and manage configuration.
"""

import json
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Button, Input, Label, Switch

from ai_guardian.config_utils import get_config_dir


class SecretsContent(Container):
    """Content widget for Secrets tab."""

    CSS = """
    SecretsContent {
        height: 100%;
    }

    #secrets-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    .section {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    .section-title {
        margin: 0 0 1 0;
        font-weight: bold;
    }

    .setting-row {
        margin: 0.5 0;
        height: auto;
    }

    .setting-row Label {
        margin: 0 1 0 0;
        width: auto;
    }

    .setting-row Input {
        width: 40;
    }

    .setting-row Button {
        margin: 0 0 0 1;
    }

    #actions {
        margin: 1 0;
        height: auto;
    }

    #actions Button {
        margin: 0 1 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the secrets tab content."""
        yield Static("[bold]Secret Detection Settings[/bold]", id="secrets-header")

        with VerticalScroll():
            # Gitleaks section
            with Container(classes="section"):
                yield Static("[bold]Gitleaks Configuration[/bold]", classes="section-title")
                yield Static("Secret scanning is enabled by default using Gitleaks.", id="gitleaks-status")
                yield Static("Config file: .gitleaks.toml (project-specific) or built-in rules", id="gitleaks-config")

            # Pattern server section
            with Container(classes="section"):
                yield Static("[bold]Pattern Server (Enhanced Detection)[/bold]", classes="section-title")
                yield Static("", id="pattern-server-status")

                with Horizontal(classes="setting-row"):
                    yield Label("Server URL:")
                    yield Input(placeholder="http://localhost:8080", id="pattern-server-url")
                    yield Button("Test Connection", id="test-pattern-server")

            # Violation logging section
            with Container(classes="section"):
                yield Static("[bold]Secret Violation Logging[/bold]", classes="section-title")
                yield Static("", id="violation-logging-status")

            with Horizontal(id="actions"):
                yield Button("Refresh", id="refresh-secrets", variant="primary")
                yield Button("View Secret Violations", id="view-secret-violations")

    def on_mount(self) -> None:
        """Load configuration when mounted."""
        self.load_config()

    def refresh_content(self) -> None:
        """Refresh configuration (called by parent app)."""
        self.load_config()

    def load_config(self) -> None:
        """Load and display secret detection configuration."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        # Load config
        config = {}
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except Exception as e:
                self.app.notify(f"Error loading config: {e}", severity="error")

        # Pattern server status
        pattern_server = config.get("pattern_server", {})
        enabled = pattern_server.get("enabled", False)
        server_url = pattern_server.get("server_url", "http://localhost:8080")

        status_text = f"Status: {'✓ Enabled' if enabled else '✗ Disabled'}"
        self.query_one("#pattern-server-status", Static).update(status_text)
        self.query_one("#pattern-server-url", Input).value = server_url

        # Violation logging status
        violation_logging = config.get("violation_logging", {})
        log_enabled = violation_logging.get("enabled", True)
        log_types = violation_logging.get("log_types", [])
        logs_secrets = "secret_detected" in log_types or not log_types

        log_status = f"Status: {'✓ Enabled' if log_enabled and logs_secrets else '✗ Disabled'}"
        self.query_one("#violation-logging-status", Static).update(log_status)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "refresh-secrets":
            self.load_config()
            self.app.notify("Secrets configuration refreshed", severity="information")

        elif button_id == "test-pattern-server":
            self.test_pattern_server()

        elif button_id == "view-secret-violations":
            # Switch to Violations tab and filter by secrets
            self.app.notify("Switching to Violations tab - use 'Secrets' filter", severity="information")

    def test_pattern_server(self) -> None:
        """Test connection to pattern server."""
        server_url = self.query_one("#pattern-server-url", Input).value.strip()

        if not server_url:
            self.app.notify("Please enter a server URL", severity="error")
            return

        try:
            import requests
            response = requests.get(f"{server_url}/health", timeout=5)
            if response.status_code == 200:
                self.app.notify(f"✓ Pattern server is reachable at {server_url}", severity="success")
            else:
                self.app.notify(f"Pattern server returned status {response.status_code}", severity="warning")
        except ImportError:
            self.app.notify("requests library not installed - cannot test connection", severity="error")
        except Exception as e:
            self.app.notify(f"✗ Cannot connect to pattern server: {e}", severity="error")
