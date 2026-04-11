#!/usr/bin/env python3
"""
Prompt Injection Tab Content

View and configure prompt injection detection settings.
"""

import json
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Button, Input, Label, Select

from ai_guardian.config_utils import get_config_dir


class PromptInjectionContent(Container):
    """Content widget for Prompt Injection tab."""

    CSS = """
    PromptInjectionContent {
        height: 100%;
    }

    #prompt-injection-header {
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

    .setting-row Select {
        width: 30;
    }

    .setting-row Input {
        width: 50;
    }

    .setting-row Button {
        margin: 0 0 0 1;
    }

    #allowlist-patterns {
        margin: 1 0;
        padding: 1;
        background: $surface;
        border: solid $primary;
        min-height: 8;
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
        """Compose the prompt injection tab content."""
        yield Static("[bold]Prompt Injection Detection Settings[/bold]", id="prompt-injection-header")

        with VerticalScroll():
            # Detection status section
            with Container(classes="section"):
                yield Static("[bold]Detection Status[/bold]", classes="section-title")
                yield Static("", id="detection-status")

                with Horizontal(classes="setting-row"):
                    yield Label("Sensitivity:")
                    yield Select(
                        [("Low (0.5)", "0.5"), ("Medium (0.7)", "0.7"), ("High (0.9)", "0.9")],
                        value="0.7",
                        id="sensitivity-select"
                    )
                    yield Button("Update", id="update-sensitivity")

            # Allowlist patterns section
            with Container(classes="section"):
                yield Static("[bold]Allowlist Patterns[/bold]", classes="section-title")
                yield Static("Patterns that should be ignored (e.g., for documentation):", classes="setting-row")
                yield Static("", id="allowlist-patterns")

                with Horizontal(classes="setting-row"):
                    yield Input(placeholder="Enter pattern to allowlist", id="new-pattern-input")
                    yield Button("Add Pattern", id="add-pattern")

            # Statistics section
            with Container(classes="section"):
                yield Static("[bold]Detection Statistics[/bold]", classes="section-title")
                yield Static("", id="detection-stats")

            with Horizontal(id="actions"):
                yield Button("Refresh", id="refresh-prompt-injection", variant="primary")
                yield Button("View Prompt Injection Violations", id="view-pi-violations")

    def on_mount(self) -> None:
        """Load configuration when mounted."""
        self.load_config()

    def refresh_content(self) -> None:
        """Refresh configuration (called by parent app)."""
        self.load_config()

    def load_config(self) -> None:
        """Load and display prompt injection detection configuration."""
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

        # Prompt injection settings
        pi_config = config.get("prompt_injection", {})
        enabled = pi_config.get("enabled", True)
        sensitivity = pi_config.get("sensitivity", 0.7)
        allowlist = pi_config.get("allowlist_patterns", [])

        # Update status
        status_text = f"Status: {'✓ Enabled' if enabled else '✗ Disabled'}\nSensitivity: {sensitivity}"
        self.query_one("#detection-status", Static).update(status_text)

        # Update sensitivity selector
        try:
            sensitivity_str = str(sensitivity)
            select_widget = self.query_one("#sensitivity-select", Select)
            if select_widget:
                select_widget.value = sensitivity_str
        except Exception:
            pass  # Widget may not be fully mounted yet

        # Update allowlist patterns
        if allowlist:
            patterns_text = "\n".join(f"  • {pattern}" for pattern in allowlist)
        else:
            patterns_text = "[dim]No allowlist patterns configured[/dim]"
        self.query_one("#allowlist-patterns", Static).update(patterns_text)

        # Get violation stats
        from ai_guardian.violation_logger import ViolationLogger
        violation_logger = ViolationLogger()
        violations = violation_logger.get_recent_violations(
            limit=1000,
            violation_type="prompt_injection",
            resolved=None
        )
        total = len(violations)
        unresolved = len([v for v in violations if not v.get("resolved", False)])

        stats_text = f"Total prompt injection violations: {total}\nUnresolved: {unresolved}"
        self.query_one("#detection-stats", Static).update(stats_text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "refresh-prompt-injection":
            self.load_config()
            self.app.notify("Prompt injection configuration refreshed", severity="information")

        elif button_id == "update-sensitivity":
            self.update_sensitivity()

        elif button_id == "add-pattern":
            self.add_allowlist_pattern()

        elif button_id == "view-pi-violations":
            self.app.notify("Switching to Violations tab - use 'Prompt Injection' filter", severity="information")

    def update_sensitivity(self) -> None:
        """Update prompt injection detection sensitivity."""
        sensitivity_str = self.query_one("#sensitivity-select", Select).value
        sensitivity = float(sensitivity_str)

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "prompt_injection" not in config:
                config["prompt_injection"] = {}

            config["prompt_injection"]["sensitivity"] = sensitivity

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.load_config()
            self.app.notify(f"✓ Sensitivity updated to {sensitivity}", severity="success")

        except Exception as e:
            self.app.notify(f"Error updating sensitivity: {e}", severity="error")

    def add_allowlist_pattern(self) -> None:
        """Add a pattern to the allowlist."""
        pattern = self.query_one("#new-pattern-input", Input).value.strip()

        if not pattern:
            self.app.notify("Please enter a pattern", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "prompt_injection" not in config:
                config["prompt_injection"] = {}

            if "allowlist_patterns" not in config["prompt_injection"]:
                config["prompt_injection"]["allowlist_patterns"] = []

            # Check if pattern already exists
            if pattern in config["prompt_injection"]["allowlist_patterns"]:
                self.app.notify("Pattern already in allowlist", severity="warning")
                return

            config["prompt_injection"]["allowlist_patterns"].append(pattern)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Clear input
            self.query_one("#new-pattern-input", Input).value = ""

            self.load_config()
            self.app.notify(f"✓ Added pattern to allowlist: {pattern}", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding pattern: {e}", severity="error")
