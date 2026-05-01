#!/usr/bin/env python3
"""
Prompt Injection Patterns

Manage allowlist patterns (false positive exclusions) and
custom detection patterns.
"""

import json
from datetime import datetime, timezone

from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Static, Input

from ai_guardian.config_utils import get_config_dir


class PIPatternsContent(Container):
    """Content widget for Prompt Injection Patterns."""

    CSS = """
    PIPatternsContent {
        height: 100%;
    }

    #pi-patterns-header {
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

    #allowlist-patterns, #custom-patterns {
        margin: 1 0;
        padding: 1;
        background: $surface;
        border: solid $primary;
        min-height: 6;
    }

    Input:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold]Prompt Injection — Patterns[/bold]", id="pi-patterns-header")

        with VerticalScroll():
            with Container(classes="section"):
                yield Static("[bold]Allowlist Patterns[/bold]", classes="section-title")
                yield Static(
                    "[dim]Regex patterns to ignore (for false positive exclusions). "
                    "Supports time-based patterns with expiration.[/dim]",
                    classes="setting-row",
                )
                yield Static("", id="allowlist-patterns")
                yield Input(
                    placeholder="Enter regex pattern to allowlist (press Enter or 'a' to add)",
                    id="new-allowlist-input",
                )

            with Container(classes="section"):
                yield Static("[bold]Custom Detection Patterns[/bold]", classes="section-title")
                yield Static(
                    "[dim]Additional regex patterns to detect as prompt injection. "
                    "Matched against tool inputs and outputs.[/dim]",
                    classes="setting-row",
                )
                yield Static("", id="custom-patterns")
                yield Input(
                    placeholder="Enter custom detection pattern (press Enter or 'c' to add)",
                    id="new-custom-input",
                )

    def on_mount(self) -> None:
        self.load_config()

    def refresh_content(self) -> None:
        self.load_config()

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("Patterns refreshed", severity="information")

    def action_add_pattern(self) -> None:
        self._add_allowlist_pattern()

    def action_add_custom(self) -> None:
        self._add_custom_pattern()

    def load_config(self) -> None:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        config = {}
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except Exception as e:
                self.app.notify(f"Error loading config: {e}", severity="error")

        pi_config = config.get("prompt_injection", {})
        allowlist = pi_config.get("allowlist_patterns", [])
        custom = pi_config.get("custom_patterns", [])

        if allowlist:
            pattern_lines = []
            for pattern in allowlist:
                if isinstance(pattern, dict):
                    pattern_str = pattern.get("pattern", "")
                    valid_until = pattern.get("valid_until", "")
                    if valid_until:
                        try:
                            expiry_dt = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
                            now = datetime.now(timezone.utc)
                            if expiry_dt <= now:
                                pattern_lines.append(f"  {pattern_str} [status-error][EXPIRED][/status-error]")
                            elif (expiry_dt - now).total_seconds() < 86400:
                                pattern_lines.append(f"  {pattern_str} [status-warn][expires {valid_until}][/status-warn]")
                            else:
                                pattern_lines.append(f"  {pattern_str} [dim][until {valid_until}][/dim]")
                        except Exception:
                            pattern_lines.append(f"  {pattern_str} [dim][until {valid_until}][/dim]")
                    else:
                        pattern_lines.append(f"  {pattern_str}")
                else:
                    pattern_lines.append(f"  {pattern}")
            patterns_text = "\n".join(pattern_lines)
        else:
            patterns_text = "[dim]No allowlist patterns configured[/dim]"

        try:
            self.query_one("#allowlist-patterns", Static).update(patterns_text)
        except Exception:
            pass

        if custom:
            custom_text = "\n".join(f"  {p}" for p in custom)
        else:
            custom_text = "[dim]No custom patterns configured[/dim]"

        try:
            self.query_one("#custom-patterns", Static).update(custom_text)
        except Exception:
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "new-allowlist-input":
            self._add_allowlist_pattern()
        elif event.input.id == "new-custom-input":
            self._add_custom_pattern()

    def _add_allowlist_pattern(self) -> None:
        self._add_pattern("allowlist_patterns", "new-allowlist-input", "allowlist")

    def _add_custom_pattern(self) -> None:
        self._add_pattern("custom_patterns", "new-custom-input", "custom patterns")

    def _add_pattern(self, field: str, input_id: str, label: str) -> None:
        input_widget = self.query_one(f"#{input_id}", Input)
        pattern = input_widget.value.strip()

        if not pattern:
            self.app.notify("Please enter a pattern", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

            if "prompt_injection" not in config:
                config["prompt_injection"] = {}
            if field not in config["prompt_injection"]:
                config["prompt_injection"][field] = []

            if pattern in config["prompt_injection"][field]:
                self.app.notify(f"Pattern already in {label}", severity="warning")
                return

            config["prompt_injection"][field].append(pattern)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            input_widget.value = ""
            self.load_config()
            self.app.notify(f"Added to {label}: {pattern}", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding pattern: {e}", severity="error")
