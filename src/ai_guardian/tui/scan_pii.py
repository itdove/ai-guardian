#!/usr/bin/env python3
"""
PII Detection Tab Content

View and configure PII (Personally Identifiable Information) detection settings.
Scans user prompts, file reads, and tool outputs for SSNs, credit cards, etc.
"""

import json
from typing import Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Button, Input, Label, Select, Checkbox

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.schema_defaults import (
    SchemaDefaultsMixin, select_options_with_default,
)
from ai_guardian.tui.widgets import TimeBasedToggle


ALL_PII_TYPES = [
    ("ssn", "Social Security Numbers (XXX-XX-XXXX)"),
    ("credit_card", "Credit Card Numbers (Visa, MC, Amex, etc.)"),
    ("phone", "US Phone Numbers"),
    ("email", "Email Addresses"),
    ("us_passport", "US Passport Numbers"),
    ("iban", "International Bank Account Numbers"),
    ("intl_phone", "International Phone Numbers (+country code)"),
]


class ScanPIIContent(SchemaDefaultsMixin, Container):
    """Content widget for PII Detection tab."""

    SCHEMA_SECTION = "scan_pii"
    SCHEMA_FIELDS = [
        ("pii-action-select", "action", "select"),
    ]

    CSS = """
    ScanPIIContent {
        height: 100%;
    }

    #pii-header {
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
        width: 40;
    }

    .pii-type-row {
        margin: 0.25 0;
        height: auto;
    }

    .pii-type-row Checkbox {
        margin: 0 1 0 0;
    }

    #ignore-files-list, #ignore-tools-list, #pii-allowlist-patterns {
        margin: 1 0;
        padding: 1;
        background: $surface;
        border: solid $primary;
        min-height: 4;
    }

    #actions {
        margin: 1 0;
        height: auto;
    }

    #actions Button {
        margin: 0 1 0 0;
    }

    Input:focus {
        border-left: heavy $accent;
        text-style: bold;
    }

    Button:focus {
        border-left: heavy $accent;
        text-style: bold;
    }

    Select:focus {
        border-left: heavy $accent;
        text-style: bold;
    }

    Checkbox:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold]PII Detection Settings[/bold]", id="pii-header")

        with VerticalScroll():
            yield TimeBasedToggle(
                title="PII Detection",
                config_key="scan_pii_enabled",
                current_value=True,
                help_text="Scan prompts, file reads, and tool outputs for personally identifiable information (GDPR/CCPA compliance)",
                id="scan_pii_enabled_toggle",
            )

            with Container(classes="section"):
                yield Static("[bold]Action on PII Detection[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Action Mode:")
                    yield Select(
                        select_options_with_default(
                            [
                                ("Block (reject operation)", "block"),
                                ("Redact (mask PII in output)", "redact"),
                                ("Warn (allow with warning)", "warn"),
                                ("Log Only (silent logging)", "log-only"),
                            ],
                            "scan_pii.action",
                        ),
                        value="block",
                        id="pii-action-select",
                    )

                yield Static(
                    "[dim]  block: Reject the operation entirely\n"
                    "  redact: Mask PII in PostToolUse, block in PreToolUse/UserPromptSubmit\n"
                    "  warn: Log violation and show warning but allow\n"
                    "  log-only: Log violation silently[/dim]",
                    classes="setting-row",
                )

            with Container(classes="section"):
                yield Static("[bold]PII Types to Detect[/bold]", classes="section-title")
                yield Static(
                    "[dim]Uncheck types to disable detection for specific PII categories.[/dim]",
                    classes="section-title",
                )

                for pii_type, description in ALL_PII_TYPES:
                    with Horizontal(classes="pii-type-row"):
                        yield Checkbox(
                            description,
                            id=f"pii-type-{pii_type}",
                            value=True,
                        )

            with Container(classes="section"):
                yield Static("[bold]Ignore Files[/bold]", classes="section-title")
                yield Static(
                    "[dim]Glob patterns for files to skip during PII scanning "
                    "(e.g., test files with example PII data).[/dim]",
                    classes="section-title",
                )
                yield Static("", id="ignore-files-list")
                yield Input(
                    placeholder="Enter glob pattern (e.g., tests/**, *.test.py)",
                    id="pii-ignore-file-input",
                )

            with Container(classes="section"):
                yield Static("[bold]Ignore Tools[/bold]", classes="section-title")
                yield Static(
                    "[dim]Tool name patterns to skip during PII scanning "
                    "(e.g., mcp__*, Skill:*, Bash).[/dim]",
                    classes="section-title",
                )
                yield Static("", id="ignore-tools-list")
                yield Input(
                    placeholder="Enter tool name pattern (e.g., mcp__*, Skill:*)",
                    id="pii-ignore-tool-input",
                )

            with Container(classes="section"):
                yield Static("[bold]Allowlist Patterns[/bold]", classes="section-title")
                yield Static(
                    "[dim]Regex patterns for known-safe PII values to ignore "
                    "(e.g., @anthropic.com emails, @example.com addresses). "
                    "Unlike ignore_files, this keeps scanning but skips matching values.[/dim]",
                    classes="section-title",
                )
                yield Static("", id="pii-allowlist-patterns")
                yield Input(
                    placeholder="Enter regex pattern (e.g., \\b[\\w.+-]+@example\\.com\\b)",
                    id="pii-allowlist-input",
                )

    def on_mount(self) -> None:
        self.load_config()

    def refresh_content(self) -> None:
        self.load_config()

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("PII detection configuration refreshed", severity="information")

    def action_save_setting(self) -> None:
        self.app.notify("Settings auto-saved on change", severity="information")

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

        pii_config = config.get("scan_pii", {})
        enabled_value = pii_config.get("enabled", True)
        action = pii_config.get("action", "block")
        pii_types = pii_config.get("pii_types", [t for t, _ in ALL_PII_TYPES])
        ignore_files = pii_config.get("ignore_files", [])
        ignore_tools = pii_config.get("ignore_tools", [])

        try:
            toggle = self.query_one("#scan_pii_enabled_toggle", TimeBasedToggle)
            toggle.load_value(enabled_value)
        except Exception:
            pass

        try:
            self.query_one("#pii-action-select", Select).value = action
        except Exception:
            pass

        for pii_type, _ in ALL_PII_TYPES:
            try:
                cb = self.query_one(f"#pii-type-{pii_type}", Checkbox)
                cb.value = pii_type in pii_types
            except Exception:
                pass

        if ignore_files:
            files_text = "\n".join([f"  {f}" for f in ignore_files])
        else:
            files_text = "[dim]No ignore patterns configured[/dim]"
        try:
            self.query_one("#ignore-files-list", Static).update(files_text)
        except Exception:
            pass

        if ignore_tools:
            tools_text = "\n".join([f"  {t}" for t in ignore_tools])
        else:
            tools_text = "[dim]No ignored tools configured[/dim]"
        try:
            self.query_one("#ignore-tools-list", Static).update(tools_text)
        except Exception:
            pass

        allowlist = pii_config.get("allowlist_patterns", [])
        if allowlist:
            pattern_lines = []
            for pattern in allowlist:
                if isinstance(pattern, dict):
                    pattern_str = pattern.get("pattern", "")
                    valid_until = pattern.get("valid_until", "")
                    if valid_until:
                        from datetime import datetime, timezone
                        try:
                            expiry_dt = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
                            now = datetime.now(timezone.utc)
                            if expiry_dt <= now:
                                pattern_lines.append(f"  {pattern_str} [EXPIRED]")
                            elif (expiry_dt - now).total_seconds() < 86400:
                                pattern_lines.append(f"  {pattern_str} [expires {valid_until}]")
                            else:
                                pattern_lines.append(f"  {pattern_str} [until {valid_until}]")
                        except (ValueError, TypeError):
                            pattern_lines.append(f"  {pattern_str}")
                    else:
                        pattern_lines.append(f"  {pattern_str}")
                else:
                    pattern_lines.append(f"  {pattern}")
            allowlist_text = "\n".join(pattern_lines)
        else:
            allowlist_text = "[dim]No allowlist patterns configured[/dim]"
        try:
            self.query_one("#pii-allowlist-patterns", Static).update(allowlist_text)
        except Exception:
            pass

        self._apply_default_indicators(pii_config)

    def _save_config(self, updates: Dict[str, Any]) -> bool:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

            if "scan_pii" not in config:
                config["scan_pii"] = {}

            config["scan_pii"].update(updates)

            config_dir.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            return True
        except Exception as e:
            self.app.notify(f"Error saving config: {e}", severity="error")
            return False

    def on_select_changed(self, event) -> None:
        if event.select.id == "pii-action-select":
            self._save_config({"action": event.value})
            self.app.notify(f"PII action set to: {event.value}", severity="information")
        elif event.select.id and "scan_pii_enabled" in event.select.id:
            toggle = self.query_one("#scan_pii_enabled_toggle", TimeBasedToggle)
            if toggle.current_mode == "temp_disabled":
                return
            self._save_config({"enabled": toggle.get_value()})

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        checkbox_id = event.checkbox.id
        if not checkbox_id:
            return

        if checkbox_id.startswith("pii-type-"):
            enabled_types = []
            for pii_type, _ in ALL_PII_TYPES:
                try:
                    cb = self.query_one(f"#pii-type-{pii_type}", Checkbox)
                    if cb.value:
                        enabled_types.append(pii_type)
                except Exception:
                    pass
            self._save_config({"pii_types": enabled_types})
            self.app.notify(f"PII types updated ({len(enabled_types)} enabled)", severity="information")
        elif "scan_pii_enabled" in checkbox_id:
            toggle = self.query_one("#scan_pii_enabled_toggle", TimeBasedToggle)
            value = toggle.get_value()
            self._save_config({"enabled": value})

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "pii-ignore-file-input":
            self._add_ignore_file()
        elif event.input.id == "pii-ignore-tool-input":
            self._add_ignore_tool()
        elif event.input.id == "pii-allowlist-input":
            self._add_allowlist_pattern()
        elif event.input.id and "scan_pii_enabled" in event.input.id:
            toggle = self.query_one("#scan_pii_enabled_toggle", TimeBasedToggle)
            value = toggle.get_value()
            self._save_config({"enabled": value})

    def _add_ignore_file(self) -> None:
        input_widget = self.query_one("#pii-ignore-file-input", Input)
        pattern = input_widget.value.strip()

        if not pattern:
            self.app.notify("Please enter a glob pattern", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

            if "scan_pii" not in config:
                config["scan_pii"] = {}
            if "ignore_files" not in config["scan_pii"]:
                config["scan_pii"]["ignore_files"] = []

            if pattern in config["scan_pii"]["ignore_files"]:
                self.app.notify("Pattern already in list", severity="warning")
                return

            config["scan_pii"]["ignore_files"].append(pattern)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            input_widget.value = ""
            self.load_config()
            self.app.notify(f"Added ignore pattern: {pattern}", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding pattern: {e}", severity="error")

    def _add_ignore_tool(self) -> None:
        input_widget = self.query_one("#pii-ignore-tool-input", Input)
        pattern = input_widget.value.strip()

        if not pattern:
            self.app.notify("Please enter a tool name pattern", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

            if "scan_pii" not in config:
                config["scan_pii"] = {}
            if "ignore_tools" not in config["scan_pii"]:
                config["scan_pii"]["ignore_tools"] = []

            if pattern in config["scan_pii"]["ignore_tools"]:
                self.app.notify("Pattern already in list", severity="warning")
                return

            config["scan_pii"]["ignore_tools"].append(pattern)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            input_widget.value = ""
            self.load_config()
            self.app.notify(f"Added ignore tool pattern: {pattern}", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding pattern: {e}", severity="error")

    def _add_allowlist_pattern(self) -> None:
        input_widget = self.query_one("#pii-allowlist-input", Input)
        pattern = input_widget.value.strip()

        if not pattern:
            self.app.notify("Please enter a regex pattern", severity="error")
            return

        import re
        try:
            re.compile(pattern)
        except re.error as e:
            self.app.notify(f"Invalid regex: {e}", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

            if "scan_pii" not in config:
                config["scan_pii"] = {}
            if "allowlist_patterns" not in config["scan_pii"]:
                config["scan_pii"]["allowlist_patterns"] = []

            if pattern in config["scan_pii"]["allowlist_patterns"]:
                self.app.notify("Pattern already in allowlist", severity="warning")
                return

            config["scan_pii"]["allowlist_patterns"].append(pattern)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            input_widget.value = ""
            self.load_config()
            self.app.notify(f"Added allowlist pattern: {pattern}", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding pattern: {e}", severity="error")
