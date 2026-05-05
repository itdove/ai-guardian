#!/usr/bin/env python3
"""
Global Settings Tab Content

Centralized quick-toggle dashboard for all security features.
Uses TimeBasedToggle widgets (same as individual panels) without help text for compact display.
"""

import json
from typing import Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Label, Select

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.schema_defaults import SchemaDefaultsMixin, select_options_with_default
from ai_guardian.tui.widgets import TimeBasedToggle, sanitize_enabled_value


FEATURES = [
    ("permissions", "permissions_enabled", "🔐 Tool Permissions Enforcement"),
    ("secret_scanning", "secret_scanning", "🔍 Secret Scanning"),
    ("secret_redaction", "gs_secret_redaction", "🔒 Secret Redaction"),
    ("prompt_injection", "gs_prompt_injection", "🛡️ Prompt Injection Detection"),
    ("scan_pii", "gs_scan_pii", "👤 PII Detection"),
    ("ssrf_protection", "gs_ssrf_protection", "🌐 SSRF Protection"),
    ("config_file_scanning", "gs_config_file_scanning", "📄 Config File Scanning"),
    ("violation_logging", "gs_violation_logging", "📝 Violation Logging"),
]

FEATURE_ACTIONS = {
    "secret_redaction": {
        "schema_path": "secret_redaction.action",
        "options": [
            ("Log Only", "log-only"),
            ("Warn", "warn"),
        ],
        "default": "warn",
    },
    "prompt_injection": {
        "schema_path": "prompt_injection.action",
        "options": [
            ("Block", "block"),
            ("Warn", "warn"),
            ("Log Only", "log-only"),
        ],
        "default": "block",
    },
    "scan_pii": {
        "schema_path": "scan_pii.action",
        "options": [
            ("Block", "block"),
            ("Redact", "redact"),
            ("Warn", "warn"),
            ("Log Only", "log-only"),
        ],
        "default": "block",
    },
    "ssrf_protection": {
        "schema_path": "ssrf_protection.action",
        "options": [
            ("Block", "block"),
            ("Warn", "warn"),
            ("Log Only", "log-only"),
        ],
        "default": "block",
    },
    "config_file_scanning": {
        "schema_path": "config_file_scanning.action",
        "options": [
            ("Block", "block"),
            ("Warn", "warn"),
            ("Log Only", "log-only"),
        ],
        "default": "block",
    },
}


class GlobalSettingsContent(SchemaDefaultsMixin, Container):
    """Content widget for Global Settings tab."""

    SCHEMA_SECTION = ""
    SCHEMA_FIELDS = []

    CSS = """
    GlobalSettingsContent {
        height: 100%;
    }

    #global-settings-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    .gs-action-section {
        margin: 0 0 1 2;
        padding: 1;
        background: $panel;
        border: solid $primary;
        height: auto;
    }

    .gs-action-row {
        margin: 0;
        height: auto;
    }

    .gs-action-row Label {
        margin: 0 1 0 0;
        width: auto;
    }

    .gs-action-row Select {
        width: 30;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold]Global Security Settings[/bold]", id="global-settings-header")

        with VerticalScroll():
            yield Static(
                "[dim]Quick-toggle dashboard — use each feature's panel for full settings.[/dim]"
            )

            for section, config_key, title in FEATURES:
                yield TimeBasedToggle(
                    title=title,
                    config_key=config_key,
                    current_value=True,
                    id=f"{config_key}_toggle",
                )
                if section in FEATURE_ACTIONS:
                    action_info = FEATURE_ACTIONS[section]
                    with Container(classes="gs-action-section"):
                        with Horizontal(classes="gs-action-row"):
                            yield Label("Action:")
                            yield Select(
                                select_options_with_default(
                                    action_info["options"],
                                    action_info["schema_path"],
                                ),
                                value=action_info["default"],
                                id=f"{config_key}_action",
                            )

    def on_mount(self) -> None:
        self._loading = False
        self.load_config()

    def refresh_content(self) -> None:
        self.load_config()

    def load_config(self) -> None:
        self._loading = True
        try:
            config_dir = get_config_dir()
            config_path = config_dir / "ai-guardian.json"

            config = {}
            if config_path.exists():
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                except Exception as e:
                    self.app.notify(f"Error loading config: {e}", severity="error")
                    return

            for section, config_key, _ in FEATURES:
                section_data = config.get(section, {})
                raw = section_data.get("enabled", True) if isinstance(section_data, dict) else True
                try:
                    toggle = self.query_one(f"#{config_key}_toggle", TimeBasedToggle)
                    toggle.load_value(raw)
                except Exception:
                    pass

                if section in FEATURE_ACTIONS:
                    action_info = FEATURE_ACTIONS[section]
                    action_value = section_data.get("action", action_info["default"]) if isinstance(section_data, dict) else action_info["default"]
                    try:
                        self.query_one(f"#{config_key}_action", Select).value = action_value
                    except Exception:
                        pass
        finally:
            self._loading = False

    def on_button_pressed(self, event) -> None:
        if self._loading:
            return
        bid = event.button.id
        if not bid:
            return

        for section, config_key, title in FEATURES:
            if config_key in bid:
                toggle = self.query_one(f"#{config_key}_toggle", TimeBasedToggle)
                if toggle.current_mode == "temp_disabled":
                    return
                value = sanitize_enabled_value(toggle.get_value())
                self._save(section, value, title)
                return

    def on_input_submitted(self, event) -> None:
        if self._loading:
            return
        iid = event.input.id
        if not iid:
            return

        for section, config_key, title in FEATURES:
            if config_key in iid:
                toggle = self.query_one(f"#{config_key}_toggle", TimeBasedToggle)
                value = sanitize_enabled_value(toggle.get_value())
                self._save(section, value, title)
                return

    def on_select_changed(self, event) -> None:
        """Handle select changes - save action immediately."""
        if self._loading:
            return
        select_id = event.select.id
        if not select_id:
            return

        for section, config_key, title in FEATURES:
            if select_id == f"{config_key}_action" and section in FEATURE_ACTIONS:
                self._save_action(section, event.value, title)
                return

    def _save_action(self, section: str, value: str, display: str) -> None:
        """Save an action value for a feature section."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if section not in config or not isinstance(config[section], dict):
                config[section] = {}

            config[section]["action"] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.app.notify(f"✓ {display}: action = {value}", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving: {e}", severity="error")

    def _save(self, section: str, value: Any, display: str) -> None:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if section not in config or not isinstance(config[section], dict):
                config[section] = {}

            config[section]["enabled"] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            if isinstance(value, bool):
                status = "enabled" if value else "disabled"
                self.app.notify(f"✓ {display}: {status}", severity="success")
            elif isinstance(value, dict) and value.get("disabled_until"):
                from ai_guardian.tui.widgets import format_local_time
                self.app.notify(
                    f"✓ {display}: temp disabled until {format_local_time(value['disabled_until'])}",
                    severity="success",
                )

        except Exception as e:
            self.app.notify(f"Error saving: {e}", severity="error")

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("Global settings refreshed", severity="information")
