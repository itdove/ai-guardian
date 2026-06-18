#!/usr/bin/env python3
"""
Global Settings Tab Content

Centralized quick-toggle dashboard for all security features.
Uses TimeBasedToggle widgets (same as individual panels) without help text for compact display.
"""

import json
from pathlib import Path
from typing import Any, Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Label, Select

from ai_guardian.config_utils import (
    get_config_dir,
    get_project_config_path,
    GLOBAL_ONLY_SECTIONS,
)
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
    ("context_poisoning", "gs_context_poisoning", "🧪 Context Poisoning Detection"),
    ("supply_chain", "gs_supply_chain", "🔗 Supply Chain Scanning"),
    ("violation_logging", "gs_violation_logging", "📝 Violation Logging"),
    ("latency_tracking", "gs_latency_tracking", "⏱️ Latency Tracking"),
]

FEATURE_ACTIONS = {
    "secret_scanning": {
        "schema_path": "secret_scanning.action",
        "options": [
            ("Block", "block"),
            ("Ask (block if headless)", "ask"),
            ("Ask (warn if headless)", "ask:warn"),
            ("Ask (log-only if headless)", "ask:log-only"),
            ("Warn", "warn"),
            ("Log Only", "log-only"),
        ],
        "default": "block",
    },
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
            ("Ask (block if headless)", "ask"),
            ("Ask (warn if headless)", "ask:warn"),
            ("Ask (log-only if headless)", "ask:log-only"),
            ("Warn", "warn"),
            ("Log Only", "log-only"),
        ],
        "default": "block",
    },
    "scan_pii": {
        "schema_path": "scan_pii.action",
        "options": [
            ("Block", "block"),
            ("Ask (block if headless)", "ask"),
            ("Ask (warn if headless)", "ask:warn"),
            ("Ask (log-only if headless)", "ask:log-only"),
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
            ("Ask (block if headless)", "ask"),
            ("Ask (warn if headless)", "ask:warn"),
            ("Ask (log-only if headless)", "ask:log-only"),
            ("Warn", "warn"),
            ("Log Only", "log-only"),
        ],
        "default": "block",
    },
    "context_poisoning": {
        "schema_path": "context_poisoning.action",
        "options": [
            ("Block", "block"),
            ("Ask (block if headless)", "ask"),
            ("Ask (warn if headless)", "ask:warn"),
            ("Ask (log-only if headless)", "ask:log-only"),
            ("Warn", "warn"),
            ("Log Only", "log-only"),
        ],
        "default": "warn",
    },
    "supply_chain": {
        "schema_path": "supply_chain.action",
        "options": [
            ("Block", "block"),
            ("Ask (block if headless)", "ask"),
            ("Ask (warn if headless)", "ask:warn"),
            ("Ask (log-only if headless)", "ask:log-only"),
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

    #scope-notice {
        margin: 0 0 1 0;
        padding: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold]Security Settings[/bold]", id="global-settings-header")

        with VerticalScroll():
            yield Static("", id="scope-notice")

            with Container(classes="gs-action-section"):
                with Horizontal(classes="gs-action-row"):
                    yield Label("⚠️  On Scan Error:")
                    yield Select(
                        select_options_with_default(
                            [("Allow (fail-open)", "allow"), ("Block (fail-closed)", "block")],
                            "on_scan_error",
                        ),
                        value="allow",
                        id="on_scan_error_select",
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._loading = False
        self._global_config: dict = {}

    def on_mount(self) -> None:
        self.load_config()

    def refresh_content(self) -> None:
        self.load_config()

    @property
    def _is_project_scope(self) -> bool:
        try:
            return self.app.config_scope == "project"
        except Exception:
            return False

    def _get_config_path(self) -> Path:
        """Return the config path for the current scope."""
        if self._is_project_scope:
            project_path = get_project_config_path()
            if project_path:
                return project_path
            from ai_guardian.config_utils import _find_git_root
            root = _find_git_root() or Path.cwd()
            return root / ".ai-guardian" / "ai-guardian.json"
        config_dir = get_config_dir()
        return config_dir / "ai-guardian.json"

    def _load_global_immutable_fields(self) -> dict:
        """Load immutable field lists from the global config."""
        config_dir = get_config_dir()
        global_path = config_dir / "ai-guardian.json"
        immutables: dict = {}
        if global_path.exists():
            try:
                with open(global_path, 'r', encoding='utf-8') as f:
                    global_cfg = json.load(f)
                for section, data in global_cfg.items():
                    if not isinstance(data, dict):
                        continue
                    immutable = data.get("immutable")
                    if immutable is True:
                        immutables[section] = True
                    elif immutable == "tighten-only":
                        immutables[section] = "tighten-only"
                    elif isinstance(immutable, list):
                        immutables[section] = immutable
            except Exception:
                pass
        return immutables

    def _update_scope_notice(self) -> None:
        """Update the scope notice text."""
        try:
            notice = self.query_one("#scope-notice", Static)
            if self._is_project_scope:
                path = self._get_config_path()
                if path.exists():
                    notice.update(f"[dim]Editing project config: {path}[/dim]")
                else:
                    notice.update(f"[yellow]Project config will be created at: {path}[/yellow]")
            else:
                path = self._get_config_path()
                notice.update(f"[dim]Editing global config: {path}[/dim]")
        except Exception:
            pass

    def load_config(self) -> None:
        self._loading = True
        try:
            config_path = self._get_config_path()

            config = {}
            if config_path.exists():
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                except Exception as e:
                    self.app.notify(f"Error loading config: {e}", severity="error")
                    return

            if not self._is_project_scope:
                self._global_config = config

            immutables = self._load_global_immutable_fields() if self._is_project_scope else {}

            try:
                on_scan_error = config.get("on_scan_error", "allow")
                select_widget = self.query_one("#on_scan_error_select", Select)
                select_widget.value = on_scan_error
                select_widget.disabled = self._is_project_scope
            except Exception:
                pass

            for section, config_key, _ in FEATURES:
                section_data = config.get(section, {})
                raw = section_data.get("enabled", True) if isinstance(section_data, dict) else True
                is_global_only = section in GLOBAL_ONLY_SECTIONS
                section_immutable = immutables.get(section)
                section_fully_locked = section_immutable is True
                locked_fields = section_immutable if isinstance(section_immutable, list) else []
                enabled_locked = section_fully_locked or "enabled" in locked_fields

                try:
                    toggle = self.query_one(f"#{config_key}_toggle", TimeBasedToggle)
                    toggle.load_value(raw)
                    toggle.disabled = (self._is_project_scope and is_global_only) or enabled_locked
                except Exception:
                    pass

                if section in FEATURE_ACTIONS:
                    action_info = FEATURE_ACTIONS[section]
                    action_value = section_data.get("action", action_info["default"]) if isinstance(section_data, dict) else action_info["default"]
                    action_locked = section_fully_locked or "action" in locked_fields
                    try:
                        action_select = self.query_one(f"#{config_key}_action", Select)
                        action_select.value = action_value
                        action_select.disabled = (self._is_project_scope and is_global_only) or action_locked
                    except Exception:
                        pass

            self._update_scope_notice()
            self._update_provenance_badges()
        finally:
            self._loading = False

    def _update_provenance_badges(self) -> None:
        """Show provenance badges on each feature toggle when project scope is active."""
        if not self._is_project_scope:
            return
        try:
            from ai_guardian.config_writer import compute_provenance
            prov = compute_provenance()
        except Exception:
            return

        for section, config_key, title in FEATURES:
            section_prov = prov.get(section, {})
            if isinstance(section_prov, str):
                badge = section_prov
            elif isinstance(section_prov, dict):
                enabled_prov = section_prov.get("enabled", "global")
                badge = enabled_prov
            else:
                badge = "global"

            badge_text = "[dim cyan] ⓟ[/dim cyan]" if badge == "project" else "[dim] ⓖ[/dim]"
            try:
                toggle = self.query_one(f"#{config_key}_toggle", TimeBasedToggle)
                title_static = toggle.query(".tbt-title")[0]
                title_static.update(f"[bold]{title}[/bold] {badge_text}")
            except Exception:
                pass

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

        if select_id == "on_scan_error_select":
            self._save_on_scan_error(event.value)
            return

        for section, config_key, title in FEATURES:
            if select_id == f"{config_key}_action" and section in FEATURE_ACTIONS:
                self._save_action(section, event.value, title)
                return

    def _save_on_scan_error(self, value: str) -> None:
        """Save the global on_scan_error setting."""
        config_path = self._get_config_path()

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config_path.parent.mkdir(parents=True, exist_ok=True)
                config = {}

            config["on_scan_error"] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            label = "fail-open" if value == "allow" else "fail-closed"
            self.app.notify(f"✓ On Scan Error: {value} ({label})", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving: {e}", severity="error")

    def _save_action(self, section: str, value: str, display: str) -> None:
        """Save an action value for a feature section."""
        config_path = self._get_config_path()

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config_path.parent.mkdir(parents=True, exist_ok=True)
                config = {}

            if section not in config or not isinstance(config[section], dict):
                config[section] = {}

            config[section]["action"] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            scope = "project" if self._is_project_scope else "global"
            self.app.notify(f"✓ {display}: action = {value} [{scope}]", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving: {e}", severity="error")

    def _save(self, section: str, value: Any, display: str) -> None:
        config_path = self._get_config_path()

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config_path.parent.mkdir(parents=True, exist_ok=True)
                config = {}

            if section not in config or not isinstance(config[section], dict):
                config[section] = {}

            config[section]["enabled"] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            scope = "project" if self._is_project_scope else "global"
            if isinstance(value, bool):
                status = "enabled" if value else "disabled"
                self.app.notify(f"✓ {display}: {status} [{scope}]", severity="success")
            elif isinstance(value, dict) and value.get("disabled_until"):
                from ai_guardian.tui.widgets import format_local_time
                self.app.notify(
                    f"✓ {display}: temp disabled until {format_local_time(value['disabled_until'])} [{scope}]",
                    severity="success",
                )

        except Exception as e:
            self.app.notify(f"Error saving: {e}", severity="error")

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("Global settings refreshed", severity="information")
