#!/usr/bin/env python3
"""
Global Settings Tab Content

Manage global security feature toggles:
- permissions_enabled: Global tool permissions enforcement
- secret_scanning: Secret scanning
"""

import json
from typing import Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Static

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.schema_defaults import SchemaDefaultsMixin
from ai_guardian.tui.widgets import TimeBasedToggle


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

    .section {
        margin: 1 0;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the global settings tab content."""
        yield Static("[bold]Global Security Settings[/bold]", id="global-settings-header")

        with VerticalScroll():
            # Permissions enabled toggle
            yield TimeBasedToggle(
                title="🔐 Tool Permissions Enforcement",
                config_key="permissions_enabled",
                current_value=True,
                help_text="Controls whether AI Guardian enforces tool permission rules. When disabled, all tools are allowed. (default: enabled)",
                id="permissions_enabled_toggle",
                classes="section",
            )

            # Secret scanning toggle
            yield TimeBasedToggle(
                title="🔍 Secret Scanning",
                config_key="secret_scanning",
                current_value=True,
                help_text="Controls whether AI Guardian scans for secrets using the configured scanner engine. When disabled, no secret detection is performed. (default: enabled)",
                id="secret_scanning_toggle",
                classes="section",
            )

            # Information section
            with Container(classes="section"):
                yield Static(
                    "[bold]ℹ️  About Time-Based Toggles[/bold]\n\n"
                    "[dim]These settings support three modes:[/dim]\n"
                    "  • [status-ok]Permanently Enabled[/status-ok] - Feature always active\n"
                    "  • [status-error]Permanently Disabled[/status-error] - Feature always inactive\n"
                    "  • [status-warn]Temporarily Disabled[/status-warn] - Disabled until specified time, then auto re-enables\n\n"
                    "[dim]Temporary disable use cases:[/dim]\n"
                    "  • Emergency debugging sessions\n"
                    "  • Incident response requiring unrestricted access\n"
                    "  • Scheduled maintenance windows\n\n"
                    "[dim]Configuration is saved to ~/.config/ai-guardian/ai-guardian.json[/dim]"
                )

    def on_mount(self) -> None:
        """Load configuration when mounted."""
        self.load_config()

    def refresh_content(self) -> None:
        """Refresh configuration (called by parent app)."""
        self.load_config()

    def load_config(self) -> None:
        """Load and display global settings configuration."""
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
                return

        # Load permissions.enabled setting (NEW unified structure in v1.4.0)
        permissions = config.get("permissions", {})
        if isinstance(permissions, dict):
            permissions_value = permissions.get("enabled", True)
        else:
            # Default if permissions section doesn't exist
            permissions_value = True

        # Load secret_scanning setting
        secret_scanning = config.get("secret_scanning", {})
        if isinstance(secret_scanning, dict):
            scanning_value = secret_scanning.get("enabled", True)
        else:
            # Legacy format - just a boolean at top level
            scanning_value = config.get("secret_scanning", True)

        # Update toggles
        try:
            permissions_toggle = self.query_one("#permissions_enabled_toggle", TimeBasedToggle)
            # Reconstruct the toggle with new value
            permissions_toggle.load_value(permissions_value)

            scanning_toggle = self.query_one("#secret_scanning_toggle", TimeBasedToggle)
            scanning_toggle.load_value(scanning_value)
        except Exception:
            pass  # Widgets may not be mounted yet

    def mount_toggle(self, toggle: TimeBasedToggle, config_key: str, value: Union[bool, Dict[str, Any]]) -> None:
        """Update a toggle widget with new configuration value."""
        # Parse value
        if isinstance(value, dict):
            toggle.is_enabled = value.get("value", True)
            toggle.disabled_until = value.get("disabled_until", "")
            toggle.reason = value.get("reason", "")
        else:
            toggle.is_enabled = value
            toggle.disabled_until = ""
            toggle.reason = ""

        # Determine mode
        if toggle.is_enabled:
            toggle.current_mode = "enabled"
        elif toggle.disabled_until:
            toggle.current_mode = "temp_disabled"
        else:
            toggle.current_mode = "disabled"

        # Update widgets
        try:
            mode_select = toggle.query_one(f"#{config_key}_mode_select")
            mode_select.value = toggle.current_mode

            disabled_until_input = toggle.query_one(f"#{config_key}_disabled_until")
            from ai_guardian.tui.widgets import duration_from_timestamp
            dur = duration_from_timestamp(toggle.disabled_until) if toggle.disabled_until else ""
            disabled_until_input.value = dur if dur != "expired" else ""

            reason_input = toggle.query_one(f"#{config_key}_reason")
            reason_input.value = toggle.reason

            toggle.update_temp_fields_visibility()
            toggle.update_status_display()
        except Exception:
            pass

    def on_input_submitted(self, event) -> None:
        """Handle Enter key in input fields - save the value."""
        input_id = event.input.id

        if input_id and ("permissions_enabled" in input_id or "secret_scanning" in input_id):
            # Determine which config key this belongs to
            if "permissions_enabled" in input_id:
                config_key = "permissions_enabled"
                toggle = self.query_one("#permissions_enabled_toggle", TimeBasedToggle)
            else:
                config_key = "secret_scanning"
                toggle = self.query_one("#secret_scanning_toggle", TimeBasedToggle)

            # Get the value from the toggle
            value = toggle.get_value()

            # Save to config
            self.save_config(config_key, value)

    def on_select_changed(self, event) -> None:
        """Handle mode selector change - save for enabled/disabled, defer for temp_disabled."""
        select_id = event.select.id

        if select_id and ("permissions_enabled" in select_id or "secret_scanning" in select_id):
            if "permissions_enabled" in select_id:
                config_key = "permissions_enabled"
                toggle = self.query_one("#permissions_enabled_toggle", TimeBasedToggle)
            else:
                config_key = "secret_scanning"
                toggle = self.query_one("#secret_scanning_toggle", TimeBasedToggle)

            if toggle.current_mode == "temp_disabled":
                return

            value = toggle.get_value()
            self.save_config(config_key, value)

    def save_config(self, config_key: str, value: Union[bool, Dict[str, Any]]) -> None:
        """Save a global setting to config."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # NEW unified structure in v1.4.0: save to nested structure
            if config_key == "permissions_enabled":
                # Save to permissions.enabled instead
                if "permissions" not in config or not isinstance(config["permissions"], dict):
                    config["permissions"] = {"enabled": True, "rules": []}

                # Update the enabled field
                if isinstance(value, bool):
                    config["permissions"]["enabled"] = value
                else:
                    config["permissions"]["enabled"] = value
            elif config_key == "secret_scanning":
                # Secret scanning keeps its own top-level structure
                if isinstance(value, bool):
                    if "secret_scanning" not in config or not isinstance(config["secret_scanning"], dict):
                        config["secret_scanning"] = {}
                    config["secret_scanning"]["enabled"] = value
                else:
                    if "secret_scanning" not in config or not isinstance(config["secret_scanning"], dict):
                        config["secret_scanning"] = {}
                    config["secret_scanning"]["enabled"] = value
            else:
                # Other settings (if any in the future)
                if isinstance(value, bool):
                    config[config_key] = {"enabled": value}
                else:
                    config[config_key] = {"enabled": value}

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Show status message
            if isinstance(value, bool):
                status = "enabled" if value else "disabled"
                self.app.notify(f"✓ {config_key}: {status}", severity="success")
            else:
                if value.get("disabled_until"):
                    self.app.notify(
                        f"✓ {config_key}: temporarily disabled until {value['disabled_until']}",
                        severity="success"
                    )
                else:
                    self.app.notify(f"✓ {config_key}: disabled", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving {config_key}: {e}", severity="error")

    def action_refresh(self) -> None:
        """Refresh configuration (triggered by 'r' key)."""
        self.load_config()
        self.app.notify("Global settings refreshed", severity="information")
