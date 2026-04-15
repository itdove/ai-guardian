#!/usr/bin/env python3
"""
Reusable TUI Widgets

Common widgets used across multiple TUI tabs.
"""

from datetime import datetime
from typing import Optional, Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Input, Label, Select, Checkbox
from textual.validation import Validator, ValidationResult


class ISO8601Validator(Validator):
    """Validator for ISO 8601 datetime format."""

    def validate(self, value: str) -> ValidationResult:
        """Validate that value is a valid ISO 8601 datetime in UTC."""
        if not value or not value.strip():
            return self.success()  # Allow empty for optional field

        try:
            # Parse ISO 8601 format
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))

            # Check if it ends with Z (UTC)
            if not value.strip().endswith('Z'):
                return self.failure("Timestamp must be in UTC (end with 'Z')")

            return self.success()
        except Exception:
            return self.failure("Invalid ISO 8601 format. Expected: YYYY-MM-DDTHH:MM:SSZ")


class TimeBasedToggle(Container):
    """
    A widget for time-based feature toggles.

    Supports three modes:
    - Permanently enabled (enabled=true)
    - Permanently disabled (enabled=false)
    - Temporarily disabled (enabled=false with disabled_until + reason)

    This matches the JSON schema time_based_feature format:
    {
      "value": false,
      "disabled_until": "2026-04-13T18:00:00Z",
      "reason": "Emergency debugging - production incident"
    }
    """

    CSS = """
    TimeBasedToggle {
        height: auto;
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    TimeBasedToggle .tbt-title {
        margin: 0 0 1 0;
        font-weight: bold;
    }

    TimeBasedToggle .tbt-status {
        margin: 0 0 1 0;
        padding: 1;
        background: $surface;
    }

    TimeBasedToggle .tbt-mode-row {
        margin: 0.5 0;
        height: auto;
        align: left middle;
    }

    TimeBasedToggle .tbt-mode-row Label {
        margin: 0 2 0 0;
        width: 20;
        content-align: right middle;
    }

    TimeBasedToggle .tbt-mode-row Select {
        width: 30;
        margin: 0 1 0 0;
    }

    TimeBasedToggle .tbt-field-row {
        margin: 0.5 0;
        height: auto;
        align: left middle;
    }

    TimeBasedToggle .tbt-field-row Label {
        margin: 0 2 0 0;
        width: 20;
        content-align: right middle;
    }

    TimeBasedToggle .tbt-field-row Input {
        width: 40;
        margin: 0 1 0 0;
    }

    TimeBasedToggle .tbt-field-row Static {
        margin: 0 0 0 0;
    }
    """

    def __init__(
        self,
        title: str,
        config_key: str,
        current_value: Union[bool, Dict[str, Any]] = True,
        help_text: str = "",
        **kwargs,
    ):
        """
        Initialize time-based toggle.

        Args:
            title: Display title for this toggle
            config_key: Configuration key for this toggle (e.g., "permissions_enabled")
            current_value: Current value - either bool or dict with time-based format
            help_text: Help text to display
        """
        super().__init__(**kwargs)
        self.title_text = title
        self.config_key = config_key
        self._help_text = help_text

        # Parse current value
        if isinstance(current_value, dict):
            self.is_enabled = current_value.get("value", True)
            self.disabled_until = current_value.get("disabled_until", "")
            self.reason = current_value.get("reason", "")
        else:
            self.is_enabled = current_value
            self.disabled_until = ""
            self.reason = ""

        # Determine current mode
        if self.is_enabled:
            self.current_mode = "enabled"
        elif self.disabled_until:
            self.current_mode = "temp_disabled"
        else:
            self.current_mode = "disabled"

    def compose(self) -> ComposeResult:
        """Compose the time-based toggle widgets."""
        yield Static(f"[bold]{self.title_text}[/bold]", classes="tbt-title")

        if self._help_text:
            yield Static(f"[dim]{self._help_text}[/dim]", classes="tbt-title")

        # Status display
        yield Static("", id=f"{self.config_key}_status", classes="tbt-status")

        # Mode selector
        with Horizontal(classes="tbt-mode-row"):
            yield Label("Mode:")
            yield Select(
                [
                    ("Permanently Enabled", "enabled"),
                    ("Permanently Disabled", "disabled"),
                    ("Temporarily Disabled", "temp_disabled"),
                ],
                value=self.current_mode,
                id=f"{self.config_key}_mode_select",
            )

        # Time-based fields container (shown only in temp_disabled mode)
        with Vertical(id=f"{self.config_key}_temp_fields"):
            with Horizontal(classes="tbt-field-row"):
                yield Label("Disabled Until:")
                yield Input(
                    value=self.disabled_until,
                    placeholder="2026-04-13T18:00:00Z",
                    validators=[ISO8601Validator()],
                    id=f"{self.config_key}_disabled_until",
                )
                yield Static("[dim]ISO 8601 UTC (Press Enter to save)[/dim]")

            with Horizontal(classes="tbt-field-row"):
                yield Label("Reason:")
                yield Input(
                    value=self.reason,
                    placeholder="e.g., Emergency debugging - production incident",
                    id=f"{self.config_key}_reason",
                )
                yield Static("[dim](Press Enter to save)[/dim]")

    def on_mount(self) -> None:
        """Update status and visibility when mounted."""
        self.update_status_display()
        self.update_temp_fields_visibility()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle mode selector change."""
        if event.select.id == f"{self.config_key}_mode_select":
            self.current_mode = event.value
            self.update_temp_fields_visibility()
            self.update_status_display()

    def update_temp_fields_visibility(self) -> None:
        """Show/hide time-based fields based on mode."""
        try:
            temp_fields = self.query_one(f"#{self.config_key}_temp_fields", Vertical)
            if self.current_mode == "temp_disabled":
                temp_fields.display = True
            else:
                temp_fields.display = False
        except Exception:
            pass  # Widgets may not be mounted yet

    def update_status_display(self) -> None:
        """Update the status display text."""
        try:
            status_widget = self.query_one(f"#{self.config_key}_status", Static)

            if self.current_mode == "enabled":
                status_text = "[status-ok]✓ ENABLED[/status-ok] - Feature is permanently enabled"
            elif self.current_mode == "disabled":
                status_text = "[status-error]✗ DISABLED[/status-error] - Feature is permanently disabled"
            else:  # temp_disabled
                disabled_until_input = self.query_one(f"#{self.config_key}_disabled_until", Input)
                reason_input = self.query_one(f"#{self.config_key}_reason", Input)

                disabled_until = disabled_until_input.value.strip()
                reason = reason_input.value.strip()

                if disabled_until:
                    try:
                        dt = datetime.fromisoformat(disabled_until.replace('Z', '+00:00'))
                        now = datetime.now(dt.tzinfo)

                        if dt > now:
                            # Still disabled
                            status_text = f"[status-warn]⏸ TEMPORARILY DISABLED[/status-warn] until {disabled_until}"
                            if reason:
                                status_text += f"\nReason: {reason}"
                        else:
                            # Expired - auto re-enabled
                            status_text = "[status-ok]✓ AUTO RE-ENABLED[/status-ok] - Temporary disable period expired"
                    except Exception:
                        status_text = "[status-warn]⏸ TEMPORARILY DISABLED[/status-warn] - Invalid timestamp"
                else:
                    status_text = "[status-warn]⏸ TEMPORARILY DISABLED[/status-warn] - Set disabled_until timestamp"

            status_widget.update(status_text)
        except Exception:
            pass  # Widgets may not be mounted yet

    def get_value(self) -> Union[bool, Dict[str, Any]]:
        """
        Get the current configuration value.

        Returns:
            bool for simple enabled/disabled, or dict for time-based format
        """
        try:
            mode_select = self.query_one(f"#{self.config_key}_mode_select", Select)
            mode = mode_select.value

            if mode == "enabled":
                return True
            elif mode == "disabled":
                return False
            else:  # temp_disabled
                disabled_until_input = self.query_one(f"#{self.config_key}_disabled_until", Input)
                reason_input = self.query_one(f"#{self.config_key}_reason", Input)

                disabled_until = disabled_until_input.value.strip()
                reason = reason_input.value.strip()

                result = {"value": False}
                if disabled_until:
                    result["disabled_until"] = disabled_until
                if reason:
                    result["reason"] = reason

                return result
        except Exception:
            # Fallback to simple boolean
            return self.is_enabled
