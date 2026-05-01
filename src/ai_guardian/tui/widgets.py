#!/usr/bin/env python3
"""
Reusable TUI Widgets

Common widgets used across multiple TUI tabs.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Input, Label, Select, Checkbox
from textual.validation import Validator, ValidationResult


DURATION_PATTERN = re.compile(
    r'^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?$'
)


def parse_duration(text: str) -> Optional[timedelta]:
    """Parse a duration string like '30m', '2h', '1d', '1h30m', '2d12h'.

    Returns timedelta or None if invalid.
    """
    text = text.strip().lower()
    if not text:
        return None
    m = DURATION_PATTERN.match(text)
    if not m:
        return None
    days = int(m.group(1) or 0)
    hours = int(m.group(2) or 0)
    minutes = int(m.group(3) or 0)
    if days == 0 and hours == 0 and minutes == 0:
        return None
    return timedelta(days=days, hours=hours, minutes=minutes)


def duration_from_timestamp(timestamp: str) -> str:
    """Convert an ISO 8601 timestamp to a human-readable remaining duration."""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        if dt <= now:
            return "expired"
        delta = dt - now
        total_minutes = int(delta.total_seconds() / 60)
        days = total_minutes // (24 * 60)
        hours = (total_minutes % (24 * 60)) // 60
        minutes = total_minutes % 60
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes or not parts:
            parts.append(f"{minutes}m")
        return "".join(parts)
    except Exception:
        return ""


class ISO8601Validator(Validator):
    """Validator for ISO 8601 datetime format."""

    def validate(self, value: str) -> ValidationResult:
        if not value or not value.strip():
            return self.success()

        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
            if not value.strip().endswith('Z'):
                return self.failure("Timestamp must be in UTC (end with 'Z')")
            return self.success()
        except Exception:
            return self.failure("Invalid ISO 8601 format. Expected: YYYY-MM-DDTHH:MM:SSZ")


class DurationValidator(Validator):
    """Validator for duration strings like 30m, 2h, 1d, 1h30m."""

    def validate(self, value: str) -> ValidationResult:
        if not value or not value.strip():
            return self.success()
        if parse_duration(value) is not None:
            return self.success()
        return self.failure("Invalid duration. Use: 30m, 2h, 1d, 1h30m, 2d12h")


class TimeBasedToggle(Container):
    """
    A widget for time-based feature toggles.

    Supports three modes:
    - Permanently enabled (enabled=true)
    - Permanently disabled (enabled=false)
    - Temporarily disabled (enabled=false with disabled_until + reason)

    Duration input (e.g., '2h', '1d') is converted to an ISO 8601 timestamp.
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
        margin: 0 1 0 0;
        width: 10;
    }

    TimeBasedToggle .tbt-mode-row Select {
        width: 1fr;
        margin: 0 1 0 0;
    }

    TimeBasedToggle .tbt-mode-row Input {
        width: 1fr;
        margin: 0 1 0 0;
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
        super().__init__(**kwargs)
        self.title_text = title
        self.config_key = config_key
        self._help_text = help_text

        if isinstance(current_value, dict):
            self.is_enabled = current_value.get("value", True)
            self.disabled_until = current_value.get("disabled_until", "")
            self.reason = current_value.get("reason", "")
        else:
            self.is_enabled = current_value
            self.disabled_until = ""
            self.reason = ""

        if self.is_enabled:
            self.current_mode = "enabled"
        elif self.disabled_until:
            self.current_mode = "temp_disabled"
        else:
            self.current_mode = "disabled"

    def compose(self) -> ComposeResult:
        yield Static(f"[bold]{self.title_text}[/bold]", classes="tbt-title")

        if self._help_text:
            yield Static(f"[dim]{self._help_text}[/dim]", classes="tbt-title")

        yield Static("", id=f"{self.config_key}_status", classes="tbt-status")

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

        # Duration field — shown only in temp_disabled mode
        duration_display = duration_from_timestamp(self.disabled_until) if self.disabled_until else ""
        with Horizontal(id=f"{self.config_key}_until_row", classes="tbt-mode-row"):
            yield Label("Duration:")
            yield Input(
                value=duration_display,
                placeholder="e.g. 30m, 2h, 1d, 1h30m",
                validators=[DurationValidator()],
                id=f"{self.config_key}_disabled_until",
            )

        # Reason field — shown only in temp_disabled mode
        with Horizontal(id=f"{self.config_key}_reason_row", classes="tbt-mode-row"):
            yield Label("Reason:")
            yield Input(
                value=self.reason,
                placeholder="e.g., Emergency debugging",
                id=f"{self.config_key}_reason",
            )

    def on_mount(self) -> None:
        self.update_status_display()
        self.update_temp_fields_visibility()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == f"{self.config_key}_mode_select":
            self.current_mode = event.value
            self.update_temp_fields_visibility()
            self.update_status_display()

    def update_temp_fields_visibility(self) -> None:
        show = self.current_mode == "temp_disabled"
        for suffix in ("_until_row", "_reason_row"):
            try:
                row = self.query_one(f"#{self.config_key}{suffix}", Horizontal)
                row.display = show
            except Exception:
                pass

    def update_status_display(self) -> None:
        try:
            status_widget = self.query_one(f"#{self.config_key}_status", Static)

            if self.current_mode == "enabled":
                status_text = "[status-ok]✓ ENABLED[/status-ok] - Feature is permanently enabled"
            elif self.current_mode == "disabled":
                status_text = "[status-error]✗ DISABLED[/status-error] - Feature is permanently disabled"
            else:
                if self.disabled_until:
                    try:
                        dt = datetime.fromisoformat(self.disabled_until.replace('Z', '+00:00'))
                        now = datetime.now(timezone.utc)

                        if dt > now:
                            remaining = duration_from_timestamp(self.disabled_until)
                            end_str = dt.strftime("%Y-%m-%d %H:%M UTC")
                            status_text = f"[status-warn]⏸ TEMPORARILY DISABLED[/status-warn] for {remaining} (until {end_str})"
                            if self.reason:
                                status_text += f"\nReason: {self.reason}"
                        else:
                            status_text = "[status-ok]✓ AUTO RE-ENABLED[/status-ok] - Temporary disable period expired"
                    except Exception:
                        status_text = "[status-warn]⏸ TEMPORARILY DISABLED[/status-warn] - Invalid timestamp"
                else:
                    status_text = "[status-warn]⏸ TEMPORARILY DISABLED[/status-warn] - Enter a duration (e.g. 2h, 1d)"

            status_widget.update(status_text)
        except Exception:
            pass

    def get_value(self) -> Union[bool, Dict[str, Any]]:
        try:
            mode_select = self.query_one(f"#{self.config_key}_mode_select", Select)
            mode = mode_select.value

            if mode == "enabled":
                return True
            elif mode == "disabled":
                return False
            else:
                reason_input = self.query_one(f"#{self.config_key}_reason", Input)
                reason = reason_input.value.strip()

                result = {"value": False}
                if self.disabled_until:
                    result["disabled_until"] = self.disabled_until
                if reason:
                    result["reason"] = reason

                return result
        except Exception:
            return self.is_enabled

    def load_value(self, value: Union[bool, Dict[str, Any]]) -> None:
        """Load a config value and update all widgets.

        Call this from parent panels instead of manually setting fields.
        """
        if isinstance(value, dict):
            self.is_enabled = value.get("value", True)
            self.disabled_until = value.get("disabled_until", "")
            self.reason = value.get("reason", "")
        else:
            self.is_enabled = value
            self.disabled_until = ""
            self.reason = ""

        if self.is_enabled:
            self.current_mode = "enabled"
        elif self.disabled_until:
            self.current_mode = "temp_disabled"
        else:
            self.current_mode = "disabled"

        try:
            self.query_one(f"#{self.config_key}_mode_select", Select).value = self.current_mode

            dur_input = self.query_one(f"#{self.config_key}_disabled_until", Input)
            dur = duration_from_timestamp(self.disabled_until) if self.disabled_until else ""
            dur_input.value = dur if dur != "expired" else ""

            self.query_one(f"#{self.config_key}_reason", Input).value = self.reason

            self.update_temp_fields_visibility()
            self.update_status_display()
        except Exception:
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter on duration or reason fields."""
        if event.input.id == f"{self.config_key}_disabled_until":
            duration_text = event.input.value.strip()
            if not duration_text:
                return

            delta = parse_duration(duration_text)
            if delta is None:
                self.app.notify("Invalid duration. Use: 30m, 2h, 1d, 1h30m", severity="error")
                return

            end_time = datetime.now(timezone.utc) + delta
            self.disabled_until = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            self.update_status_display()
