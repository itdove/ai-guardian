#!/usr/bin/env python3
"""
Reusable TUI Widgets

Common widgets used across multiple TUI tabs.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import HorizontalGroup, VerticalGroup
from textual.widgets import Static, Input, Button
from textual.validation import Validator, ValidationResult


DURATION_PATTERN = re.compile(
    r'^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?$'
)


def format_local_time(utc_timestamp: str) -> str:
    """Convert a UTC ISO 8601 timestamp to a local time display string."""
    try:
        dt = datetime.fromisoformat(utc_timestamp.replace('Z', '+00:00'))
        return dt.astimezone().strftime("%Y-%m-%d %H:%M %Z")
    except Exception:
        return utc_timestamp


def sanitize_enabled_value(value: Union[bool, Dict[str, Any]]) -> Union[bool, Dict[str, Any]]:
    """Sanitize an enabled config value before saving.

    Valid formats:
      - True / False (permanent enable/disable)
      - {"value": bool, "disabled_until": "ISO8601Z", "reason": "..."} (temporary)

    A dict without disabled_until is invalid — collapses to a plain bool.
    """
    if isinstance(value, bool):
        return value
    if not isinstance(value, dict):
        return bool(value)
    if not value.get("disabled_until"):
        return value.get("value", False)
    return value


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


class TimeBasedToggle(VerticalGroup):
    """
    A widget for time-based feature toggles.

    Supports three modes via buttons:
    - Permanently enabled (enabled=true)
    - Permanently disabled (enabled=false)
    - Temporarily disabled (enabled=false with disabled_until)

    Duration input (e.g., '2h', '1d') is converted to an ISO 8601 timestamp.
    """

    CSS = """
    TimeBasedToggle {
        height: auto;
        margin: 1 0;
        padding: 0;
    }

    TimeBasedToggle .tbt-title {
        margin: 0;
        font-weight: bold;
    }

    TimeBasedToggle .tbt-status {
        margin: 0;
        padding: 0 1;
        background: $surface;
    }

    TimeBasedToggle .tbt-btn-row {
        height: auto;
    }

    TimeBasedToggle .tbt-btn {
        margin: 0 1 0 0;
        min-width: 16;
    }

    TimeBasedToggle .tbt-temp-row {
        height: auto;
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
            self._reason = current_value.get("reason", "")
        else:
            self.is_enabled = current_value
            self.disabled_until = ""
            self._reason = ""

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

        with HorizontalGroup(classes="tbt-btn-row"):
            yield Button("Enable", id=f"{self.config_key}_btn_enable", classes="tbt-btn")
            yield Button("Disable", id=f"{self.config_key}_btn_disable", classes="tbt-btn")
            yield Button("Temp Disable", id=f"{self.config_key}_btn_temp", classes="tbt-btn")

        dur = Input(
            placeholder="Duration: 30m, 2h, 1d",
            validators=[DurationValidator()],
            id=f"{self.config_key}_disabled_until",
        )
        dur.styles.width = "30"
        reason = Input(
            placeholder="Reason (optional)",
            id=f"{self.config_key}_reason",
        )
        reason.styles.width = "1fr"
        with HorizontalGroup(classes="tbt-temp-row"):
            yield dur
            yield reason

    def on_mount(self) -> None:
        self._update_ui()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == f"{self.config_key}_btn_enable":
            self.current_mode = "enabled"
            self.is_enabled = True
            self.disabled_until = ""
        elif bid == f"{self.config_key}_btn_disable":
            self.current_mode = "disabled"
            self.is_enabled = False
            self.disabled_until = ""
        elif bid == f"{self.config_key}_btn_temp":
            self.current_mode = "temp_disabled"
            self.is_enabled = False
        else:
            return
        self._update_ui()

    def _update_ui(self) -> None:
        """Update buttons, status, and temp fields visibility."""
        try:
            btn_en = self.query_one(f"#{self.config_key}_btn_enable", Button)
            btn_dis = self.query_one(f"#{self.config_key}_btn_disable", Button)
            btn_tmp = self.query_one(f"#{self.config_key}_btn_temp", Button)
            temp_row = self.query_one(".tbt-temp-row", HorizontalGroup)
            dur_input = self.query_one(f"#{self.config_key}_disabled_until", Input)
            reason_input = self.query_one(f"#{self.config_key}_reason", Input)
        except Exception:
            return

        btn_en.label = "● Enable" if self.current_mode == "enabled" else "Enable"
        btn_en.variant = "success" if self.current_mode == "enabled" else "primary"
        btn_dis.label = "● Disable" if self.current_mode == "disabled" else "Disable"
        btn_dis.variant = "error" if self.current_mode == "disabled" else "primary"
        btn_tmp.label = "● Temp Disable" if self.current_mode == "temp_disabled" else "Temp Disable"
        btn_tmp.variant = "warning" if self.current_mode == "temp_disabled" else "primary"

        is_temp = self.current_mode == "temp_disabled"
        temp_row.display = is_temp
        if is_temp:
            dur = duration_from_timestamp(self.disabled_until) if self.disabled_until else ""
            dur_input.value = dur if dur and dur != "expired" else ""
            reason_input.value = getattr(self, '_reason', "")

        self.update_status_display()

    def update_temp_fields_visibility(self) -> None:
        try:
            temp_row = self.query_one(".tbt-temp-row", HorizontalGroup)
            temp_row.display = self.current_mode == "temp_disabled"
        except Exception:
            pass

    def update_status_display(self) -> None:
        try:
            status_widget = self.query_one(f"#{self.config_key}_status", Static)

            if self.current_mode == "enabled":
                status_text = "[green]✓ ENABLED[/green]"
            elif self.current_mode == "disabled":
                status_text = "[red]✗ DISABLED[/red]"
            else:
                if self.disabled_until:
                    try:
                        dt = datetime.fromisoformat(self.disabled_until.replace('Z', '+00:00'))
                        now = datetime.now(timezone.utc)

                        if dt > now:
                            remaining = duration_from_timestamp(self.disabled_until)
                            end_str = dt.astimezone().strftime("%Y-%m-%d %H:%M %Z")
                            status_text = f"[yellow]⏸ TEMP DISABLED[/yellow] for {remaining} (until {end_str})"
                        else:
                            status_text = "[green]✓ AUTO RE-ENABLED[/green] (expired)"
                    except Exception:
                        status_text = "[yellow]⏸ TEMP DISABLED[/yellow]"
                else:
                    status_text = "[yellow]⏸ TEMP DISABLED[/yellow] — enter duration and press Enter"

            status_widget.update(status_text)
        except Exception:
            pass

    def get_value(self) -> Union[bool, Dict[str, Any]]:
        if self.current_mode == "enabled":
            return True
        elif self.current_mode == "disabled":
            return False
        else:
            result: Dict[str, Any] = {"value": False}
            if self.disabled_until:
                result["disabled_until"] = self.disabled_until
            try:
                reason = self.query_one(f"#{self.config_key}_reason", Input).value.strip()
                if reason:
                    result["reason"] = reason
            except Exception:
                pass
            return result

    def load_value(self, value: Union[bool, Dict[str, Any]]) -> None:
        """Load a config value and update all widgets."""
        if isinstance(value, dict):
            self.is_enabled = value.get("value", True)
            self.disabled_until = value.get("disabled_until", "")
            self._reason = value.get("reason", "")
        else:
            self.is_enabled = value
            self.disabled_until = ""
            self._reason = ""

        if self.is_enabled:
            self.current_mode = "enabled"
        elif self.disabled_until:
            self.current_mode = "temp_disabled"
        else:
            self.current_mode = "disabled"

        self._update_ui()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter on duration field."""
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
