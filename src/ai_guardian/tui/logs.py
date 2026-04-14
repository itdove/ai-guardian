#!/usr/bin/env python3
"""
Logs Tab Content

Display application logs with filtering, refresh, clear, and export functionality.
"""

import re
from pathlib import Path
from typing import List, Tuple, Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll, Vertical
from textual.widgets import Button, Static, Select, Label
from textual.screen import ModalScreen

from ai_guardian.config_utils import get_config_dir


class ConfirmClearModal(ModalScreen):
    """Modal for confirming log file clear."""

    CSS = """
    ConfirmClearModal {
        align: center middle;
    }

    #modal-container {
        width: 60;
        height: auto;
        background: $panel;
        border: thick $error;
        padding: 1 2;
    }

    #modal-header {
        margin: 0 0 1 0;
        text-align: center;
        color: $error;
    }

    #modal-content {
        margin: 1 0;
        text-align: center;
    }

    #modal-actions {
        margin: 1 0 0 0;
        height: auto;
        align: center middle;
    }

    #modal-actions Button {
        margin: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the modal."""
        with Container(id="modal-container"):
            yield Static("[bold]⚠ Clear Log File?[/bold]", id="modal-header")
            yield Static(
                "This will permanently delete all log entries.\n"
                "This action cannot be undone.",
                id="modal-content"
            )
            with Horizontal(id="modal-actions"):
                yield Button("Clear Log", id="confirm-clear", variant="error")
                yield Button("Cancel (ESC)", id="cancel-clear", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "confirm-clear":
            self.dismiss(True)
        else:
            self.dismiss(False)


class LogEntry(Static):
    """Display a single log entry with color coding."""

    def __init__(self, timestamp: str, module: str, level: str, message: str, *args, **kwargs):
        """Initialize log entry."""
        self.timestamp = timestamp
        self.module = module
        self.level = level
        self.message = message

        # Color code based on level
        level_colors = {
            "DEBUG": "dim",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red bold"
        }
        level_color = level_colors.get(level, "")

        # Format the log line
        log_line = f"[dim]{timestamp}[/dim] [{level_color}]{level:8}[/{level_color}] [cyan]{module}[/cyan] {message}"

        super().__init__(log_line, *args, **kwargs)


class LogLevelFilter(Container):
    """A labeled select dropdown for log level filtering."""

    DEFAULT_CSS = """
    LogLevelFilter {
        height: auto;
        margin: 1 0;
    }

    LogLevelFilter > Label {
        width: 100%;
        padding: 0 0;
    }

    LogLevelFilter > Select {
        width: 100%;
        margin: 0 0 0 0;
    }

    LogLevelFilter > .help-text {
        color: $text-muted;
        width: 100%;
        padding: 0 0;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        """Compose the select widget."""
        yield Label("Filter by minimum log level:")
        yield Select(
            options=[
                ("All (DEBUG and above)", "DEBUG"),
                ("INFO and above", "INFO"),
                ("WARNING and above", "WARNING"),
                ("ERROR and above", "ERROR"),
                ("CRITICAL only", "CRITICAL"),
            ],
            value="DEBUG",
            allow_blank=False,
            id="log-level-filter",
        )
        yield Label(
            "[dim]Shows selected level and all higher severity levels[/dim]",
            classes="help-text"
        )

    def get_value(self) -> str:
        """Get current filter value."""
        select = self.query_one("#log-level-filter", Select)
        return select.value if select.value != Select.BLANK else "DEBUG"


class LogsContent(Container):
    """Content widget for Logs tab."""

    CSS = """
    LogsContent {
        height: 100%;
    }

    #logs-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    #logs-controls {
        margin: 1 0;
        height: auto;
    }

    #logs-controls Button {
        margin: 0 1 0 0;
    }


    #logs-display {
        height: 100%;
        border: solid $primary;
        background: $surface;
        padding: 1;
    }

    LogEntry {
        height: auto;
    }

    #no-logs {
        margin: 2;
        padding: 2;
        text-align: center;
        color: $text-muted;
    }

    #log-error {
        margin: 2;
        padding: 2;
        text-align: center;
        color: $error;
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log_file = get_config_dir() / "ai-guardian.log"
        self.current_filter = "DEBUG"  # Start with DEBUG (show all)

    def compose(self) -> ComposeResult:
        """Compose the logs tab content."""
        yield Static("[bold]📝 Application Logs[/bold]", id="logs-header")
        yield Static(
            "[dim]Debug and informational messages from ai-guardian. "
            "Log file: ~/.config/ai-guardian/ai-guardian.log[/dim]"
        )

        # Action buttons
        with Horizontal(id="logs-controls"):
            yield Button("🔄 Refresh", id="refresh-logs", variant="primary")
            yield Button("🗑️ Clear Log", id="clear-logs", variant="error")
            yield Button("💾 Export", id="export-logs")

        # Filter control
        yield LogLevelFilter()

        # Log display area
        yield VerticalScroll(id="logs-display")

    def on_mount(self) -> None:
        """Load logs when mounted."""
        self.load_logs()

    def refresh_content(self) -> None:
        """Refresh logs (called by parent app)."""
        self.load_logs()

    def action_refresh(self) -> None:
        """Refresh action for keybinding."""
        self.load_logs()

    def parse_log_line(self, line: str) -> Optional[Tuple[str, str, str, str]]:
        """
        Parse a log line into components.

        Format: 2026-04-13 12:34:56 - module.name - LEVEL - message

        Returns:
            Tuple of (timestamp, module, level, message) or None if parsing fails
        """
        # Match the log format
        pattern = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([^ ]+) - ([A-Z]+) - (.+)$'
        match = re.match(pattern, line)

        if match:
            return match.groups()
        return None

    def _should_show_log(self, level: str, min_level: str) -> bool:
        """
        Determine if a log entry should be shown based on minimum level.

        Args:
            level: The log level of the entry
            min_level: The minimum level to show

        Returns:
            True if the log entry should be shown
        """
        # Log level hierarchy (lower number = more severe)
        level_priority = {
            "DEBUG": 10,
            "INFO": 20,
            "WARNING": 30,
            "ERROR": 40,
            "CRITICAL": 50
        }

        entry_priority = level_priority.get(level, 0)
        min_priority = level_priority.get(min_level, 0)

        # Show if entry level is >= minimum level (higher severity or equal)
        return entry_priority >= min_priority

    def load_logs(self, filter_level: Optional[str] = None) -> None:
        """
        Read log file and display entries.

        Args:
            filter_level: Minimum log level to show (DEBUG, INFO, WARNING, ERROR, CRITICAL)
                         Shows this level and all higher severity levels
        """
        if filter_level is None:
            filter_level = self.current_filter
        else:
            self.current_filter = filter_level

        logs_display = self.query_one("#logs-display", VerticalScroll)
        logs_display.remove_children()

        # Check if log file exists
        if not self.log_file.exists():
            logs_display.mount(
                Static(
                    "No log file found.\n\n"
                    "[dim]The log file will be created when ai-guardian runs.[/dim]",
                    id="no-logs"
                )
            )
            return

        try:
            # Read last 100 lines from the log file
            lines = self._read_last_n_lines(self.log_file, 100)

            if not lines:
                logs_display.mount(
                    Static(
                        "Log file is empty.\n\n"
                        "[dim]Log entries will appear here when ai-guardian runs.[/dim]",
                        id="no-logs"
                    )
                )
                return

            # Parse and filter log lines
            log_entries = []
            for line in lines:
                parsed = self.parse_log_line(line.strip())
                if parsed:
                    timestamp, module, level, message = parsed

                    # Apply filter - show logs at selected level and above
                    if not self._should_show_log(level, filter_level):
                        continue

                    log_entries.append((timestamp, module, level, message))

            if not log_entries:
                logs_display.mount(
                    Static(
                        f"No log entries at {filter_level} level or above.\n\n"
                        "[dim]Try selecting a lower severity level (e.g., DEBUG shows all).[/dim]",
                        id="no-logs"
                    )
                )
                return

            # Display log entries
            for timestamp, module, level, message in log_entries:
                logs_display.mount(LogEntry(timestamp, module, level, message))

            # Auto-scroll to bottom
            logs_display.scroll_end(animate=False)

        except Exception as e:
            logs_display.mount(
                Static(
                    f"Error reading log file: {str(e)}\n\n"
                    "[dim]The log file may be corrupted or in use.[/dim]",
                    id="log-error"
                )
            )

    def _read_last_n_lines(self, file_path: Path, n: int) -> List[str]:
        """
        Read the last N lines from a file efficiently.

        Args:
            file_path: Path to the file
            n: Number of lines to read

        Returns:
            List of lines (oldest first)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read all lines (for files under 5MB, this is fine)
                lines = f.readlines()
                return lines[-n:] if len(lines) > n else lines
        except Exception:
            return []

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "refresh-logs":
            self.load_logs()
            self.app.notify("Logs refreshed", severity="information")

        elif button_id == "clear-logs":
            # Show confirmation modal
            def handle_clear_result(confirmed: bool) -> None:
                if confirmed:
                    self.clear_log_file()

            self.app.push_screen(ConfirmClearModal(), handle_clear_result)

        elif button_id == "export-logs":
            self.export_logs()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle filter selection change."""
        if event.select.id == "log-level-filter":
            min_level = event.value
            self.load_logs(filter_level=min_level)


    def clear_log_file(self) -> None:
        """Clear the log file."""
        try:
            if self.log_file.exists():
                # Clear the file by truncating it
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    pass

                self.load_logs()
                self.app.notify("Log file cleared", severity="information")
            else:
                self.app.notify("No log file to clear", severity="warning")
        except Exception as e:
            self.app.notify(f"Error clearing log file: {str(e)}", severity="error")

    def export_logs(self) -> None:
        """Export logs to a file."""
        try:
            if not self.log_file.exists():
                self.app.notify("No log file to export", severity="warning")
                return

            # Export to a timestamped file in the same directory
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_file = self.log_file.parent / f"ai-guardian-export-{timestamp}.log"

            # Copy the log file
            import shutil
            shutil.copy2(self.log_file, export_file)

            self.app.notify(
                f"Logs exported to: {export_file}",
                severity="information",
                timeout=5
            )
        except Exception as e:
            self.app.notify(f"Error exporting logs: {str(e)}", severity="error")
