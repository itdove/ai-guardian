#!/usr/bin/env python3
"""
Violations Tab Content

Display all recent violations with filtering and one-click approval.
"""

import json
from pathlib import Path
from typing import Dict, Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Static, TabbedContent, TabPane

from ai_guardian.violation_logger import ViolationLogger
from ai_guardian.config_utils import get_config_dir


class ViolationCard(Container):
    """Display a single violation with action buttons."""

    def __init__(self, violation: Dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.violation = violation

    def compose(self) -> ComposeResult:
        """Compose the violation card."""
        timestamp = self.violation.get("timestamp", "Unknown")
        vtype = self.violation.get("violation_type", "unknown")
        severity = self.violation.get("severity", "warning")
        blocked = self.violation.get("blocked", {})
        suggestion = self.violation.get("suggestion", {})
        resolved = self.violation.get("resolved", False)

        # Severity indicator
        severity_icons = {
            "warning": "⚠️",
            "high": "🔴",
            "critical": "🔒"
        }
        icon = severity_icons.get(severity, "•")

        # Title
        title = f"{icon} {vtype.upper().replace('_', ' ')}"
        if resolved:
            title += " [dim](RESOLVED)[/dim]"

        yield Static(f"[bold]{title}[/bold]", classes="violation-title")
        yield Static(f"[dim]{timestamp}[/dim]", classes="violation-timestamp")

        # Details based on violation type
        if vtype == "tool_permission":
            tool_name = blocked.get("tool_name", "Unknown")
            tool_value = blocked.get("tool_value", "")
            reason = blocked.get("reason", "")
            yield Static(f"Tool: {tool_name}/{tool_value}", classes="violation-detail")
            yield Static(f"Reason: {reason}", classes="violation-detail")

            # Show suggested rule
            if suggestion and suggestion.get("rule"):
                rule = suggestion["rule"]
                yield Static("\nSuggested rule:", classes="violation-detail")
                yield Static(
                    f"  {json.dumps(rule, indent=2)}",
                    classes="violation-suggestion"
                )

        elif vtype == "directory_blocking":
            file_path = blocked.get("file_path", "Unknown")
            denied_dir = blocked.get("denied_directory", "")
            yield Static(f"File: {file_path}", classes="violation-detail")
            yield Static(f"Denied by: {denied_dir}/.ai-read-deny", classes="violation-detail")

        elif vtype == "secret_detected":
            # Show source/location
            file_path = blocked.get("file_path")
            source = blocked.get("source", "unknown")

            if file_path:
                yield Static(f"Location: {file_path}", classes="violation-detail")
            elif source == "prompt":
                yield Static("Location: User prompt", classes="violation-detail")
            else:
                yield Static(f"Location: {source}", classes="violation-detail")

            # Show reason
            reason = blocked.get("reason", "Gitleaks detected sensitive information")
            yield Static(f"Detected by: Gitleaks scanner", classes="violation-detail")

            # Note about limited detail
            yield Static(
                "[dim]Note: Secret details not logged for security. "
                "This violation occurred when Gitleaks detected a potential secret pattern.[/dim]",
                classes="violation-detail"
            )

        elif vtype == "prompt_injection":
            source = blocked.get("source", "unknown")
            pattern = blocked.get("pattern", "Unknown")
            yield Static(f"Source: {source}", classes="violation-detail")
            yield Static(f"Pattern: {pattern}", classes="violation-detail")

        # Action buttons (only for unresolved tool_permission violations with suggestions)
        if not resolved and vtype == "tool_permission" and suggestion.get("rule"):
            with Horizontal(classes="violation-actions"):
                yield Button("✓ Approve & Add Rule", id=f"approve-{timestamp}", variant="success")
                yield Button("✗ Keep Blocked", id=f"deny-{timestamp}", variant="error")
                yield Button("Details", id=f"details-{timestamp}")


class ViolationsContent(Container):
    """Content widget for Violations tab."""

    CSS = """
    ViolationsContent {
        height: 100%;
    }

    #violations-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    ViolationCard {
        border: solid $primary;
        margin: 1 0;
        padding: 1;
        background: $panel;
    }

    .violation-title {
        margin: 0 0 1 0;
    }

    .violation-timestamp {
        margin: 0 0 1 0;
        color: $text-muted;
    }

    .violation-detail {
        margin: 0 0 0 2;
        padding: 0;
    }

    .violation-suggestion {
        margin: 0 0 0 4;
        padding: 1;
        background: $surface;
        color: $success;
    }

    .violation-actions {
        margin: 1 0 0 0;
        height: auto;
    }

    .violation-actions Button {
        margin: 0 1 0 0;
    }

    #filter-tabs {
        height: 100%;
    }

    #no-violations {
        margin: 2;
        padding: 2;
        text-align: center;
        color: $text-muted;
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.violation_logger = ViolationLogger()

    def compose(self) -> ComposeResult:
        """Compose the violations tab content."""
        yield Static("[bold]Recent Violations[/bold]", id="violations-header")
        yield Static(
            "[dim]Historical log of blocked operations. "
            "Use sub-tabs or number keys [1-5] to filter by type. "
            "Tool permission violations can be approved with button on card.[/dim]",
            classes="violation-detail"
        )

        # Sub-tabs for filtering
        with TabbedContent(id="filter-tabs"):
            with TabPane("All", id="filter-all"):
                yield VerticalScroll(id="violations-list-all")
            with TabPane("Tool Permission", id="filter-tool-permission"):
                yield VerticalScroll(id="violations-list-tool")
            with TabPane("Secrets", id="filter-secret"):
                yield VerticalScroll(id="violations-list-secret")
            with TabPane("Directories", id="filter-directory"):
                yield VerticalScroll(id="violations-list-directory")
            with TabPane("Prompt Injection", id="filter-injection"):
                yield VerticalScroll(id="violations-list-injection")

    def on_mount(self) -> None:
        """Load violations when mounted."""
        self.load_all_filters()

    def refresh_content(self) -> None:
        """Refresh violations (called by parent app)."""
        self.load_all_filters()

    def load_all_filters(self) -> None:
        """Load violations into all filter tabs."""
        # Load all violations
        all_violations = self.violation_logger.get_recent_violations(limit=50, resolved=None)
        self._populate_list("#violations-list-all", all_violations)

        # Load tool permission violations
        tool_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="tool_permission", resolved=None
        )
        self._populate_list("#violations-list-tool", tool_violations)

        # Load secret violations
        secret_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="secret_detected", resolved=None
        )
        self._populate_list("#violations-list-secret", secret_violations)

        # Load directory violations
        directory_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="directory_blocking", resolved=None
        )
        self._populate_list("#violations-list-directory", directory_violations)

        # Load prompt injection violations
        injection_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="prompt_injection", resolved=None
        )
        self._populate_list("#violations-list-injection", injection_violations)

    def _populate_list(self, list_id: str, violations: list) -> None:
        """Populate a violations list."""
        try:
            violations_list = self.query_one(list_id, VerticalScroll)
            violations_list.remove_children()

            if not violations:
                violations_list.mount(Static("No violations found."))
                return

            # Add violation cards
            for violation in violations:
                violations_list.mount(ViolationCard(violation))
        except:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses (only approve/deny/details on violation cards)."""
        button_id = event.button.id

        # Approve button
        if button_id and button_id.startswith("approve-"):
            timestamp = button_id.replace("approve-", "")
            self.approve_violation(timestamp)

        # Deny button
        elif button_id and button_id.startswith("deny-"):
            timestamp = button_id.replace("deny-", "")
            self.deny_violation(timestamp)

        # Details button
        elif button_id and button_id.startswith("details-"):
            timestamp = button_id.replace("details-", "")
            self.show_violation_details(timestamp)

    def action_filter_all(self) -> None:
        """Show all violations (triggered by '1' key)."""
        try:
            filter_tabs = self.query_one("#filter-tabs", TabbedContent)
            filter_tabs.active = "filter-all"
        except:
            pass

    def action_filter_tool(self) -> None:
        """Filter tool permission violations (triggered by '2' key)."""
        try:
            filter_tabs = self.query_one("#filter-tabs", TabbedContent)
            filter_tabs.active = "filter-tool-permission"
        except:
            pass

    def action_filter_secret(self) -> None:
        """Filter secret violations (triggered by '3' key)."""
        try:
            filter_tabs = self.query_one("#filter-tabs", TabbedContent)
            filter_tabs.active = "filter-secret"
        except:
            pass

    def action_filter_directory(self) -> None:
        """Filter directory violations (triggered by '4' key)."""
        try:
            filter_tabs = self.query_one("#filter-tabs", TabbedContent)
            filter_tabs.active = "filter-directory"
        except:
            pass

    def action_filter_injection(self) -> None:
        """Filter prompt injection violations (triggered by '5' key)."""
        try:
            filter_tabs = self.query_one("#filter-tabs", TabbedContent)
            filter_tabs.active = "filter-injection"
        except:
            pass

    def approve_violation(self, timestamp: str) -> None:
        """Approve a violation and add the suggested rule to config."""
        # Find the violation
        violations = self.violation_logger.get_recent_violations(limit=1000, resolved=None)
        violation = next((v for v in violations if v.get("timestamp") == timestamp), None)

        if not violation:
            self.app.notify("Violation not found", severity="error")
            return

        # Get the suggested rule
        suggestion = violation.get("suggestion", {})
        suggested_rule = suggestion.get("rule")

        if not suggested_rule:
            self.app.notify("No suggested rule available", severity="error")
            return

        # Load current config
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # Initialize permissions if needed
            if "permissions" not in config:
                config["permissions"] = []

            # Check if rule for this matcher already exists
            matcher = suggested_rule.get("matcher")
            mode = suggested_rule.get("mode")

            existing_rule = next(
                (r for r in config["permissions"]
                 if r.get("matcher") == matcher and r.get("mode") == mode),
                None
            )

            if existing_rule:
                # Merge patterns
                new_patterns = suggested_rule.get("patterns", [])
                existing_patterns = existing_rule.get("patterns", [])
                merged_patterns = list(set(existing_patterns + new_patterns))
                existing_rule["patterns"] = merged_patterns
                action_msg = f"Merged patterns into existing {matcher} rule"
            else:
                # Add new rule
                config["permissions"].append(suggested_rule)
                action_msg = f"Added new {matcher} rule"

            # Write updated config
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Mark violation as resolved
            self.violation_logger.mark_resolved(timestamp, action="approved")

            # Refresh the display
            self.load_violations(self.current_filter)

            self.app.notify(f"✓ {action_msg}", severity="success")

        except Exception as e:
            self.app.notify(f"Error updating config: {e}", severity="error")

    def deny_violation(self, timestamp: str) -> None:
        """Mark a violation as resolved without adding the rule."""
        if self.violation_logger.mark_resolved(timestamp, action="denied"):
            self.load_violations(self.current_filter)
            self.app.notify("Violation marked as denied", severity="information")
        else:
            self.app.notify("Failed to mark violation as denied", severity="error")

    def show_violation_details(self, timestamp: str) -> None:
        """Show detailed information about a violation."""
        violations = self.violation_logger.get_recent_violations(limit=1000, resolved=None)
        violation = next((v for v in violations if v.get("timestamp") == timestamp), None)

        if violation:
            details = json.dumps(violation, indent=2)
            self.app.notify(f"Violation details:\n{details}", severity="information", timeout=10)
        else:
            self.app.notify("Violation not found", severity="error")
