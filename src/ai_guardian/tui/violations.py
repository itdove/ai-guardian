#!/usr/bin/env python3
"""
Violations Tab Content

Display all recent violations with filtering and one-click approval.
"""

import json
from pathlib import Path
from typing import Dict, Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll, Vertical
from textual.widgets import Button, Static, TabbedContent, TabPane
from textual.screen import ModalScreen
from textual import events

from ai_guardian.violation_logger import ViolationLogger
from ai_guardian.config_utils import get_config_dir


class ViolationDetailsModal(ModalScreen):
    """Modal for displaying full violation details."""

    CSS = """
    ViolationDetailsModal {
        align: center middle;
    }

    #modal-container {
        width: 80;
        height: auto;
        max-height: 90%;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #modal-header {
        margin: 0 0 1 0;
        text-align: center;
    }

    #modal-content {
        height: auto;
        max-height: 70;
        overflow-y: auto;
        background: $surface;
        padding: 1;
        margin: 1 0;
        color: $success;
    }

    #modal-actions {
        margin: 1 0 0 0;
        height: auto;
        align: center middle;
    }

    #modal-actions Button {
        margin: 0 1 0 0;
    }
    """

    def __init__(self, violation: Dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.violation = violation

    def compose(self) -> ComposeResult:
        """Compose the modal."""
        with Container(id="modal-container"):
            yield Static("[bold]Violation Details[/bold]", id="modal-header")

            # Format the violation data as JSON
            details = json.dumps(self.violation, indent=2)
            yield Static(details, id="modal-content")

            with Horizontal(id="modal-actions"):
                yield Button("Copy", id="copy-details", variant="default")
                yield Button("Close (ESC)", id="close-details", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "copy-details":
            details = json.dumps(self.violation, indent=2)
            self.app.copy_to_clipboard(details)
            self.app.notify("Violation details copied to clipboard", severity="information")
        elif event.button.id == "close-details":
            self.dismiss()


class ViolationCard(Vertical):
    """Display a single violation with action buttons."""

    DEFAULT_CSS = """
    ViolationCard {
        height: auto;
        margin: 0;
        padding: 1;
        border: round $primary;
        background: $panel;
    }

    ViolationCard > * {
        height: auto;
    }
    """

    def __init__(self, violation: Dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.violation = violation

    def compose(self) -> ComposeResult:
        """Compose the violation card."""
        timestamp = self.violation.get("timestamp", "Unknown")
        # Sanitize timestamp for use in IDs (replace invalid chars)
        timestamp_id = timestamp.replace(":", "-").replace(".", "-").replace("T", "-")
        vtype = self.violation.get("violation_type", "unknown")
        severity = self.violation.get("severity", "warning")
        blocked = self.violation.get("blocked", {})
        suggestion = self.violation.get("suggestion", {})
        resolved = self.violation.get("resolved", False)

        # Severity indicator with color
        severity_colors = {
            "warning": "status-warn",
            "high": "status-error",
            "critical": "status-error"
        }
        severity_class = severity_colors.get(severity, "")

        severity_symbols = {
            "warning": "⚠",
            "high": "●",
            "critical": "●"
        }
        symbol = severity_symbols.get(severity, "•")

        # Title with color-coded severity
        vtype_display = vtype.upper().replace('_', ' ')
        title_parts = [f"[{severity_class}]{symbol}[/{severity_class}]" if severity_class else symbol]
        title_parts.append(vtype_display)

        if resolved:
            title_parts.append("[dim](RESOLVED)[/dim]")

        title = " ".join(title_parts)

        yield Static(f"[bold]{title}[/bold]", classes="violation-title")
        yield Static(f"[muted]{timestamp}[/muted]", classes="violation-timestamp")

        # Details based on violation type
        if vtype == "tool_permission":
            tool_name = blocked.get("tool_name", "Unknown")
            tool_value = blocked.get("tool_value", "")
            reason = blocked.get("reason", "")
            yield Static(f"Tool: {tool_name}/{tool_value}", classes="violation-detail")
            if blocked.get("file_path"):
                yield Static(f"File: {blocked['file_path']}", classes="violation-detail")
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
            line_number = blocked.get("line_number")
            end_line = blocked.get("end_line")
            secret_type = blocked.get("secret_type", "Unknown")
            total_findings = blocked.get("total_findings")

            # Location with path and line number
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    if end_line and end_line != line_number:
                        location_text += f" (lines {line_number}-{end_line})"
                    else:
                        location_text += f" (line {line_number})"
                yield Static(location_text, classes="violation-detail")
            elif source == "prompt":
                location_text = "Location: User prompt"
                if line_number:
                    location_text += f" (line {line_number})"
                yield Static(location_text, classes="violation-detail")
            else:
                yield Static(f"Location: {source}", classes="violation-detail")

            # Show secret type (rule ID)
            if secret_type and secret_type != "Unknown":
                yield Static(f"Type: {secret_type}", classes="violation-detail")

            # Show detection info
            yield Static(f"Detected by: Gitleaks scanner", classes="violation-detail")

            # Show total findings if multiple secrets detected
            if total_findings and total_findings > 1:
                yield Static(f"Total findings: {total_findings}", classes="violation-detail")

            # Note about limited detail
            yield Static(
                "[dim]Note: Secret values are redacted for security. "
                "Review the file at the line number shown above.[/dim]",
                classes="violation-detail"
            )

        elif vtype == "prompt_injection":
            source = blocked.get("source", "unknown")
            file_path = blocked.get("file_path")
            pattern = blocked.get("pattern", "Unknown")
            if file_path:
                yield Static(f"File: {file_path}", classes="violation-detail")
            else:
                yield Static(f"Source: {source}", classes="violation-detail")
            yield Static(f"Pattern: {pattern}", classes="violation-detail")

        elif vtype == "secret_redaction":
            tool = blocked.get("tool", "Unknown")
            file_path = blocked.get("file_path")
            line_number = blocked.get("line_number")
            redaction_count = blocked.get("redaction_count", 0)
            redacted_types = blocked.get("redacted_types", [])
            yield Static(f"Tool: {tool}", classes="violation-detail")
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    location_text += f" (line {line_number})"
                yield Static(location_text, classes="violation-detail")
            yield Static(f"Redacted: {redaction_count} secret(s)", classes="violation-detail")
            if redacted_types:
                yield Static(f"Types: {', '.join(redacted_types)}", classes="violation-detail")

        elif vtype == "pii_detected":
            tool = blocked.get("tool", "Unknown")
            hook = blocked.get("hook", "Unknown")
            file_path = blocked.get("file_path")
            line_number = blocked.get("line_number")
            pii_count = blocked.get("pii_count", 0)
            pii_types = blocked.get("pii_types", [])
            yield Static(f"Hook: {hook}", classes="violation-detail")
            yield Static(f"Tool: {tool}", classes="violation-detail")
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    location_text += f" (line {line_number})"
                yield Static(location_text, classes="violation-detail")
            yield Static(f"PII found: {pii_count} item(s)", classes="violation-detail")
            if pii_types:
                yield Static(f"Types: {', '.join(pii_types)}", classes="violation-detail")

        elif vtype == "jailbreak_detected":
            file_path = blocked.get("file_path")
            confidence = blocked.get("confidence", 0.0)
            if file_path:
                yield Static(f"File: {file_path}", classes="violation-detail")
            else:
                tool = blocked.get("tool", "Unknown")
                matched_text = blocked.get("matched_text", "")
                yield Static(f"Tool: {tool}", classes="violation-detail")
                if matched_text:
                    yield Static(f"Matched: {matched_text[:60]}", classes="violation-detail")
            if confidence:
                yield Static(f"Confidence: {confidence:.2f}", classes="violation-detail")

        # Action buttons
        if not resolved:
            # Unresolved violations - show approve/deny buttons
            can_approve = False
            approve_label = "✓ Approve & Add to Allowlist"

            if vtype == "tool_permission" and suggestion.get("rule"):
                can_approve = True
            elif vtype == "prompt_injection":
                can_approve = True  # Can add to allowlist
            elif vtype == "jailbreak_detected":
                can_approve = True  # Can add to allowlist
            elif vtype == "secret_detected":
                can_approve = True  # Can suggest gitleaks:allow comment
                approve_label = "ℹ Show Allowlist Instruction"
            elif vtype == "directory_blocking":
                can_approve = True  # Can remove .ai-read-deny file
                approve_label = "✓ Remove .ai-read-deny File"

            if can_approve:
                with Horizontal(classes="violation-actions"):
                    if vtype == "secret_detected":
                        yield Button(approve_label, id=f"approve-{timestamp_id}", variant="primary")
                    else:
                        yield Button(approve_label, id=f"approve-{timestamp_id}", variant="success")
                    yield Button("✗ Keep Blocked", id=f"deny-{timestamp_id}", variant="error")
                    yield Button("Details", id=f"details-{timestamp_id}")
        else:
            # Resolved violations - show undo button
            with Horizontal(classes="violation-actions"):
                yield Button("↺ Undo Resolution", id=f"undo-{timestamp_id}", variant="warning")
                yield Button("Details", id=f"details-{timestamp_id}")


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
        border: round $primary;
        margin: 0 0 1 0;
        padding: 1;
        background: $panel;
    }

    .violation-actions {
        height: auto;
    }

    .violation-actions Button {
        margin: 0 1 0 0;
    }

    #filter-tabs {
        height: 100%;
    }

    VerticalScroll {
        height: 100%;
    }

    VerticalScroll > ViolationCard {
        height: auto;
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
            "Use sub-tabs to filter by type. "
            "Tool permission violations can be approved with action buttons.[/dim]",
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
            with TabPane("Secret Redaction", id="filter-redaction"):
                yield VerticalScroll(id="violations-list-redaction")
            with TabPane("Directories", id="filter-directory"):
                yield VerticalScroll(id="violations-list-directory")
            with TabPane("Prompt Injection", id="filter-injection"):
                yield VerticalScroll(id="violations-list-injection")
            with TabPane("Jailbreak", id="filter-jailbreak"):
                yield VerticalScroll(id="violations-list-jailbreak")
            with TabPane("SSRF Blocked", id="filter-ssrf"):
                yield VerticalScroll(id="violations-list-ssrf")
            with TabPane("Config Exfil", id="filter-config-exfil"):
                yield VerticalScroll(id="violations-list-config-exfil")
            with TabPane("PII Detected", id="filter-pii"):
                yield VerticalScroll(id="violations-list-pii")

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

        # Load secret redaction violations
        redaction_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="secret_redaction", resolved=None
        )
        self._populate_list("#violations-list-redaction", redaction_violations)

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

        # Load jailbreak detected violations
        jailbreak_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="jailbreak_detected", resolved=None
        )
        self._populate_list("#violations-list-jailbreak", jailbreak_violations)

        # Load SSRF blocked violations
        ssrf_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="ssrf_blocked", resolved=None
        )
        self._populate_list("#violations-list-ssrf", ssrf_violations)

        # Load config file exfil violations
        config_exfil_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="config_file_exfil", resolved=None
        )
        self._populate_list("#violations-list-config-exfil", config_exfil_violations)

        # Load PII detected violations
        pii_violations = self.violation_logger.get_recent_violations(
            limit=50, violation_type="pii_detected", resolved=None
        )
        self._populate_list("#violations-list-pii", pii_violations)

    def _populate_list(self, list_id: str, violations: list) -> None:
        """Populate a violations list."""
        try:
            violations_list = self.query_one(list_id, VerticalScroll)
            violations_list.remove_children()

            if not violations:
                empty_msg = Static(
                    "No violations found.\n\n"
                    "[dim]Violations appear here when AI Guardian blocks an operation.[/dim]",
                    classes="empty-state"
                )
                violations_list.mount(empty_msg)
                return

            # Add violation cards
            for violation in violations:
                violations_list.mount(ViolationCard(violation))
        except:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses (only approve/deny/details/undo on violation cards)."""
        button_id = event.button.id

        # Approve button
        if button_id and button_id.startswith("approve-"):
            timestamp_id = button_id.replace("approve-", "")
            # Convert sanitized ID back to original timestamp format
            timestamp = self._unsanitize_timestamp(timestamp_id)
            self.approve_violation(timestamp)

        # Deny button
        elif button_id and button_id.startswith("deny-"):
            timestamp_id = button_id.replace("deny-", "")
            timestamp = self._unsanitize_timestamp(timestamp_id)
            self.deny_violation(timestamp)

        # Undo button
        elif button_id and button_id.startswith("undo-"):
            timestamp_id = button_id.replace("undo-", "")
            timestamp = self._unsanitize_timestamp(timestamp_id)
            self.undo_violation(timestamp)

        # Details button
        elif button_id and button_id.startswith("details-"):
            timestamp_id = button_id.replace("details-", "")
            timestamp = self._unsanitize_timestamp(timestamp_id)
            self.show_violation_details(timestamp)

    def _unsanitize_timestamp(self, timestamp_id: str) -> str:
        """Convert sanitized timestamp ID back to original format."""
        # Find matching violation by checking all recent violations
        violations = self.violation_logger.get_recent_violations(limit=1000, resolved=None)
        for v in violations:
            original = v.get("timestamp", "")
            sanitized = original.replace(":", "-").replace(".", "-").replace("T", "-")
            if sanitized == timestamp_id:
                return original
        # Fallback: return as-is
        return timestamp_id

    def on_key(self, event: events.Key) -> None:
        """Handle arrow key navigation for violation cards."""
        focused = self.app.focused

        # Only handle if we're focused on a button inside a violation card
        if not isinstance(focused, Button):
            return

        # Find the parent ViolationCard
        parent = focused.parent
        while parent and not isinstance(parent, ViolationCard):
            parent = parent.parent

        if not parent:
            return

        # Get all violation cards in the current list
        try:
            active_tab = self.query_one("#filter-tabs", TabbedContent).active
            list_id_map = {
                "filter-all": "#violations-list-all",
                "filter-tool-permission": "#violations-list-tool",
                "filter-secret": "#violations-list-secret",
                "filter-redaction": "#violations-list-redaction",
                "filter-directory": "#violations-list-directory",
                "filter-injection": "#violations-list-injection",
                "filter-jailbreak": "#violations-list-jailbreak"
            }
            list_id = list_id_map.get(active_tab)
            if not list_id:
                return

            violations_list = self.query_one(list_id, VerticalScroll)
            cards = list(violations_list.query(ViolationCard))

            if not cards:
                return

            current_index = cards.index(parent)

        except Exception:
            return

        # Handle arrow keys
        if event.key == "down":
            # Move to next violation card
            if current_index < len(cards) - 1:
                next_card = cards[current_index + 1]
                # Focus first button in next card
                buttons = list(next_card.query(Button))
                if buttons:
                    buttons[0].focus()
                    event.prevent_default()
                    event.stop()

        elif event.key == "up":
            # Move to previous violation card
            if current_index > 0:
                prev_card = cards[current_index - 1]
                # Focus first button in previous card
                buttons = list(prev_card.query(Button))
                if buttons:
                    buttons[0].focus()
                    event.prevent_default()
                    event.stop()

        elif event.key == "left":
            # Move to previous button in same card
            buttons = list(parent.query(Button))
            try:
                current_button_index = buttons.index(focused)
                if current_button_index > 0:
                    buttons[current_button_index - 1].focus()
                    event.prevent_default()
                    event.stop()
            except ValueError:
                pass

        elif event.key == "right":
            # Move to next button in same card
            buttons = list(parent.query(Button))
            try:
                current_button_index = buttons.index(focused)
                if current_button_index < len(buttons) - 1:
                    buttons[current_button_index + 1].focus()
                    event.prevent_default()
                    event.stop()
            except ValueError:
                pass

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

    def action_filter_redaction(self) -> None:
        """Filter secret redaction violations (triggered by '6' key)."""
        try:
            filter_tabs = self.query_one("#filter-tabs", TabbedContent)
            filter_tabs.active = "filter-redaction"
        except:
            pass

    def approve_violation(self, timestamp: str) -> None:
        """Approve a violation and add appropriate allowlist rule."""
        # Find the violation
        violations = self.violation_logger.get_recent_violations(limit=1000, resolved=None)
        violation = next((v for v in violations if v.get("timestamp") == timestamp), None)

        if not violation:
            self.app.notify("Violation not found", severity="error")
            return

        vtype = violation.get("violation_type")
        blocked = violation.get("blocked", {})
        suggestion = violation.get("suggestion", {})

        # Load current config
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # Handle different violation types
            if vtype == "tool_permission":
                # Original logic - use suggested rule
                suggested_rule = suggestion.get("rule")
                if not suggested_rule:
                    self.app.notify("No suggested rule available", severity="error")
                    return

                permissions_obj = config.get("permissions", {})
                if isinstance(permissions_obj, dict):
                    all_permissions = permissions_obj.get("rules", [])
                    is_dict_format = True
                elif isinstance(permissions_obj, list):
                    all_permissions = permissions_obj
                    is_dict_format = False
                else:
                    all_permissions = []
                    is_dict_format = False

                matcher = suggested_rule.get("matcher")
                mode = suggested_rule.get("mode")

                existing_rule = next(
                    (r for r in all_permissions
                     if r.get("matcher") == matcher and r.get("mode") == mode),
                    None
                )

                if existing_rule:
                    new_patterns = suggested_rule.get("patterns", [])
                    existing_patterns = existing_rule.get("patterns", [])
                    merged_patterns = list(set(existing_patterns + new_patterns))
                    existing_rule["patterns"] = merged_patterns
                    action_msg = f"Merged patterns into existing {matcher} rule"
                else:
                    all_permissions.append(suggested_rule)
                    action_msg = f"Added new {matcher} rule"

                if is_dict_format:
                    config["permissions"]["rules"] = all_permissions
                else:
                    config["permissions"] = all_permissions

            elif vtype in ("prompt_injection", "jailbreak_detected"):
                # Both share the same prompt_injection allowlist_patterns
                source = blocked.get("source", "unknown")
                pattern = blocked.get("pattern", "")

                if not pattern:
                    self.app.notify("No pattern found to allowlist", severity="error")
                    return

                if "prompt_injection" not in config:
                    config["prompt_injection"] = {}
                if "allowlist_patterns" not in config["prompt_injection"]:
                    config["prompt_injection"]["allowlist_patterns"] = []

                if pattern in config["prompt_injection"]["allowlist_patterns"]:
                    self.app.notify("Pattern already in allowlist", severity="warning")
                    return

                config["prompt_injection"]["allowlist_patterns"].append(pattern)
                label = "jailbreak" if vtype == "jailbreak_detected" else "prompt injection"
                action_msg = f"Added '{pattern}' to {label} allowlist"

            elif vtype == "secret_detected":
                file_path = blocked.get("file_path", "")
                line_number = blocked.get("line_number", "")
                secret_type = blocked.get("rule_id", blocked.get("secret_type", "unknown"))

                details = f"[bold]How to Allow This Secret[/bold]\n\n"
                details += f"Secret type: {secret_type}\n"
                if file_path:
                    details += f"File: {file_path}"
                    if line_number:
                        details += f":{line_number}"
                    details += "\n"
                details += (
                    "\n[bold]Option 1:[/bold] Add comment before the line:\n"
                    "  # gitleaks:allow\n\n"
                    "[bold]Option 2:[/bold] Add to .gitleaks.toml allowlist\n\n"
                    "[dim]Note: Secret scanning cannot be bypassed via TUI config — "
                    "the scanner engine controls allowlisting.[/dim]"
                )

                self.violation_logger.mark_resolved(timestamp, action="info_shown")
                self.load_all_filters()
                from ai_guardian.tui.app import HelpModal
                self.app.push_screen(HelpModal("Secret Allowlisting", details))
                return

            elif vtype == "directory_blocking":
                # Remove the .ai-read-deny file
                denied_dir = blocked.get("denied_directory")

                if not denied_dir:
                    self.app.notify("Cannot find directory path", severity="error")
                    return

                from pathlib import Path
                deny_file = Path(denied_dir) / ".ai-read-deny"

                try:
                    if deny_file.exists():
                        deny_file.unlink()
                        action_msg = f"Removed {deny_file}"
                    else:
                        self.app.notify(f"File not found: {deny_file}", severity="warning")
                        return
                except Exception as e:
                    self.app.notify(f"Error removing file: {e}", severity="error")
                    return

                # Mark as resolved
                self.violation_logger.mark_resolved(timestamp, action="approved")
                self.load_all_filters()
                self.app.notify(f"✓ {action_msg}", severity="success")
                return

            else:
                self.app.notify(f"Cannot approve {vtype} violations", severity="error")
                return

            # Write updated config (except for secret_detected which returned early)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Mark violation as resolved
            self.violation_logger.mark_resolved(timestamp, action="approved")

            # Refresh the display
            self.load_all_filters()

            self.app.notify(f"✓ {action_msg}", severity="success")

        except Exception as e:
            self.app.notify(f"Error updating config: {e}", severity="error")

    def deny_violation(self, timestamp: str) -> None:
        """Mark a violation as resolved without adding the rule."""
        if self.violation_logger.mark_resolved(timestamp, action="denied"):
            self.load_all_filters()
            self.app.notify("Violation marked as denied", severity="information")
        else:
            self.app.notify("Failed to mark violation as denied", severity="error")

    def undo_violation(self, timestamp: str) -> None:
        """Undo resolution - mark as unresolved and reverse config change."""
        violations = self.violation_logger.get_recent_violations(limit=1000, resolved=None)
        violation = next((v for v in violations if v.get("timestamp") == timestamp), None)

        if not violation:
            self.app.notify("Violation not found", severity="error")
            return

        vtype = violation.get("violation_type")
        blocked = violation.get("blocked", {})
        suggestion = violation.get("suggestion", {})
        resolved_action = violation.get("resolved_action", "")

        if resolved_action == "approved":
            config_dir = get_config_dir()
            config_path = config_dir / "ai-guardian.json"

            try:
                if config_path.exists():
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                else:
                    config = {}

                reversed_config = False

                if vtype == "tool_permission":
                    suggested_rule = suggestion.get("rule", {})
                    matcher = suggested_rule.get("matcher")
                    mode = suggested_rule.get("mode")
                    patterns_to_remove = suggested_rule.get("patterns", [])

                    permissions_obj = config.get("permissions", {})
                    if isinstance(permissions_obj, dict):
                        all_permissions = permissions_obj.get("rules", [])
                    elif isinstance(permissions_obj, list):
                        all_permissions = permissions_obj
                    else:
                        all_permissions = []

                    for perm in all_permissions:
                        if perm.get("matcher") == matcher and perm.get("mode") == mode:
                            existing = perm.get("patterns", [])
                            perm["patterns"] = [p for p in existing if p not in patterns_to_remove]
                            if not perm["patterns"]:
                                all_permissions.remove(perm)
                            reversed_config = True
                            break

                    if isinstance(config.get("permissions"), dict):
                        config["permissions"]["rules"] = all_permissions
                    else:
                        config["permissions"] = all_permissions

                elif vtype in ("prompt_injection", "jailbreak_detected"):
                    pattern = blocked.get("pattern", "")
                    if pattern:
                        allowlist = config.get("prompt_injection", {}).get("allowlist_patterns", [])
                        if pattern in allowlist:
                            allowlist.remove(pattern)
                            reversed_config = True

                if reversed_config:
                    with open(config_path, 'w', encoding='utf-8') as f:
                        json.dump(config, f, indent=2)

            except Exception as e:
                self.app.notify(f"Error reversing config: {e}", severity="error")
                return

        if self.violation_logger.mark_unresolved(timestamp):
            self.load_all_filters()
            self.app.notify("✓ Violation undone (config change reversed)", severity="success")
        else:
            self.app.notify("Failed to undo violation", severity="error")

    def show_violation_details(self, timestamp: str) -> None:
        """Show detailed information about a violation in a modal."""
        violations = self.violation_logger.get_recent_violations(limit=1000, resolved=None)
        violation = next((v for v in violations if v.get("timestamp") == timestamp), None)

        if violation:
            self.app.push_screen(ViolationDetailsModal(violation))
        else:
            self.app.notify("Violation not found", severity="error")
