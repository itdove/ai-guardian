#!/usr/bin/env python3
"""
Violations Tab Content

Display all recent violations with filtering and resolution instructions.
"""

import json
from typing import Dict

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll, Vertical
from textual.widgets import Button, Static, TabbedContent, TabPane
from textual.screen import ModalScreen
from textual.binding import Binding
from textual import events

from ai_guardian.violation_logger import ViolationLogger
from ai_guardian.tui.widgets import format_local_time


class ViolationDetailsModal(ModalScreen):
    """Modal for displaying full violation details."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
    ]

    CSS = """
    ViolationDetailsModal {
        align: center middle;
    }

    #modal-container {
        width: 80;
        height: 80%;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #modal-header {
        margin: 0 0 1 0;
        text-align: center;
    }

    #modal-content {
        height: 1fr;
        background: $surface;
        padding: 1;
        margin: 1 0;
    }

    #modal-content-text {
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

    def _get_resolution_instructions(self):
        """Return (instructions_text, config_snippet) for this violation type."""
        vtype = self.violation.get("violation_type", "")
        blocked = self.violation.get("blocked", {})
        suggestion = self.violation.get("suggestion", {})

        if vtype == "tool_permission":
            rule = suggestion.get("rule", {})
            snippet = json.dumps({"permissions": {"rules": [rule]}}, indent=2) if rule else ""
            return (
                "Add this rule to [bold]permissions.rules[/bold] in ai-guardian.json:",
                snippet,
            )

        elif vtype == "prompt_injection":
            pattern = blocked.get("pattern", "<pattern>")
            snippet = json.dumps(
                {"prompt_injection": {"allowlist_patterns": [pattern]}}, indent=2
            )
            return (
                "Add this pattern to [bold]prompt_injection.allowlist_patterns[/bold]:",
                snippet,
            )

        elif vtype == "jailbreak_detected":
            pattern = blocked.get("pattern", blocked.get("matched_text", "<pattern>"))
            snippet = json.dumps(
                {"prompt_injection": {"allowlist_patterns": [pattern]}}, indent=2
            )
            return (
                "Add this pattern to [bold]prompt_injection.allowlist_patterns[/bold]:",
                snippet,
            )

        elif vtype == "secret_detected":
            file_path = blocked.get("file_path", "<file>")
            secret_type = blocked.get("rule_id", blocked.get("secret_type", "unknown"))
            instructions = (
                f"Secret type: {secret_type}\n\n"
                "[bold]Option 1:[/bold] Add a regex pattern to ai-guardian.json:\n"
                '  "secret_scanning": {{\n'
                '    "allowlist_patterns": ["your-regex-pattern"]\n'
                "  }}\n\n"
                "[bold]Option 2:[/bold] Add inline comment at the end of the line:\n"
                "  YOUR_SECRET_LINE # gitleaks:allow\n\n"
                "[bold]Option 3:[/bold] Add to .gitleaks.toml allowlist\n\n"
                "[dim]Tip: Option 1 works for both file scanning and tool output scanning.\n"
                "Options 2-3 only work for file scanning (PreToolUse).[/dim]"
            )
            snippet = json.dumps(
                {"secret_scanning": {"allowlist_patterns": ["your-regex-pattern"]}}, indent=2
            )
            return (instructions, snippet)

        elif vtype == "directory_blocking":
            denied_dir = blocked.get("denied_directory", "<directory>")
            instructions = (
                "Add an allow rule to [bold]directory_rules.rules[/bold] or remove the deny pattern.\n\n"
                f"To remove the deny file:\n  rm {denied_dir}/.ai-read-deny"
            )
            snippet = f"rm {denied_dir}/.ai-read-deny"
            return (instructions, snippet)

        elif vtype == "pii_detected":
            file_path = blocked.get("file_path", "<file>")
            snippet = json.dumps(
                {"scan_pii": {"allowlist_patterns": ["<pattern>"], "ignore_files": [file_path]}},
                indent=2,
            )
            return (
                "Add pattern to [bold]scan_pii.allowlist_patterns[/bold] "
                "or file to [bold]scan_pii.ignore_files[/bold]:",
                snippet,
            )

        elif vtype == "secret_redaction":
            snippet = json.dumps(
                {"secret_scanning": {"allowlist_patterns": ["<pattern>"]}}, indent=2
            )
            return (
                "Add pattern to [bold]secret_scanning.allowlist_patterns[/bold]:",
                snippet,
            )

        elif vtype == "ssrf_blocked":
            tool_value = blocked.get("tool_value", "")
            domain = "<domain>"
            if tool_value:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(tool_value)
                    if parsed.hostname:
                        domain = parsed.hostname
                except Exception:
                    pass
            snippet = json.dumps(
                {"ssrf_protection": {"additional_allowed_domains": [domain]}}, indent=2
            )
            return (
                "Add domain to [bold]ssrf_protection.additional_allowed_domains[/bold]:",
                snippet,
            )

        elif vtype == "config_file_exfil":
            file_path = blocked.get("file_path", "<file>")
            snippet = json.dumps(
                {"config_file_scanning": {"ignore_files": [file_path]}}, indent=2
            )
            return (
                "Add file to [bold]config_file_scanning.ignore_files[/bold]:",
                snippet,
            )

        return ("No specific resolution instructions available for this violation type.", "")

    def compose(self) -> ComposeResult:
        """Compose the modal."""
        instructions, snippet = self._get_resolution_instructions()

        with Container(id="modal-container"):
            yield Static("[bold]Violation Details[/bold]", id="modal-header")

            details = json.dumps(self.violation, indent=2)
            with VerticalScroll(id="modal-content"):
                yield Static(details, id="modal-content-text")
                yield Static("\n[bold]--- How to Resolve ---[/bold]\n")
                yield Static(instructions)
                if snippet:
                    yield Static(f"\n[bold]Config snippet:[/bold]\n{snippet}")

            with Horizontal(id="modal-actions"):
                yield Button("Copy Details", id="copy-details", variant="default")
                if snippet:
                    yield Button("Copy Snippet", id="copy-snippet", variant="success")
                yield Button("Close (ESC)", id="close-details", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "copy-details":
            details = json.dumps(self.violation, indent=2)
            if self.app.copy_to_clipboard(details):
                self.app.notify("Violation details copied to clipboard", severity="information")
        elif event.button.id == "copy-snippet":
            _, snippet = self._get_resolution_instructions()
            if snippet:
                if self.app.copy_to_clipboard(snippet):
                    self.app.notify("Config snippet copied to clipboard", severity="information")
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
        yield Static(f"[muted]{format_local_time(timestamp)}[/muted]", classes="violation-timestamp")

        # Details based on violation type
        if vtype == "tool_permission":
            tool_name = blocked.get("tool_name", "Unknown")
            tool_value = blocked.get("tool_value", "")
            reason = blocked.get("reason", "")
            yield Static(f"Tool: {tool_name}/{tool_value}", classes="violation-detail")
            if blocked.get("file_path"):
                location_text = f"File: {blocked['file_path']}"
                if blocked.get("line_number"):
                    location_text += f" (line {blocked['line_number']}"
                    if blocked.get("position"):
                        location_text += f", pos {blocked['position']}"
                    location_text += ")"
                yield Static(location_text, classes="violation-detail")
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
            position = blocked.get("position")
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    if end_line and end_line != line_number:
                        location_text += f" (lines {line_number}-{end_line}"
                    else:
                        location_text += f" (line {line_number}"
                    if position:
                        location_text += f", pos {position}"
                    location_text += ")"
                yield Static(location_text, classes="violation-detail")
            elif source == "prompt":
                location_text = "Location: User prompt"
                if line_number:
                    location_text += f" (line {line_number}"
                    if position:
                        location_text += f", pos {position}"
                    location_text += ")"
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
            line_number = blocked.get("line_number")
            position = blocked.get("position")
            pattern = blocked.get("pattern", "Unknown")
            matched_text = blocked.get("matched_text")
            confidence = blocked.get("confidence")
            method = blocked.get("method")
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    location_text += f" (line {line_number}"
                    if position:
                        location_text += f", pos {position}"
                    location_text += ")"
                yield Static(location_text, classes="violation-detail")
            else:
                yield Static(f"Source: {source}", classes="violation-detail")
            yield Static(f"Pattern: {pattern}", classes="violation-detail")
            if matched_text:
                yield Static(f"Matched: {matched_text[:80]}", classes="violation-detail")
            if method:
                yield Static(f"Method: {method}", classes="violation-detail")
            if confidence:
                yield Static(f"Confidence: {confidence:.2f}", classes="violation-detail")

        elif vtype == "secret_redaction":
            tool = blocked.get("tool", "Unknown")
            file_path = blocked.get("file_path")
            line_number = blocked.get("line_number")
            position = blocked.get("position")
            redaction_count = blocked.get("redaction_count", 0)
            redacted_types = blocked.get("redacted_types", [])
            command = blocked.get("command")
            context_snippet = blocked.get("context_snippet")
            yield Static(f"Tool: {tool}", classes="violation-detail")
            if command:
                yield Static(f"Command: {command[:120]}", classes="violation-detail")
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    location_text += f" (line {line_number}"
                    if position:
                        location_text += f", pos {position}"
                    location_text += ")"
                yield Static(location_text, classes="violation-detail")
            elif context_snippet:
                yield Static(f"Context: {context_snippet}", classes="violation-detail")
            yield Static(f"Redacted: {redaction_count} secret(s)", classes="violation-detail")
            if redacted_types:
                yield Static(f"Types: {', '.join(redacted_types)}", classes="violation-detail")

        elif vtype == "pii_detected":
            tool = blocked.get("tool", "Unknown")
            hook = blocked.get("hook", "Unknown")
            file_path = blocked.get("file_path")
            line_number = blocked.get("line_number")
            position = blocked.get("position")
            pii_count = blocked.get("pii_count", 0)
            pii_types = blocked.get("pii_types", [])
            command = blocked.get("command")
            context_snippet = blocked.get("context_snippet")
            yield Static(f"Hook: {hook}", classes="violation-detail")
            yield Static(f"Tool: {tool}", classes="violation-detail")
            if command:
                yield Static(f"Command: {command[:120]}", classes="violation-detail")
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    location_text += f" (line {line_number}"
                    if position:
                        location_text += f", pos {position}"
                    location_text += ")"
                yield Static(location_text, classes="violation-detail")
            elif context_snippet:
                yield Static(f"Context: {context_snippet}", classes="violation-detail")
            yield Static(f"PII found: {pii_count} item(s)", classes="violation-detail")
            if pii_types:
                yield Static(f"Types: {', '.join(pii_types)}", classes="violation-detail")

        elif vtype == "jailbreak_detected":
            file_path = blocked.get("file_path")
            line_number = blocked.get("line_number")
            position = blocked.get("position")
            confidence = blocked.get("confidence", 0.0)
            matched_text = blocked.get("matched_text", "")
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    location_text += f" (line {line_number}"
                    if position:
                        location_text += f", pos {position}"
                    location_text += ")"
                yield Static(location_text, classes="violation-detail")
            else:
                tool = blocked.get("tool", "Unknown")
                yield Static(f"Tool: {tool}", classes="violation-detail")
            if matched_text:
                yield Static(f"Matched: {matched_text[:80]}", classes="violation-detail")
            if confidence:
                yield Static(f"Confidence: {confidence:.2f}", classes="violation-detail")

        elif vtype == "ssrf_blocked":
            tool_name = blocked.get("tool_name", "Unknown")
            tool_value = blocked.get("tool_value", "")
            file_path = blocked.get("file_path")
            line_number = blocked.get("line_number")
            position = blocked.get("position")
            reason = blocked.get("reason", "")
            yield Static(f"Tool: {tool_name}", classes="violation-detail")
            if tool_value:
                yield Static(f"Target: {tool_value[:120]}", classes="violation-detail")
            if file_path:
                location_text = f"File: {file_path}"
                if line_number:
                    location_text += f" (line {line_number}"
                    if position:
                        location_text += f", pos {position}"
                    location_text += ")"
                yield Static(location_text, classes="violation-detail")
            if reason:
                yield Static(f"Reason: {reason}", classes="violation-detail")

        elif vtype == "config_file_exfil":
            file_path = blocked.get("file_path", "Unknown")
            reason = blocked.get("reason", "")
            details = blocked.get("details", "")
            yield Static(f"File: {file_path}", classes="violation-detail")
            if reason:
                yield Static(f"Reason: {reason}", classes="violation-detail")
            if details:
                yield Static(f"Details: {details[:120]}", classes="violation-detail")

        # Action buttons — Details only (shows resolution instructions)
        with Horizontal(classes="violation-actions"):
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
        margin: 1 0 0 0;
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
            "Click Details on any violation for resolution instructions.[/dim]",
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
        """Handle button presses (details on violation cards)."""
        button_id = event.button.id

        if button_id and button_id.startswith("details-"):
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
                "filter-jailbreak": "#violations-list-jailbreak",
                "filter-ssrf": "#violations-list-ssrf",
                "filter-config-exfil": "#violations-list-config-exfil",
                "filter-pii": "#violations-list-pii",
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

    def show_violation_details(self, timestamp: str) -> None:
        """Show detailed information about a violation in a modal."""
        violations = self.violation_logger.get_recent_violations(limit=1000, resolved=None)
        violation = next((v for v in violations if v.get("timestamp") == timestamp), None)

        if violation:
            self.app.push_screen(ViolationDetailsModal(violation))
        else:
            self.app.notify("Violation not found", severity="error")
