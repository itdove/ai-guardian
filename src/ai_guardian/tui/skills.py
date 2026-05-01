#!/usr/bin/env python3
"""
Skills Tab Content

Manage Skill permissions (allow/deny lists for Skill tools).
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Static, Input, Label

from ai_guardian.config_utils import get_config_dir


class PatternRow(Horizontal):
    """Display a single pattern with remove button (supports time-based patterns)."""

    DEFAULT_CSS = """
    PatternRow {
        height: 3;
        width: 100%;
        layout: horizontal;
    }

    PatternRow Static {
        width: 1fr;
        height: 3;
        content-align: left middle;
    }

    PatternRow Button {
        width: 12;
        height: 3;
        min-width: 12;
    }
    """

    def __init__(self, pattern: Union[str, Dict[str, Any]], index: int, mode: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pattern_data = pattern
        self.index = index
        self.mode = mode

        # Parse pattern (supports simple string or time-based dict)
        if isinstance(pattern, dict):
            self.pattern_str = pattern.get("pattern", "")
            self.valid_until = pattern.get("valid_until", "")
        else:
            self.pattern_str = pattern
            self.valid_until = ""

    def compose(self) -> ComposeResult:
        """Compose the pattern row with optional expiration badge."""
        # Mode indicator
        if self.mode == "allow":
            mode_badge = "[status-ok]✓[/status-ok]"
        else:
            mode_badge = "[status-error]✗[/status-error]"

        # Build pattern display with expiration info
        pattern_display = f"  {mode_badge} {self.pattern_str}"

        if self.valid_until:
            # Add expiration badge with color coding
            try:
                expiry_dt = datetime.fromisoformat(self.valid_until.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc)

                if expiry_dt <= now:
                    # Expired
                    pattern_display += " [status-error][EXPIRED][/status-error]"
                else:
                    # Check if expiring soon (within 24 hours)
                    time_remaining = expiry_dt - now
                    if time_remaining.total_seconds() < 86400:  # 24 hours
                        pattern_display += f" [status-warn][expires {self.valid_until}][/status-warn]"
                    else:
                        pattern_display += f" [dim][until {self.valid_until}][/dim]"
            except Exception:
                pattern_display += f" [dim][until {self.valid_until}][/dim]"

        yield Static(pattern_display)
        yield Button("Remove", id=f"remove-{self.mode}-{self.index}", variant="error")


class SkillsContent(Container):
    """Content widget for Skills tab."""

    CSS = """
    SkillsContent {
        height: 100%;
    }

    #skills-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    .section {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    .section-title {
        margin: 0 0 1 0;
        font-weight: bold;
    }

    .pattern-item {
        margin: 0.5 0;
        height: auto;
    }

    .pattern-item Static {
        margin: 0 1 0 0;
        width: auto;
    }

    .pattern-item Button {
        margin: 0 0 0 1;
    }

    .add-pattern-row {
        margin: 1 0 0 0;
        height: auto;
    }

    .add-pattern-row Input {
        width: 40;
    }

    .add-pattern-row Button {
        margin: 0 0 0 1;
    }

    #patterns-allow-container, #patterns-deny-container {
        margin: 0.5 0;
        padding: 1;
        background: $surface;
        border: solid $primary;
        min-height: 5;
    }

    .pattern-row {
        margin: 0.5 0;
        height: 3;
        width: 100%;
    }

    .pattern-row Static {
        width: auto;
        margin: 0 1 0 0;
        height: 3;
        content-align: left middle;
    }

    .pattern-row Button {
        width: 12;
        height: 3;
        border: solid $error;
    }

    /* Input and Button defaults */
    Input {
        border: none;
        background: $surface;
    }

    Button {
        border: none;
        background: $panel;
    }

    /* Focus indicators */
    Input:focus {
        border: none;
        border-left: heavy $accent;
        text-style: bold;
        background: $surface;
    }

    Button:focus {
        border: none;
        border-left: heavy $accent;
        text-style: bold;
    }

    Checkbox:focus {
        border-left: heavy $accent;
        text-style: bold;
    }

    #actions {
        margin: 1 0;
        height: auto;
    }

    #actions Button {
        margin: 0 1 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the skills tab content."""
        yield Static("[bold]Skill Permissions[/bold]", id="skills-header")

        with VerticalScroll():
            # Allow list section
            with Container(classes="section"):
                yield Static("[bold][green]✓ Allow List[/green][/bold]", classes="section-title")
                yield Static("Skills matching these patterns will be allowed.", classes="section-title")
                yield Static("[dim]Add pattern: Press 'a' or Enter • Remove: Focus Remove button and press Enter[/dim]")
                yield VerticalScroll(id="patterns-allow-container")
                yield Input(placeholder="Enter pattern (e.g., daf-*, hello)", id="new-allow-pattern")

            # Deny list section
            with Container(classes="section"):
                yield Static("[bold][red]✗ Deny List[/red][/bold]", classes="section-title")
                yield Static("Skills matching these patterns will be blocked.", classes="section-title")
                yield Static("[dim]Add pattern: Press 'd' or Enter • Remove: Focus Remove button and press Enter[/dim]")
                yield VerticalScroll(id="patterns-deny-container")
                yield Input(placeholder="Enter pattern (e.g., dangerous-*)", id="new-deny-pattern")

    def on_mount(self) -> None:
        """Load permissions when mounted."""
        self.load_patterns()

    def refresh_content(self) -> None:
        """Refresh permissions (called by parent app)."""
        self.load_patterns()

    def load_patterns(self) -> None:
        """Load and display allow/deny patterns."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        allow_patterns = []
        deny_patterns = []

        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # NEW unified structure in v1.4.0
                    permissions_obj = config.get("permissions", {})
                    if isinstance(permissions_obj, dict):
                        all_permissions = permissions_obj.get("rules", [])
                    else:
                        all_permissions = permissions_obj if isinstance(permissions_obj, list) else []

                    # Extract allow and deny patterns for Skill matcher
                    for perm in all_permissions:
                        if perm.get("matcher") == "Skill":
                            mode = perm.get("mode", "allow")
                            patterns = perm.get("patterns", [])
                            if mode == "allow":
                                allow_patterns = patterns
                            elif mode == "deny":
                                deny_patterns = patterns
            except Exception as e:
                self.app.notify(f"Error loading permissions: {e}", severity="error")

        # Display allow patterns
        allow_container = self.query_one("#patterns-allow-container", VerticalScroll)
        allow_container.remove_children()

        if allow_patterns:
            for idx, pattern in enumerate(allow_patterns):
                allow_container.mount(PatternRow(pattern, idx, "allow", classes="pattern-row"))
        else:
            allow_container.mount(Static(
                "[muted]No allow patterns configured.\n"
                "Add patterns to allow specific skills.[/muted]",
                classes="empty-state"
            ))

        # Display deny patterns
        deny_container = self.query_one("#patterns-deny-container", VerticalScroll)
        deny_container.remove_children()

        if deny_patterns:
            for idx, pattern in enumerate(deny_patterns):
                deny_container.mount(PatternRow(pattern, idx, "deny", classes="pattern-row"))
        else:
            deny_container.mount(Static(
                "[muted]No deny patterns configured.\n"
                "Add patterns to block specific skills.[/muted]",
                classes="empty-state"
            ))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses (only remove buttons)."""
        button_id = event.button.id

        if button_id and button_id.startswith("remove-allow-"):
            idx = int(button_id.replace("remove-allow-", ""))
            self.remove_pattern_by_index("allow", idx)

        elif button_id and button_id.startswith("remove-deny-"):
            idx = int(button_id.replace("remove-deny-", ""))
            self.remove_pattern_by_index("deny", idx)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input fields."""
        if event.input.id == "new-allow-pattern":
            self.add_pattern("allow")
        elif event.input.id == "new-deny-pattern":
            self.add_pattern("deny")

    def action_add_allow(self) -> None:
        """Add pattern to allow list (triggered by 'a' key)."""
        self.add_pattern("allow")

    def action_add_deny(self) -> None:
        """Add pattern to deny list (triggered by 'd' key)."""
        self.add_pattern("deny")

    def action_refresh(self) -> None:
        """Refresh patterns (triggered by 'r' key)."""
        self.load_patterns()
        self.app.notify("Skill permissions refreshed", severity="information")

    def add_pattern(self, mode: str) -> None:
        """Add a pattern to allow or deny list."""
        input_id = f"new-{mode}-pattern"
        pattern = self.query_one(f"#{input_id}", Input).value.strip()

        if not pattern:
            self.app.notify("Please enter a pattern", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

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

            # Find existing Skill rule with this mode
            existing_rule = None
            for perm in all_permissions:
                if perm.get("matcher") == "Skill" and perm.get("mode") == mode:
                    existing_rule = perm
                    break

            if existing_rule:
                if pattern in existing_rule.get("patterns", []):
                    self.app.notify(f"Pattern already in {mode} list", severity="warning")
                    return
                existing_rule.setdefault("patterns", []).append(pattern)
            else:
                all_permissions.append({
                    "matcher": "Skill",
                    "mode": mode,
                    "patterns": [pattern]
                })

            if is_dict_format:
                config["permissions"]["rules"] = all_permissions
            else:
                config["permissions"] = all_permissions

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Clear input
            self.query_one(f"#{input_id}", Input).value = ""

            self.load_patterns()
            self.app.notify(f"✓ Added pattern to {mode} list: {pattern}", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding pattern: {e}", severity="error")

    def remove_pattern_by_index(self, mode: str, index: int) -> None:
        """Remove a pattern from allow or deny list by index."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            self.app.notify("Config file not found", severity="error")
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # NEW unified structure in v1.4.0
            permissions_obj = config.get("permissions", {})
            if isinstance(permissions_obj, dict):
                all_permissions = permissions_obj.get("rules", [])
            else:
                all_permissions = permissions_obj if isinstance(permissions_obj, list) else []

            # Find and remove pattern
            for perm in all_permissions:
                if perm.get("matcher") == "Skill" and perm.get("mode") == mode:
                    patterns = perm.get("patterns", [])
                    if index < len(patterns):
                        removed_pattern = patterns.pop(index)
                        # Remove rule if no patterns left
                        if not patterns:
                            all_permissions.remove(perm)

                        # Save back to new structure
                        if isinstance(config.get("permissions"), dict):
                            config["permissions"]["rules"] = all_permissions
                        else:
                            config["permissions"] = {"enabled": True, "rules": all_permissions}

                        with open(config_path, 'w', encoding='utf-8') as f:
                            json.dump(config, f, indent=2)

                        self.load_patterns()
                        self.app.notify(f"✓ Removed pattern from {mode} list: {removed_pattern}", severity="success")
                        return

            self.app.notify(f"Pattern not found at index {index}", severity="error")

        except Exception as e:
            self.app.notify(f"Error removing pattern: {e}", severity="error")
