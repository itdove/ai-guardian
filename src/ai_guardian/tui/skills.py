#!/usr/bin/env python3
"""
Skills Tab Content

Manage Skill permissions (allow/deny rules for Skill tools).
"""

import json
from pathlib import Path
from typing import Dict

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Static, Input, Select, Label
from textual.screen import ModalScreen

from ai_guardian.config_utils import get_config_dir


class SkillPermissionCard(Container):
    """Display a single Skill permission rule."""

    def __init__(self, rule: Dict, index: int, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rule = rule
        self.index = index

    def compose(self) -> ComposeResult:
        """Compose the permission card."""
        mode = self.rule.get("mode", "allow")
        patterns = self.rule.get("patterns", [])

        # Mode indicator
        mode_icon = "✓" if mode == "allow" else "✗"
        mode_color = "green" if mode == "allow" else "red"

        yield Static(f"[bold]{mode_icon} Skill[/bold]", classes="permission-title")
        yield Static(f"Mode: [{mode_color}]{mode}[/{mode_color}]", classes="permission-detail")
        yield Static(f"Patterns: {', '.join(patterns)}", classes="permission-detail")

        with Horizontal(classes="permission-actions"):
            yield Button("Edit", id=f"edit-{self.index}")
            yield Button("Delete", id=f"delete-{self.index}", variant="error")


class AddSkillPermissionModal(ModalScreen):
    """Modal for adding/editing Skill permission rules."""

    CSS = """
    AddSkillPermissionModal {
        align: center middle;
    }

    #modal-container {
        width: 60;
        height: auto;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #modal-header {
        margin: 0 0 1 0;
        text-align: center;
    }

    .modal-field {
        margin: 1 0;
    }

    .modal-field Label {
        margin: 0 0 0 0;
    }

    .modal-field Input,
    .modal-field Select {
        margin: 0 0 0 0;
        width: 100%;
    }

    #modal-actions {
        margin: 1 0 0 0;
        height: auto;
    }

    #modal-actions Button {
        margin: 0 1 0 0;
    }
    """

    def __init__(self, rule: Dict = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rule = rule or {}
        self.is_edit = bool(rule)

    def compose(self) -> ComposeResult:
        """Compose the modal."""
        with Container(id="modal-container"):
            title = "Edit Skill Permission" if self.is_edit else "Add Skill Permission"
            yield Static(f"[bold]{title}[/bold]", id="modal-header")

            with Container(classes="modal-field"):
                yield Label("Mode:")
                yield Select(
                    [(line, line) for line in ["allow", "deny"]],
                    value=self.rule.get("mode", "allow"),
                    id="select-mode"
                )

            with Container(classes="modal-field"):
                yield Label("Patterns (comma-separated):")
                patterns = self.rule.get("patterns", [])
                patterns_str = ", ".join(patterns) if patterns else ""
                yield Input(
                    value=patterns_str,
                    placeholder="daf-*, release, gh-cli",
                    id="input-patterns"
                )

            with Horizontal(id="modal-actions"):
                yield Button("Save", id="save-permission", variant="success")
                yield Button("Cancel", id="cancel-permission", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "save-permission":
            # Get values
            mode = self.query_one("#select-mode", Select).value
            patterns_str = self.query_one("#input-patterns", Input).value.strip()

            # Validate
            if not patterns_str:
                self.app.notify("At least one pattern is required", severity="error")
                return

            # Parse patterns
            patterns = [p.strip() for p in patterns_str.split(",") if p.strip()]

            # Build rule
            rule = {
                "matcher": "Skill",
                "mode": mode,
                "patterns": patterns
            }

            self.dismiss(rule)

        elif event.button.id == "cancel-permission":
            self.dismiss(None)


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

    SkillPermissionCard {
        border: solid $primary;
        margin: 1 0;
        padding: 1;
        background: $panel;
    }

    .permission-title {
        margin: 0 0 1 0;
    }

    .permission-detail {
        margin: 0 0 0 2;
        padding: 0;
    }

    .permission-actions {
        margin: 1 0 0 0;
        height: auto;
    }

    .permission-actions Button {
        margin: 0 1 0 0;
    }

    #skills-actions {
        margin: 1 0;
        height: auto;
    }

    #skills-actions Button {
        margin: 0 1 0 0;
    }

    #no-permissions {
        margin: 2;
        padding: 2;
        text-align: center;
        color: $text-muted;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the skills tab content."""
        yield Static("[bold]Skill Permissions[/bold] (daf-*, gh-cli, etc.)", id="skills-header")

        with Horizontal(id="skills-actions"):
            yield Button("Add Permission", id="add-permission", variant="primary")

        yield VerticalScroll(id="skills-list")

    def on_mount(self) -> None:
        """Load permissions when mounted."""
        self.load_permissions()

    def refresh_content(self) -> None:
        """Refresh permissions (called by parent app)."""
        self.load_permissions()

    def load_permissions(self) -> None:
        """Load and display Skill permission rules."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        permissions = []
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # Filter only Skill permissions
                    all_permissions = config.get("permissions", [])
                    permissions = [p for p in all_permissions if p.get("matcher") == "Skill"]
            except Exception as e:
                self.app.notify(f"Error loading permissions: {e}", severity="error")

        # Get the permissions list container
        permissions_list = self.query_one("#skills-list", VerticalScroll)
        permissions_list.remove_children()

        if not permissions:
            permissions_list.mount(
                Static("No Skill permissions defined. Click 'Add Permission' to create one.", id="no-permissions")
            )
            return

        # Add permission cards (with correct indices from full permissions list)
        for idx, rule in enumerate(permissions):
            permissions_list.mount(SkillPermissionCard(rule, idx))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "add-permission":
            self.add_permission()
        elif button_id and button_id.startswith("edit-"):
            idx = int(button_id.replace("edit-", ""))
            self.edit_permission(idx)
        elif button_id and button_id.startswith("delete-"):
            idx = int(button_id.replace("delete-", ""))
            self.delete_permission(idx)

    def add_permission(self) -> None:
        """Show modal to add a new Skill permission rule."""
        def handle_result(rule: Dict) -> None:
            if rule:
                self.save_permission(rule)

        self.app.push_screen(AddSkillPermissionModal(), handle_result)

    def edit_permission(self, index: int) -> None:
        """Show modal to edit an existing Skill permission rule."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            self.app.notify("Config file not found", severity="error")
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                all_permissions = config.get("permissions", [])
                skill_permissions = [p for p in all_permissions if p.get("matcher") == "Skill"]

            if index >= len(skill_permissions):
                self.app.notify("Permission not found", severity="error")
                return

            rule = skill_permissions[index]

            def handle_result(updated_rule: Dict) -> None:
                if updated_rule:
                    # Find the actual index in the full permissions list
                    skill_count = 0
                    for i, perm in enumerate(all_permissions):
                        if perm.get("matcher") == "Skill":
                            if skill_count == index:
                                all_permissions[i] = updated_rule
                                break
                            skill_count += 1

                    config["permissions"] = all_permissions

                    with open(config_path, 'w', encoding='utf-8') as f:
                        json.dump(config, f, indent=2)

                    self.load_permissions()
                    self.app.notify("Skill permission updated", severity="success")

            self.app.push_screen(AddSkillPermissionModal(rule), handle_result)

        except Exception as e:
            self.app.notify(f"Error editing permission: {e}", severity="error")

    def delete_permission(self, index: int) -> None:
        """Delete a Skill permission rule."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        if not config_path.exists():
            self.app.notify("Config file not found", severity="error")
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                all_permissions = config.get("permissions", [])

            # Find and remove the Skill permission
            skill_count = 0
            for i, perm in enumerate(all_permissions):
                if perm.get("matcher") == "Skill":
                    if skill_count == index:
                        removed_rule = all_permissions.pop(i)
                        break
                    skill_count += 1

            config["permissions"] = all_permissions

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.load_permissions()
            self.app.notify("Skill permission deleted", severity="success")

        except Exception as e:
            self.app.notify(f"Error deleting permission: {e}", severity="error")

    def save_permission(self, rule: Dict) -> None:
        """Save a new Skill permission rule to config."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "permissions" not in config:
                config["permissions"] = []

            config["permissions"].append(rule)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.load_permissions()
            self.app.notify("Skill permission added", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving permission: {e}", severity="error")
