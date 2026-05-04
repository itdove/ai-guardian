#!/usr/bin/env python3
"""
Directory Rules Tab Content

Manage directory_rules configuration for path-level allow/deny access control.
Uses a JSON editor for the rules array, matching the Config Editor pattern.
"""

import json
import shutil
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Button, Label, Select, TextArea

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.console_settings import load_editor_theme


class DirectoryRulesContent(Container):
    """Content widget for Directory Rules tab."""

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("ctrl+r", "reload", "Reload", show=True),
    ]

    CSS = """
    DirectoryRulesContent {
        height: 100%;
    }

    #directory-rules-header {
        height: auto;
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

    .setting-row {
        margin: 0.5 0;
        height: auto;
        align: left middle;
    }

    .setting-row Label {
        margin: 0 2 0 0;
        width: auto;
    }

    #rules-editor {
        height: 1fr;
        min-height: 10;
        border: solid $primary;
    }

    #editor-status {
        height: auto;
        padding: 0 1;
        background: $surface;
    }

    .status-valid {
        color: $success;
    }

    .status-invalid {
        color: $error;
    }

    .info-box {
        margin: 1 0;
        padding: 1;
        background: $surface;
        border: solid $primary;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Directory Rules[/bold]  "
            "[dim]Ctrl+S[/dim] Save  "
            "[dim]Ctrl+R[/dim] Reload",
            id="directory-rules-header",
        )

        with Container(classes="section"):
            yield Static("[bold]Violation Action[/bold]", classes="section-title")
            yield Static(
                "[dim]What happens when a directory rule denies access.[/dim]"
            )
            with Horizontal(classes="setting-row"):
                yield Label("Action on deny:")
                yield Select(
                    [("block", "block"), ("warn", "warn"), ("log-only", "log-only")],
                    value="block",
                    id="action-select",
                    allow_blank=False,
                )

        yield Static("[bold]Rules[/bold]  [dim](edit JSON below)[/dim]")

        theme = load_editor_theme()
        yield TextArea(
            "[]",
            language="json",
            theme=theme,
            show_line_numbers=True,
            tab_behavior="indent",
            id="rules-editor",
        )

        yield Static("", id="editor-status")

        with Container(classes="info-box"):
            yield Static("How directory rules work", markup=False)
            yield Static(
                "Rules are evaluated top to bottom. Last matching rule wins.\n"
                "If no rules match, access is ALLOWED (default permissive).\n"
                "Common pattern: deny broad, then allow specific.\n\n"
                "Example rules array:\n"
                '[\n'
                '  {"mode": "deny",  "paths": ["~/.ssh/**", "~/.aws/**"]},\n'
                '  {"mode": "allow", "paths": ["~/dev/workspace/**"]}\n'
                ']\n\n'
                "Pattern syntax:\n"
                "  ~   Expands to home directory\n"
                "  *   Matches single directory level\n"
                "  **  Matches recursively",
                markup=False,
            )

    def on_mount(self) -> None:
        self.load_config()

    def on_show(self) -> None:
        self._apply_saved_theme()

    def refresh_content(self) -> None:
        self._apply_saved_theme()
        self.load_config()

    def _apply_saved_theme(self) -> None:
        try:
            editor = self.query_one("#rules-editor", TextArea)
            theme = load_editor_theme()
            if editor.theme != theme:
                editor.theme = theme
        except Exception:
            pass

    def load_config(self) -> None:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        config = {}
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except Exception as e:
                self.app.notify(f"Error loading config: {e}", severity="error")
                return

        dir_rules_config = config.get("directory_rules", {})

        if isinstance(dir_rules_config, dict):
            action = dir_rules_config.get("action", "block")
            rules = dir_rules_config.get("rules", [])
        elif isinstance(dir_rules_config, list):
            action = "block"
            rules = dir_rules_config
        else:
            action = "block"
            rules = []

        try:
            self.query_one("#action-select", Select).value = action
        except Exception:
            pass

        # Filter out internal keys for display
        display_rules = []
        for rule in rules:
            if isinstance(rule, dict):
                clean = {k: v for k, v in rule.items() if not k.startswith("_")}
                display_rules.append(clean)

        rules_json = json.dumps(display_rules, indent=2)
        try:
            editor = self.query_one("#rules-editor", TextArea)
            editor.load_text(rules_json)
            self._update_status(rules_json)
        except Exception:
            pass

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if event.text_area.id == "rules-editor":
            self._update_status(event.text_area.text)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "action-select":
            self._save_action(str(event.value))

    def _update_status(self, text: str) -> None:
        rules, error = self._parse_rules(text)
        status = self.query_one("#editor-status", Static)
        if error:
            status.update(f"Invalid: {error}")
            status.remove_class("status-valid")
            status.add_class("status-invalid")
        else:
            count = len(rules)
            status.update(f"Valid JSON — {count} rule(s)")
            status.remove_class("status-invalid")
            status.add_class("status-valid")

    def _parse_rules(self, text: str):
        """Parse rules JSON. Returns (rules_list, error_string)."""
        if not text.strip():
            return [], None
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            return None, f"Line {e.lineno}, col {e.colno}: {e.msg}"

        if not isinstance(data, list):
            return None, "Rules must be a JSON array"

        for i, rule in enumerate(data):
            if not isinstance(rule, dict):
                return None, f"Rule {i + 1} must be an object"
            if rule.get("mode") not in ("allow", "deny"):
                return None, f'Rule {i + 1}: mode must be "allow" or "deny"'
            if not isinstance(rule.get("paths"), list):
                return None, f"Rule {i + 1}: paths must be an array"

        return data, None

    def action_save(self) -> None:
        editor = self.query_one("#rules-editor", TextArea)
        text = editor.text

        rules, error = self._parse_rules(text)
        if error:
            self.app.notify(f"Cannot save: {error}", severity="error")
            return

        try:
            config = self._load_config_dict()
            dr = self._get_rules_section(config)

            # Preserve generated/immutable rules
            preserved = [r for r in dr.get("rules", [])
                         if isinstance(r, dict) and (r.get("_generated") or r.get("_immutable"))]

            dr["rules"] = rules + preserved
            config["directory_rules"] = dr
            self._save_config_dict(config)
            self.app.notify(f"Saved {len(rules)} rule(s)", severity="information")
        except Exception as e:
            self.app.notify(f"Save failed: {e}", severity="error")

    def action_reload(self) -> None:
        self.load_config()
        self.app.notify("Reloaded from disk", severity="information")

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("Directory rules refreshed", severity="information")

    def _save_action(self, action: str) -> None:
        try:
            config = self._load_config_dict()
            dr = self._get_rules_section(config)
            dr["action"] = action
            config["directory_rules"] = dr
            self._save_config_dict(config)
            self.app.notify(f"Action set to: {action}", severity="success")
        except Exception as e:
            self.app.notify(f"Error saving action: {e}", severity="error")

    def _load_config_dict(self) -> dict:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}

    def _save_config_dict(self, config: dict) -> None:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"
        if config_path.exists():
            backup_path = config_path.with_suffix(".json.bak")
            shutil.copy2(config_path, backup_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

    def _get_rules_section(self, config: dict) -> dict:
        dr = config.get("directory_rules", {})
        if isinstance(dr, dict):
            return dr
        return {"action": "block", "rules": dr if isinstance(dr, list) else []}
