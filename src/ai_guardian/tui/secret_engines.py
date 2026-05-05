#!/usr/bin/env python3
"""
Secret Scanning Engine Configuration Panel

Manage multi-engine scanner configuration using a JSON editor for the
engines array and dropdowns for execution strategy settings.
"""

import json
import shutil

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Label, Select, Input, TextArea

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.console_settings import load_editor_theme


class SecretEnginesContent(Container):
    """Content widget for Secret Engine Configuration panel."""

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("ctrl+r", "reload", "Reload", show=True),
    ]

    CSS = """
    SecretEnginesContent {
        height: 100%;
    }

    #secret-engines-header {
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

    #engines-editor {
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

    #threshold-input {
        width: 10;
    }

    #threshold-row {
        display: none;
    }

    #threshold-row.visible {
        display: block;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Engine Configuration[/bold]  "
            "[dim]Ctrl+S[/dim] Save  "
            "[dim]Ctrl+R[/dim] Reload",
            id="secret-engines-header",
        )

        with Container(classes="section"):
            yield Static("[bold]Execution Strategy[/bold]", classes="section-title")
            yield Static(
                "[dim]How multiple engines combine results.[/dim]"
            )
            with Horizontal(classes="setting-row"):
                yield Label("Strategy:")
                yield Select(
                    [
                        ("first-match (default)", "first-match"),
                        ("any-match (block if ANY finds secrets)", "any-match"),
                        ("consensus (block if N engines agree)", "consensus"),
                    ],
                    value="first-match",
                    id="strategy-select",
                    allow_blank=False,
                )
            with Horizontal(classes="setting-row", id="threshold-row"):
                yield Label("Consensus threshold:")
                yield Input(
                    value="2",
                    type="integer",
                    id="threshold-input",
                )

        yield Static("[bold]Engines[/bold]  [dim](edit JSON below)[/dim]")

        theme = load_editor_theme()
        yield TextArea(
            '["gitleaks"]',
            language="json",
            theme=theme,
            show_line_numbers=True,
            tab_behavior="indent",
            id="engines-editor",
        )

        yield Static("", id="editor-status")

        with Container(classes="info-box"):
            yield Static("Engine configuration reference", markup=False)
            yield Static(
                "Engines are tried in order. Simple format (string) or advanced (object).\n\n"
                "Simple: just engine names\n"
                '  ["gitleaks", "trufflehog"]\n\n'
                "Advanced: per-engine config with file routing and ignore patterns\n"
                '[\n'
                '  "gitleaks",\n'
                '  {\n'
                '    "type": "trufflehog",\n'
                '    "binary": "trufflehog",\n'
                '    "ignore_files": ["**/test/**"],\n'
                '    "file_patterns": ["*.env*", "*.yaml"]\n'
                '  }\n'
                ']\n\n'
                "Built-in engines: gitleaks, betterleaks, leaktk, trufflehog, detect-secrets, secretlint, gitguardian\n"
                "Per-engine options: ignore_files, pattern_server, file_patterns\n"
                "Cloud engines (gitguardian): require consent via 'ai-guardian engine consent'",
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
            editor = self.query_one("#engines-editor", TextArea)
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

        ss = config.get("secret_scanning", {})
        if not isinstance(ss, dict):
            ss = {}

        engines = ss.get("engines", ["gitleaks"])
        strategy = ss.get("execution_strategy", "first-match")
        threshold = ss.get("consensus_threshold", 2)

        try:
            self.query_one("#strategy-select", Select).value = strategy
        except Exception:
            pass

        try:
            self.query_one("#threshold-input", Input).value = str(threshold)
        except Exception:
            pass

        self._update_threshold_visibility(strategy)

        engines_json = json.dumps(engines, indent=2)
        try:
            editor = self.query_one("#engines-editor", TextArea)
            editor.load_text(engines_json)
            self._update_status(engines_json)
        except Exception:
            pass

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if event.text_area.id == "engines-editor":
            self._update_status(event.text_area.text)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "strategy-select":
            value = str(event.value)
            self._update_threshold_visibility(value)
            self._save_strategy(value)

    def _update_threshold_visibility(self, strategy: str) -> None:
        try:
            row = self.query_one("#threshold-row")
            if strategy == "consensus":
                row.add_class("visible")
            else:
                row.remove_class("visible")
        except Exception:
            pass

    def _update_status(self, text: str) -> None:
        engines, error = self._parse_engines(text)
        status = self.query_one("#editor-status", Static)
        if error:
            status.update(f"Invalid: {error}")
            status.remove_class("status-valid")
            status.add_class("status-invalid")
        else:
            count = len(engines)
            status.update(f"Valid JSON — {count} engine(s)")
            status.remove_class("status-invalid")
            status.add_class("status-valid")

    def _parse_engines(self, text: str):
        """Parse engines JSON. Returns (engines_list, error_string)."""
        if not text.strip():
            return [], None
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            return None, f"Line {e.lineno}, col {e.colno}: {e.msg}"

        if not isinstance(data, list):
            return None, "Engines must be a JSON array"

        valid_presets = {"gitleaks", "betterleaks", "leaktk", "trufflehog", "detect-secrets", "secretlint", "gitguardian"}
        for i, entry in enumerate(data):
            if isinstance(entry, str):
                if entry not in valid_presets:
                    return None, f"Engine {i + 1}: unknown preset '{entry}'"
            elif isinstance(entry, dict):
                if "type" not in entry:
                    return None, f"Engine {i + 1}: missing 'type' field"
                if "binary" not in entry and entry.get("type") != "custom":
                    pass  # built-in types don't need binary
            else:
                return None, f"Engine {i + 1}: must be a string or object"

        return data, None

    def action_save(self) -> None:
        editor = self.query_one("#engines-editor", TextArea)
        text = editor.text

        engines, error = self._parse_engines(text)
        if error:
            self.app.notify(f"Cannot save: {error}", severity="error")
            return

        try:
            config = self._load_config_dict()
            ss = config.get("secret_scanning", {})
            if not isinstance(ss, dict):
                ss = {"enabled": True}

            ss["engines"] = engines

            # Save threshold if consensus
            try:
                threshold_input = self.query_one("#threshold-input", Input)
                threshold = int(threshold_input.value) if threshold_input.value else 2
                ss["consensus_threshold"] = max(1, threshold)
            except Exception:
                pass

            config["secret_scanning"] = ss
            self._save_config_dict(config)
            self.app.notify(f"Saved {len(engines)} engine(s)", severity="information")
        except Exception as e:
            self.app.notify(f"Save failed: {e}", severity="error")

    def action_reload(self) -> None:
        self.load_config()
        self.app.notify("Reloaded from disk", severity="information")

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("Engine config refreshed", severity="information")

    def _save_strategy(self, strategy: str) -> None:
        try:
            config = self._load_config_dict()
            ss = config.get("secret_scanning", {})
            if not isinstance(ss, dict):
                ss = {"enabled": True}
            ss["execution_strategy"] = strategy
            config["secret_scanning"] = ss
            self._save_config_dict(config)
            self.app.notify(f"Strategy set to: {strategy}", severity="success")
        except Exception as e:
            self.app.notify(f"Error saving strategy: {e}", severity="error")

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
