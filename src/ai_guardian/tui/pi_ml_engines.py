#!/usr/bin/env python3
"""
ML Prompt Injection Engines Panel

Configure ML engines, execution strategy, fallback, and consensus threshold
for prompt injection detection.
"""

import json
import shutil

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Label, Select, Input, TextArea

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.console_settings import load_editor_theme

VALID_ML_ENGINE_TYPES = {"llm-guard"}


class PIMLEnginesContent(Container):
    """Content widget for ML Prompt Injection Engines panel."""

    BINDINGS = [
        Binding("ctrl+s", "save", "Save Engines", show=True),
        Binding("ctrl+r", "reload", "Reload", show=True),
    ]

    CSS = """
    PIMLEnginesContent {
        height: 100%;
    }

    #ml-engines-header {
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

    #ml-engines-editor {
        height: 1fr;
        min-height: 10;
        border: solid $primary;
    }

    #ml-editor-status {
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

    #ml-threshold-input {
        width: 10;
    }

    #ml-threshold-row {
        display: none;
    }

    #ml-threshold-row.visible {
        display: block;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]ML Prompt Injection Engines[/bold]  "
            "[dim]Ctrl+S[/dim] Save  "
            "[dim]Ctrl+R[/dim] Reload",
            id="ml-engines-header",
        )

        with VerticalScroll():
            # ML Status
            with Container(classes="section"):
                yield Static("[bold]ML Status[/bold]", classes="section-title")
                yield Static("", id="ml-status-info")

            # Strategy
            with Container(classes="section"):
                yield Static("[bold]Execution Strategy[/bold]", classes="section-title")
                yield Static("[dim]How multiple ML engines combine results.[/dim]")
                with Horizontal(classes="setting-row"):
                    yield Label("Strategy:")
                    yield Select(
                        [
                            ("any-match (default — flag if ANY detects)", "any-match"),
                            ("first-match (use first engine result)", "first-match"),
                            ("consensus (flag if N engines agree)", "consensus"),
                        ],
                        value="any-match",
                        id="ml-strategy-select",
                        allow_blank=False,
                    )
                with Horizontal(classes="setting-row", id="ml-threshold-row"):
                    yield Label("Consensus threshold:")
                    yield Input(
                        value="2",
                        type="integer",
                        id="ml-threshold-input",
                    )

            # Fallback
            with Container(classes="section"):
                yield Static("[bold]Fallback on Error[/bold]", classes="section-title")
                yield Static("[dim]Action when ML detection is unavailable.[/dim]")
                with Horizontal(classes="setting-row"):
                    yield Label("Fallback:")
                    yield Select(
                        [
                            ("heuristic (default — pattern detection)", "heuristic"),
                            ("block (fail closed)", "block"),
                            ("allow (fail open)", "allow"),
                        ],
                        value="heuristic",
                        id="ml-fallback-select",
                        allow_blank=False,
                    )

            # Engines editor
            yield Static("[bold]ML Engines[/bold]  [dim](edit JSON below)[/dim]")

            theme = load_editor_theme()
            yield TextArea(
                "[]",
                language="json",
                theme=theme,
                show_line_numbers=True,
                tab_behavior="indent",
                id="ml-engines-editor",
            )

            yield Static("", id="ml-editor-status")

            # Reference
            with Container(classes="info-box"):
                yield Static("ML engine configuration reference", markup=False)
                yield Static(
                    "Each engine requires 'type' and 'model' fields.\n\n"
                    "Example:\n"
                    "[\n"
                    "  {\n"
                    '    "type": "llm-guard",\n'
                    '    "model": "protectai/deberta-v3-base-prompt-injection-v2",\n'
                    '    "threshold": 0.85\n'
                    "  }\n"
                    "]\n\n"
                    "Valid engine types: llm-guard\n"
                    "threshold: 0.0-1.0 (default 0.85)\n\n"
                    "Requires: onnxruntime (included on Python < 3.13)\n"
                    "Download models: ai-guardian ml download",
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
            editor = self.query_one("#ml-engines-editor", TextArea)
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
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except Exception as e:
                self.app.notify(f"Error loading config: {e}", severity="error")
                return

        pi = config.get("prompt_injection", {})
        if not isinstance(pi, dict):
            pi = {}

        engines = pi.get("ml_engines", [])
        strategy = pi.get("ml_strategy", "any-match")
        threshold = pi.get("consensus_threshold", 2)
        fallback = pi.get("fallback_on_error", "heuristic")

        try:
            self.query_one("#ml-strategy-select", Select).value = strategy
        except Exception:
            pass

        try:
            self.query_one("#ml-threshold-input", Input).value = str(threshold)
        except Exception:
            pass

        try:
            self.query_one("#ml-fallback-select", Select).value = fallback
        except Exception:
            pass

        self._update_threshold_visibility(strategy)

        engines_json = json.dumps(engines, indent=2) if engines else "[]"
        try:
            editor = self.query_one("#ml-engines-editor", TextArea)
            editor.load_text(engines_json)
            self._update_status(engines_json)
        except Exception:
            pass

        self._update_ml_status_info()

    def _update_ml_status_info(self) -> None:
        try:
            from ai_guardian.ml_detection import is_ml_available, list_registered_models

            available = is_ml_available()
            models = list_registered_models()

            lines = []
            if available:
                lines.append(
                    "[green]ML dependencies available (onnxruntime, tokenizers)[/green]"
                )
            else:
                lines.append("[red]ML dependencies not available[/red]")
                lines.append(
                    "[dim]onnxruntime required (included on Python < 3.13 via rapidocr-onnxruntime)[/dim]"
                )

            for m in models:
                status = (
                    "[green]downloaded[/green]"
                    if m.get("downloaded")
                    else "[dim]not downloaded[/dim]"
                )
                lines.append(f"  {m['name']} — {status}")

            if models and not all(m.get("downloaded") for m in models):
                lines.append("[dim]Download models: ai-guardian ml download[/dim]")

            self.query_one("#ml-status-info", Static).update("\n".join(lines))
        except Exception as e:
            self.query_one("#ml-status-info", Static).update(
                f"[dim]Status check failed: {e}[/dim]"
            )

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if event.text_area.id == "ml-engines-editor":
            self._update_status(event.text_area.text)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "ml-strategy-select":
            value = str(event.value)
            self._update_threshold_visibility(value)
            self._save_strategy(value)
        elif event.select.id == "ml-fallback-select":
            self._save_fallback(str(event.value))

    def _update_threshold_visibility(self, strategy: str) -> None:
        try:
            row = self.query_one("#ml-threshold-row")
            if strategy == "consensus":
                row.add_class("visible")
            else:
                row.remove_class("visible")
        except Exception:
            pass

    def _update_status(self, text: str) -> None:
        engines, error = self._parse_engines(text)
        status = self.query_one("#ml-editor-status", Static)
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
        """Parse ML engines JSON. Returns (engines_list, error_string)."""
        text = text.strip()
        if not text:
            return [], None
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            return None, f"Line {e.lineno}, col {e.colno}: {e.msg}"

        if not isinstance(data, list):
            return None, "Engines must be a JSON array"

        for i, entry in enumerate(data):
            if not isinstance(entry, dict):
                return (
                    None,
                    f"Engine {i + 1}: must be an object with 'type' and 'model'",
                )
            etype = entry.get("type")
            if not etype:
                return None, f"Engine {i + 1}: missing 'type' field"
            if etype not in VALID_ML_ENGINE_TYPES:
                return None, f"Engine {i + 1}: unknown type '{etype}'"
            if not entry.get("model"):
                return None, f"Engine {i + 1}: missing 'model' field"
            threshold = entry.get("threshold")
            if threshold is not None:
                if not isinstance(threshold, (int, float)):
                    return None, f"Engine {i + 1}: threshold must be a number"
                if not 0.0 <= threshold <= 1.0:
                    return None, f"Engine {i + 1}: threshold must be 0.0-1.0"

        return data, None

    def action_save(self) -> None:
        editor = self.query_one("#ml-engines-editor", TextArea)
        text = editor.text

        engines, error = self._parse_engines(text)
        if error:
            self.app.notify(f"Cannot save: {error}", severity="error")
            return

        try:
            config = self._load_config_dict()
            pi = config.get("prompt_injection", {})
            if not isinstance(pi, dict):
                pi = {}

            pi["ml_engines"] = engines

            try:
                threshold_input = self.query_one("#ml-threshold-input", Input)
                threshold = int(threshold_input.value) if threshold_input.value else 2
                pi["consensus_threshold"] = max(1, threshold)
            except Exception:
                pass

            config["prompt_injection"] = pi
            self._save_config_dict(config)
            self.app.notify(
                f"Saved {len(engines)} ML engine(s)", severity="information"
            )
        except Exception as e:
            self.app.notify(f"Save failed: {e}", severity="error")

    def action_reload(self) -> None:
        self.load_config()
        self.app.notify("Reloaded from disk", severity="information")

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("ML engines config refreshed", severity="information")

    def _save_strategy(self, strategy: str) -> None:
        try:
            config = self._load_config_dict()
            pi = config.get("prompt_injection", {})
            if not isinstance(pi, dict):
                pi = {}
            pi["ml_strategy"] = strategy
            config["prompt_injection"] = pi
            self._save_config_dict(config)
            self.app.notify(f"Strategy set to: {strategy}", severity="success")
        except Exception as e:
            self.app.notify(f"Error saving strategy: {e}", severity="error")

    def _save_fallback(self, fallback: str) -> None:
        try:
            config = self._load_config_dict()
            pi = config.get("prompt_injection", {})
            if not isinstance(pi, dict):
                pi = {}
            pi["fallback_on_error"] = fallback
            config["prompt_injection"] = pi
            self._save_config_dict(config)
            self.app.notify(f"Fallback set to: {fallback}", severity="success")
        except Exception as e:
            self.app.notify(f"Error saving fallback: {e}", severity="error")

    def _load_config_dict(self) -> dict:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _save_config_dict(self, config: dict) -> None:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"
        if config_path.exists():
            backup_path = config_path.with_suffix(".json.bak")
            shutil.copy2(config_path, backup_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
