#!/usr/bin/env python3
"""
Prompt Injection Detection Settings

Core detection settings: enabled toggle, action, detector, sensitivity,
score threshold, ignore files, and ignore tools.
"""

import json
from typing import Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Input, Label, Select

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.widgets import TimeBasedToggle


class PIDetectionContent(Container):
    """Content widget for Prompt Injection Detection Settings."""

    CSS = """
    PIDetectionContent {
        height: 100%;
    }

    #pi-detection-header {
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

    .setting-row {
        margin: 0.5 0;
        height: auto;
    }

    .setting-row Label {
        margin: 0 1 0 0;
        width: 20;
    }

    .setting-row Select {
        width: 40;
    }

    .setting-row Input {
        width: 50;
    }

    #ignore-files-list, #ignore-tools-list {
        margin: 1 0;
        padding: 1;
        background: $surface;
        border: solid $primary;
        min-height: 4;
    }

    Input:focus {
        border-left: heavy $accent;
        text-style: bold;
    }

    Select:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold]Prompt Injection — Detection Settings[/bold]", id="pi-detection-header")

        with VerticalScroll():
            yield TimeBasedToggle(
                title="Prompt Injection Detection",
                config_key="prompt_injection_enabled",
                current_value=True,
                help_text="Protects against prompt injection attacks that try to manipulate AI behavior",
                id="prompt_injection_enabled_toggle",
            )

            with Container(classes="section"):
                yield Static("[bold]Detection Engine[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Detector:")
                    yield Select(
                        [
                            ("Heuristic (fast, local)", "heuristic"),
                            ("Rebuff (ML-based)", "rebuff"),
                            ("LLM Guard", "llm-guard"),
                        ],
                        value="heuristic",
                        id="detector-select",
                    )

                with Horizontal(classes="setting-row"):
                    yield Label("Sensitivity:")
                    yield Select(
                        [("Low", "low"), ("Medium", "medium"), ("High", "high")],
                        value="medium",
                        id="sensitivity-select",
                    )

                with Horizontal(classes="setting-row"):
                    yield Label("Score Threshold:")
                    yield Input(placeholder="0.75", id="score-threshold-input")
                    yield Static("[dim]0.0-1.0 (press Enter to save)[/dim]")

            with Container(classes="section"):
                yield Static("[bold]Action on Detection[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Action Mode:")
                    yield Select(
                        [
                            ("Block (prevent execution)", "block"),
                            ("Warn (allow with warning)", "warn"),
                            ("Log Only (silent logging)", "log-only"),
                        ],
                        value="block",
                        id="pi-action-select",
                    )

                yield Static(
                    "[dim]  block: Prevent execution entirely (default)\n"
                    "  warn: Log violation and show warning but allow\n"
                    "  log-only: Log violation silently[/dim]",
                    classes="setting-row",
                )

            with Container(classes="section"):
                yield Static("[bold]Ignore Files[/bold]", classes="section-title")
                yield Static(
                    "[dim]Glob patterns for files to skip during scanning[/dim]",
                    classes="section-title",
                )
                yield Static("", id="ignore-files-list")
                yield Input(
                    placeholder="Enter glob pattern (e.g., tests/**, docs/*.md)",
                    id="pi-ignore-file-input",
                )

            with Container(classes="section"):
                yield Static("[bold]Ignore Tools[/bold]", classes="section-title")
                yield Static(
                    "[dim]Tool names to skip during scanning[/dim]",
                    classes="section-title",
                )
                yield Static("", id="ignore-tools-list")
                yield Input(
                    placeholder="Enter tool name to ignore",
                    id="pi-ignore-tool-input",
                )

            with Container(classes="section"):
                yield Static("[bold]Detection Statistics[/bold]", classes="section-title")
                yield Static("", id="pi-detection-stats")

    def on_mount(self) -> None:
        self.load_config()

    def refresh_content(self) -> None:
        self.load_config()

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("Detection settings refreshed", severity="information")

    def action_update_sensitivity(self) -> None:
        self._save_settings()

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

        pi_config = config.get("prompt_injection", {})
        enabled_value = pi_config.get("enabled", True)
        detector = pi_config.get("detector", "heuristic")
        sensitivity = pi_config.get("sensitivity", "medium")
        score_threshold = pi_config.get("max_score_threshold", 0.75)
        action = pi_config.get("action", "block")
        ignore_files = pi_config.get("ignore_files", [])
        ignore_tools = pi_config.get("ignore_tools", [])

        try:
            toggle = self.query_one("#prompt_injection_enabled_toggle", TimeBasedToggle)
            toggle.load_value(enabled_value)
        except Exception:
            pass

        try:
            self.query_one("#detector-select", Select).value = detector
            self.query_one("#sensitivity-select", Select).value = sensitivity
            self.query_one("#score-threshold-input", Input).value = str(score_threshold)
            self.query_one("#pi-action-select", Select).value = action
        except Exception:
            pass

        files_text = "\n".join(f"  {f}" for f in ignore_files) if ignore_files else "[dim]No ignore patterns configured[/dim]"
        tools_text = "\n".join(f"  {t}" for t in ignore_tools) if ignore_tools else "[dim]No ignored tools configured[/dim]"
        try:
            self.query_one("#ignore-files-list", Static).update(files_text)
            self.query_one("#ignore-tools-list", Static).update(tools_text)
        except Exception:
            pass

        self._load_statistics()

    def _load_statistics(self) -> None:
        try:
            from ai_guardian.violation_logger import ViolationLogger
            logger = ViolationLogger()
            violations = logger.get_recent_violations(limit=1000, violation_type="prompt_injection", resolved=None)
            total = len(violations)
            unresolved = len([v for v in violations if not v.get("resolved", False)])
            self.query_one("#pi-detection-stats", Static).update(
                f"Total prompt injection violations: {total}\nUnresolved: {unresolved}"
            )
        except Exception as e:
            self.query_one("#pi-detection-stats", Static).update(f"[dim]Error: {e}[/dim]")

    def _save_field(self, field: str, value) -> None:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"
        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            if "prompt_injection" not in config:
                config["prompt_injection"] = {}
            config["prompt_injection"][field] = value
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            self.app.notify(f"Saved {field}", severity="success")
        except Exception as e:
            self.app.notify(f"Error saving {field}: {e}", severity="error")

    def _save_settings(self) -> None:
        try:
            detector = self.query_one("#detector-select", Select).value
            sensitivity = self.query_one("#sensitivity-select", Select).value
            config_dir = get_config_dir()
            config_path = config_dir / "ai-guardian.json"
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            if "prompt_injection" not in config:
                config["prompt_injection"] = {}
            config["prompt_injection"]["detector"] = detector
            config["prompt_injection"]["sensitivity"] = sensitivity
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            self.app.notify(f"Updated detector: {detector}, sensitivity: {sensitivity}", severity="success")
        except Exception as e:
            self.app.notify(f"Error: {e}", severity="error")

    def on_select_changed(self, event) -> None:
        sid = event.select.id
        if sid == "pi-action-select":
            self._save_field("action", event.value)
        elif sid and "prompt_injection_enabled" in sid:
            toggle = self.query_one("#prompt_injection_enabled_toggle", TimeBasedToggle)
            if toggle.current_mode == "temp_disabled":
                return
            self._save_field("enabled", toggle.get_value())

    def on_input_submitted(self, event: Input.Submitted) -> None:
        iid = event.input.id
        if iid and "prompt_injection_enabled" in iid:
            toggle = self.query_one("#prompt_injection_enabled_toggle", TimeBasedToggle)
            self._save_field("enabled", toggle.get_value())
        elif iid == "score-threshold-input":
            try:
                val = float(event.value)
                if 0.0 <= val <= 1.0:
                    self._save_field("max_score_threshold", val)
                else:
                    self.app.notify("Must be between 0.0 and 1.0", severity="error")
            except ValueError:
                self.app.notify("Must be a number", severity="error")
        elif iid == "pi-ignore-file-input":
            self._add_list_item("ignore_files", event.input)
        elif iid == "pi-ignore-tool-input":
            self._add_list_item("ignore_tools", event.input)

    def _add_list_item(self, field: str, input_widget: Input) -> None:
        value = input_widget.value.strip()
        if not value:
            self.app.notify("Please enter a value", severity="error")
            return
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"
        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            if "prompt_injection" not in config:
                config["prompt_injection"] = {}
            if field not in config["prompt_injection"]:
                config["prompt_injection"][field] = []
            if value in config["prompt_injection"][field]:
                self.app.notify("Already in list", severity="warning")
                return
            config["prompt_injection"][field].append(value)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            input_widget.value = ""
            self.load_config()
            self.app.notify(f"Added to {field}: {value}", severity="success")
        except Exception as e:
            self.app.notify(f"Error: {e}", severity="error")
