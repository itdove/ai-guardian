"""
Context Poisoning Detection Settings (LLM03)

Settings: enabled toggle, action, sensitivity, ignore files, and ignore tools.
"""

import json

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Button, Input, Label, Select

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.schema_defaults import (
    SchemaDefaultsMixin, default_indicator,
    select_options_with_default,
)
from ai_guardian.tui.widgets import TimeBasedToggle, sanitize_enabled_value


class CPDetectionContent(SchemaDefaultsMixin, Container):
    """Content widget for Context Poisoning Detection Settings."""

    SCHEMA_SECTION = "context_poisoning"
    SCHEMA_FIELDS = [
        ("cp-sensitivity-select", "sensitivity", "select"),
        ("cp-action-select", "action", "select"),
    ]

    CSS = """
    CPDetectionContent {
        height: 100%;
    }

    #cp-detection-header {
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

    #cp-ignore-files-list, #cp-ignore-tools-list {
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
        yield Static("[bold]Context Poisoning — Detection Settings (LLM03)[/bold]", id="cp-detection-header")

        with VerticalScroll():
            yield TimeBasedToggle(
                title="Context Poisoning Detection",
                config_key="context_poisoning_enabled",
                current_value=True,
                help_text="Detect persistent instruction injection in prompts and file reads (OWASP LLM03)",
                id="context_poisoning_enabled_toggle",
            )

            with Container(classes="section"):
                yield Static("[bold]Action on Detection[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Action Mode:")
                    yield Select(
                        select_options_with_default(
                            [
                                ("Warn (allow with warning)", "warn"),
                                ("Block (prevent execution)", "block"),
                                ("Ask (block if headless)", "ask"),
                                ("Ask (warn if headless)", "ask:warn"),
                                ("Ask (log-only if headless)", "ask:log-only"),
                                ("Log Only (silent)", "log-only"),
                            ],
                            "context_poisoning.action",
                        ),
                        id="cp-action-select",
                        allow_blank=False,
                    )
                yield Static(
                    f"[dim]'Warn' recommended due to false positives[/dim] "
                    f"{default_indicator('context_poisoning.action')}"
                )

            with Container(classes="section"):
                yield Static("[bold]Sensitivity[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Sensitivity:")
                    yield Select(
                        select_options_with_default(
                            [
                                ("Low — dangerous combinations only", "low"),
                                ("Medium — balanced", "medium"),
                                ("High — any persistence keyword", "high"),
                            ],
                            "context_poisoning.sensitivity",
                        ),
                        id="cp-sensitivity-select",
                        allow_blank=False,
                    )
                yield Static(
                    f"{default_indicator('context_poisoning.sensitivity')}"
                )

            with Container(classes="section"):
                yield Static("[bold]Ignore Files[/bold]", classes="section-title")
                yield Static(
                    "[dim]Glob patterns for files to skip during scanning[/dim]",
                    classes="section-title",
                )
                yield Static("", id="cp-ignore-files-list")
                yield Input(
                    placeholder="Enter glob pattern (e.g., tests/**, docs/*.md)",
                    id="cp-ignore-file-input",
                )

            with Container(classes="section"):
                yield Static("[bold]Ignore Tools[/bold]", classes="section-title")
                yield Static(
                    "[dim]Tool names to skip during scanning[/dim]",
                    classes="section-title",
                )
                yield Static("", id="cp-ignore-tools-list")
                yield Input(
                    placeholder="Enter tool name to ignore",
                    id="cp-ignore-tool-input",
                )

            with Container(classes="section"):
                yield Static("[bold]Detection Statistics[/bold]", classes="section-title")
                yield Static("", id="cp-detection-stats")

    def on_mount(self) -> None:
        self._loading = False
        self.load_config()

    def refresh_content(self) -> None:
        self.load_config()

    def load_config(self) -> None:
        self._loading = True
        try:
            self._do_load_config()
        finally:
            self._loading = False

    def _do_load_config(self) -> None:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        config = {}
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except Exception as e:
                self.app.notify(f"Error loading config: {e}", severity="error")

        cp_config = config.get("context_poisoning", {})
        enabled_value = cp_config.get("enabled", True)
        sensitivity = cp_config.get("sensitivity", "medium")
        action = cp_config.get("action", "warn")
        ignore_files = cp_config.get("ignore_files", [])
        ignore_tools = cp_config.get("ignore_tools", [])

        try:
            toggle = self.query_one("#context_poisoning_enabled_toggle", TimeBasedToggle)
            toggle.load_value(enabled_value)
        except Exception:
            pass

        try:
            self.query_one("#cp-sensitivity-select", Select).value = sensitivity
            self.query_one("#cp-action-select", Select).value = action
        except Exception:
            pass

        files_text = "\n".join(f"  {f}" for f in ignore_files) if ignore_files else "[dim]No ignore patterns configured[/dim]"
        tools_text = "\n".join(f"  {t}" for t in ignore_tools) if ignore_tools else "[dim]No ignored tools configured[/dim]"
        try:
            self.query_one("#cp-ignore-files-list", Static).update(files_text)
            self.query_one("#cp-ignore-tools-list", Static).update(tools_text)
        except Exception:
            pass

        self._apply_default_indicators(cp_config)
        self._load_statistics()

    def _load_statistics(self) -> None:
        try:
            from ai_guardian.violation_logger import ViolationLogger
            logger = ViolationLogger()
            violations = logger.get_recent_violations(limit=1000, violation_type="context_poisoning", resolved=None)
            total = len(violations)
            unresolved = len([v for v in violations if not v.get("resolved", False)])
            self.query_one("#cp-detection-stats", Static).update(
                f"Total context poisoning violations: {total}\nUnresolved: {unresolved}"
            )
        except Exception as e:
            self.query_one("#cp-detection-stats", Static).update(f"[dim]Error: {e}[/dim]")

    def _save_field(self, field: str, value) -> None:
        if field == "enabled":
            value = sanitize_enabled_value(value)
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"
        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            if "context_poisoning" not in config:
                config["context_poisoning"] = {}
            config["context_poisoning"][field] = value
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            self.app.notify(f"Saved {field}", severity="success")
        except Exception as e:
            self.app.notify(f"Error saving {field}: {e}", severity="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if getattr(self, '_loading', False):
            return
        bid = event.button.id
        if bid and "context_poisoning_enabled" in bid:
            toggle = self.query_one("#context_poisoning_enabled_toggle", TimeBasedToggle)
            if toggle.current_mode == "temp_disabled":
                return
            self._save_field("enabled", toggle.get_value())

    def on_select_changed(self, event) -> None:
        if getattr(self, '_loading', False):
            return
        sid = event.select.id
        if sid == "cp-action-select":
            self._save_field("action", event.value)
        elif sid == "cp-sensitivity-select":
            self._save_field("sensitivity", event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if getattr(self, '_loading', False):
            return
        iid = event.input.id
        if iid and "context_poisoning_enabled" in iid:
            toggle = self.query_one("#context_poisoning_enabled_toggle", TimeBasedToggle)
            self._save_field("enabled", toggle.get_value())
        elif iid == "cp-ignore-file-input":
            self._add_list_item("ignore_files", event.input)
        elif iid == "cp-ignore-tool-input":
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
            if "context_poisoning" not in config:
                config["context_poisoning"] = {}
            if field not in config["context_poisoning"]:
                config["context_poisoning"][field] = []
            if value in config["context_poisoning"][field]:
                self.app.notify("Already in list", severity="warning")
                return
            config["context_poisoning"][field].append(value)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            input_widget.value = ""
            self.load_config()
            self.app.notify(f"Added to {field}: {value}", severity="success")
        except Exception as e:
            self.app.notify(f"Error: {e}", severity="error")
