"""
Hook Simulator Panel

Simulate hook events (UserPromptSubmit, PreToolUse, PostToolUse) and see
how ai-guardian would respond — without triggering real hooks or logging
violations.
"""

import json
import logging
import os
import sys
import tempfile
from io import StringIO
from unittest.mock import patch as mock_patch

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.widgets import Static, Input, Button, Select, TextArea


HOOK_EVENTS = [
    ("UserPromptSubmit", "UserPromptSubmit"),
    ("PreToolUse", "PreToolUse"),
    ("PostToolUse", "PostToolUse"),
]

TOOL_OPTIONS = [
    ("Read", "Read"),
    ("Bash", "Bash"),
    ("Edit", "Edit"),
    ("Write", "Write"),
    ("Grep", "Grep"),
    ("Glob", "Glob"),
    ("WebFetch", "WebFetch"),
    ("Skill", "Skill"),
    ("mcp__custom", "mcp__custom"),
]

IDE_OPTIONS = [
    ("Claude Code", "claude"),
    ("Cursor", "cursor"),
    ("GitHub Copilot", "copilot"),
]


def build_hook_data(hook_event, tool_name=None, file_path=None, content=""):
    """Build the JSON dict that an IDE would send to ai-guardian.

    Args:
        hook_event: One of UserPromptSubmit, PreToolUse, PostToolUse.
        tool_name: Tool name (required for PreToolUse/PostToolUse).
        file_path: Optional file path for tool-use hooks.
        content: The text to scan.

    Returns:
        dict matching the hook input schema.
    """
    hook_data = {"hook_event_name": hook_event}

    if hook_event == "UserPromptSubmit":
        hook_data["prompt"] = content
    elif hook_event == "PreToolUse":
        parameters = {}
        if file_path:
            parameters["file_path"] = file_path
        if tool_name == "Bash":
            parameters["command"] = content
        elif not parameters.get("file_path"):
            parameters["file_path"] = file_path or ""
        hook_data["tool_use"] = {
            "name": tool_name or "Read",
            "parameters": parameters,
        }
    elif hook_event == "PostToolUse":
        hook_data["tool_name"] = tool_name or "Bash"
        hook_data["tool_response"] = {"output": content}

    return hook_data


def parse_simulation_result(result):
    """Parse the dict returned by process_hook_input() into display fields.

    Args:
        result: Dict with 'output' (JSON string or None) and 'exit_code'.

    Returns:
        dict with keys:
            decision: "BLOCKED" | "ALLOWED" | "ALLOWED WITH WARNING"
            reason: str or None
            redacted_output: str or None
            raw_json: str (pretty-printed JSON)
    """
    output_str = result.get("output")
    exit_code = result.get("exit_code", 0)

    if output_str is None:
        decision = "BLOCKED" if exit_code == 2 else "ALLOWED"
        return {
            "decision": decision,
            "reason": None,
            "redacted_output": None,
            "raw_json": json.dumps({"exit_code": exit_code}, indent=2),
        }

    try:
        output = json.loads(output_str)
    except (json.JSONDecodeError, TypeError):
        return {
            "decision": "BLOCKED" if exit_code == 2 else "ALLOWED",
            "reason": output_str,
            "redacted_output": None,
            "raw_json": output_str,
        }

    reason = None
    redacted_output = None

    is_blocked = False
    if output.get("decision") == "block":
        is_blocked = True
        reason = output.get("reason")
    elif "hookSpecificOutput" in output:
        hso = output["hookSpecificOutput"]
        if hso.get("permissionDecision") == "deny":
            is_blocked = True
            reason = output.get("systemMessage")
        if "updatedToolOutput" in hso:
            redacted_output = hso["updatedToolOutput"]
    if not is_blocked and output.get("permission") == "deny":
        is_blocked = True
        reason = output.get("user_message")
    if not is_blocked and output.get("continue") is False:
        is_blocked = True
        reason = output.get("user_message")
    if not is_blocked and output.get("permissionDecision") == "deny":
        is_blocked = True
        reason = output.get("permissionDecisionReason")

    if not reason and output.get("systemMessage"):
        reason = output.get("systemMessage")

    if is_blocked:
        decision = "BLOCKED"
    elif output.get("systemMessage") or redacted_output:
        decision = "ALLOWED WITH WARNING"
    else:
        decision = "ALLOWED"

    return {
        "decision": decision,
        "reason": reason,
        "redacted_output": redacted_output,
        "raw_json": json.dumps(output, indent=2),
    }


class HookSimulatorContent(ScrollableContainer):
    """Interactive hook event simulator for testing detection rules."""

    CSS = """
    HookSimulatorContent {
        overflow-x: hidden;
    }

    #sim-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    .sim-section {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    .sim-section-title {
        margin: 0 0 1 0;
        text-style: bold;
    }

    .sim-row {
        margin: 0 0 1 0;
        height: auto;
    }

    .sim-row Select {
        width: 40;
    }

    .sim-row Input {
        width: 1fr;
    }

    .sim-label {
        width: 16;
        margin: 0 1 0 0;
    }

    #sim-content-area {
        height: 10;
        margin: 0 0 1 0;
    }

    #sim-run-btn {
        margin: 0 2 0 0;
    }

    #sim-ide-select {
        width: 30;
    }

    #sim-decision {
        margin: 0 0 1 0;
    }

    #sim-details {
        margin: 0 0 1 0;
    }

    #sim-redacted-section {
        margin: 0 0 1 0;
    }

    #sim-raw-json {
        margin: 1 0 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Hook Simulator[/bold]  "
            "[dim]Test detection rules without triggering real hooks[/dim]",
            id="sim-header",
        )

        with Container(id="sim-input-section", classes="sim-section"):
            yield Static("Input", classes="sim-section-title")

            with Horizontal(classes="sim-row"):
                yield Static("Hook Event", classes="sim-label")
                yield Select(
                    HOOK_EVENTS,
                    value="UserPromptSubmit",
                    id="sim-hook-event",
                    allow_blank=False,
                )

            with Container(id="sim-tool-section"):
                with Horizontal(classes="sim-row"):
                    yield Static("Tool", classes="sim-label")
                    yield Select(
                        TOOL_OPTIONS,
                        value="Read",
                        id="sim-tool-name",
                        allow_blank=False,
                    )

            with Container(id="sim-filepath-section"):
                with Horizontal(classes="sim-row"):
                    yield Static("File Path", classes="sim-label")
                    yield Input(
                        placeholder="/path/to/file.py",
                        id="sim-file-path",
                    )

            yield Static(
                "[dim]Content / Prompt — enter text to scan[/dim]",
                classes="sim-row",
            )
            yield TextArea(id="sim-content-area")

            with Horizontal(id="sim-action-row", classes="sim-row"):
                yield Button(
                    "Run Simulation",
                    variant="primary",
                    id="sim-run-btn",
                )
                yield Select(
                    IDE_OPTIONS,
                    value="claude",
                    id="sim-ide-select",
                    allow_blank=False,
                )

        with Container(id="sim-results-section", classes="sim-section"):
            yield Static("Results", classes="sim-section-title")
            yield Static("", id="sim-decision")
            yield Static("", id="sim-details")

            with Container(id="sim-redacted-section"):
                yield Static(
                    "[bold]Redacted Output:[/bold]",
                    classes="sim-row",
                )
                yield Static("", id="sim-redacted-text")

            yield Static("[bold]Raw Response:[/bold]", classes="sim-row")
            yield Static("", id="sim-raw-json")

    def on_mount(self) -> None:
        self._last_hook_data = None
        self._last_result = None
        self._update_field_visibility("UserPromptSubmit")
        for widget_id in (
            "#sim-input-section",
            "#sim-results-section", "#sim-redacted-section",
            "#sim-tool-section", "#sim-filepath-section",
        ):
            w = self.query_one(widget_id)
            w.styles.height = "auto"
        self.query_one("#sim-results-section").display = False
        self.query_one("#sim-redacted-section").display = False

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "sim-hook-event":
            self._update_field_visibility(event.value)
        elif event.select.id == "sim-ide-select":
            if self._last_hook_data is not None:
                self._rerun_for_ide(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "sim-run-btn":
            self._run_simulation()

    def refresh_content(self) -> None:
        self._clear_results()

    def action_refresh(self) -> None:
        self._clear_results()

    def _update_field_visibility(self, hook_event):
        show_tool_fields = hook_event != "UserPromptSubmit"
        self.query_one("#sim-tool-section").display = show_tool_fields
        self.query_one("#sim-filepath-section").display = show_tool_fields

    def _run_simulation(self):
        hook_event = self.query_one("#sim-hook-event", Select).value
        if hook_event is Select.BLANK:
            return

        content = self.query_one("#sim-content-area", TextArea).text

        tool_name = None
        file_path = None
        if hook_event in ("PreToolUse", "PostToolUse"):
            tool_val = self.query_one("#sim-tool-name", Select).value
            tool_name = tool_val if tool_val is not Select.BLANK else "Read"
            file_path = self.query_one("#sim-file-path", Input).value.strip() or None

        hook_data = build_hook_data(hook_event, tool_name, file_path, content)
        self._last_hook_data = hook_data

        ide_val = self.query_one("#sim-ide-select", Select).value
        ide_type = ide_val if ide_val is not Select.BLANK else "claude"

        result = self._execute_simulation(hook_data, ide_type)
        if result is None:
            return

        self._last_result = result
        self._display_results(result)

    def _rerun_for_ide(self, ide_type):
        if self._last_hook_data is None:
            return

        result = self._execute_simulation(self._last_hook_data, ide_type)
        if result is None:
            return

        self._last_result = result
        parsed = parse_simulation_result(result)
        self.query_one("#sim-raw-json", Static).update(
            f"[dim]```json[/dim]\n{parsed['raw_json']}\n[dim]```[/dim]"
        )

    def _execute_simulation(self, hook_data, ide_type="claude"):
        import ai_guardian

        ide_env_map = {
            "claude": "claude",
            "cursor": "cursor",
            "copilot": "github_copilot",
        }

        with tempfile.TemporaryDirectory() as tmp_state:
            env_overrides = {
                "AI_GUARDIAN_STATE_DIR": tmp_state,
                "AI_GUARDIAN_IDE_TYPE": ide_env_map.get(ide_type, "claude"),
            }

            stdin_data = json.dumps(hook_data)
            devnull = StringIO()

            with mock_patch.dict(os.environ, env_overrides):
                with mock_patch("sys.stdin", StringIO(stdin_data)), \
                     mock_patch("sys.stderr", devnull), \
                     mock_patch("sys.stdout", devnull):
                    logging.disable(logging.CRITICAL)
                    try:
                        result = ai_guardian.process_hook_input()
                    except Exception as exc:
                        logging.disable(logging.NOTSET)
                        self._show_error(str(exc))
                        return None
                    finally:
                        logging.disable(logging.NOTSET)

        return result

    def _display_results(self, result):
        parsed = parse_simulation_result(result)

        w = self.query_one("#sim-results-section")
        w.display = True
        w.styles.height = "auto"

        decision_widget = self.query_one("#sim-decision", Static)
        if parsed["decision"] == "BLOCKED":
            decision_widget.update("[red bold]BLOCKED[/red bold]")
        elif parsed["decision"] == "ALLOWED WITH WARNING":
            decision_widget.update(
                "[#d4aa00 bold]ALLOWED WITH WARNING[/#d4aa00 bold]"
            )
        else:
            decision_widget.update("[green bold]ALLOWED[/green bold]")

        details_widget = self.query_one("#sim-details", Static)
        if parsed["reason"]:
            details_widget.update(parsed["reason"])
        else:
            details_widget.update(
                "[dim]No detections — content passed all checks[/dim]"
            )

        if parsed["redacted_output"]:
            w = self.query_one("#sim-redacted-section")
            w.display = True
            w.styles.height = "auto"
            self.query_one("#sim-redacted-text", Static).update(
                parsed["redacted_output"]
            )
        else:
            self.query_one("#sim-redacted-section").display = False

        self.query_one("#sim-raw-json", Static).update(
            f"[dim]```json[/dim]\n{parsed['raw_json']}\n[dim]```[/dim]"
        )

    def _show_error(self, message):
        w = self.query_one("#sim-results-section")
        w.display = True
        w.styles.height = "auto"

        self.query_one("#sim-decision", Static).update(
            "[red bold]ERROR[/red bold]"
        )
        self.query_one("#sim-details", Static).update(message)

    def _clear_results(self):
        self._last_hook_data = None
        self._last_result = None

        self.query_one("#sim-results-section").display = False
        self.query_one("#sim-redacted-section").display = False

        self.query_one("#sim-decision", Static).update("")
        self.query_one("#sim-details", Static).update("")
        self.query_one("#sim-redacted-text", Static).update("")
        self.query_one("#sim-raw-json", Static).update("")

        self.query_one("#sim-content-area", TextArea).clear()
        self.query_one("#sim-file-path", Input).value = ""
        self.query_one("#sim-hook-event", Select).value = "UserPromptSubmit"
        self._update_field_visibility("UserPromptSubmit")
