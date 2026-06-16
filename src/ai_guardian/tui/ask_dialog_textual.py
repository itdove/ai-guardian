"""Textual (terminal TUI) implementation of the ask dialog.

Terminal-based dialog for ask mode decisions with pattern editor
and inline config editor using TextArea.
"""

from ai_guardian.tui.ask_dialog import (
    AskDecision,
    AskViolationInfo,
    AskResult,
    _write_config_text,
)


class _TextualAskDialog:
    """Terminal-based ask dialog using Textual."""

    def __init__(self, violation: AskViolationInfo, timeout_seconds: int = 300):
        self._violation = violation
        self._timeout = timeout_seconds
        self._result = AskResult(decision=AskDecision.BLOCK)

    def run(self) -> AskResult:
        from textual.app import App, ComposeResult
        from textual.containers import Container, Horizontal, Vertical
        from textual.widgets import Static, Button, Input, Select, Header, Footer, TextArea
        from textual.binding import Binding

        violation = self._violation
        dialog_self = self

        class AskApp(App):
            CSS = """
            Screen {
                align: center middle;
            }
            #ask-container {
                width: 80;
                max-height: 40;
                border: solid $primary;
                background: $panel;
                padding: 1 2;
            }
            #title {
                text-style: bold;
                margin: 0 0 1 0;
            }
            .detail-row {
                height: auto;
                margin: 0 0 0 0;
            }
            #matched-text {
                height: 4;
                border: solid $accent;
                background: $surface;
                padding: 0 1;
                margin: 1 0;
            }
            #button-bar {
                height: auto;
                margin: 1 0 0 0;
            }
            #button-bar Button {
                margin: 0 1 0 0;
            }
            #editor-section {
                display: none;
                border: solid $accent;
                padding: 1;
                margin: 1 0;
            }
            #editor-section.visible {
                display: block;
            }
            #editor-status {
                margin: 0 0 1 0;
            }
            #editor-preview {
                height: 6;
                border: solid $primary;
                background: $surface;
                padding: 0 1;
            }
            """

            BINDINGS = [Binding("escape", "quit", "Block & Close")]

            def compose(self) -> ComposeResult:
                v = violation
                yield Header(show_clock=False)
                with Container(id="ask-container"):
                    yield Static("[bold]ai-guardian: Violation Detected[/bold]", id="title")
                    yield Static(f"[bold]Type:[/bold] {v.violation_type}", classes="detail-row")
                    yield Static(f"[bold]Summary:[/bold] {v.summary}", classes="detail-row")
                    if v.file_path:
                        loc = v.file_path
                        if v.line_number:
                            loc += f":{v.line_number}"
                        yield Static(f"[bold]Location:[/bold] {loc}", classes="detail-row")
                    yield Static(v.matched_text[:300], id="matched-text")

                    with Horizontal(id="button-bar"):
                        yield Button("Allow Once", id="btn-allow-once", variant="primary")
                        yield Button("Allow Always...", id="btn-allow-always", variant="success")
                        yield Button("Block", id="btn-block", variant="error")

                    with Container(id="editor-section"):
                        yield Static("[bold]Pattern Editor[/bold]")
                        yield Input(
                            placeholder="Enter pattern",
                            id="pattern-input",
                        )
                        yield Static("", id="editor-status")
                        yield Button("Test Pattern", id="btn-test", variant="default")
                        yield Static("", id="editor-preview")
                        with Horizontal():
                            yield Button("Add to Allowlist", id="btn-confirm", variant="success")
                            yield Button("Cancel Editor", id="btn-cancel-editor", variant="default")

                yield Footer()

            def on_mount(self):
                from ai_guardian.tui.pattern_editor import suggest_pattern
                try:
                    self.query_one("#pattern-input", Input).value = suggest_pattern(violation.matched_text, violation.config_section)
                except Exception:
                    pass

            def on_button_pressed(self, event: Button.Pressed):
                bid = event.button.id
                if bid == "btn-allow-once":
                    dialog_self._result = AskResult(decision=AskDecision.ALLOW_ONCE)
                    self.exit()
                elif bid == "btn-block":
                    dialog_self._result = AskResult(decision=AskDecision.BLOCK)
                    self.exit()
                elif bid == "btn-allow-always":
                    self._show_editor()
                elif bid == "btn-test":
                    self._test_pattern()
                elif bid == "btn-confirm":
                    self._confirm_pattern()
                elif bid == "btn-cancel-editor":
                    self._hide_editor()
                elif bid == "btn-save-config":
                    self._save_config_editor()
                elif bid == "btn-cancel-config":
                    self._hide_config_editor()

            def on_input_changed(self, event: Input.Changed):
                if event.input.id == "pattern-input":
                    if hasattr(self, '_debounce_timer') and self._debounce_timer is not None:
                        self._debounce_timer.stop()
                    self._debounce_timer = self.set_timer(0.3, self._test_pattern)

            def _show_editor(self):
                try:
                    section = self.query_one("#editor-section")
                    section.add_class("visible")
                    self._test_pattern()
                except Exception:
                    pass

            def _hide_editor(self):
                try:
                    section = self.query_one("#editor-section")
                    section.remove_class("visible")
                except Exception:
                    pass

            def _test_pattern(self):
                from ai_guardian.tui.pattern_editor import (
                    validate_pattern, generate_config_preview,
                    get_pattern_type_for_section,
                )
                try:
                    pat = self.query_one("#pattern-input", Input).value.strip()
                    ptype = get_pattern_type_for_section(violation.config_section)
                    valid, msg = validate_pattern(pat, ptype, violation.matched_text)
                    status = self.query_one("#editor-status", Static)
                    preview = self.query_one("#editor-preview", Static)
                    if valid:
                        status.update(f"[green]PASS: {msg}[/green]")
                        preview.update(generate_config_preview(pat, violation.config_section))
                    else:
                        status.update(f"[red]FAIL: {msg}[/red]")
                        preview.update("")
                except Exception:
                    pass

            def _confirm_pattern(self):
                from ai_guardian.tui.pattern_editor import validate_pattern, get_pattern_type_for_section
                try:
                    pat = self.query_one("#pattern-input", Input).value.strip()
                    ptype = get_pattern_type_for_section(violation.config_section)
                    valid, _ = validate_pattern(pat, ptype, violation.matched_text)
                    if not valid:
                        self.query_one("#editor-status", Static).update(
                            "[red]FAIL: Fix the pattern before confirming[/red]"
                        )
                        return
                    self._pending_save_pat = pat
                    self._show_config_editor(pat)
                except Exception:
                    pass

            def _show_config_editor(self, save_pat):
                from ai_guardian.tui.pattern_editor import prepare_config_with_pattern
                try:
                    json_text, line_number = prepare_config_with_pattern(save_pat, violation.config_section)
                    section = self.query_one("#editor-section")
                    section.remove_class("visible")
                    container = self.query_one("#ask-container")
                    for child in list(container.children):
                        child.remove()
                    container.mount(Static("[bold]Config Editor — ai-guardian.json[/bold]", id="title"))
                    container.mount(Static("[dim]Review the config, then Save or Cancel.[/dim]"))
                    config_area = TextArea(
                        json_text, language="json",
                        show_line_numbers=True, tab_behavior="indent",
                        id="config-text-editor",
                    )
                    container.mount(config_area)
                    container.mount(Static("Valid JSON", id="config-editor-status"))
                    with Horizontal(id="button-bar") as bar:
                        pass
                    container.mount(bar)
                    bar.mount(Button("Save", id="btn-save-config", variant="success"))
                    bar.mount(Button("Cancel", id="btn-cancel-config", variant="default"))
                    config_area.cursor_location = (line_number - 1, 0)
                    config_area.scroll_cursor_visible(center=True)
                except Exception:
                    self.exit()

            def _save_config_editor(self):
                import json as json_mod
                try:
                    text = self.query_one("#config-text-editor", TextArea).text
                    try:
                        json_mod.loads(text)
                    except json_mod.JSONDecodeError as e:
                        self.query_one("#config-editor-status", Static).update(
                            f"[red]Invalid JSON: {e}[/red]"
                        )
                        return
                    if _write_config_text(text):
                        dialog_self._result = AskResult(
                            decision=AskDecision.ALLOW_ALWAYS,
                            allowlist_pattern=self._pending_save_pat,
                            config_saved=True,
                        )
                        self.exit()
                    else:
                        self.query_one("#config-editor-status", Static).update(
                            "[red]Failed to write config file[/red]"
                        )
                except Exception:
                    pass

            def _hide_config_editor(self):
                self.exit()

            def action_quit(self):
                dialog_self._result = AskResult(decision=AskDecision.BLOCK)
                self.exit()

        AskApp().run()
        return self._result
