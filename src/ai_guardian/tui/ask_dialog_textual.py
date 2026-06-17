"""Textual (terminal TUI) implementation of the ask dialog.

Terminal-based dialog for ask mode decisions with pattern editor
and inline config editor using TextArea.
"""

from ai_guardian.tui.ask_dialog import (
    AskDecision,
    AskViolationInfo,
    AskResult,
    _write_config_text,
    _write_aiguardignore_text,
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
                        if v.file_path:
                            from ai_guardian.tui.source_annotator import get_comment_prefix
                            if get_comment_prefix(v.file_path) is not None:
                                yield Button("Suppress in Source...", id="btn-suppress-source", variant="warning")
                            yield Button("Ignore File...", id="btn-ignore-file", variant="warning")
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
                elif bid == "btn-suppress-source":
                    self._show_suppress_in_source()
                elif bid == "btn-ignore-file":
                    self._show_ignore_file()
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
                elif bid == "btn-save-source":
                    self._save_source_editor()
                elif bid == "btn-cancel-source":
                    self.exit()
                elif bid == "btn-save-ignore":
                    self._save_ignore_editor()
                elif bid == "btn-cancel-ignore":
                    self.exit()

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

            def _save_source_editor(self):
                from ai_guardian.tui.source_annotator import write_annotated_source
                try:
                    text = self.query_one("#source-text-editor", TextArea).text
                    if write_annotated_source(self._source_file_path, text):
                        dialog_self._result = AskResult(
                            decision=AskDecision.SUPPRESS_IN_SOURCE,
                            source_annotation_saved=True,
                        )
                        self.exit()
                    else:
                        self.query_one("#source-editor-status", Static).update(
                            "[red]Failed to write file[/red]"
                        )
                except Exception:
                    pass

            def _save_ignore_editor(self):
                try:
                    path = self.query_one("#ignore-path-input", Input).value.strip()
                    from ai_guardian.tui.ignore_file_editor import validate_ignore_path
                    valid, msg = validate_ignore_path(path)
                    if not valid:
                        self.query_one("#ignore-path-status", Static).update(f"[red]{msg}[/red]")
                        return
                    toml_text = self.query_one("#ignore-preview", TextArea).text
                    if _write_aiguardignore_text(toml_text):
                        dialog_self._result = AskResult(
                            decision=AskDecision.IGNORE_FILE,
                            ignore_path=path,
                            ignore_scanner_types=[self._ignore_config_section],
                            config_saved=True,
                        )
                        self.exit()
                    else:
                        self.query_one("#ignore-editor-status", Static).update(
                            "[red]Failed to write .aiguardignore.toml[/red]"
                        )
                except Exception:
                    pass

            def _hide_config_editor(self):
                self.exit()

            def _show_suppress_in_source(self):
                from ai_guardian.tui.source_annotator import prepare_annotation, write_annotated_source
                v = violation
                result = prepare_annotation(v.file_path, v.line_number or 1)
                if result is None:
                    return
                modified_content, highlight_line, annotation_type = result

                container = self.query_one("#ask-container")
                for child in list(container.children):
                    child.remove()

                ann_label = "inline" if annotation_type == "inline" else "block"
                container.mount(Static(
                    f"[bold]Suppress in Source — {ann_label}[/bold]\n"
                    f"File: {v.file_path}",
                    id="title",
                ))
                container.mount(Static("[dim]Review the annotated source. Save to write the file.[/dim]"))
                source_area = TextArea(
                    modified_content,
                    show_line_numbers=True, tab_behavior="indent",
                    id="source-text-editor",
                )
                container.mount(source_area)
                container.mount(Static("", id="source-editor-status"))
                with Horizontal(id="button-bar") as bar:
                    pass
                container.mount(bar)
                bar.mount(Button("Save", id="btn-save-source", variant="success"))
                bar.mount(Button("Cancel", id="btn-cancel-source", variant="default"))
                source_area.cursor_location = (max(0, highlight_line - 1), 0)
                source_area.scroll_cursor_visible(center=True)
                self._source_file_path = v.file_path

            def _show_ignore_file(self):
                from ai_guardian.tui.ignore_file_editor import (
                    SCANNER_LABELS, resolve_scanner_types,
                    validate_ignore_path, suggest_ignore_path,
                )
                from ai_guardian.aiguardignore import (
                    SCANNER_TYPES, generate_aiguardignore_preview,
                )

                v = violation
                rel_path = suggest_ignore_path(v.file_path)

                container = self.query_one("#ask-container")
                for child in list(container.children):
                    child.remove()

                scanner_label = SCANNER_LABELS.get(v.config_section, v.config_section)
                container.mount(Static(
                    f"[bold]Ignore File — .aiguardignore.toml[/bold]\n"
                    f"File: {v.file_path}",
                    id="title",
                ))
                container.mount(Static("\n[bold]Path pattern:[/bold]"))
                container.mount(Input(value=rel_path, id="ignore-path-input"))
                container.mount(Static("", id="ignore-path-status"))
                container.mount(Static(f"\nScope: [bold]This scanner only ({scanner_label})[/bold]"))
                container.mount(Static("\n[bold]Preview:[/bold]"))

                try:
                    toml_text, _ = generate_aiguardignore_preview(rel_path, [v.config_section])
                except Exception:
                    toml_text = ""
                container.mount(TextArea(toml_text, id="ignore-preview", read_only=True))
                container.mount(Static("", id="ignore-editor-status"))
                with Horizontal(id="button-bar") as bar:
                    pass
                container.mount(bar)
                bar.mount(Button("Save", id="btn-save-ignore", variant="success"))
                bar.mount(Button("Cancel", id="btn-cancel-ignore", variant="default"))
                self._ignore_config_section = v.config_section

            def action_quit(self):
                dialog_self._result = AskResult(decision=AskDecision.BLOCK)
                self.exit()

        AskApp().run()
        return self._result
