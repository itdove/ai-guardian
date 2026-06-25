"""Shared Textual modals for the 'Ignore File...' flow.

Used by violations page and directory scan page.
"""

from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from ai_guardian.aiguardignore import SCANNER_TYPES
from ai_guardian.tui.ignore_file_editor import (
    SCOPE_THIS_SCANNER,
    SCOPE_ALL_SCANNERS,
    SCOPE_SELECT_SCANNERS,
    SCANNER_LABELS,
    resolve_scanner_types,
    validate_ignore_path,
    suggest_ignore_path,
)


class IgnoreFileEditorModal(ModalScreen):
    """Modal for editing path and scope before adding to .aiguardignore.toml."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
    ]

    CSS = """
    IgnoreFileEditorModal {
        align: center middle;
    }

    #ignore-file-container {
        width: 80;
        height: 80%;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #ignore-preview {
        height: 1fr;
    }
    """

    def __init__(self, file_path: str, config_section: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.file_path = file_path
        self.config_section = config_section
        self._scope = SCOPE_THIS_SCANNER
        from ai_guardian.tui.ignore_file_editor import get_project_root_for_file

        self._project_root = get_project_root_for_file(file_path)

    def compose(self):
        from textual.widgets import Input, Select, TextArea

        rel_path = suggest_ignore_path(self.file_path)

        with Container(id="ignore-file-container"):
            yield Static("[bold]Ignore File — Add to .aiguardignore.toml[/bold]")
            yield Static(f"\n[bold]File:[/bold] {self.file_path}")
            yield Static("\n[bold]Path pattern (editable):[/bold]")
            yield Input(value=rel_path, id="ignore-path-input")
            yield Static("", id="ignore-path-status")

            yield Static("\n[bold]Scope:[/bold]")
            scanner_label = SCANNER_LABELS.get(self.config_section, self.config_section)
            scope_options = [
                (f"This scanner only ({scanner_label})", SCOPE_THIS_SCANNER),
                ("All scanners", SCOPE_ALL_SCANNERS),
                ("Select scanners...", SCOPE_SELECT_SCANNERS),
            ]
            yield Select(scope_options, value=SCOPE_THIS_SCANNER, id="scope-select")

            yield Static(
                "\n[bold]Select scanners:[/bold]",
                id="scanner-select-label",
                classes="hidden",
            )
            for st in sorted(SCANNER_TYPES):
                label = SCANNER_LABELS.get(st, st)
                from textual.widgets import Checkbox

                yield Checkbox(
                    label,
                    id=f"scanner-{st}",
                    value=(st == self.config_section),
                    classes="scanner-checkbox hidden",
                )

            yield Static("\n[bold]Preview:[/bold]")
            yield TextArea("", id="ignore-preview", read_only=True)

            with Horizontal(id="modal-actions"):
                yield Button(
                    "Add to .aiguardignore.toml", id="confirm-ignore", variant="success"
                )
                yield Button("Cancel", id="cancel-ignore", variant="primary")

    def on_mount(self) -> None:
        self._update_preview()

    def on_select_changed(self, event) -> None:
        if event.select.id == "scope-select":
            self._scope = event.value
            show_scanners = self._scope == SCOPE_SELECT_SCANNERS
            try:
                label = self.query_one("#scanner-select-label", Static)
                label.set_class(not show_scanners, "hidden")

                for cb in self.query(".scanner-checkbox"):
                    cb.set_class(not show_scanners, "hidden")
            except Exception:
                pass
            self._update_preview()

    def on_input_changed(self, event) -> None:
        if event.input.id == "ignore-path-input":
            self._update_preview()

    def on_checkbox_changed(self, event) -> None:
        if event.checkbox.id and event.checkbox.id.startswith("scanner-"):
            self._update_preview()

    def _get_selected_scanners(self):
        from textual.widgets import Checkbox

        selected = []
        for cb in self.query(".scanner-checkbox"):
            if isinstance(cb, Checkbox) and cb.value and cb.id:
                scanner_type = cb.id.replace("scanner-", "")
                selected.append(scanner_type)
        return selected

    def _update_preview(self):
        from textual.widgets import Input, TextArea

        try:
            path_input = self.query_one("#ignore-path-input", Input)
            path = path_input.value.strip()
        except Exception:
            return

        valid, msg = validate_ignore_path(path)
        status = self.query_one("#ignore-path-status", Static)
        if not valid:
            status.update(f"[red]{msg}[/red]")
            return
        status.update(f"[green]{msg}[/green]")

        scanner_types = resolve_scanner_types(
            self._scope, self.config_section, self._get_selected_scanners()
        )

        try:
            from ai_guardian.aiguardignore import generate_aiguardignore_preview

            toml_text, _ = generate_aiguardignore_preview(
                path, scanner_types, project_root=self._project_root
            )
            preview = self.query_one("#ignore-preview", TextArea)
            preview.load_text(toml_text)
        except Exception:
            pass  # intentionally silent — optional dependency

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm-ignore":
            self._confirm()
        elif event.button.id == "cancel-ignore":
            self.dismiss()

    def _confirm(self):
        from textual.widgets import Input

        path_input = self.query_one("#ignore-path-input", Input)
        path = path_input.value.strip()

        valid, msg = validate_ignore_path(path)
        if not valid:
            status = self.query_one("#ignore-path-status", Static)
            status.update(f"[red]{msg}[/red]")
            return

        scanner_types = resolve_scanner_types(
            self._scope, self.config_section, self._get_selected_scanners()
        )

        self.app.push_screen(
            IgnoreFileConfigEditorModal(
                path, scanner_types, project_root=self._project_root
            )
        )


class IgnoreFileConfigEditorModal(ModalScreen):
    """Modal for reviewing and saving .aiguardignore.toml content."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
    ]

    CSS = """
    IgnoreFileConfigEditorModal {
        align: center middle;
    }

    #toml-editor-container {
        width: 90;
        height: 90%;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #toml-editor-area {
        height: 1fr;
    }
    """

    def __init__(
        self, path_pattern: str, scanner_types, *args, project_root=None, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.path_pattern = path_pattern
        self.scanner_types = scanner_types
        self._project_root = project_root

    def compose(self):
        from textual.widgets import TextArea

        from ai_guardian.aiguardignore import generate_aiguardignore_preview

        toml_text, line_number = generate_aiguardignore_preview(
            self.path_pattern,
            self.scanner_types,
            project_root=self._project_root,
        )

        with Container(id="toml-editor-container"):
            yield Static(
                "[bold]Config Editor — .aiguardignore.toml[/bold]\n"
                "Review the file. Save to persist.",
            )

            editor = TextArea(toml_text, id="toml-editor-area")
            editor.cursor_location = (max(0, line_number - 1), 0)
            yield editor

            yield Static("", id="toml-status")

            with Horizontal(id="modal-actions"):
                yield Button("Save", id="save-toml", variant="success")
                yield Button("Cancel", id="cancel-toml", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-toml":
            self._save()
        elif event.button.id == "cancel-toml":
            self.dismiss()

    def _save(self):
        from textual.widgets import TextArea

        editor = self.query_one("#toml-editor-area", TextArea)
        text = editor.text

        from ai_guardian.tui.ask_dialog import _write_aiguardignore_text

        if _write_aiguardignore_text(text, project_root=self._project_root):
            self.app.notify("Path saved to .aiguardignore.toml", severity="information")
            self.dismiss()
            parent = self.app.screen
            if isinstance(parent, IgnoreFileEditorModal):
                parent.dismiss()
        else:
            status = self.query_one("#toml-status", Static)
            status.update("[red]Failed to write .aiguardignore.toml[/red]")
