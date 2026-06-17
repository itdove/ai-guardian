"""Shared Textual modals for the 'Suppress in Source...' flow.

Used by violations page and directory scan page.
"""

from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class SourceAnnotationEditorModal(ModalScreen):
    """Modal for previewing and saving source annotation changes."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
    ]

    CSS = """
    SourceAnnotationEditorModal {
        align: center middle;
    }

    #source-editor-container {
        width: 90;
        height: 90%;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #source-editor-area {
        height: 1fr;
    }
    """

    def __init__(
        self,
        file_path: str,
        modified_content: str,
        annotation_type: str,
        preview_snippet: str,
        *args, **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.file_path = file_path
        self.modified_content = modified_content
        self.annotation_type = annotation_type
        self.preview_snippet = preview_snippet

    def compose(self):
        from textual.widgets import TextArea

        ann_label = "inline" if self.annotation_type == "inline" else "block (begin-allow/end-allow)"

        with Container(id="source-editor-container"):
            yield Static(
                f"[bold]Suppress in Source — {ann_label}[/bold]\n"
                f"File: {self.file_path}\n"
                "Review the annotated source. Save to write the file.",
            )

            yield TextArea(
                self.modified_content,
                id="source-editor-area",
                language="python" if self.file_path.endswith((".py", ".pyw", ".pyi")) else None,
            )

            yield Static("", id="source-status")

            with Horizontal(id="modal-actions"):
                yield Button("Save", id="save-source", variant="success")
                yield Button("Cancel", id="cancel-source", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-source":
            self._save()
        elif event.button.id == "cancel-source":
            self.dismiss()

    def _save(self):
        from textual.widgets import TextArea

        editor = self.query_one("#source-editor-area", TextArea)
        text = editor.text

        from ai_guardian.tui.source_annotator import write_annotated_source
        if write_annotated_source(self.file_path, text):
            self.app.notify(
                f"Annotation saved to {self.file_path}", severity="information",
            )
            self.dismiss()
        else:
            status = self.query_one("#source-status", Static)
            status.update("[red]Failed to write file[/red]")
