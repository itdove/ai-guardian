"""
Textual app for collecting tray plugin parameters.

Launched by the tray via `ai-guardian tray-prompt --params '<json>' --command '<template>'`.
Displays a form with text inputs and dropdowns, then returns the substituted command.
"""

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.widgets import Button, Footer, Header, Input, Label, Select, Static


class TrayPromptApp(App):
    """Interactive parameter form for tray plugin commands."""

    CSS = """
    #form-container {
        padding: 1 2;
    }
    .param-row {
        margin: 1 0 0 0;
    }
    .param-row Label {
        margin: 0 0 0 0;
    }
    .param-row Input, .param-row Select {
        width: 100%;
    }
    #button-row {
        margin: 2 0 0 0;
    }
    #button-row Button {
        margin: 0 1 0 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, params, command_template, command_type="terminal",
                 extra_vars=None):
        super().__init__()
        self._params = params
        self._command_template = command_template
        self._command_type = command_type
        self._extra_vars = extra_vars or {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="form-container"):
            yield Static("[bold]Plugin Parameters[/bold]")
            for param in self._params:
                with Container(classes="param-row"):
                    label_text = param["name"]
                    if param.get("hint"):
                        label_text += f"  [dim]({param['hint']})[/dim]"
                    yield Label(label_text)
                    if param.get("options"):
                        options = [(opt, opt) for opt in param["options"]]
                        default = self._resolve_default(
                            param.get("default", param["options"][0]),
                        )
                        yield Select(
                            options,
                            value=default,
                            id=f"param-{param['name']}",
                        )
                    else:
                        yield Input(
                            value=self._resolve_default(
                                param.get("default", ""),
                            ),
                            placeholder=param.get("hint", ""),
                            id=f"param-{param['name']}",
                        )
            with Horizontal(id="button-row"):
                yield Button("Submit", id="submit-btn", variant="primary")
                yield Button("Cancel", id="cancel-btn")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.exit(result=None)
        elif event.button.id == "submit-btn":
            self._submit()

    def action_cancel(self) -> None:
        self.exit(result=None)

    def _resolve_default(self, value):
        """Resolve {tray.*} variables in a param default value."""
        if not value or not self._extra_vars or "{" not in value:
            return value
        from ai_guardian.daemon.tray_plugins import substitute_params
        return substitute_params(value, self._extra_vars)

    def _submit(self):
        values = {}
        for param in self._params:
            widget_id = f"param-{param['name']}"
            try:
                widget = self.query_one(f"#{widget_id}")
            except Exception:
                values[param["name"]] = param.get("default", "")
                continue

            if isinstance(widget, Select):
                val = widget.value
                values[param["name"]] = str(val) if val is not Select.BLANK else ""
            else:
                values[param["name"]] = widget.value

        from ai_guardian.daemon.tray_plugins import substitute_params
        final_command = substitute_params(self._command_template, values)
        self.exit(result=final_command)
