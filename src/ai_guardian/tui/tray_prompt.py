"""
Popup for collecting tray plugin parameters.

Launched by the tray via `ai-guardian tray-prompt --params '<json>' --command '<template>'`.

Primary UI: tkinter native popup (no terminal window).
Fallback: Textual TUI in a terminal (when tkinter / _tkinter is not installed).

To enable the tkinter popup, install the optional tkinter package:
  - macOS (pyenv): brew install tcl-tk && pyenv install <version> --force
  - UBI / RHEL:    dnf install -y python3-tkinter
  - Debian/Ubuntu: apt install -y python3-tk
  - Windows:       included by default in the python.org installer

tkinter is part of the Python standard library but requires the Tcl/Tk
system library at compile time.  When unavailable the Textual fallback
is used automatically.
"""


def _tkinter_available():
    """Return True if tkinter can be imported."""
    try:
        import tkinter  # noqa: F401
        return True
    except ImportError:
        return False


# -- tkinter implementation --------------------------------------------------

class _TkinterPromptApp:
    """Native tkinter parameter form (no terminal window)."""

    def __init__(self, params, command_template, command_type="terminal",
                 extra_vars=None, title=None):
        self._params = params
        self._command_template = command_template
        self._command_type = command_type
        self._extra_vars = extra_vars or {}
        self._title = title or "Plugin Parameters"
        self._result = None
        self._widgets = {}

    def run(self):
        import tkinter as tk
        from tkinter import ttk, messagebox

        self._tk = tk
        self._ttk = ttk
        self._messagebox = messagebox

        self._root = tk.Tk()
        self._root.title(self._title)
        self._root.resizable(False, False)
        self._root.protocol("WM_DELETE_WINDOW", self._cancel)
        self._root.bind("<Escape>", lambda e: self._cancel())

        frame = ttk.Frame(self._root, padding=16)
        frame.grid(row=0, column=0, sticky="nsew")

        for i, param in enumerate(self._params):
            label_text = param["name"]
            if param.get("required", True):
                label_text = "* " + label_text
            hint = param.get("hint", "")
            if hint:
                label_text += f"  ({hint})"

            ttk.Label(frame, text=label_text).grid(
                row=i, column=0, sticky="w", pady=(8, 2),
            )

            ptype = param.get("type", "string")
            default = self._resolve_default(param.get("default", ""))

            if ptype == "boolean":
                var = tk.BooleanVar(value=str(default).lower() == "true")
                widget = ttk.Checkbutton(frame, variable=var)
                widget.grid(row=i, column=1, sticky="w", pady=(8, 2))
                self._widgets[param["name"]] = ("boolean", var)

            elif ptype == "choice" or (
                ptype == "string" and param.get("options")
            ):
                options = param.get("options", [])
                if not default and options:
                    default = options[0]
                var = tk.StringVar(value=default)
                widget = ttk.OptionMenu(frame, var, default, *options)
                widget.grid(row=i, column=1, sticky="ew", pady=(8, 2))
                self._widgets[param["name"]] = ("choice", var)

            elif ptype == "combobox" and param.get("options"):
                var = tk.StringVar(value=default)
                widget = ttk.Combobox(
                    frame, textvariable=var, values=param["options"],
                )
                widget.grid(row=i, column=1, sticky="ew", pady=(8, 2))
                self._widgets[param["name"]] = ("combobox", var)

            elif ptype in ("int", "number"):
                var = tk.StringVar(value=str(default) if default else "")
                p_min = param.get("min")
                p_max = param.get("max")
                kwargs = {}
                if p_min is not None:
                    kwargs["from_"] = float(p_min)
                if p_max is not None:
                    kwargs["to"] = float(p_max)
                if kwargs:
                    widget = ttk.Spinbox(
                        frame, textvariable=var, width=20, **kwargs,
                    )
                else:
                    widget = ttk.Entry(frame, textvariable=var, width=30)
                widget.grid(row=i, column=1, sticky="ew", pady=(8, 2))
                self._widgets[param["name"]] = ("entry", var)

            elif ptype in ("path-file", "path-dir"):
                var = tk.StringVar(value=default)
                path_frame = ttk.Frame(frame)
                path_frame.grid(row=i, column=1, sticky="ew", pady=(8, 2))
                entry = ttk.Entry(path_frame, textvariable=var, width=25)
                entry.pack(side="left", fill="x", expand=True)
                browse_btn = ttk.Button(
                    path_frame, text="Browse…",
                    command=self._make_browse_callback(var, ptype),
                )
                browse_btn.pack(side="left", padx=(4, 0))
                self._widgets[param["name"]] = ("entry", var)

            else:
                var = tk.StringVar(value=default)
                widget = ttk.Entry(frame, textvariable=var, width=30)
                widget.grid(row=i, column=1, sticky="ew", pady=(8, 2))
                self._widgets[param["name"]] = ("entry", var)

        frame.columnconfigure(1, weight=1)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(
            row=len(self._params), column=0, columnspan=2,
            pady=(16, 0), sticky="e",
        )
        ttk.Button(btn_frame, text="Cancel", command=self._cancel).pack(
            side="left", padx=(0, 8),
        )
        ttk.Button(btn_frame, text="OK", command=self._submit).pack(
            side="left",
        )

        self._root.bind("<Return>", lambda e: self._submit())

        self._root.update_idletasks()
        self._root.minsize(360, self._root.winfo_reqheight())

        self._root.lift()
        self._root.attributes("-topmost", True)
        self._root.after(100, lambda: self._root.attributes("-topmost", False))
        self._root.focus_force()

        self._root.mainloop()
        return self._result

    def _cancel(self):
        self._result = None
        self._root.destroy()

    def _resolve_default(self, value):
        if not value or not self._extra_vars or "{" not in str(value):
            return value
        from ai_guardian.daemon.tray_plugins import substitute_params
        return substitute_params(str(value), self._extra_vars)

    def _make_browse_callback(self, var, ptype):
        def _browse():
            from tkinter import filedialog
            initial = var.get() or None
            if ptype == "path-dir":
                path = filedialog.askdirectory(
                    parent=self._root,
                    initialdir=initial,
                )
            else:
                path = filedialog.askopenfilename(
                    parent=self._root,
                    initialdir=initial,
                )
            if path:
                var.set(path)
        return _browse

    def _submit(self):
        import shlex
        from ai_guardian.daemon.tray_plugins import (
            PluginParam, substitute_params, validate_param_value,
        )

        values = {}
        for param in self._params:
            name = param["name"]
            if name not in self._widgets:
                values[name] = param.get("default", "")
                continue
            wtype, var = self._widgets[name]
            if wtype == "boolean":
                values[name] = "true" if var.get() else "false"
            else:
                values[name] = var.get()

        for param in self._params:
            pp = PluginParam(
                name=param["name"],
                type=param.get("type", "string"),
                required=param.get("required", True),
                pattern=param.get("pattern"),
                options=param.get("options"),
                min=float(param["min"]) if param.get("min") is not None else None,
                max=float(param["max"]) if param.get("max") is not None else None,
            )
            valid, err = validate_param_value(pp, values.get(param["name"], ""))
            if not valid:
                self._messagebox.showerror(
                    "Validation Error", err, parent=self._root,
                )
                return

        for param in self._params:
            ptype = param.get("type", "string")
            name = param["name"]
            if ptype in ("path-file", "path-dir") and values.get(name):
                values[name] = shlex.quote(values[name])

        self._result = substitute_params(self._command_template, values)
        self._root.destroy()


# -- Textual fallback --------------------------------------------------------

class _TextualPromptApp:
    """Textual TUI fallback (requires a terminal window)."""

    def __init__(self, params, command_template, command_type="terminal",
                 extra_vars=None, title=None):
        self._params = params
        self._command_template = command_template
        self._command_type = command_type
        self._extra_vars = extra_vars or {}
        self._title = title

    def run(self):
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Container, Horizontal
        from textual.widgets import (
            Button, Checkbox, Footer, Header, Input, Label, Select, Static,
        )

        params = self._params
        command_template = self._command_template
        extra_vars = self._extra_vars
        form_title = self._title or "Plugin Parameters"

        class _App(App):
            CSS = """
            #form-container { padding: 1 2; }
            .param-row { margin: 1 0 0 0; }
            .param-row Label { margin: 0 0 0 0; }
            .param-row Input, .param-row Select { width: 100%; }
            #button-row { margin: 2 0 0 0; }
            #button-row Button { margin: 0 1 0 0; }
            """
            BINDINGS = [Binding("escape", "cancel", "Cancel")]

            def compose(self_inner) -> ComposeResult:
                yield Header(show_clock=False)
                with Container(id="form-container"):
                    yield Static(f"[bold]{form_title}[/bold]")
                    for param in params:
                        with Container(classes="param-row"):
                            label_text = param["name"]
                            if param.get("required", True):
                                label_text = "* " + label_text
                            if param.get("hint"):
                                label_text += (
                                    f"  [dim]({param['hint']})[/dim]"
                                )
                            yield Label(label_text)

                            ptype = param.get("type", "string")
                            widget_id = f"param-{param['name']}"

                            if ptype == "boolean":
                                dv = _resolve(
                                    param.get("default", "false"), extra_vars,
                                )
                                yield Checkbox(
                                    "",
                                    value=dv.lower() == "true",
                                    id=widget_id,
                                )
                            elif ptype == "choice" or (
                                ptype == "string" and param.get("options")
                            ):
                                options = [
                                    (o, o) for o in param["options"]
                                ]
                                default = _resolve(
                                    param.get(
                                        "default", param["options"][0],
                                    ),
                                    extra_vars,
                                )
                                yield Select(
                                    options, value=default, id=widget_id,
                                )
                            else:
                                placeholder = param.get("hint", "")
                                if ptype == "path-file":
                                    suffix = " [file path]"
                                    placeholder = (
                                        placeholder + suffix
                                        if placeholder
                                        else "Enter file path"
                                    )
                                elif ptype == "path-dir":
                                    suffix = " [directory path]"
                                    placeholder = (
                                        placeholder + suffix
                                        if placeholder
                                        else "Enter directory path"
                                    )
                                elif (
                                    ptype == "combobox"
                                    and param.get("options")
                                ):
                                    sug = ", ".join(param["options"])
                                    placeholder = (
                                        f"{placeholder} [{sug}]"
                                        if placeholder else sug
                                    )
                                yield Input(
                                    value=_resolve(
                                        param.get("default", ""),
                                        extra_vars,
                                    ),
                                    placeholder=placeholder,
                                    id=widget_id,
                                )
                    with Horizontal(id="button-row"):
                        yield Button(
                            "Submit", id="submit-btn", variant="primary",
                        )
                        yield Button("Cancel", id="cancel-btn")
                yield Footer()

            def on_button_pressed(self_inner, event):
                if event.button.id == "cancel-btn":
                    self_inner.exit(result=None)
                elif event.button.id == "submit-btn":
                    self_inner._do_submit()

            def action_cancel(self_inner):
                self_inner.exit(result=None)

            def _do_submit(self_inner):
                import shlex
                from ai_guardian.daemon.tray_plugins import (
                    PluginParam, substitute_params, validate_param_value,
                )
                values = {}
                for param in params:
                    wid = f"param-{param['name']}"
                    try:
                        widget = self_inner.query_one(f"#{wid}")
                    except Exception:
                        values[param["name"]] = param.get("default", "")
                        continue
                    if isinstance(widget, Checkbox):
                        values[param["name"]] = (
                            "true" if widget.value else "false"
                        )
                    elif isinstance(widget, Select):
                        val = widget.value
                        values[param["name"]] = (
                            str(val) if val is not Select.BLANK else ""
                        )
                    else:
                        values[param["name"]] = widget.value

                for param in params:
                    pp = PluginParam(
                        name=param["name"],
                        type=param.get("type", "string"),
                        required=param.get("required", True),
                        pattern=param.get("pattern"),
                        options=param.get("options"),
                        min=(
                            float(param["min"])
                            if param.get("min") is not None else None
                        ),
                        max=(
                            float(param["max"])
                            if param.get("max") is not None else None
                        ),
                    )
                    valid, err = validate_param_value(
                        pp, values.get(param["name"], ""),
                    )
                    if not valid:
                        self_inner.notify(err, severity="error")
                        return

                for param in params:
                    ptype = param.get("type", "string")
                    name = param["name"]
                    if ptype in ("path-file", "path-dir") and values.get(name):
                        values[name] = shlex.quote(values[name])

                final = substitute_params(command_template, values)
                self_inner.exit(result=final)

        return _App().run()


def _resolve(value, extra_vars):
    if not value or not extra_vars or "{" not in value:
        return value
    from ai_guardian.daemon.tray_plugins import substitute_params
    return substitute_params(value, extra_vars)


# -- Public API --------------------------------------------------------------

class TrayPromptApp:
    """Parameter form that uses tkinter when available, Textual otherwise.

    The ``needs_terminal`` attribute is set after construction so callers
    can decide whether to launch in a terminal window or as a headless
    subprocess.
    """

    def __init__(self, params, command_template, command_type="terminal",
                 extra_vars=None, title=None):
        self._params = params
        self._command_template = command_template
        self._command_type = command_type
        self._extra_vars = extra_vars or {}
        self._title = title
        self._result = None
        self.needs_terminal = not _tkinter_available()

    def run(self):
        if not self.needs_terminal:
            app = _TkinterPromptApp(
                self._params, self._command_template,
                self._command_type, self._extra_vars, self._title,
            )
        else:
            app = _TextualPromptApp(
                self._params, self._command_template,
                self._command_type, self._extra_vars, self._title,
            )
        return app.run()

    def _resolve_default(self, value):
        """Resolve {tray.*} variables in a param default value."""
        return _resolve(value, self._extra_vars)
