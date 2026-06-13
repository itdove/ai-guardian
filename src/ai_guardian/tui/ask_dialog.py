"""Interactive ask dialog for the 'ask' action mode.

When a violation is detected and the action is 'ask', this module shows
an interactive dialog letting the user choose: Allow Once, Allow Always
(with pattern editor), or Block.

Cascade: tkinter (native popup) -> NiceGUI (browser) -> Textual (terminal) -> headless fallback.

Environment overrides:
  AI_GUARDIAN_NO_TKINTER=1   skip tkinter even when installed
  AI_GUARDIAN_NO_NICEGUI=1   skip NiceGUI even when installed
"""

import logging
import os
import platform
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class AskDecision(str, Enum):
    """User's decision from the ask dialog."""
    ALLOW_ONCE = "allow_once"
    ALLOW_ALWAYS = "allow_always"
    BLOCK = "block"


@dataclass
class AskViolationInfo:
    """Violation details presented in the ask dialog."""
    violation_type: str
    summary: str
    matched_text: str
    config_section: str
    error_message: str = ""
    matched_pattern: str = ""
    file_path: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class AskResult:
    """Result from the ask dialog."""
    decision: AskDecision
    allowlist_pattern: Optional[str] = None


def _tkinter_available():
    """Check if tkinter is available (import only, no Tk() instantiation)."""
    if os.environ.get("AI_GUARDIAN_NO_TKINTER"):
        return False
    try:
        import tkinter  # noqa: F401
        return True
    except ImportError:
        return False


def _nicegui_available():
    """Check if NiceGUI is available."""
    if os.environ.get("AI_GUARDIAN_NO_NICEGUI"):
        return False
    try:
        import nicegui  # noqa: F401
        return True
    except ImportError:
        return False


def _textual_available():
    """Check if Textual is available and a TTY is present."""
    try:
        import textual  # noqa: F401
        return os.isatty(0)
    except ImportError:
        return False


def is_interactive_available() -> bool:
    """Return True if any interactive dialog tier is available."""
    return _tkinter_available() or _nicegui_available() or _textual_available()


def _map_fallback_to_decision(fallback_action: str) -> AskDecision:
    """Map a fallback action string to an AskDecision."""
    if fallback_action in ("warn", "log-only"):
        return AskDecision.ALLOW_ONCE
    return AskDecision.BLOCK


def _show_via_subprocess(
    violation: AskViolationInfo,
    fallback_action: str = "block",
    timeout_seconds: int = 300,
) -> Optional[AskResult]:
    """Launch ask-prompt as a separate subprocess with display access.

    The hook subprocess can't show GUI directly — this delegates to a
    fresh process via 'ai-guardian ask-prompt', same pattern as tray-prompt.
    """
    import json
    import shutil
    import subprocess
    import sys
    import tempfile
    import time

    violation_json = json.dumps({
        "violation_type": violation.violation_type,
        "summary": violation.summary,
        "matched_text": violation.matched_text,
        "config_section": violation.config_section,
        "error_message": violation.error_message,
        "matched_pattern": violation.matched_pattern,
        "file_path": violation.file_path,
        "line_number": violation.line_number,
    })

    tmpdir = tempfile.mkdtemp(prefix="ai-guardian-ask-")
    output_path = os.path.join(tmpdir, "result.json")

    ag_path = shutil.which("ai-guardian")
    if ag_path:
        cmd = [ag_path, "ask-prompt"]
    else:
        cmd = [sys.executable, "-m", "ai_guardian", "ask-prompt"]
    logger.debug(f"ask-prompt cmd: {cmd[0]}")
    cmd += [
        "--violation", violation_json,
        "--output-file", output_path,
        "--fallback", fallback_action,
        "--timeout", str(timeout_seconds),
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        _, stderr_out = proc.communicate(timeout=timeout_seconds + 10)
        if proc.returncode != 0 and stderr_out:
            logger.warning(f"ask-prompt stderr: {stderr_out.decode('utf-8', errors='replace')[:500]}")
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        logger.warning("ask-prompt subprocess timed out")
        return None
    except Exception as e:
        logger.warning(f"ask-prompt subprocess failed: {e}")
        return None

    try:
        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            decision_str = data.get("decision", "block")
            try:
                decision = AskDecision(decision_str)
            except ValueError:
                decision = AskDecision.BLOCK
            return AskResult(
                decision=decision,
                allowlist_pattern=data.get("allowlist_pattern"),
            )
    except Exception as e:
        logger.warning(f"Failed to read ask-prompt result: {e}")
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    return None


def show_ask_dialog(
    violation: AskViolationInfo,
    fallback_action: str = "block",
    timeout_seconds: int = 300,
) -> AskResult:
    """Show interactive dialog for a violation, falling back if headless.

    When called from a hook subprocess (common case), delegates to a
    separate 'ai-guardian ask-prompt' process that has display access.
    Falls back to headless action if no dialog tier is available.

    Args:
        violation: Violation details to display.
        fallback_action: Action to use when no interactive tier available.
        timeout_seconds: Auto-dismiss timeout (Block by default).

    Returns:
        AskResult with the user's decision and optional allowlist pattern.
    """
    result = _show_via_subprocess(violation, fallback_action, timeout_seconds)
    if result is not None:
        return result

    decision = _map_fallback_to_decision(fallback_action)
    logger.info(f"Ask dialog headless fallback: {fallback_action} -> {decision}")
    return AskResult(decision=decision)


def _ensure_tcl_library():
    """Set TCL_LIBRARY if not already set, searching common install locations.

    uv/pyenv venvs often can't find the system Tcl/Tk — this resolves the
    "Can't find a usable init.tcl" error at tk.Tk() time.
    """
    if os.environ.get("TCL_LIBRARY"):
        return

    import pathlib
    import sys

    candidates = []
    real_exe = pathlib.Path(sys.executable).resolve()
    candidates.append(real_exe.parent.parent / "lib" / "tcl8.6")

    if platform.system() == "Darwin":
        candidates += [
            pathlib.Path("/opt/homebrew/Cellar/tcl-tk@8") / "8.6.18" / "lib" / "tcl8.6",
            pathlib.Path("/opt/homebrew/opt/tcl-tk@8/lib/tcl8.6"),
            pathlib.Path("/opt/homebrew/opt/tcl-tk/lib/tcl8.6"),
            pathlib.Path("/usr/local/opt/tcl-tk/lib/tcl8.6"),
        ]
        import glob
        for match in glob.glob("/opt/homebrew/Cellar/tcl-tk@8/*/lib/tcl8.6"):
            candidates.append(pathlib.Path(match))
    elif platform.system() == "Linux":
        candidates += [
            pathlib.Path("/usr/lib/tcl8.6"),
            pathlib.Path("/usr/share/tcltk/tcl8.6"),
        ]

    for path in candidates:
        if (path / "init.tcl").exists():
            os.environ["TCL_LIBRARY"] = str(path)
            return


# ---------------------------------------------------------------------------
# Tkinter implementation
# ---------------------------------------------------------------------------

class _TkinterAskDialog:
    """Native tkinter dialog for ask mode decisions."""

    def __init__(self, violation: AskViolationInfo, timeout_seconds: int = 300):
        self._violation = violation
        self._timeout = timeout_seconds
        self._result = AskResult(decision=AskDecision.BLOCK)

    def run(self) -> AskResult:
        import tkinter as tk
        from tkinter import ttk

        _ensure_tcl_library()

        root = tk.Tk()

        if platform.system() == "Darwin":
            try:
                from AppKit import NSApplication
                NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
            except Exception:
                pass

        root.title("ai-guardian: Violation Detected")
        root.resizable(False, False)
        root.protocol("WM_DELETE_WINDOW", lambda: self._on_decision(root, AskDecision.BLOCK))
        root.bind("<Escape>", lambda e: self._on_decision(root, AskDecision.BLOCK))

        root.attributes("-topmost", True)

        main = ttk.Frame(root, padding=15)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="Violation Detected", font=("", 14, "bold")).pack(anchor="w")
        ttk.Separator(main, orient="horizontal").pack(fill="x", pady=(5, 10))

        info_frame = ttk.LabelFrame(main, text="Details", padding=10)
        info_frame.pack(fill="x", pady=(0, 10))

        v = self._violation
        details = [
            ("Type", v.violation_type),
            ("Summary", v.summary),
        ]
        if v.file_path:
            loc = v.file_path
            if v.line_number:
                loc += f":{v.line_number}"
            details.append(("Location", loc))

        for label, value in details:
            row = ttk.Frame(info_frame)
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=f"{label}:", font=("", 0, "bold"), width=12, anchor="w").pack(side="left")
            ttk.Label(row, text=value, wraplength=400).pack(side="left", fill="x", expand=True)

        text_frame = ttk.LabelFrame(main, text="Matched Text", padding=5)
        text_frame.pack(fill="x", pady=(0, 10))
        matched_display = tk.Text(text_frame, height=3, width=60, wrap="word", state="normal")
        matched_display.insert("1.0", v.matched_text[:500])
        matched_display.config(state="disabled")
        matched_display.pack(fill="x")

        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill="x", pady=(5, 0))

        ttk.Button(
            btn_frame, text="Allow Once",
            command=lambda: self._on_decision(root, AskDecision.ALLOW_ONCE),
        ).pack(side="left", padx=(0, 5))

        ttk.Button(
            btn_frame, text="Allow Always...",
            command=lambda: self._on_allow_always(root),
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame, text="Block",
            command=lambda: self._on_decision(root, AskDecision.BLOCK),
        ).pack(side="right")

        if self._timeout > 0:
            root.after(self._timeout * 1000, lambda: self._on_decision(root, AskDecision.BLOCK))

        root.mainloop()
        return self._result

    def _on_decision(self, root, decision: AskDecision):
        self._result = AskResult(decision=decision)
        root.destroy()

    def _on_allow_always(self, root):
        """Open the pattern editor and process the result."""
        import tkinter as tk
        from tkinter import ttk

        from ai_guardian.tui.pattern_editor import (
            validate_pattern, convert_to_regex, generate_config_preview, suggest_pattern,
            get_pattern_type_for_section, PATTERN_TYPES,
        )

        v = self._violation
        ptype = get_pattern_type_for_section(v.config_section)
        ptype_label = PATTERN_TYPES.get(ptype, ptype)

        root.withdraw()
        editor = tk.Toplevel(root)
        editor.title("Allow Always — Edit Pattern")
        editor.resizable(False, False)
        editor.attributes("-topmost", True)
        editor.protocol("WM_DELETE_WINDOW", lambda: (editor.destroy(), root.deiconify()))
        editor.focus_force()
        editor.grab_set()

        frame = ttk.Frame(editor, padding=15)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Allow Always — Edit Pattern", font=("", 12, "bold")).pack(anchor="w")
        ttk.Label(frame, text=f"Edit the {ptype_label.lower()} below to match this text. The pattern will be added to the allowlist.", wraplength=500).pack(anchor="w", pady=(0, 5))
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=(0, 10))

        ttk.Label(frame, text="Matched text (reference):", font=("", 0, "bold")).pack(anchor="w")
        matched_display = tk.Text(frame, height=2, width=60, wrap="word", state="normal")
        matched_display.insert("1.0", v.matched_text[:500])
        matched_display.config(state="disabled", background="#2a2a2a", foreground="#aaaaaa")
        matched_display.pack(fill="x", pady=(0, 10))

        ttk.Label(frame, text=f"Pattern ({ptype_label}):", font=("", 0, "bold")).pack(anchor="w")
        pattern_var = tk.StringVar(value=suggest_pattern(v.matched_text) if v.matched_text else "")
        pattern_entry = ttk.Entry(frame, textvariable=pattern_var, width=60)
        pattern_entry.pack(fill="x", pady=(0, 5))

        test_frame = ttk.Frame(frame)
        test_frame.pack(fill="x", pady=(0, 10))

        status_var = tk.StringVar(value="")
        status_label = tk.Label(test_frame, textvariable=status_var, font=("", 11, "bold"), anchor="w")
        status_label.pack(side="right", fill="x", expand=True, padx=(10, 0))

        def do_test():
            pat = pattern_var.get().strip()
            valid, msg = validate_pattern(pat, ptype, v.matched_text)
            if valid:
                status_var.set(f"✅ PASS: {msg}")
                status_label.config(fg="#00cc00")
                regex_pat = convert_to_regex(pat, ptype)
                preview_text.config(state="normal")
                preview_text.delete("1.0", "end")
                preview_text.insert("1.0", generate_config_preview(regex_pat, v.config_section))
                preview_text.config(state="disabled")
            else:
                status_var.set(f"❌ FAIL: {msg}")
                status_label.config(fg="#ff4444")

        ttk.Button(test_frame, text="Test Pattern", command=do_test).pack(side="left")

        ttk.Label(frame, text="Config preview:", font=("", 0, "bold")).pack(anchor="w")
        preview_text = tk.Text(frame, height=6, width=60, wrap="word", state="disabled")
        preview_text.pack(fill="x", pady=(0, 10))

        do_test()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x")

        def on_confirm():
            pat = pattern_var.get().strip()
            valid, _ = validate_pattern(pat, ptype, v.matched_text)
            if not valid:
                status_var.set("❌ FAIL: Fix the pattern before confirming")
                status_label.config(fg="#ff4444")
                return
            regex_pat = convert_to_regex(pat, ptype)
            self._result = AskResult(
                decision=AskDecision.ALLOW_ALWAYS,
                allowlist_pattern=regex_pat,
            )
            editor.destroy()
            root.destroy()

        def on_cancel():
            editor.destroy()
            root.deiconify()

        ttk.Button(btn_frame, text="Add to Allowlist", command=on_confirm).pack(side="right", padx=(5, 0))
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side="right")


# ---------------------------------------------------------------------------
# NiceGUI implementation
# ---------------------------------------------------------------------------

class _NiceGuiAskDialog:
    """Browser-based ask dialog using NiceGUI."""

    def __init__(self, violation: AskViolationInfo, timeout_seconds: int = 300):
        self._violation = violation
        self._timeout = timeout_seconds
        self._result = AskResult(decision=AskDecision.BLOCK)

    def run(self) -> AskResult:
        from nicegui import ui, app

        port = self._find_free_port()
        v = self._violation
        dialog_self = self

        @ui.page("/")
        def main_page():
            from ai_guardian.tui.pattern_editor import (
                validate_pattern, convert_to_regex, generate_config_preview,
                suggest_pattern, get_pattern_type_for_section, PATTERN_TYPES,
            )

            ptype = get_pattern_type_for_section(v.config_section)
            ptype_label = PATTERN_TYPES.get(ptype, ptype)

            with ui.card().classes("w-full max-w-2xl mx-auto mt-8"):
                ui.label("ai-guardian: Violation Detected").classes("text-xl font-bold")
                ui.separator()

                with ui.card_section():
                    ui.label(f"Type: {v.violation_type}").classes("text-sm")
                    ui.label(f"Summary: {v.summary}").classes("text-sm")
                    if v.file_path:
                        loc = v.file_path
                        if v.line_number:
                            loc += f":{v.line_number}"
                        ui.label(f"Location: {loc}").classes("text-sm")

                with ui.card_section():
                    ui.label("Matched Text").classes("font-bold")
                    ui.code(v.matched_text[:500]).classes("w-full")

                with ui.row().classes("w-full justify-between mt-4"):
                    def decide(decision):
                        dialog_self._result = AskResult(decision=decision)
                        ui.run_javascript("window.close()")
                        app.shutdown()

                    ui.button("Allow Once", on_click=lambda: decide(AskDecision.ALLOW_ONCE)).props("color=primary")

                    def show_editor():
                        with ui.dialog() as dlg, ui.card().classes("w-full max-w-xl"):
                            ui.label("Allow Always — Edit Pattern").classes("text-lg font-bold")
                            ui.separator()

                            ui.label("Matched text (reference):").classes("font-bold text-sm")
                            ui.code(v.matched_text[:200]).classes("w-full")

                            ui.label(f"Pattern ({ptype_label}):").classes("font-bold text-sm mt-2")
                            pattern_input = ui.input(
                                value=suggest_pattern(v.matched_text) if v.matched_text else "",
                            ).props("dense outlined").classes("w-full").style("font-family: monospace")

                            status_label = ui.label("").classes("text-sm")
                            preview_code = ui.code("").classes("w-full")

                            def do_test():
                                pat = pattern_input.value.strip()
                                valid, msg = validate_pattern(pat, ptype, v.matched_text)
                                if valid:
                                    status_label.text = f"✅ PASS: {msg}"
                                    status_label.classes(replace="text-sm text-green")
                                    regex_pat = convert_to_regex(pat, ptype)
                                    preview_code.set_content(generate_config_preview(regex_pat, v.config_section))
                                else:
                                    status_label.text = f"❌ FAIL: {msg}"
                                    status_label.classes(replace="text-sm text-red")

                            ui.button("Test Pattern", on_click=do_test, icon="play_arrow").props("dense")
                            do_test()

                            with ui.row().classes("w-full justify-end mt-4"):
                                ui.button("Cancel", on_click=dlg.close).props("flat")

                                def on_confirm():
                                    pat = pattern_input.value.strip()
                                    valid, _ = validate_pattern(pat, ptype, v.matched_text)
                                    if not valid:
                                        status_label.text = "❌ FAIL: Fix the pattern before confirming"
                                        status_label.classes(replace="text-sm text-red")
                                        return
                                    regex_pat = convert_to_regex(pat, ptype)
                                    dialog_self._result = AskResult(
                                        decision=AskDecision.ALLOW_ALWAYS,
                                        allowlist_pattern=regex_pat,
                                    )
                                    ui.run_javascript("window.close()")
                                    app.shutdown()

                                ui.button("Add to Allowlist", on_click=on_confirm).props("color=positive")

                        dlg.open()

                    ui.button("Allow Always...", on_click=show_editor).props("color=positive")
                    ui.button("Block", on_click=lambda: decide(AskDecision.BLOCK)).props("color=negative")

        import subprocess as _sp
        import webbrowser

        front_app = None
        if platform.system() == "Darwin":
            try:
                front_app = _sp.run(
                    ["osascript", "-e", 'tell application "System Events" to get name of first application process whose frontmost is true'],
                    capture_output=True, text=True, timeout=3,
                ).stdout.strip()
            except Exception:
                pass

        webbrowser.open(f"http://127.0.0.1:{port}")

        ui.run(port=port, show=False, reload=False, dark=True, title="ai-guardian: Violation Detected")

        if front_app and platform.system() == "Darwin":
            try:
                _sp.run(
                    ["osascript", "-e", f'tell application "{front_app}" to activate'],
                    capture_output=True, timeout=3,
                )
            except Exception:
                pass

        return self._result

    @staticmethod
    def _find_free_port():
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Textual implementation
# ---------------------------------------------------------------------------

class _TextualAskDialog:
    """Terminal-based ask dialog using Textual."""

    def __init__(self, violation: AskViolationInfo, timeout_seconds: int = 300):
        self._violation = violation
        self._timeout = timeout_seconds
        self._result = AskResult(decision=AskDecision.BLOCK)

    def run(self) -> AskResult:
        from textual.app import App, ComposeResult
        from textual.containers import Container, Horizontal, Vertical
        from textual.widgets import Static, Button, Input, Select, Header, Footer
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
                    self.query_one("#pattern-input", Input).value = suggest_pattern(violation.matched_text)
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
                    validate_pattern, convert_to_regex, generate_config_preview,
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
                        regex_pat = convert_to_regex(pat, ptype)
                        preview.update(generate_config_preview(regex_pat, violation.config_section))
                    else:
                        status.update(f"[red]FAIL: {msg}[/red]")
                        preview.update("")
                except Exception:
                    pass

            def _confirm_pattern(self):
                from ai_guardian.tui.pattern_editor import validate_pattern, convert_to_regex, get_pattern_type_for_section
                try:
                    pat = self.query_one("#pattern-input", Input).value.strip()
                    ptype = get_pattern_type_for_section(violation.config_section)
                    valid, _ = validate_pattern(pat, ptype, violation.matched_text)
                    if not valid:
                        self.query_one("#editor-status", Static).update(
                            "[red]FAIL: Fix the pattern before confirming[/red]"
                        )
                        return
                    regex_pat = convert_to_regex(pat, ptype)
                    dialog_self._result = AskResult(
                        decision=AskDecision.ALLOW_ALWAYS,
                        allowlist_pattern=regex_pat,
                    )
                    self.exit()
                except Exception:
                    pass

            def action_quit(self):
                dialog_self._result = AskResult(decision=AskDecision.BLOCK)
                self.exit()

        AskApp().run()
        return self._result
