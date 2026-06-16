"""NiceGUI (browser-based) implementation of the ask dialog.

Browser popup dialog for ask mode decisions with pattern editor
and inline config editor using CodeMirror.
"""

import platform

from ai_guardian.tui.ask_dialog import (
    AskDecision,
    AskViolationInfo,
    AskResult,
    _write_config_text,
)


def _show_nicegui_config_editor(dialog_self, app, save_pat, config_section):
    """Show a NiceGUI config editor dialog with the pattern inserted in memory."""
    import json as json_mod
    from nicegui import ui
    from ai_guardian.tui.pattern_editor import prepare_config_with_pattern

    json_text, _line_number = prepare_config_with_pattern(save_pat, config_section)

    with ui.dialog().props("persistent maximized") as editor_dlg, ui.card().classes("w-full h-full"):
        ui.label("Config Editor — ai-guardian.json").classes("text-lg font-bold")
        ui.label(
            "Review the full config with the inserted pattern. Save to persist or Cancel to discard."
        ).classes("text-sm text-grey-6")
        ui.separator()

        editor = ui.codemirror(
            json_text, language="JSON", theme="dracula", line_wrapping=True,
        ).classes("w-full flex-grow").style("min-height: 400px")

        editor_status = ui.label("Valid JSON").classes("text-sm text-green")

        def on_editor_change(e):
            try:
                json_mod.loads(e.value)
                editor_status.text = "Valid JSON"
                editor_status.classes(replace="text-sm text-green")
            except json_mod.JSONDecodeError as exc:
                editor_status.text = f"Invalid JSON: {exc}"
                editor_status.classes(replace="text-sm text-red")

        editor.on_value_change(on_editor_change)

        with ui.row().classes("w-full justify-end mt-2"):
            def on_cancel():
                editor_dlg.close()

            def on_save():
                text = editor.value
                try:
                    json_mod.loads(text)
                except json_mod.JSONDecodeError as exc:
                    editor_status.text = f"Invalid JSON: {exc}"
                    editor_status.classes(replace="text-sm text-red")
                    return
                if _write_config_text(text):
                    dialog_self._result = AskResult(
                        decision=AskDecision.ALLOW_ALWAYS,
                        allowlist_pattern=save_pat,
                        config_saved=True,
                    )
                    ui.run_javascript("window.close()")
                    app.shutdown()
                else:
                    editor_status.text = "Failed to write config file"
                    editor_status.classes(replace="text-sm text-red")

            ui.button("Cancel", on_click=on_cancel).props("flat")
            ui.button("Save", on_click=on_save).props("color=positive")

    editor_dlg.open()


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
                validate_pattern, generate_config_preview,
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
                                value=suggest_pattern(v.matched_text, v.config_section) if v.matched_text else "",
                            ).props("dense outlined").classes("w-full").style("font-family: monospace")

                            status_label = ui.label("").classes("text-sm")
                            preview_code = ui.code("").classes("w-full")

                            def do_test():
                                pat = pattern_input.value.strip()
                                valid, msg = validate_pattern(pat, ptype, v.matched_text)
                                if valid:
                                    status_label.text = f"✅ PASS: {msg}"
                                    status_label.classes(replace="text-sm text-green")
                                    preview_code.set_content(generate_config_preview(pat, v.config_section))
                                else:
                                    status_label.text = f"❌ FAIL: {msg}"
                                    status_label.classes(replace="text-sm text-red")

                            ui.button("Test Pattern", on_click=do_test, icon="play_arrow").props("dense")
                            do_test()
                            pattern_input.on_value_change(lambda _: do_test())

                            with ui.row().classes("w-full justify-end mt-4"):
                                ui.button("Cancel", on_click=dlg.close).props("flat")

                                def on_confirm():
                                    pat = pattern_input.value.strip()
                                    valid, _ = validate_pattern(pat, ptype, v.matched_text)
                                    if not valid:
                                        status_label.text = "❌ FAIL: Fix the pattern before confirming"
                                        status_label.classes(replace="text-sm text-red")
                                        return
                                    dlg.close()
                                    _show_nicegui_config_editor(dialog_self, app, pat, v.config_section)

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
