"""Interactive ask dialog for the 'ask' action mode.

When a violation is detected and the action is 'ask', this module shows
an interactive dialog letting the user choose: Allow Once, Allow Always
(with pattern editor), or Block.

Cascade: tkinter (native popup) -> NiceGUI (browser) -> Textual (terminal) -> headless fallback.
"""

import logging
import os
import platform
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ai_guardian.tui.display import (
    _tkinter_available,
    _nicegui_available,
    _textual_available,
    is_interactive_available,
    _ensure_tcl_library,
)

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
    config_saved: bool = False


def _map_fallback_to_decision(fallback_action: str) -> AskDecision:
    """Map a fallback action string to an AskDecision."""
    if fallback_action in ("warn", "log-only"):
        return AskDecision.ALLOW_ONCE
    return AskDecision.BLOCK


def _save_pattern_to_config(pattern: str, config_section: str) -> bool:
    """Save a pattern to the config file. Returns True on success."""
    try:
        if config_section == "ssrf_protection":
            from ai_guardian.config_writer import add_allowed_domain
            return add_allowed_domain(pattern)
        else:
            from ai_guardian.config_writer import add_allowlist_pattern
            return add_allowlist_pattern(config_section, pattern)
    except Exception as e:
        logger.warning("Failed to save pattern to config: %s", e)
        return False


def _write_config_text(json_text: str) -> bool:
    """Write JSON text directly to ai-guardian.json with backup. Returns True on success."""
    import shutil
    try:
        from ai_guardian.config_utils import get_config_dir
        config_path = get_config_dir() / "ai-guardian.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        if config_path.exists():
            shutil.copy2(config_path, config_path.with_suffix(".json.bak"))
        config_path.write_text(json_text, encoding="utf-8")
        try:
            from ai_guardian.config_loaders import _clear_config_cache
            _clear_config_cache()
        except ImportError:
            pass
        return True
    except Exception as e:
        logger.warning("Failed to write config: %s", e)
        return False


def _show_via_daemon(
    violation: AskViolationInfo,
    fallback_action: str = "block",
    timeout_seconds: int = 300,
) -> Optional[AskResult]:
    """Send prompt request to daemon REST API (direct call, no subprocess).

    The daemon process has display access (via the tray), so the ask
    dialog runs in-process there — avoiding Python interpreter startup
    overhead from subprocess spawning.

    Returns None if the daemon is not running or the request fails.
    """
    import json
    from urllib.request import Request, urlopen
    from urllib.error import URLError

    try:
        from ai_guardian.daemon import get_pid_path, is_pid_alive
    except ImportError:
        return None

    pid_path = get_pid_path()
    if not pid_path.exists():
        return None

    try:
        pid_info = json.loads(pid_path.read_text())
        rest_port = pid_info.get("rest_port")
        if not rest_port:
            return None
        pid = pid_info.get("pid", 0)
        if not pid or not is_pid_alive(pid):
            return None
    except (json.JSONDecodeError, OSError, ValueError):
        return None

    body = json.dumps({
        "mode": "ask",
        "violation": {
            "violation_type": violation.violation_type,
            "summary": violation.summary,
            "matched_text": violation.matched_text,
            "config_section": violation.config_section,
            "error_message": violation.error_message,
            "matched_pattern": violation.matched_pattern,
            "file_path": violation.file_path,
            "line_number": violation.line_number,
        },
        "fallback": fallback_action,
        "timeout": timeout_seconds,
    }).encode("utf-8")

    url = f"http://127.0.0.1:{rest_port}/api/prompt"
    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")

    auth_token = pid_info.get("auth_token")
    if auth_token:
        req.add_header("Authorization", f"Bearer {auth_token}")

    try:
        with urlopen(req, timeout=timeout_seconds + 10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        decision_str = data.get("decision", "block")
        try:
            decision = AskDecision(decision_str)
        except ValueError:
            decision = AskDecision.BLOCK
        logger.debug("Ask dialog via daemon: %s", decision_str)
        return AskResult(
            decision=decision,
            allowlist_pattern=data.get("allowlist_pattern"),
            config_saved=data.get("config_saved", False),
        )
    except (URLError, OSError, json.JSONDecodeError, ValueError) as e:
        logger.debug("Daemon prompt request failed: %s", e)
        return None


def _show_via_subprocess(
    violation: AskViolationInfo,
    fallback_action: str = "block",
    timeout_seconds: int = 300,
) -> Optional[AskResult]:
    """Launch prompt --mode ask as a separate subprocess with display access.

    The hook subprocess can't show GUI directly — this delegates to a
    fresh process via 'ai-guardian prompt --mode ask'.
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
        cmd = [ag_path, "prompt", "--mode", "ask"]
    else:
        cmd = [sys.executable, "-m", "ai_guardian", "prompt", "--mode", "ask"]
    logger.debug(f"prompt --mode ask cmd: {cmd[0]}")
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
            logger.warning(f"prompt ask stderr: {stderr_out.decode('utf-8', errors='replace')[:500]}")
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        logger.warning("prompt ask subprocess timed out")
        return None
    except Exception as e:
        logger.warning(f"prompt ask subprocess failed: {e}")
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
                config_saved=data.get("config_saved", False),
            )
    except Exception as e:
        logger.warning(f"Failed to read prompt ask result: {e}")
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

    Tries the daemon REST API first (direct call, no subprocess overhead),
    then falls back to subprocess spawn, then to headless action.

    Args:
        violation: Violation details to display.
        fallback_action: Action to use when no interactive tier available.
        timeout_seconds: Auto-dismiss timeout (Block by default).

    Returns:
        AskResult with the user's decision and optional allowlist pattern.
    """
    from ai_guardian.tui.display import get_preferred_ui

    if get_preferred_ui() == "headless":
        decision = _map_fallback_to_decision(fallback_action)
        logger.info("preferred_ui=headless, using fallback: %s -> %s",
                     fallback_action, decision)
        return AskResult(decision=decision)

    result = _show_via_daemon(violation, fallback_action, timeout_seconds)
    if result is not None:
        return result

    result = _show_via_subprocess(violation, fallback_action, timeout_seconds)
    if result is not None:
        return result

    decision = _map_fallback_to_decision(fallback_action)
    logger.info(f"Ask dialog headless fallback: {fallback_action} -> {decision}")
    return AskResult(decision=decision)


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

    def _show_config_editor(self, root, regex_pat):
        """Show a full config editor with the pattern inserted in memory."""
        import tkinter as tk
        from tkinter import ttk

        from ai_guardian.tui.pattern_editor import prepare_config_with_pattern

        v = self._violation
        json_text, line_number = prepare_config_with_pattern(regex_pat, v.config_section)

        root.deiconify()
        for w in root.winfo_children():
            w.destroy()

        root.title("Config Editor — ai-guardian.json")
        root.resizable(True, True)
        root.geometry("700x500")

        frame = ttk.Frame(root, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Review Config", font=("", 14, "bold")).pack(anchor="w")
        ttk.Label(
            frame,
            text="The pattern has been inserted below. Review the full config, then Save or Cancel.",
            wraplength=650,
        ).pack(anchor="w", pady=(0, 5))
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=(0, 5))

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill="both", expand=True, pady=(0, 5))

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")

        config_text = tk.Text(
            text_frame, wrap="none", undo=True,
            font=("Menlo" if platform.system() == "Darwin" else "Consolas", 11),
            yscrollcommand=scrollbar.set,
        )
        config_text.pack(fill="both", expand=True)
        scrollbar.config(command=config_text.yview)

        config_text.insert("1.0", json_text)
        config_text.mark_set("insert", f"{line_number}.0")
        config_text.see(f"{line_number}.0")
        config_text.tag_add("highlight", f"{line_number}.0", f"{line_number}.end")
        config_text.tag_config("highlight", background="#3a3a00")

        status_var = tk.StringVar(value="Valid JSON")
        status_label = tk.Label(frame, textvariable=status_var, font=("", 11), anchor="w", fg="#00cc00")
        status_label.pack(fill="x")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(5, 0))

        def on_save():
            import json as json_mod
            text = config_text.get("1.0", "end-1c")
            try:
                json_mod.loads(text)
            except json_mod.JSONDecodeError as e:
                status_var.set(f"Invalid JSON: {e}")
                status_label.config(fg="#ff4444")
                return
            if _write_config_text(text):
                self._result = AskResult(
                    decision=AskDecision.ALLOW_ALWAYS,
                    allowlist_pattern=regex_pat,
                    config_saved=True,
                )
                root.destroy()
            else:
                status_var.set("Failed to write config file")
                status_label.config(fg="#ff4444")

        def on_cancel():
            root.destroy()
            root.quit()

        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side="right")
        ttk.Button(btn_frame, text="Save", command=on_save).pack(side="right", padx=(0, 5))

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
        pattern_var = tk.StringVar(value=suggest_pattern(v.matched_text, v.config_section) if v.matched_text else "")
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

        _debounce_id = [None]
        def _on_pattern_change(*_args):
            if _debounce_id[0] is not None:
                editor.after_cancel(_debounce_id[0])
            _debounce_id[0] = editor.after(300, do_test)
        pattern_var.trace_add("write", _on_pattern_change)

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
            editor.destroy()
            self._show_config_editor(root, regex_pat)

        def on_cancel():
            editor.destroy()
            root.deiconify()

        ttk.Button(btn_frame, text="Add to Allowlist", command=on_confirm).pack(side="right", padx=(5, 0))
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side="right")


# ---------------------------------------------------------------------------
# NiceGUI implementation
# ---------------------------------------------------------------------------

def _show_nicegui_config_editor(dialog_self, app, regex_pat, config_section):
    """Show a NiceGUI config editor dialog with the pattern inserted in memory."""
    import json as json_mod
    from nicegui import ui
    from ai_guardian.tui.pattern_editor import prepare_config_with_pattern

    json_text, _line_number = prepare_config_with_pattern(regex_pat, config_section)

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
                        allowlist_pattern=regex_pat,
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
                                    regex_pat = convert_to_regex(pat, ptype)
                                    preview_code.set_content(generate_config_preview(regex_pat, v.config_section))
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
                                    regex_pat = convert_to_regex(pat, ptype)
                                    dlg.close()
                                    _show_nicegui_config_editor(dialog_self, app, regex_pat, v.config_section)

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
                    self._pending_regex_pat = regex_pat
                    self._show_config_editor(regex_pat)
                except Exception:
                    pass

            def _show_config_editor(self, regex_pat):
                from ai_guardian.tui.pattern_editor import prepare_config_with_pattern
                try:
                    json_text, line_number = prepare_config_with_pattern(regex_pat, violation.config_section)
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
                            allowlist_pattern=self._pending_regex_pat,
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
