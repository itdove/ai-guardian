"""Regex Tester page — test patterns against sample text."""

import re as re_mod

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config

TARGET_SECTIONS = {
    "prompt_injection": "Prompt Injection (allowlist_patterns)",
    "scan_pii": "PII Scanning (allowlist_patterns)",
    "secret_scanning": "Secret Scanning (allowlist_patterns)",
}

MAX_MATCHES = 100


def _test_regex(pattern, text, case_insensitive=True, multiline=True,
                max_matches=MAX_MATCHES):
    """Test a regex pattern against text.

    Returns (matches_list, error_string).
    Each match is {match, start, end, line}.
    """
    if not pattern:
        return [], "No pattern provided"

    flags = 0
    if case_insensitive:
        flags |= re_mod.IGNORECASE
    if multiline:
        flags |= re_mod.MULTILINE

    try:
        compiled = re_mod.compile(pattern, flags)
    except re_mod.error as e:
        return [], f"Regex error: {e}"

    matches = []
    for m in compiled.finditer(text):
        if len(matches) >= max_matches:
            break
        line_num = text[:m.start()].count("\n") + 1
        matches.append({
            "match": m.group(),
            "start": m.start(),
            "end": m.end(),
            "line": line_num,
        })

    return matches, None


def _validate_pattern(pattern):
    """Check pattern for ReDoS safety. Returns (is_safe, error_msg)."""
    if not pattern:
        return False, "Empty pattern"
    try:
        from ai_guardian.config_utils import validate_regex_pattern
        is_safe = validate_regex_pattern(pattern)
        if not is_safe:
            return False, "Pattern may be vulnerable to ReDoS"
        return True, ""
    except Exception as e:
        return False, str(e)



def create_regex_tester_page(service, daemon_name: str):
    """Create the Regex Tester page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/regex-tester")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Regex Tester").classes("text-2xl font-bold")
            ui.label(
                "Test regex patterns and add them to config allowlists."
            ).classes("text-xs text-grey-6")

            with ui.card().classes("w-full"):
                ui.label("Pattern").classes("text-lg font-bold")
                pattern_input = ui.input(
                    placeholder="Enter regex pattern"
                ).props("dense outlined").classes("w-full").style(
                    "font-family: monospace"
                )
                validation_label = ui.label("").classes("text-xs")

                def on_pattern_change(e):
                    val = e.value if hasattr(e, "value") else e.args
                    if not val:
                        validation_label.text = ""
                        return
                    safe, msg = _validate_pattern(val)
                    if safe:
                        validation_label.text = "Valid pattern"
                        validation_label.classes(
                            replace="text-xs text-green"
                        )
                    else:
                        validation_label.text = msg
                        validation_label.classes(
                            replace="text-xs text-amber"
                        )

                pattern_input.on(
                    "update:model-value", on_pattern_change
                )

            with ui.card().classes("w-full"):
                ui.label("Test Text").classes("text-lg font-bold")
                text_input = ui.textarea(
                    placeholder="Enter sample text to test against"
                ).props("outlined").classes("w-full").style(
                    "font-family: monospace; min-height: 150px"
                )

            with ui.row().classes("items-center gap-4"):
                ci_check = ui.checkbox(
                    "Case Insensitive", value=True
                )
                ml_check = ui.checkbox("Multiline", value=True)

            results_container = ui.column().classes("w-full gap-4")

            async def do_test():
                pat = pattern_input.value
                txt = text_input.value or ""
                if not pat:
                    ui.notify("Enter a pattern", type="negative")
                    return

                matches, err = _test_regex(
                    pat, txt, ci_check.value, ml_check.value
                )

                results_container.clear()
                with results_container:
                    with ui.card().classes("w-full"):
                        if err:
                            ui.label(f"Error: {err}").classes(
                                "text-sm text-red"
                            )
                        else:
                            count = len(matches)
                            suffix = (
                                f" (showing {MAX_MATCHES})"
                                if count >= MAX_MATCHES else ""
                            )
                            ui.label(
                                f"Matches: {count}{suffix}"
                            ).classes("text-lg font-bold")

                            if matches:
                                with ui.scroll_area().classes(
                                    "w-full"
                                ).style("max-height: 400px"):
                                    for m in matches:
                                        with ui.row().classes(
                                            "items-center gap-2"
                                        ):
                                            ui.badge(
                                                f"L{m['line']}",
                                                color="blue",
                                            ).classes("text-xs")
                                            ui.label(
                                                f"[{m['start']}:{m['end']}]"
                                            ).classes(
                                                "text-xs text-grey-6"
                                            )
                                            ui.label(
                                                repr(m["match"])
                                            ).classes("text-sm").style(
                                                "font-family: monospace"
                                            )

            ui.button(
                "Test", icon="play_arrow", on_click=do_test
            ).props("dense")

            with ui.card().classes("w-full"):
                ui.label("Add to Config").classes("text-lg font-bold")
                ui.label(
                    "Add the current pattern to an allowlist in config."
                ).classes("text-xs text-grey-6")

                section_sel = ui.select(
                    options=TARGET_SECTIONS,
                    value="prompt_injection",
                ).classes("w-64")

                async def add_pattern():
                    pat = pattern_input.value
                    if not pat:
                        ui.notify("Enter a pattern first", type="negative")
                        return
                    section = section_sel.value
                    cfg = await run.io_bound(load_web_config)
                    sect = cfg.get(section, {})
                    if not isinstance(sect, dict):
                        sect = {}
                    patterns = sect.get("allowlist_patterns", [])
                    if pat in patterns:
                        ui.notify("Pattern already exists", type="warning")
                        return
                    patterns.append(pat)
                    sect["allowlist_patterns"] = patterns
                    cfg[section] = sect
                    await run.io_bound(save_web_config, cfg)
                    ui.notify(
                        f"Added to {section}", type="positive"
                    )

                ui.button(
                    "Add Pattern", icon="add", on_click=add_pattern
                ).props("dense")
