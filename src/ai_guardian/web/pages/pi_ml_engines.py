"""ML Prompt Injection Engines — configure ML engines, strategy, and fallback."""

import json

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config

VALID_ML_ENGINE_TYPES = {"llm-guard"}


def _validate_ml_engines_json(text):
    """Validate ML engines JSON, returning (parsed_list, error_string)."""
    text = text.strip()
    if not text:
        return [], None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"
    if not isinstance(data, list):
        return None, "Engines must be a JSON array"
    for i, engine in enumerate(data):
        if not isinstance(engine, dict):
            return None, f"Engine {i + 1}: must be an object with 'type' and 'model'"
        etype = engine.get("type")
        if not etype:
            return None, f"Engine {i + 1}: missing 'type' field"
        if etype not in VALID_ML_ENGINE_TYPES:
            return None, f"Engine {i + 1}: unknown type '{etype}'"
        if not engine.get("model"):
            return None, f"Engine {i + 1}: missing 'model' field"
        threshold = engine.get("threshold")
        if threshold is not None:
            if not isinstance(threshold, (int, float)):
                return None, f"Engine {i + 1}: threshold must be a number"
            if not 0.0 <= threshold <= 1.0:
                return None, f"Engine {i + 1}: threshold must be 0.0-1.0"
    return data, None


def _load_ml_status():
    """Check ML availability and model download status."""
    try:
        from ai_guardian.ml_detection import is_ml_available, list_registered_models
        available = is_ml_available()
        models = list_registered_models()
        return available, models
    except Exception:
        return False, []


def create_pi_ml_engines_page(service, daemon_name: str):
    """Create the ML Prompt Injection Engines page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/pi-ml-engines")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("ML Prompt Injection Engines").classes("text-2xl font-bold")
            ui.label(
                "Configure ML-based prompt injection detection engines and execution strategy."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    pi = config.get("prompt_injection", {})
                    if not isinstance(pi, dict):
                        pi = {}

                    # --- ML Status ---
                    with ui.card().classes("w-full"):
                        ui.label("ML Status").classes("text-lg font-bold")
                        available, models = await run.io_bound(_load_ml_status)
                        with ui.row().classes("items-center gap-2"):
                            if available:
                                ui.icon("check_circle").classes("text-green")
                                ui.label("ML dependencies available (onnxruntime, tokenizers)").classes("text-sm")
                            else:
                                ui.icon("error").classes("text-red")
                                ui.label("ML dependencies not available").classes("text-sm text-red")
                                ui.label(
                                    "onnxruntime required (included on Python < 3.13 via rapidocr-onnxruntime)"
                                ).classes("text-xs text-grey-6")

                        if models:
                            ui.label("Registered Models:").classes("text-sm font-bold mt-2")
                            for m in models:
                                with ui.row().classes("items-center gap-2"):
                                    if m.get("downloaded"):
                                        ui.icon("cloud_done").classes("text-green")
                                    else:
                                        ui.icon("cloud_download").classes("text-grey-5")
                                    ui.label(m["name"]).classes("text-sm").style(
                                        "font-family: monospace"
                                    )
                                    if m.get("downloaded"):
                                        ui.badge("Downloaded", color="green").classes("text-xs")
                                    else:
                                        ui.badge("Not downloaded", color="grey").classes("text-xs")
                            if not all(m.get("downloaded") for m in models):
                                ui.label(
                                    "Download models with: ai-guardian ml download"
                                ).classes("text-xs text-grey-6 mt-1")

                    # --- ML Strategy ---
                    with ui.card().classes("w-full"):
                        ui.label("Execution Strategy").classes("text-lg font-bold")
                        ui.label(
                            "How multiple ML engines coordinate detection."
                        ).classes("text-xs text-grey-6")

                        strategy = pi.get("ml_strategy", "any-match")
                        strat_sel = ui.select(
                            options={
                                "first-match": "First Match — use first engine result",
                                "any-match": "Any Match — flag if ANY engine detects",
                                "consensus": "Consensus — flag if N engines agree",
                            },
                            value=strategy,
                        ).classes("w-96")

                        threshold_row = ui.row().classes("items-center gap-2")
                        ct = pi.get("consensus_threshold", 2)
                        with threshold_row:
                            ui.label("Consensus Threshold:").classes("text-sm")
                            thresh_input = ui.input(
                                value=str(ct),
                            ).props("dense outlined type=number").classes("w-24")
                        threshold_row.set_visibility(strategy == "consensus")

                        async def save_strategy(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("prompt_injection", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["ml_strategy"] = e.value
                            cfg["prompt_injection"] = sect
                            await run.io_bound(save_web_config, cfg)
                            threshold_row.set_visibility(e.value == "consensus")
                            ui.notify(f"Strategy: {e.value}", type="positive")

                        strat_sel.on_value_change(save_strategy)

                        async def save_threshold():
                            try:
                                val = int(thresh_input.value)
                                if val < 1:
                                    ui.notify("Threshold must be at least 1", type="negative")
                                    return
                            except (ValueError, TypeError):
                                ui.notify("Invalid threshold", type="negative")
                                return
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("prompt_injection", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["consensus_threshold"] = val
                            cfg["prompt_injection"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Threshold: {val}", type="positive")

                        ui.button(
                            "Save Threshold",
                            icon="save",
                            on_click=save_threshold,
                        ).props("dense flat").bind_visibility_from(
                            threshold_row, "visible"
                        )

                    # --- Fallback ---
                    with ui.card().classes("w-full"):
                        ui.label("Fallback on Error").classes("text-lg font-bold")
                        ui.label(
                            "What happens when ML detection is unavailable "
                            "(daemon not running, model not loaded)."
                        ).classes("text-xs text-grey-6")

                        fallback = pi.get("fallback_on_error", "heuristic")
                        fb_sel = ui.select(
                            options={
                                "heuristic": "Heuristic — fall back to pattern detection",
                                "block": "Block — fail closed (reject input)",
                                "allow": "Allow — fail open (accept input)",
                            },
                            value=fallback,
                        ).classes("w-96")

                        async def save_fallback(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("prompt_injection", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["fallback_on_error"] = e.value
                            cfg["prompt_injection"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Fallback: {e.value}", type="positive")

                        fb_sel.on_value_change(save_fallback)

                    # --- ML Engines Editor ---
                    with ui.card().classes("w-full"):
                        ui.label("ML Engines").classes("text-lg font-bold")
                        ui.label(
                            "Configure which ML engines to use for detection."
                        ).classes("text-xs text-grey-6")

                        engines = pi.get("ml_engines", [])
                        engines_text = json.dumps(engines, indent=2) if engines else "[]"

                        editor = ui.textarea(
                            value=engines_text,
                        ).props("outlined autogrow").classes("w-full").style(
                            "font-family: monospace; min-height: 150px"
                        )

                        count = len(engines)
                        status_label = ui.label(
                            f"Valid JSON — {count} engine(s)"
                        ).classes("text-xs text-green")

                        def on_edit(e):
                            parsed, err = _validate_ml_engines_json(e.args)
                            if err:
                                status_label.text = err
                                status_label.classes(replace="text-xs text-red")
                            else:
                                status_label.text = f"Valid JSON — {len(parsed)} engine(s)"
                                status_label.classes(replace="text-xs text-green")

                        editor.on("update:model-value", on_edit)

                        with ui.row().classes("gap-2 mt-2"):

                            async def save_engines():
                                parsed, err = _validate_ml_engines_json(editor.value)
                                if err:
                                    ui.notify(err, type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("prompt_injection", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                sect["ml_engines"] = parsed
                                cfg["prompt_injection"] = sect
                                await run.io_bound(save_web_config, cfg)
                                ui.notify(
                                    f"Saved {len(parsed)} engine(s)", type="positive"
                                )

                            async def reload_engines():
                                await refresh()
                                ui.notify("Engines reloaded", type="positive")

                            ui.button(
                                "Save", icon="save", on_click=save_engines
                            ).props("dense")
                            ui.button(
                                "Reload", icon="refresh", on_click=reload_engines
                            ).props("dense flat")

                    # --- Reference ---
                    with ui.card().classes("w-full"):
                        ui.label("ML Engine Reference").classes("text-sm font-bold")
                        ui.label(
                            f"Valid engine types: {', '.join(sorted(VALID_ML_ENGINE_TYPES))}"
                        ).classes("text-xs text-grey-6")
                        ui.label("Engine format (each entry requires type and model):").classes(
                            "text-xs text-grey-6 mt-1"
                        )
                        ui.code(
                            '[\n'
                            '  {\n'
                            '    "type": "llm-guard",\n'
                            '    "model": "protectai/deberta-v3-base-prompt-injection-v2",\n'
                            '    "threshold": 0.85\n'
                            '  }\n'
                            ']',
                            language="json",
                        ).classes("text-xs")
                        ui.label(
                            "threshold is optional (default: 0.85, range: 0.0-1.0)"
                        ).classes("text-xs text-grey-6 mt-1")
                        ui.label(
                            "Requires: onnxruntime (included on Python < 3.13) and ai-guardian ml download"
                        ).classes("text-xs text-grey-6")

            ui.timer(0.1, refresh, once=True)
