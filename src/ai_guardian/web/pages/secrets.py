"""Secret Scanning page — secret detection settings and pattern server config."""

import re as re_mod
from datetime import datetime, timedelta, timezone

from nicegui import run, ui

from ai_guardian.web.components.header import create_header, create_sidebar
from ai_guardian.web.config_helpers import load_web_config, save_web_config

DURATION_RE = re_mod.compile(r"^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?$", re_mod.IGNORECASE)


def _parse_duration(text):
    text = text.strip()
    m = DURATION_RE.match(text)
    if not m:
        try:
            return timedelta(minutes=int(text))
        except ValueError:
            return None
    d, h, mi = int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0)
    if d == 0 and h == 0 and mi == 0:
        return None
    return timedelta(days=d, hours=h, minutes=mi)


def _format_remaining(dt):
    remaining = dt - datetime.now(timezone.utc)
    total = max(0, int(remaining.total_seconds()))
    if total == 0:
        return "expired"
    d = total // 86400
    h = (total % 86400) // 3600
    m = (total % 3600) // 60
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    return " ".join(parts) if parts else "<1m"


def _parse_enabled(raw):
    """Parse an enabled value, returning (is_temp, until_dt, reason, is_enabled)."""
    if isinstance(raw, dict):
        disabled_until = raw.get("disabled_until")
        if disabled_until:
            try:
                until_dt = datetime.fromisoformat(disabled_until.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) < until_dt:
                    return True, until_dt, raw.get("reason", ""), False
            except (ValueError, TypeError):
                pass  # intentionally silent — invalid value uses default
        return False, None, "", bool(raw.get("value", True))
    return False, None, "", bool(raw)


def _render_toggle(
    label, desc, is_temp, until_dt, reason, is_enabled, save_fn, refresh_fn
):
    """Render a toggle card with temp-disable support.

    save_fn(value) — called with bool or dict to persist.
    refresh_fn()   — called to reload the page.
    """
    with ui.card().classes("w-full"):
        if is_temp and until_dt:
            remaining = _format_remaining(until_dt)
            with ui.row().classes("items-center gap-2 w-full"):
                ui.icon("timer").classes("text-amber")
                ui.label(label).classes("font-bold text-sm flex-grow")
                ui.badge(f"TEMP DISABLED — {remaining}", color="amber").classes(
                    "text-xs"
                )
            ui.label(desc).classes("text-xs text-grey-6 ml-8")
            if reason:
                ui.label(f"Reason: {reason}").classes("text-xs text-grey-7 ml-8")

            async def do_reenable():
                await run.io_bound(save_fn, True)
                ui.notify(f"{label} re-enabled", type="positive")
                await refresh_fn()

            ui.button(
                "Re-enable Now", icon="play_arrow", color="green", on_click=do_reenable
            ).props("dense size=sm").classes("ml-8")
        else:
            with ui.row().classes("items-center gap-2 w-full"):
                sw = ui.switch(label, value=bool(is_enabled)).classes("flex-grow")
                ui.label(desc).classes("text-xs text-grey-6")

                async def on_toggle(e):
                    await run.io_bound(save_fn, e.value)
                    ui.notify(
                        f"{label} {'enabled' if e.value else 'disabled'}",
                        type="positive",
                    )

                sw.on_value_change(on_toggle)

            with ui.row().classes("items-center gap-2 ml-8"):
                dur = (
                    ui.input(placeholder="e.g. 30m, 2h, 1d")
                    .props("dense outlined")
                    .classes("w-32")
                )
                rsn = (
                    ui.input(placeholder="Reason")
                    .props("dense outlined")
                    .classes("w-40")
                )

                async def do_temp(d=dur, r=rsn):
                    delta = _parse_duration(d.value or "30m")
                    if not delta:
                        ui.notify(
                            "Invalid duration (e.g. 30m, 2h, 1d)", type="negative"
                        )
                        return
                    until_ts = (datetime.now(timezone.utc) + delta).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    entry = {"value": False, "disabled_until": until_ts}
                    rv = r.value.strip()
                    if rv:
                        entry["reason"] = rv
                    await run.io_bound(save_fn, entry)
                    ui.notify(
                        f"{label} temp disabled for {d.value or '30m'}", type="warning"
                    )
                    await refresh_fn()

                ui.button("Temp Disable", icon="timer", on_click=do_temp).props(
                    "dense size=sm"
                )


def create_secrets_page(service, daemon_name: str):
    """Create the Secret Scanning settings page."""
    create_header(daemon_name)

    with ui.row().classes("w-full min-h-screen no-wrap"):
        create_sidebar(daemon_name, current=f"/{daemon_name}/secrets")

        with ui.column().classes("flex-grow p-6 gap-4"):
            ui.label("Secret Detection Settings").classes("text-2xl font-bold")
            ui.label(
                "Configure secret scanning, allowlist patterns, and pattern server."
            ).classes("text-xs text-grey-6")

            content = ui.column().classes("w-full gap-4")

            async def refresh():
                content.clear()
                config = await run.io_bound(load_web_config)

                with content:
                    ss = config.get("secret_scanning", {})
                    if not isinstance(ss, dict):
                        ss = {}

                    # --- Secret scanning toggle ---
                    is_temp, until_dt, reason, is_enabled = _parse_enabled(
                        ss.get("enabled", True)
                    )

                    def save_scanning(value):
                        cfg = load_web_config()
                        sect = cfg.get("secret_scanning", {})
                        if not isinstance(sect, dict):
                            sect = {}
                        sect["enabled"] = value
                        cfg["secret_scanning"] = sect
                        save_web_config(cfg)

                    _render_toggle(
                        "Secret Scanning",
                        "Scan for API keys, tokens, and credentials in tool inputs/outputs.",
                        is_temp,
                        until_dt,
                        reason,
                        is_enabled,
                        save_scanning,
                        refresh,
                    )

                    # --- Action mode ---
                    with ui.card().classes("w-full"):
                        ui.label("Action Mode").classes("text-lg font-bold")
                        ui.label("What happens when secrets are detected.").classes(
                            "text-xs text-grey-6"
                        )
                        action = ss.get("action", "block")
                        action_sel = ui.select(
                            options={
                                "block": "Block — reject the operation",
                                "ask": "Ask — interactive prompt (block if headless)",
                                "ask:warn": "Ask — interactive prompt (warn if headless)",
                                "ask:log-only": "Ask — interactive prompt (log-only if headless)",
                                "warn": "Warn — allow with warning",
                                "log-only": "Log Only — silent logging",
                            },
                            value=action,
                        ).classes("w-64")

                        async def save_action(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("secret_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["action"] = e.value
                            cfg["secret_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Action: {e.value}", type="positive")

                        action_sel.on_value_change(save_action)

                    # --- Allowlist patterns ---
                    with ui.card().classes("w-full"):
                        ui.label("Allowlist Patterns").classes("text-lg font-bold")
                        ui.label(
                            "Regex patterns for known-safe secret values that should be ignored."
                        ).classes("text-xs text-grey-6")

                        allowlist = ss.get("allowlist_patterns", [])
                        if allowlist:
                            for idx, pat in enumerate(allowlist):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("check").classes("text-green")
                                    ui.label(pat).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_pat(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("secret_scanning", {})
                                        if not isinstance(sect, dict):
                                            return
                                        pats = sect.get("allowlist_patterns", [])
                                        if i < len(pats):
                                            pats.pop(i)
                                            sect["allowlist_patterns"] = pats
                                            cfg["secret_scanning"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify(
                                                "Pattern removed", type="positive"
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete", on_click=remove_pat, color="red"
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No allowlist patterns.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            al_input = (
                                ui.input(
                                    placeholder="Enter regex (e.g., pk_test_[A-Za-z0-9]{24,})"
                                )
                                .props("dense outlined")
                                .classes("flex-grow")
                            )

                            async def add_allowlist():
                                pattern = al_input.value.strip()
                                if not pattern:
                                    ui.notify("Enter a pattern", type="negative")
                                    return
                                try:
                                    re_mod.compile(pattern)
                                except re_mod.error as e:
                                    ui.notify(f"Invalid regex: {e}", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("secret_scanning", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                pats = sect.get("allowlist_patterns", [])
                                if pattern in pats:
                                    ui.notify("Pattern already exists", type="warning")
                                    return
                                pats.append(pattern)
                                sect["allowlist_patterns"] = pats
                                cfg["secret_scanning"] = sect
                                await run.io_bound(save_web_config, cfg)
                                al_input.value = ""
                                ui.notify(f"Added: {pattern}", type="positive")
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_allowlist).props(
                                "dense"
                            )

                    # --- False Positive Filtering: Entropy (Issue #1091) ---
                    with ui.card().classes("w-full"):
                        ui.label("Minimum Entropy Threshold").classes(
                            "text-lg font-bold"
                        )
                        ui.label(
                            "Shannon entropy filter for secret detection. Matches below "
                            "this threshold are rejected as likely placeholders. "
                            "Range: 0.0 (identical chars) to ~6.0 (fully random). "
                            "Real API keys typically score 4.0+."
                        ).classes("text-xs text-grey-6")

                        current_entropy = ss.get("min_entropy")
                        entropy_input = (
                            ui.number(
                                label="Min Entropy (empty = disabled)",
                                value=current_entropy,
                                min=0.0,
                                max=8.0,
                                step=0.1,
                            )
                            .props("dense outlined clearable")
                            .classes("w-48")
                        )

                        ui.label(
                            "0.0 = identical (XXXX) · ~1.0 = two chars (abab) · "
                            "~3.3 = lowercase · ~4.7 = alphanumeric · "
                            "Recommended: 3.0"
                        ).classes("text-xs text-grey-5 mt-1")

                        async def save_entropy(e):
                            val = e.value
                            if val is None or val == "":
                                val = None
                            else:
                                try:
                                    val = float(val)
                                    if val < 0 or val > 8:
                                        ui.notify(
                                            "Entropy must be between 0.0 and 8.0",
                                            type="negative",
                                        )
                                        return
                                except (ValueError, TypeError):
                                    ui.notify("Must be a number", type="negative")
                                    return
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("secret_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["min_entropy"] = val
                            cfg["secret_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            status = f"{val}" if val is not None else "disabled"
                            ui.notify(f"Min entropy: {status}", type="positive")

                        entropy_input.on("blur", save_entropy)

                    # --- False Positive Filtering: Stopwords (Issue #1091) ---
                    with ui.card().classes("w-full"):
                        ui.label("Stopwords").classes("text-lg font-bold")
                        ui.label(
                            "Matched secrets containing these words are suppressed "
                            "(case-insensitive substring match). User words are merged "
                            "with bundled stopwords — bundled words cannot be removed."
                        ).classes("text-xs text-grey-6")

                        # Show bundled stopwords count
                        bundled_count = 0
                        try:
                            from ai_guardian.patterns import BUNDLED_FILES

                            sw_path = BUNDLED_FILES.get("stopwords")
                            if sw_path and sw_path.exists():
                                import sys as _sys

                                if _sys.version_info >= (3, 11):
                                    import tomllib as _tomllib
                                else:
                                    import tomli as _tomllib
                                with open(sw_path, "rb") as f:
                                    sw_data = _tomllib.load(f)
                                bundled_count = len(
                                    sw_data.get("stopwords", {}).get("words", [])
                                )
                        except Exception:
                            pass  # intentionally silent — optional dependency

                        ui.label(
                            f"Bundled: {bundled_count} words (always active)"
                        ).classes("text-xs text-grey-5")

                        user_sw = ss.get("stopwords", [])
                        if user_sw:
                            ui.label(f"User-added: {len(user_sw)} words").classes(
                                "text-xs text-grey-5"
                            )
                            for idx, word in enumerate(user_sw):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("block").classes("text-orange")
                                    ui.label(word).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_sw(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("secret_scanning", {})
                                        if not isinstance(sect, dict):
                                            return
                                        words = sect.get("stopwords", [])
                                        if i < len(words):
                                            removed = words.pop(i)
                                            sect["stopwords"] = words
                                            cfg["secret_scanning"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify(
                                                f"Removed: {removed}",
                                                type="positive",
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete", on_click=remove_sw, color="red"
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No user-added stopwords.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            sw_input = (
                                ui.input(placeholder="Enter stopword (min 3 chars)")
                                .props("dense outlined")
                                .classes("flex-grow")
                            )

                            async def add_stopword():
                                word = sw_input.value.strip().lower()
                                if not word:
                                    ui.notify("Enter a word", type="negative")
                                    return
                                if len(word) < 3:
                                    ui.notify(
                                        "Stopword must be at least 3 characters",
                                        type="negative",
                                    )
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("secret_scanning", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                words = sect.get("stopwords", [])
                                if word in [w.lower() for w in words]:
                                    ui.notify("Stopword already added", type="warning")
                                    return
                                words.append(word)
                                sect["stopwords"] = words
                                cfg["secret_scanning"] = sect
                                await run.io_bound(save_web_config, cfg)
                                sw_input.value = ""
                                ui.notify(f"Added: {word}", type="positive")
                                await refresh()

                            ui.button("Add", icon="add", on_click=add_stopword).props(
                                "dense"
                            )

                    # --- Ignore files ---
                    with ui.card().classes("w-full"):
                        ui.label("Ignore Files").classes("text-lg font-bold")
                        ui.label(
                            "Glob patterns for files to exclude from secret scanning."
                        ).classes("text-xs text-grey-6")

                        ignore_files = ss.get("ignore_files", [])
                        if ignore_files:
                            for idx, entry in enumerate(ignore_files):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("visibility_off").classes("text-grey-6")
                                    ui.label(entry).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_ignore_file(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("secret_scanning", {})
                                        if not isinstance(sect, dict):
                                            return
                                        items = sect.get("ignore_files", [])
                                        if i < len(items):
                                            items.pop(i)
                                            sect["ignore_files"] = items
                                            cfg["secret_scanning"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify(
                                                "File pattern removed", type="positive"
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_ignore_file,
                                        color="red",
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No ignore file patterns.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            if_input = (
                                ui.input(
                                    placeholder="Enter glob pattern (e.g. **/tests/fixtures/**)"
                                )
                                .props("dense outlined")
                                .classes("flex-grow")
                            )

                            async def add_ignore_file():
                                val = if_input.value.strip()
                                if not val:
                                    ui.notify("Enter a pattern", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("secret_scanning", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                items = sect.get("ignore_files", [])
                                if val in items:
                                    ui.notify("Pattern already exists", type="warning")
                                    return
                                items.append(val)
                                sect["ignore_files"] = items
                                cfg["secret_scanning"] = sect
                                await run.io_bound(save_web_config, cfg)
                                if_input.value = ""
                                ui.notify(f"Added: {val}", type="positive")
                                await refresh()

                            ui.button(
                                "Add", icon="add", on_click=add_ignore_file
                            ).props("dense")

                    # --- Ignore tools ---
                    with ui.card().classes("w-full"):
                        ui.label("Ignore Tools").classes("text-lg font-bold")
                        ui.label(
                            "Tool name patterns to exclude from secret scanning."
                        ).classes("text-xs text-grey-6")

                        ignore_tools = ss.get("ignore_tools", [])
                        if ignore_tools:
                            for idx, entry in enumerate(ignore_tools):
                                with ui.row().classes("items-center gap-2 w-full"):
                                    ui.icon("build").classes("text-grey-6")
                                    ui.label(entry).classes("flex-grow text-sm").style(
                                        "font-family: monospace"
                                    )

                                    async def remove_ignore_tool(i=idx):
                                        cfg = await run.io_bound(load_web_config)
                                        sect = cfg.get("secret_scanning", {})
                                        if not isinstance(sect, dict):
                                            return
                                        items = sect.get("ignore_tools", [])
                                        if i < len(items):
                                            items.pop(i)
                                            sect["ignore_tools"] = items
                                            cfg["secret_scanning"] = sect
                                            await run.io_bound(save_web_config, cfg)
                                            ui.notify(
                                                "Tool pattern removed", type="positive"
                                            )
                                            await refresh()

                                    ui.button(
                                        icon="delete",
                                        on_click=remove_ignore_tool,
                                        color="red",
                                    ).props("flat dense size=sm")
                        else:
                            ui.label("No ignore tool patterns.").classes(
                                "text-grey-6 text-sm"
                            )

                        with ui.row().classes("items-center gap-2 mt-2"):
                            it_input = (
                                ui.input(
                                    placeholder="Enter tool name pattern (e.g. mcp__*)"
                                )
                                .props("dense outlined")
                                .classes("flex-grow")
                            )

                            async def add_ignore_tool():
                                val = it_input.value.strip()
                                if not val:
                                    ui.notify("Enter a pattern", type="negative")
                                    return
                                cfg = await run.io_bound(load_web_config)
                                sect = cfg.get("secret_scanning", {})
                                if not isinstance(sect, dict):
                                    sect = {}
                                items = sect.get("ignore_tools", [])
                                if val in items:
                                    ui.notify("Pattern already exists", type="warning")
                                    return
                                items.append(val)
                                sect["ignore_tools"] = items
                                cfg["secret_scanning"] = sect
                                await run.io_bound(save_web_config, cfg)
                                it_input.value = ""
                                ui.notify(f"Added: {val}", type="positive")
                                await refresh()

                            ui.button(
                                "Add", icon="add", on_click=add_ignore_tool
                            ).props("dense")

                    # --- Pattern server toggle ---
                    ps = ss.get("pattern_server", {})
                    if not isinstance(ps, dict):
                        ps = {}

                    ps_temp, ps_until, ps_reason, ps_on = _parse_enabled(
                        ps.get("enabled", False)
                    )

                    def save_ps_enabled(value):
                        cfg = load_web_config()
                        sect = cfg.get("secret_scanning", {})
                        if not isinstance(sect, dict):
                            sect = {}
                        if "pattern_server" not in sect or not isinstance(
                            sect["pattern_server"], dict
                        ):
                            sect["pattern_server"] = {}
                        sect["pattern_server"]["enabled"] = value
                        cfg["secret_scanning"] = sect
                        save_web_config(cfg)

                    _render_toggle(
                        "Pattern Server (Enhanced Patterns)",
                        "Enable remote pattern server for extended detection rules.",
                        ps_temp,
                        ps_until,
                        ps_reason,
                        ps_on,
                        save_ps_enabled,
                        refresh,
                    )

                    # --- Pattern server settings ---
                    with ui.card().classes("w-full"):
                        ui.label("Pattern Server Settings").classes("text-lg font-bold")
                        ps_url = (
                            ui.input(
                                label="Server URL",
                                value=ps.get("url", ""),
                                placeholder="https://patterns.example.com",
                            )
                            .props("outlined dense")
                            .classes("w-full")
                        )
                        ps_endpoint = (
                            ui.input(
                                label="Patterns Endpoint",
                                value=ps.get(
                                    "patterns_endpoint", "/patterns/gitleaks/8.18.1"
                                ),
                            )
                            .props("outlined dense")
                            .classes("w-full")
                        )

                        auth = ps.get("auth", {})
                        if not isinstance(auth, dict):
                            auth = {}
                        ps_auth_method = (
                            ui.input(
                                label="Auth Method",
                                value=auth.get("method", ""),
                                placeholder="bearer",
                            )
                            .props("outlined dense")
                            .classes("w-48")
                        )
                        ps_token_env = (
                            ui.input(
                                label="Token Env Var",
                                value=auth.get("token_env", ""),
                                placeholder="AI_GUARDIAN_PATTERN_TOKEN",
                            )
                            .props("outlined dense")
                            .classes("w-64")
                        )
                        ps_token_file = (
                            ui.input(
                                label="Token File",
                                value=auth.get("token_file", ""),
                            )
                            .props("outlined dense")
                            .classes("w-full")
                        )

                        ps_warn = ui.switch(
                            "Warn on Failure", value=ps.get("warn_on_failure", True)
                        )

                        async def save_ps_settings():
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("secret_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            if "pattern_server" not in sect or not isinstance(
                                sect["pattern_server"], dict
                            ):
                                sect["pattern_server"] = {}
                            psc = sect["pattern_server"]
                            psc["url"] = ps_url.value.strip()
                            psc["patterns_endpoint"] = ps_endpoint.value.strip()
                            psc["warn_on_failure"] = ps_warn.value
                            psc["auth"] = {
                                "method": ps_auth_method.value.strip(),
                                "token_env": ps_token_env.value.strip(),
                                "token_file": ps_token_file.value.strip(),
                            }
                            cfg["secret_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify("Pattern server settings saved", type="positive")

                        ui.button(
                            "Save Settings", icon="save", on_click=save_ps_settings
                        ).props("dense").classes("mt-2")

                    # --- Cache settings ---
                    with ui.card().classes("w-full"):
                        ui.label("Pattern Cache Settings").classes("text-lg font-bold")
                        cache = ps.get("cache", {})
                        if not isinstance(cache, dict):
                            cache = {}
                        cache_path = (
                            ui.input(
                                label="Cache Path",
                                value=cache.get("path", ""),
                                placeholder="~/.config/ai-guardian/pattern-cache.json",
                            )
                            .props("outlined dense")
                            .classes("w-full")
                        )
                        cache_refresh = (
                            ui.input(
                                label="Refresh Interval (hours)",
                                value=str(cache.get("refresh_interval_hours", 12)),
                            )
                            .props("outlined dense")
                            .classes("w-48")
                        )
                        cache_expire = (
                            ui.input(
                                label="Expire After (hours)",
                                value=str(cache.get("expire_after_hours", 168)),
                            )
                            .props("outlined dense")
                            .classes("w-48")
                        )

                        async def save_cache():
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("secret_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            if "pattern_server" not in sect or not isinstance(
                                sect["pattern_server"], dict
                            ):
                                sect["pattern_server"] = {}
                            sect["pattern_server"]["cache"] = {
                                "path": cache_path.value.strip(),
                                "refresh_interval_hours": int(
                                    cache_refresh.value or 12
                                ),
                                "expire_after_hours": int(cache_expire.value or 168),
                            }
                            cfg["secret_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify("Cache settings saved", type="positive")

                        ui.button(
                            "Save Cache Settings", icon="save", on_click=save_cache
                        ).props("dense").classes("mt-2")

                    # --- Secret Validation (opt-in, Issue #976) ---
                    validate_on = ss.get("validate_secrets", False)

                    with ui.card().classes("w-full"):
                        ui.label("Secret Validation").classes("text-lg font-bold")
                        ui.label(
                            "Validate detected secrets against provider APIs "
                            "to check if they are still active."
                        ).classes("text-xs text-grey-6")

                        sv_switch = ui.switch(
                            "Enable Secret Validation",
                            value=bool(validate_on),
                        )

                        # Privacy consent banner — visible only when enabled
                        privacy_banner = (
                            ui.card()
                            .classes("w-full")
                            .style(
                                "background-color: rgba(255, 152, 0, 0.1); "
                                "border-left: 4px solid #ff9800"
                            )
                        )
                        privacy_banner.set_visibility(bool(validate_on))

                        with privacy_banner:
                            with ui.row().classes("items-center gap-2"):
                                ui.icon("warning").classes("text-amber")
                                ui.label("Privacy Warning").classes(
                                    "font-bold text-sm text-amber"
                                )
                            ui.label(
                                "Detected secrets will be sent to external provider "
                                "APIs for liveness validation. This happens "
                                "automatically on every detection. By enabling this "
                                "feature you consent to outbound network calls with "
                                "sensitive data."
                            ).classes("text-xs text-grey-7 ml-8")

                        async def on_validate_toggle(e, banner=privacy_banner):
                            banner.set_visibility(e.value)
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("secret_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["validate_secrets"] = e.value
                            cfg["secret_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(
                                f"Secret validation "
                                f"{'enabled' if e.value else 'disabled'}",
                                type="positive",
                            )

                        sv_switch.on_value_change(on_validate_toggle)

                    # --- Validation timeout ---
                    with ui.card().classes("w-full"):
                        ui.label("Validation Timeout").classes("text-lg font-bold")
                        ui.label(
                            "Timeout in milliseconds per secret validation "
                            "HTTP request (per-secret, not total)."
                        ).classes("text-xs text-grey-6")

                        timeout_val = ss.get("validation_timeout_ms", 3000)
                        timeout_input = (
                            ui.number(
                                label="Timeout (ms)",
                                value=timeout_val,
                                min=500,
                                max=30000,
                                step=100,
                            )
                            .props("dense outlined")
                            .classes("w-48")
                        )

                        async def save_timeout(e):
                            try:
                                val = int(e.value)
                                if val < 500 or val > 30000:
                                    ui.notify(
                                        "Timeout must be between 500 and 30000 ms",
                                        type="negative",
                                    )
                                    return
                            except (ValueError, TypeError):
                                ui.notify("Timeout must be a number", type="negative")
                                return
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("secret_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["validation_timeout_ms"] = val
                            cfg["secret_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Validation timeout: {val} ms", type="positive")

                        timeout_input.on("blur", save_timeout)

                    # --- On inactive action ---
                    with ui.card().classes("w-full"):
                        ui.label("Inactive Secret Action").classes("text-lg font-bold")
                        ui.label(
                            "Action to take when a detected secret is validated "
                            "as inactive (revoked/expired). Active and unverified "
                            "secrets always block regardless of this setting."
                        ).classes("text-xs text-grey-6")

                        on_inactive_val = ss.get("on_inactive", "warn")
                        inactive_sel = ui.select(
                            options={
                                "warn": "Warn — log warning, skip block",
                                "allow": "Allow — silently skip",
                            },
                            value=on_inactive_val,
                        ).classes("w-64")

                        async def save_on_inactive(e):
                            cfg = await run.io_bound(load_web_config)
                            sect = cfg.get("secret_scanning", {})
                            if not isinstance(sect, dict):
                                sect = {}
                            sect["on_inactive"] = e.value
                            cfg["secret_scanning"] = sect
                            await run.io_bound(save_web_config, cfg)
                            ui.notify(f"Inactive action: {e.value}", type="positive")

                        inactive_sel.on_value_change(save_on_inactive)

            ui.timer(0.1, refresh, once=True)
