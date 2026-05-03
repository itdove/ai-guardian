#!/usr/bin/env python3
"""
Secrets Tab Content

View secret detection settings and manage configuration.
"""

import json
from pathlib import Path
from typing import Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Button, Input, Label, Checkbox

from ai_guardian.config_utils import get_cache_dir, get_config_dir
from ai_guardian.tui.schema_defaults import (
    SchemaDefaultsMixin, default_indicator, default_placeholder,
)
from ai_guardian.tui.widgets import TimeBasedToggle


class SecretsContent(SchemaDefaultsMixin, Container):
    """Content widget for Secrets tab."""

    SCHEMA_SECTION = "secret_scanning.pattern_server"
    SCHEMA_FIELDS = [
        ("pattern-server-warn-on-failure", "warn_on_failure", "checkbox"),
    ]

    CSS = """
    SecretsContent {
        height: 100%;
    }

    #secrets-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    .section {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    .section-title {
        margin: 0 0 1 0;
        font-weight: bold;
    }

    .setting-row {
        margin: 0.5 0;
        height: auto;
        align: left middle;
    }

    .list-scroll {
        max-height: 10;
        margin: 1 0;
        background: $surface;
        border: solid $primary;
    }

    #secret-allowlist-patterns {
        padding: 1;
        min-height: 2;
    }

    .setting-row Label {
        margin: 0 2 0 0;
        width: 20;
        content-align: right middle;
    }

    .setting-row Input {
        width: 50;
        margin: 0 2 0 0;
    }

    .setting-row Checkbox {
        margin: 0 2 0 0;
    }

    .setting-row Static {
        margin: 0 1 0 0;
    }

    .setting-row Button {
        margin: 0 1 0 0;
    }

    #actions {
        margin: 1 0;
        height: auto;
    }

    #actions Button {
        margin: 0 1 0 0;
    }

    /* Focus indicators */
    Input:focus {
        border-left: heavy $accent;
        text-style: bold;
    }

    Button:focus {
        border-left: heavy $accent;
        text-style: bold;
    }

    Checkbox:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the secrets tab content."""
        yield Static("[bold]Secret Detection Settings[/bold]", id="secrets-header")

        with VerticalScroll():
            # Gitleaks section
            with Container(classes="section"):
                yield Static("[bold]Scanner Engine[/bold]", classes="section-title")
                yield Static("", id="gitleaks-status")
                yield Static(
                    "[dim]Detection sources (in priority order):\n"
                    "  1. Pattern server: Organization patterns (if enabled below)\n"
                    "  2. Project-specific: .gitleaks.toml (if exists)\n"
                    "  3. Built-in: Gitleaks default rules (AWS, GitHub, SSH keys, etc.)[/dim]",
                    id="gitleaks-config"
                )

            # Allowlist patterns section (Issue #357)
            with Container(classes="section"):
                yield Static("[bold]Allowlist Patterns[/bold]", classes="section-title")
                yield Static(
                    "[dim]Regex patterns for known-safe secret values to ignore "
                    "(e.g., test API key prefixes, example tokens). "
                    "Unlike ignore_files, this keeps scanning but skips matching values.[/dim]",
                    classes="section-title",
                )
                with VerticalScroll(classes="list-scroll"):
                    yield Static("", id="secret-allowlist-patterns")
                yield Input(
                    placeholder="Enter regex pattern (e.g., pk_test_[A-Za-z0-9]{24,})",
                    id="secret-allowlist-input",
                )

            # Pattern server toggle section (standalone)
            yield TimeBasedToggle(
                title="Pattern Server (Optional - Enhanced Patterns)",
                config_key="pattern_server_enabled",
                current_value=False,
                help_text="Enable to use custom security patterns from a remote server in addition to built-in scanner rules",
                id="pattern_server_enabled_toggle",
            )

            # Pattern server settings section
            with Container(classes="section"):
                yield Static("[bold]Pattern Server Settings[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Server URL:")
                    yield Input(placeholder="https://pattern-server.example.com", id="pattern-server-url")
                    yield Static("[dim](Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Patterns Endpoint:")
                    yield Input(
                        placeholder=default_placeholder("secret_scanning.pattern_server.patterns_endpoint"),
                        id="pattern-server-endpoint",
                    )
                    yield Static("[dim](Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Warn on Failure:")
                    yield Checkbox("", id="pattern-server-warn-on-failure", value=True)
                    yield Static(
                        f"[dim]Show warnings when pattern server fails (auth, network, etc)[/dim] "
                        f"{default_indicator('secret_scanning.pattern_server.warn_on_failure')}"
                    )

                with Horizontal(classes="setting-row"):
                    yield Label("Auth Method:")
                    yield Input(placeholder="bearer", id="pattern-server-auth-method")
                    yield Static("[dim](Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Token Env Var:")
                    yield Input(placeholder="AI_GUARDIAN_PATTERN_TOKEN", id="pattern-server-token-env")
                    yield Static("[dim](Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Token File:")
                    yield Input(placeholder="~/.config/ai-guardian/pattern-token", id="pattern-server-token-file")
                    yield Static("[dim](Press Enter to save)[/dim]")

                yield Static("[dim]Press 't' to test connection[/dim]", classes="setting-row")

            # Cache settings section
            with Container(classes="section"):
                yield Static("[bold]Pattern Cache Settings[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Cache Path:")
                    yield Input(placeholder=str(get_cache_dir() / "patterns.toml"), id="cache-path")
                    yield Static("[dim](Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Refresh Interval:")
                    yield Input(
                        placeholder=default_placeholder("secret_scanning.pattern_server.cache.refresh_interval_hours"),
                        id="cache-refresh-interval",
                    )
                    yield Static(
                        f"[dim]hours (Press Enter to save)[/dim] "
                        f"{default_indicator('secret_scanning.pattern_server.cache.refresh_interval_hours')}"
                    )

                with Horizontal(classes="setting-row"):
                    yield Label("Expire After:")
                    yield Input(
                        placeholder=default_placeholder("secret_scanning.pattern_server.cache.expire_after_hours"),
                        id="cache-expire-after",
                    )
                    yield Static(
                        f"[dim]hours (Press Enter to save)[/dim] "
                        f"{default_indicator('secret_scanning.pattern_server.cache.expire_after_hours')}"
                    )


    def on_mount(self) -> None:
        """Load configuration when mounted."""
        self.load_config()

    def refresh_content(self) -> None:
        """Refresh configuration (called by parent app)."""
        self.load_config()

    def load_config(self) -> None:
        """Load and display secret detection configuration."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        # Load config
        config = {}
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except Exception as e:
                self.app.notify(f"Error loading config: {e}", severity="error")

        # Pattern server status - read from secret_scanning.pattern_server (new location)
        # with fallback to root-level pattern_server (deprecated) for backward compatibility
        secret_scanning = config.get("secret_scanning", {})
        pattern_server = secret_scanning.get("pattern_server", {})

        # Fallback to deprecated root-level location if not found in secret_scanning
        if not pattern_server:
            pattern_server = config.get("pattern_server", {})

        enabled_value = pattern_server.get("enabled", False)
        server_url = pattern_server.get("url", pattern_server.get("server_url", ""))
        patterns_endpoint = pattern_server.get("patterns_endpoint", "/patterns/gitleaks/8.18.1")
        warn_on_failure = pattern_server.get("warn_on_failure", True)
        auth = pattern_server.get("auth", {})
        auth_method = auth.get("method", "bearer")
        token_env = auth.get("token_env", "AI_GUARDIAN_PATTERN_TOKEN")
        token_file = auth.get("token_file", "~/.config/ai-guardian/pattern-token")

        # Update time-based toggle and inputs
        try:
            toggle = self.query_one("#pattern_server_enabled_toggle", TimeBasedToggle)
            toggle.load_value(enabled_value)

            self.query_one("#pattern-server-url", Input).value = server_url
            self.query_one("#pattern-server-endpoint", Input).value = patterns_endpoint
            self.query_one("#pattern-server-warn-on-failure", Checkbox).value = warn_on_failure
            self.query_one("#pattern-server-auth-method", Input).value = auth_method
            self.query_one("#pattern-server-token-env", Input).value = token_env
            self.query_one("#pattern-server-token-file", Input).value = token_file
        except Exception:
            pass  # Widgets may not be mounted yet

        # Determine if pattern server is actually enabled (check time-based expiration)
        is_enabled = False
        if isinstance(enabled_value, dict):
            is_enabled = enabled_value.get("value", False)
        else:
            is_enabled = enabled_value

        # Gitleaks status - check for project config
        from pathlib import Path
        project_config = Path.cwd() / ".gitleaks.toml"
        if project_config.exists():
            gitleaks_status = f"[status-ok]✓[/status-ok] Using project config: {project_config}"
        elif is_enabled:
            gitleaks_status = "[status-ok]✓[/status-ok] Using pattern server (enhanced patterns)"
        else:
            gitleaks_status = "[status-ok]✓[/status-ok] Using Gitleaks built-in rules"

        self.query_one("#gitleaks-status", Static).update(gitleaks_status)

        # Allowlist patterns (Issue #357)
        allowlist = secret_scanning.get("allowlist_patterns", [])
        if allowlist:
            pattern_lines = []
            for pattern in allowlist:
                if isinstance(pattern, dict):
                    pattern_str = pattern.get("pattern", "")
                    valid_until = pattern.get("valid_until", "")
                    if valid_until:
                        from datetime import datetime, timezone
                        try:
                            expiry_dt = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
                            now = datetime.now(timezone.utc)
                            if expiry_dt <= now:
                                pattern_lines.append(f"  {pattern_str} [EXPIRED]")
                            elif (expiry_dt - now).total_seconds() < 86400:
                                pattern_lines.append(f"  {pattern_str} [expires {valid_until}]")
                            else:
                                pattern_lines.append(f"  {pattern_str} [until {valid_until}]")
                        except (ValueError, TypeError):
                            pattern_lines.append(f"  {pattern_str}")
                    else:
                        pattern_lines.append(f"  {pattern_str}")
                else:
                    pattern_lines.append(f"  {pattern}")
            allowlist_text = "\n".join(pattern_lines)
        else:
            allowlist_text = "[dim]No allowlist patterns configured[/dim]"
        try:
            self.query_one("#secret-allowlist-patterns", Static).update(allowlist_text)
        except Exception:
            pass

        # Cache settings
        cache = pattern_server.get("cache", {})
        cache_path = cache.get("path", str(get_cache_dir() / "patterns.toml"))
        refresh_interval = cache.get("refresh_interval_hours", 12)
        expire_after = cache.get("expire_after_hours", 168)

        try:
            self.query_one("#cache-path", Input).value = cache_path
            self.query_one("#cache-refresh-interval", Input).value = str(refresh_interval)
            self.query_one("#cache-expire-after", Input).value = str(expire_after)
        except Exception:
            pass  # Widgets may not be mounted yet

        self._apply_default_indicators(pattern_server)

    def mount_toggle(self, toggle: TimeBasedToggle, config_key: str, value: Union[bool, Dict[str, Any]]) -> None:
        """Update a toggle widget with new configuration value."""
        # Parse value
        if isinstance(value, dict):
            toggle.is_enabled = value.get("value", False)
            toggle.disabled_until = value.get("disabled_until", "")
            toggle.reason = value.get("reason", "")
        else:
            toggle.is_enabled = value
            toggle.disabled_until = ""
            toggle.reason = ""

        # Determine mode
        if toggle.is_enabled:
            toggle.current_mode = "enabled"
        elif toggle.disabled_until:
            toggle.current_mode = "temp_disabled"
        else:
            toggle.current_mode = "disabled"

        # Update widgets
        try:
            mode_select = toggle.query_one(f"#{config_key}_mode_select")
            mode_select.value = toggle.current_mode

            disabled_until_input = toggle.query_one(f"#{config_key}_disabled_until")
            from ai_guardian.tui.widgets import duration_from_timestamp
            dur = duration_from_timestamp(toggle.disabled_until) if toggle.disabled_until else ""
            disabled_until_input.value = dur if dur != "expired" else ""

            reason_input = toggle.query_one(f"#{config_key}_reason")
            reason_input.value = toggle.reason

            toggle.update_temp_fields_visibility()
            toggle.update_status_display()
        except Exception:
            pass

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Handle checkbox toggle."""
        if event.checkbox.id == "pattern-server-warn-on-failure":
            self.save_pattern_server_field("warn_on_failure", event.value)

    def on_select_changed(self, event) -> None:
        """Handle mode selector change in TimeBasedToggle - save immediately."""
        select_id = event.select.id

        if select_id and "pattern_server_enabled" in select_id:
            toggle = self.query_one("#pattern_server_enabled_toggle", TimeBasedToggle)
            if toggle.current_mode == "temp_disabled":
                return
            value = toggle.get_value()
            self.save_pattern_server_enabled_value(value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input fields - save the value."""
        input_id = event.input.id

        # Handle TimeBasedToggle inputs
        if input_id and "pattern_server_enabled" in input_id:
            toggle = self.query_one("#pattern_server_enabled_toggle", TimeBasedToggle)
            value = toggle.get_value()
            self.save_pattern_server_enabled_value(value)
        elif event.input.id == "pattern-server-url":
            self.save_pattern_server_field("url", event.value)
        elif event.input.id == "pattern-server-endpoint":
            self.save_pattern_server_field("patterns_endpoint", event.value)
        elif event.input.id == "pattern-server-auth-method":
            self.save_pattern_server_auth_field("method", event.value)
        elif event.input.id == "pattern-server-token-env":
            self.save_pattern_server_auth_field("token_env", event.value)
        elif event.input.id == "pattern-server-token-file":
            self.save_pattern_server_auth_field("token_file", event.value)
        elif event.input.id == "cache-path":
            self.save_cache_field("path", event.value)
        elif event.input.id == "cache-refresh-interval":
            try:
                hours = int(event.value)
                self.save_cache_field("refresh_interval_hours", hours)
            except ValueError:
                self.app.notify("Refresh interval must be a number", severity="error")
        elif event.input.id == "cache-expire-after":
            try:
                hours = int(event.value)
                self.save_cache_field("expire_after_hours", hours)
            except ValueError:
                self.app.notify("Expire after must be a number", severity="error")
        elif event.input.id == "secret-allowlist-input":
            self._add_allowlist_pattern()

    def action_test_server(self) -> None:
        """Test pattern server connection (triggered by 't' key)."""
        self.test_pattern_server()

    def action_refresh(self) -> None:
        """Refresh configuration (triggered by 'r' key)."""
        self.load_config()
        self.app.notify("Secrets configuration refreshed", severity="information")

    def save_pattern_server_enabled_value(self, value: Union[bool, Dict[str, Any]]) -> None:
        """Save pattern server enabled state to config (supports time-based format)."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # Ensure secret_scanning section exists
            if "secret_scanning" not in config:
                config["secret_scanning"] = {}

            # Ensure pattern_server section exists under secret_scanning
            if "pattern_server" not in config["secret_scanning"]:
                config["secret_scanning"]["pattern_server"] = {}

            # Save to secret_scanning.pattern_server (new location)
            config["secret_scanning"]["pattern_server"]["enabled"] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Show status message
            if isinstance(value, bool):
                status = "enabled" if value else "disabled"
                self.app.notify(f"✓ Pattern server {status}", severity="success")
            else:
                if value.get("disabled_until"):
                    self.app.notify(
                        f"✓ Pattern server temporarily disabled until {value['disabled_until']}",
                        severity="success"
                    )
                else:
                    self.app.notify("✓ Pattern server disabled", severity="success")

            # Reload to update status
            self.load_config()

        except Exception as e:
            self.app.notify(f"Error saving config: {e}", severity="error")

    def save_pattern_server_field(self, field: str, value: str) -> None:
        """Save a pattern server field to config."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # Ensure secret_scanning section exists
            if "secret_scanning" not in config:
                config["secret_scanning"] = {}

            # Ensure pattern_server section exists under secret_scanning
            if "pattern_server" not in config["secret_scanning"]:
                config["secret_scanning"]["pattern_server"] = {}

            # Save to secret_scanning.pattern_server (new location)
            config["secret_scanning"]["pattern_server"][field] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.app.notify(f"✓ Saved {field}", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving {field}: {e}", severity="error")

    def save_pattern_server_auth_field(self, field: str, value: str) -> None:
        """Save a pattern server auth field to config."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # Ensure secret_scanning section exists
            if "secret_scanning" not in config:
                config["secret_scanning"] = {}

            # Ensure pattern_server section exists under secret_scanning
            if "pattern_server" not in config["secret_scanning"]:
                config["secret_scanning"]["pattern_server"] = {}

            # Ensure auth section exists under pattern_server
            if "auth" not in config["secret_scanning"]["pattern_server"]:
                config["secret_scanning"]["pattern_server"]["auth"] = {}

            # Save to secret_scanning.pattern_server.auth (new location)
            config["secret_scanning"]["pattern_server"]["auth"][field] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.app.notify(f"✓ Saved auth {field}", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving auth {field}: {e}", severity="error")

    def save_cache_field(self, field: str, value) -> None:
        """Save a cache field to config."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # Ensure secret_scanning section exists
            if "secret_scanning" not in config:
                config["secret_scanning"] = {}

            # Ensure pattern_server section exists under secret_scanning
            if "pattern_server" not in config["secret_scanning"]:
                config["secret_scanning"]["pattern_server"] = {}

            # Ensure cache section exists under pattern_server
            if "cache" not in config["secret_scanning"]["pattern_server"]:
                config["secret_scanning"]["pattern_server"]["cache"] = {}

            # Save to secret_scanning.pattern_server.cache (new location)
            config["secret_scanning"]["pattern_server"]["cache"][field] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.app.notify(f"✓ Saved cache {field}", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving cache {field}: {e}", severity="error")

    def _add_allowlist_pattern(self) -> None:
        """Add a regex pattern to the secret scanning allowlist."""
        input_widget = self.query_one("#secret-allowlist-input", Input)
        pattern = input_widget.value.strip()

        if not pattern:
            self.app.notify("Please enter a regex pattern", severity="error")
            return

        import re
        try:
            re.compile(pattern)
        except re.error as e:
            self.app.notify(f"Invalid regex: {e}", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

            if "secret_scanning" not in config:
                config["secret_scanning"] = {}
            if "allowlist_patterns" not in config["secret_scanning"]:
                config["secret_scanning"]["allowlist_patterns"] = []

            if pattern in config["secret_scanning"]["allowlist_patterns"]:
                self.app.notify("Pattern already in allowlist", severity="warning")
                return

            config["secret_scanning"]["allowlist_patterns"].append(pattern)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            input_widget.value = ""
            self.load_config()
            self.app.notify(f"Added allowlist pattern: {pattern}", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding pattern: {e}", severity="error")

    def test_pattern_server(self) -> None:
        """Test connection to pattern server."""
        server_url = self.query_one("#pattern-server-url", Input).value.strip()

        if not server_url:
            self.app.notify("Please enter a server URL", severity="error")
            return

        try:
            import requests
            response = requests.get(f"{server_url}/health", timeout=5)
            if response.status_code == 200:
                self.app.notify(f"✓ Pattern server is reachable at {server_url}", severity="success")
            else:
                self.app.notify(f"Pattern server returned status {response.status_code}", severity="warning")
        except ImportError:
            self.app.notify("requests library not installed - cannot test connection", severity="error")
        except Exception as e:
            self.app.notify(f"✗ Cannot connect to pattern server: {e}", severity="error")
