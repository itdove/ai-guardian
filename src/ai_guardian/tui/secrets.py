#!/usr/bin/env python3
"""
Secrets Tab Content

View secret detection settings and manage configuration.
"""

import json
from pathlib import Path
from typing import Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll, Vertical
from textual.widgets import Static, Button, Input, Label, Checkbox

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.widgets import TimeBasedToggle


class SecretsContent(Container):
    """Content widget for Secrets tab."""

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
                yield Static("[bold]Gitleaks Configuration[/bold]", classes="section-title")
                yield Static("", id="gitleaks-status")
                yield Static(
                    "[dim]Detection sources (in priority order):\n"
                    "  1. Pattern server: Organization patterns (if enabled below)\n"
                    "  2. Project-specific: .gitleaks.toml (if exists)\n"
                    "  3. Built-in: Gitleaks default rules (AWS, GitHub, SSH keys, etc.)[/dim]",
                    id="gitleaks-config"
                )

            # Pattern server toggle section (standalone)
            yield TimeBasedToggle(
                title="Pattern Server (Optional - Enhanced Patterns)",
                config_key="pattern_server_enabled",
                current_value=False,
                help_text="Enable to use custom security patterns from a remote server in addition to Gitleaks defaults",
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
                    yield Input(placeholder="/patterns/gitleaks/8.18.1", id="pattern-server-endpoint")
                    yield Static("[dim](Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Warn on Failure:")
                    yield Checkbox("", id="pattern-server-warn-on-failure", value=True)
                    yield Static("[dim]Show warnings when pattern server fails (auth, network, etc)[/dim]")

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
                    yield Input(placeholder="~/.cache/ai-guardian/patterns.toml", id="cache-path")
                    yield Static("[dim](Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Refresh Interval:")
                    yield Input(placeholder="12", id="cache-refresh-interval")
                    yield Static("[dim]hours (Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Expire After:")
                    yield Input(placeholder="168", id="cache-expire-after")
                    yield Static("[dim]hours (Press Enter to save)[/dim]")

            # Violation logging section
            with Container(classes="section"):
                yield Static("[bold]Violation Logging Settings[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Enabled:")
                    yield Checkbox("", id="violation-logging-enabled")

                with Horizontal(classes="setting-row"):
                    yield Label("Max Entries:")
                    yield Input(placeholder="1000", id="violation-max-entries")
                    yield Static("[dim](Press Enter to save)[/dim]")

                with Horizontal(classes="setting-row"):
                    yield Label("Retention Days:")
                    yield Input(placeholder="30", id="violation-retention-days")
                    yield Static("[dim](Press Enter to save)[/dim]")

                yield Static("Log Types (auto-saves):", classes="setting-row")
                with Vertical(id="log-types-container"):
                    yield Checkbox("Tool Permission", id="log-type-tool", value=True)
                    yield Checkbox("Directory Blocking", id="log-type-directory", value=True)
                    yield Checkbox("Secret Detected", id="log-type-secret", value=True)
                    yield Checkbox("Secret Redaction", id="log-type-redaction", value=True)
                    yield Checkbox("Prompt Injection", id="log-type-injection", value=True)
                    yield Checkbox("SSRF Blocked", id="log-type-ssrf", value=True)
                    yield Checkbox("Config File Exfil", id="log-type-config-exfil", value=True)
                    yield Checkbox("PII Detected", id="log-type-pii", value=True)

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
            self.mount_toggle(toggle, "pattern_server_enabled", enabled_value)

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

        # Cache settings
        cache = pattern_server.get("cache", {})
        cache_path = cache.get("path", "~/.cache/ai-guardian/patterns.toml")
        refresh_interval = cache.get("refresh_interval_hours", 12)
        expire_after = cache.get("expire_after_hours", 168)

        try:
            self.query_one("#cache-path", Input).value = cache_path
            self.query_one("#cache-refresh-interval", Input).value = str(refresh_interval)
            self.query_one("#cache-expire-after", Input).value = str(expire_after)
        except Exception:
            pass  # Widgets may not be mounted yet

        # Violation logging settings
        violation_logging = config.get("violation_logging", {})
        log_enabled = violation_logging.get("enabled", True)
        max_entries = violation_logging.get("max_entries", 1000)
        retention_days = violation_logging.get("retention_days", 30)
        log_types = violation_logging.get("log_types", ["tool_permission", "directory_blocking", "secret_detected", "secret_redaction", "prompt_injection", "ssrf_blocked", "config_file_exfil", "pii_detected"])

        try:
            self.query_one("#violation-logging-enabled", Checkbox).value = log_enabled
            self.query_one("#violation-max-entries", Input).value = str(max_entries)
            self.query_one("#violation-retention-days", Input).value = str(retention_days)

            # Update checkboxes
            self.query_one("#log-type-tool", Checkbox).value = "tool_permission" in log_types
            self.query_one("#log-type-directory", Checkbox).value = "directory_blocking" in log_types
            self.query_one("#log-type-secret", Checkbox).value = "secret_detected" in log_types
            self.query_one("#log-type-redaction", Checkbox).value = "secret_redaction" in log_types
            self.query_one("#log-type-injection", Checkbox).value = "prompt_injection" in log_types
            self.query_one("#log-type-ssrf", Checkbox).value = "ssrf_blocked" in log_types
            self.query_one("#log-type-config-exfil", Checkbox).value = "config_file_exfil" in log_types
            self.query_one("#log-type-pii", Checkbox).value = "pii_detected" in log_types
        except Exception:
            pass  # Widgets may not be mounted yet

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
            disabled_until_input.value = toggle.disabled_until

            reason_input = toggle.query_one(f"#{config_key}_reason")
            reason_input.value = toggle.reason

            toggle.update_temp_fields_visibility()
            toggle.update_status_display()
        except Exception:
            pass

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Handle checkbox toggle."""
        if event.checkbox.id == "violation-logging-enabled":
            self.save_violation_logging_enabled(event.value)
        elif event.checkbox.id == "pattern-server-warn-on-failure":
            self.save_pattern_server_field("warn_on_failure", event.value)
        elif event.checkbox.id and event.checkbox.id.startswith("log-type-"):
            self.save_log_types()

    def on_select_changed(self, event) -> None:
        """Handle mode selector change in TimeBasedToggle - save immediately."""
        select_id = event.select.id

        if select_id and "pattern_server_enabled" in select_id:
            toggle = self.query_one("#pattern_server_enabled_toggle", TimeBasedToggle)
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
        elif event.input.id == "violation-max-entries":
            try:
                max_entries = int(event.value)
                self.save_violation_logging_field("max_entries", max_entries)
            except ValueError:
                self.app.notify("Max entries must be a number", severity="error")
        elif event.input.id == "violation-retention-days":
            try:
                days = int(event.value)
                self.save_violation_logging_field("retention_days", days)
            except ValueError:
                self.app.notify("Retention days must be a number", severity="error")

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

    def save_violation_logging_enabled(self, enabled: bool) -> None:
        """Save violation logging enabled state to config."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "violation_logging" not in config:
                config["violation_logging"] = {}

            config["violation_logging"]["enabled"] = enabled

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            status = "enabled" if enabled else "disabled"
            self.app.notify(f"✓ Violation logging {status}", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving config: {e}", severity="error")

    def save_violation_logging_field(self, field: str, value) -> None:
        """Save a violation logging field to config."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "violation_logging" not in config:
                config["violation_logging"] = {}

            config["violation_logging"][field] = value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.app.notify(f"✓ Saved {field}", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving {field}: {e}", severity="error")

    def save_log_types(self) -> None:
        """Save log types based on checkbox states."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "violation_logging" not in config:
                config["violation_logging"] = {}

            # Collect enabled log types
            log_types = []
            if self.query_one("#log-type-tool", Checkbox).value:
                log_types.append("tool_permission")
            if self.query_one("#log-type-directory", Checkbox).value:
                log_types.append("directory_blocking")
            if self.query_one("#log-type-secret", Checkbox).value:
                log_types.append("secret_detected")
            if self.query_one("#log-type-redaction", Checkbox).value:
                log_types.append("secret_redaction")
            if self.query_one("#log-type-injection", Checkbox).value:
                log_types.append("prompt_injection")
            if self.query_one("#log-type-ssrf", Checkbox).value:
                log_types.append("ssrf_blocked")
            if self.query_one("#log-type-config-exfil", Checkbox).value:
                log_types.append("config_file_exfil")
            if self.query_one("#log-type-pii", Checkbox).value:
                log_types.append("pii_detected")

            config["violation_logging"]["log_types"] = log_types

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.app.notify("✓ Saved log types", severity="success")

        except Exception as e:
            self.app.notify(f"Error saving log types: {e}", severity="error")

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
