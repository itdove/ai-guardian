#!/usr/bin/env python3
"""
SSRF Protection Tab Content

View and configure SSRF (Server-Side Request Forgery) protection settings.
"""

import json
from pathlib import Path
from typing import Union, Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Button, Input, Label, Select, Checkbox

from ai_guardian.config_utils import get_config_dir
from ai_guardian.tui.widgets import TimeBasedToggle


class SSRFContent(Container):
    """Content widget for SSRF Protection tab."""

    CSS = """
    SSRFContent {
        height: 100%;
    }

    #ssrf-header {
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
    }

    .setting-row Label {
        margin: 0 1 0 0;
        width: auto;
    }

    .setting-row Select {
        width: 30;
    }

    .setting-row Input {
        width: 50;
    }

    .setting-row Checkbox {
        margin: 0 1 0 0;
    }

    .setting-row Button {
        margin: 0 0 0 1;
    }

    #blocked-ips-list, #blocked-domains-list, #allowed-domains-list {
        margin: 1 0;
        padding: 1;
        background: $surface;
        border: solid $primary;
        min-height: 6;
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

    Select:focus {
        border-left: heavy $accent;
        text-style: bold;
    }

    Checkbox:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the SSRF protection tab content."""
        yield Static("[bold]SSRF Protection Settings[/bold]", id="ssrf-header")

        with VerticalScroll():
            # Protection toggle section (standalone)
            yield TimeBasedToggle(
                title="SSRF Protection",
                config_key="ssrf_protection_enabled",
                current_value=True,
                help_text="Prevents AI agents from accessing private networks, metadata endpoints, and dangerous URL schemes",
                id="ssrf_protection_enabled_toggle",
            )

            # Core protections info section
            with Container(classes="section"):
                yield Static("[bold]Core Protections (Immutable)[/bold]", classes="section-title")
                yield Static(
                    "[dim]The following protections CANNOT be disabled:\n\n"
                    "Private IP Ranges (RFC 1918):\n"
                    "  • 10.0.0.0/8 (Private network)\n"
                    "  • 172.16.0.0/12 (Private network)\n"
                    "  • 192.168.0.0/16 (Private network)\n"
                    "  • 127.0.0.0/8 (Loopback)\n"
                    "  • 169.254.0.0/16 (Link-local, AWS metadata)\n"
                    "  • ::1/128 (IPv6 loopback)\n"
                    "  • fc00::/7 (IPv6 private)\n"
                    "  • fe80::/10 (IPv6 link-local)\n\n"
                    "Cloud Metadata Endpoints:\n"
                    "  • 169.254.169.254 (AWS/Azure metadata)\n"
                    "  • metadata.google.internal (GCP)\n"
                    "  • fd00:ec2::254 (AWS IPv6)\n\n"
                    "Dangerous URL Schemes:\n"
                    "  • file://, gopher://, ftp://, data://, dict://, ldap://[/dim]",
                    id="core-protections"
                )

            # Action mode section
            with Container(classes="section"):
                yield Static("[bold]Action on SSRF Detection[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Action Mode:")
                    yield Select(
                        [
                            ("Block (default)", "block"),
                            ("Warn (allow but notify)", "warn"),
                            ("Log Only (silent)", "log-only")
                        ],
                        value="block",
                        id="action-select"
                    )
                    yield Static("[dim](Press 's' to save)[/dim]")

                yield Static(
                    "[dim]  • Block: Prevents execution (recommended)\n"
                    "  • Warn: Logs violation and shows warning, but allows execution\n"
                    "  • Log Only: Logs violation silently without user warning[/dim]",
                    classes="setting-row"
                )

            # Local development section
            with Container(classes="section"):
                yield Static("[bold]Local Development Options[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Label("Allow Localhost:")
                    yield Checkbox("", id="allow-localhost-checkbox", value=False)
                    yield Static("[dim]Enable to allow localhost (127.0.0.1, ::1) access for local dev/testing[/dim]")

            # Additional blocked IPs section
            with Container(classes="section"):
                yield Static("[bold]Additional Blocked IPs[/bold]", classes="section-title")
                yield Static("Additional IP addresses or CIDR ranges to block:", classes="setting-row")
                yield Static("", id="blocked-ips-list")
                yield Input(placeholder="Enter IP/CIDR to block (e.g., 203.0.113.0/24)", id="new-blocked-ip-input")
                yield Static("[dim]Press 'i' to add IP/CIDR[/dim]", classes="setting-row")

            # Additional blocked domains section
            with Container(classes="section"):
                yield Static("[bold]Additional Blocked Domains[/bold]", classes="section-title")
                yield Static("Additional domain names to block:", classes="setting-row")
                yield Static("", id="blocked-domains-list")
                yield Input(placeholder="Enter domain to block (e.g., internal.example.com)", id="new-blocked-domain-input")
                yield Static("[dim]Press 'd' to add domain[/dim]", classes="setting-row")

            # Allowed domains section (NEW in v1.5.0 - Issue #252)
            with Container(classes="section"):
                yield Static("[bold]Allowed Domains (Override Deny-List)[/bold]", classes="section-title")
                yield Static(
                    "Domains that override additional_blocked_domains (deny-first approach):",
                    classes="setting-row"
                )
                yield Static(
                    "[dim]⚠️  Cannot override immutable protections (metadata endpoints, private IPs, dangerous schemes)[/dim]",
                    classes="setting-row"
                )
                yield Static("", id="allowed-domains-list")
                yield Input(placeholder="Enter domain to allow (e.g., api.corp.internal)", id="new-allowed-domain-input")
                yield Static("[dim]Press 'a' to add allowed domain[/dim]", classes="setting-row")

            # Statistics section
            with Container(classes="section"):
                yield Static("[bold]Detection Statistics[/bold]", classes="section-title")
                yield Static("", id="ssrf-stats")

    def on_mount(self) -> None:
        """Load configuration when mounted."""
        self.load_config()

    def refresh_content(self) -> None:
        """Refresh configuration (called by parent app)."""
        self.load_config()

    def load_config(self) -> None:
        """Load and display SSRF protection configuration."""
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

        # SSRF protection settings
        ssrf_config = config.get("ssrf_protection", {})
        enabled_value = ssrf_config.get("enabled", True)
        action = ssrf_config.get("action", "block")
        allow_localhost = ssrf_config.get("allow_localhost", False)
        blocked_ips = ssrf_config.get("additional_blocked_ips", [])
        blocked_domains = ssrf_config.get("additional_blocked_domains", [])
        allowed_domains = ssrf_config.get("allowed_domains", [])

        # Update widgets
        try:
            toggle = self.query_one("#ssrf_protection_enabled_toggle", TimeBasedToggle)
            self.mount_toggle(toggle, "ssrf_protection_enabled", enabled_value)

            self.query_one("#action-select", Select).value = action
            self.query_one("#allow-localhost-checkbox", Checkbox).value = allow_localhost
        except Exception:
            pass  # Widgets may not be fully mounted yet

        # Update blocked IPs list
        if blocked_ips:
            ips_text = "\n".join([f"  • {ip}" for ip in blocked_ips])
        else:
            ips_text = "[dim]No additional IPs blocked[/dim]"
        self.query_one("#blocked-ips-list", Static).update(ips_text)

        # Update blocked domains list
        if blocked_domains:
            domains_text = "\n".join([f"  • {domain}" for domain in blocked_domains])
        else:
            domains_text = "[dim]No additional domains blocked[/dim]"
        self.query_one("#blocked-domains-list", Static).update(domains_text)

        # Update allowed domains list
        if allowed_domains:
            allowed_text = "\n".join([f"  • {domain}" for domain in allowed_domains])
        else:
            allowed_text = "[dim]No domains in allow-list[/dim]"
        self.query_one("#allowed-domains-list", Static).update(allowed_text)

        # Load statistics (if available)
        self._load_statistics()

    def mount_toggle(self, toggle: TimeBasedToggle, config_key: str, value: Union[bool, Dict]) -> None:
        """
        Mount a time-based toggle with the current value.

        Args:
            toggle: TimeBasedToggle widget
            config_key: Configuration key
            value: Current value (bool or time-based dict)
        """
        if isinstance(value, dict):
            # Time-based feature
            toggle.set_time_based_value(value)
        else:
            # Simple boolean
            toggle.set_value(value)

    def _load_statistics(self) -> None:
        """Load and display SSRF detection statistics."""
        try:
            from ai_guardian.violation_logger import ViolationLogger

            logger = ViolationLogger()
            stats = logger.get_statistics()

            # Filter for SSRF violations
            ssrf_count = 0
            total_violations = stats.get("total_violations", 0)

            # Get recent violations
            recent = logger.get_recent_violations(limit=100)
            for v in recent:
                if "SSRF" in v.get("reason", ""):
                    ssrf_count += 1

            stats_text = (
                f"Total SSRF Blocks: {ssrf_count}\n"
                f"Total Violations (All Types): {total_violations}"
            )

            self.query_one("#ssrf-stats", Static).update(stats_text)

        except ImportError:
            self.query_one("#ssrf-stats", Static).update("[dim]Violation logging not available[/dim]")
        except Exception as e:
            self.query_one("#ssrf-stats", Static).update(f"[dim]Error loading stats: {e}[/dim]")

    def save_config(self, config_updates: Dict[str, Any]) -> bool:
        """
        Save configuration updates.

        Args:
            config_updates: Dictionary of configuration updates

        Returns:
            bool: True if successful, False otherwise
        """
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            # Load existing config
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

            # Ensure ssrf_protection section exists
            if "ssrf_protection" not in config:
                config["ssrf_protection"] = {}

            # Update configuration
            config["ssrf_protection"].update(config_updates)

            # Save config
            config_dir.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.app.notify("SSRF protection configuration saved", severity="information")
            return True

        except Exception as e:
            self.app.notify(f"Error saving config: {e}", severity="error")
            return False

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        """Handle checkbox changes - save immediately."""
        checkbox_id = event.checkbox.id

        if checkbox_id == "allow-localhost-checkbox":
            self.save_config({"allow_localhost": event.value})
        elif checkbox_id and "ssrf_protection_enabled" in checkbox_id:
            # Handle TimeBasedToggle checkbox changes
            toggle = self.query_one("#ssrf_protection_enabled_toggle", TimeBasedToggle)
            value = toggle.get_value()
            self.save_config({"enabled": value})

    def on_select_changed(self, event) -> None:
        """Handle select changes - save immediately."""
        select_id = event.select.id

        if select_id == "action-select":
            self.save_config({"action": event.value})
        elif select_id and "ssrf_protection_enabled" in select_id:
            # Handle TimeBasedToggle select changes
            toggle = self.query_one("#ssrf_protection_enabled_toggle", TimeBasedToggle)
            value = toggle.get_value()
            self.save_config({"enabled": value})

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input fields."""
        input_id = event.input.id

        # Handle TimeBasedToggle inputs
        if input_id and "ssrf_protection_enabled" in input_id:
            toggle = self.query_one("#ssrf_protection_enabled_toggle", TimeBasedToggle)
            value = toggle.get_value()
            self.save_config({"enabled": value})
        elif input_id == "new-blocked-ip-input":
            self.add_blocked_ip()
        elif input_id == "new-blocked-domain-input":
            self.add_blocked_domain()
        elif input_id == "new-allowed-domain-input":
            self.add_allowed_domain()

    def action_add_ip(self) -> None:
        """Add blocked IP (triggered by 'i' key)."""
        self.add_blocked_ip()

    def action_add_domain(self) -> None:
        """Add blocked domain (triggered by 'd' key)."""
        self.add_blocked_domain()

    def action_add_allowed_domain(self) -> None:
        """Add allowed domain (triggered by 'a' key)."""
        self.add_allowed_domain()

    def action_save_setting(self) -> None:
        """Save settings (triggered by 's' key)."""
        # Already auto-saved on change, just notify
        self.app.notify("Settings auto-saved on change", severity="information")

    def action_refresh(self) -> None:
        """Refresh configuration (triggered by 'r' key)."""
        self.load_config()
        self.app.notify("SSRF configuration refreshed", severity="information")

    def add_blocked_ip(self) -> None:
        """Add an IP or CIDR range to the blocked list."""
        ip_input = self.query_one("#new-blocked-ip-input", Input)
        ip_value = ip_input.value.strip()

        if not ip_value:
            self.app.notify("Please enter an IP address or CIDR range", severity="error")
            return

        # Basic validation - check if it looks like an IP or CIDR
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        if not re.match(ip_pattern, ip_value):
            self.app.notify("Invalid IP address or CIDR format", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "ssrf_protection" not in config:
                config["ssrf_protection"] = {}

            if "additional_blocked_ips" not in config["ssrf_protection"]:
                config["ssrf_protection"]["additional_blocked_ips"] = []

            # Check if IP already exists
            if ip_value in config["ssrf_protection"]["additional_blocked_ips"]:
                self.app.notify("IP/CIDR already in blocked list", severity="warning")
                return

            config["ssrf_protection"]["additional_blocked_ips"].append(ip_value)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Clear input
            ip_input.value = ""

            self.load_config()
            self.app.notify(f"✓ Added {ip_value} to blocked IPs", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding IP: {e}", severity="error")

    def add_blocked_domain(self) -> None:
        """Add a domain to the blocked list."""
        domain_input = self.query_one("#new-blocked-domain-input", Input)
        domain_value = domain_input.value.strip()

        if not domain_value:
            self.app.notify("Please enter a domain name", severity="error")
            return

        # Basic validation - check if it looks like a domain
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain_value):
            self.app.notify("Invalid domain format", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "ssrf_protection" not in config:
                config["ssrf_protection"] = {}

            if "additional_blocked_domains" not in config["ssrf_protection"]:
                config["ssrf_protection"]["additional_blocked_domains"] = []

            # Check if domain already exists
            if domain_value in config["ssrf_protection"]["additional_blocked_domains"]:
                self.app.notify("Domain already in blocked list", severity="warning")
                return

            config["ssrf_protection"]["additional_blocked_domains"].append(domain_value)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Clear input
            domain_input.value = ""

            self.load_config()
            self.app.notify(f"✓ Added {domain_value} to blocked domains", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding domain: {e}", severity="error")

    def add_allowed_domain(self) -> None:
        """Add a domain to the allowed list (overrides deny-list)."""
        domain_input = self.query_one("#new-allowed-domain-input", Input)
        domain_value = domain_input.value.strip()

        if not domain_value:
            self.app.notify("Please enter a domain name", severity="error")
            return

        # Basic validation - check if it looks like a domain
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain_value):
            self.app.notify("Invalid domain format", severity="error")
            return

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            if "ssrf_protection" not in config:
                config["ssrf_protection"] = {}

            if "allowed_domains" not in config["ssrf_protection"]:
                config["ssrf_protection"]["allowed_domains"] = []

            # Check if domain already exists
            if domain_value in config["ssrf_protection"]["allowed_domains"]:
                self.app.notify("Domain already in allow-list", severity="warning")
                return

            config["ssrf_protection"]["allowed_domains"].append(domain_value)

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # Clear input
            domain_input.value = ""

            self.load_config()
            self.app.notify(f"✓ Added {domain_value} to allowed domains (overrides deny-list)", severity="success")

        except Exception as e:
            self.app.notify(f"Error adding allowed domain: {e}", severity="error")
