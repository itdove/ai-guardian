#!/usr/bin/env python3
"""
Security Dashboard Tab Content

Overview of all Hermes Security features and centralized management.
Provides quick status view, bulk operations, and security analytics.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll, Grid
from textual.widgets import Static, Button, Label

from ai_guardian.config_utils import get_config_dir


class SecurityDashboardContent(Container):
    """Content widget for Security Dashboard tab."""

    CSS = """
    SecurityDashboardContent {
        height: 100%;
    }

    #dashboard-header {
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

    .feature-grid {
        grid-size: 2 4;
        grid-gutter: 1;
        height: auto;
        margin: 1 0;
    }

    .feature-card {
        height: 5;
        padding: 1;
        background: $surface;
        border: solid $accent;
    }

    .feature-enabled {
        border: solid green;
    }

    .feature-disabled {
        border: solid red;
    }

    .setting-row {
        margin: 0.5 0;
        height: auto;
    }

    .violation-item {
        margin: 0.5 0;
        padding: 0.5;
        background: $surface;
        border-left: heavy $accent;
    }

    Button {
        margin: 0 1 0 0;
    }

    /* Focus indicators */
    Button:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the security dashboard tab content."""
        yield Static("[bold]Hermes Security Dashboard[/bold]", id="dashboard-header")

        with VerticalScroll():
            # Overview section with feature status
            with Container(classes="section"):
                yield Static("[bold]Security Features Status[/bold]", classes="section-title")
                yield Static("", id="features-overview")

                with Grid(classes="feature-grid"):
                    # SSRF Protection card
                    with Container(classes="feature-card", id="ssrf-card"):
                        yield Static("[bold]SSRF Protection[/bold]")
                        yield Static("", id="ssrf-status")

                    # Prompt Injection card
                    with Container(classes="feature-card", id="prompt-injection-card"):
                        yield Static("[bold]Prompt Injection[/bold]")
                        yield Static("", id="prompt-injection-status")

                    # Unicode Attack Detection card
                    with Container(classes="feature-card", id="unicode-card"):
                        yield Static("[bold]Unicode Attacks[/bold]")
                        yield Static("", id="unicode-status")

                    # Config File Scanner card
                    with Container(classes="feature-card", id="config-scanner-card"):
                        yield Static("[bold]Config File Scanner[/bold]")
                        yield Static("", id="config-scanner-status")

                    # Secret Redaction card
                    with Container(classes="feature-card", id="secret-redaction-card"):
                        yield Static("[bold]Secret Redaction[/bold]")
                        yield Static("", id="secret-redaction-status")

                    # Summary card
                    with Container(classes="feature-card", id="summary-card"):
                        yield Static("[bold]Summary[/bold]")
                        yield Static("", id="summary-status")

            # Quick actions section
            with Container(classes="section"):
                yield Static("[bold]Quick Actions[/bold]", classes="section-title")

                with Horizontal(classes="setting-row"):
                    yield Button("Enable All Hermes Features", id="enable-all-btn", variant="success")
                    yield Button("Disable All Hermes Features", id="disable-all-btn", variant="error")
                    yield Button("Export Security Config", id="export-config-btn", variant="primary")

            # Recent violations section
            with Container(classes="section"):
                yield Static("[bold]Recent Security Violations (Last 24 Hours)[/bold]", classes="section-title")
                yield Static("", id="recent-violations")

            # Security recommendations section
            with Container(classes="section"):
                yield Static("[bold]Security Recommendations[/bold]", classes="section-title")
                yield Static("", id="recommendations")

    def on_mount(self) -> None:
        """Load dashboard data when mounted."""
        self.load_dashboard()

    def refresh_content(self) -> None:
        """Refresh dashboard (called by parent app)."""
        self.load_dashboard()

    def load_dashboard(self) -> None:
        """Load and display security dashboard data."""
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

        # Extract feature statuses
        features = {
            "ssrf_protection": config.get("ssrf_protection", {}).get("enabled", True),
            "prompt_injection": config.get("prompt_injection", {}).get("enabled", True),
            "unicode_detection": config.get("prompt_injection", {}).get("unicode_detection", {}).get("enabled", True),
            "config_file_scanning": config.get("config_file_scanning", {}).get("enabled", True),
            "secret_redaction": config.get("secret_redaction", {}).get("enabled", True),
        }

        # Update feature cards
        self._update_feature_card("ssrf", features["ssrf_protection"])
        self._update_feature_card("prompt-injection", features["prompt_injection"])
        self._update_feature_card("unicode", features["unicode_detection"])
        self._update_feature_card("config-scanner", features["config_file_scanning"])
        self._update_feature_card("secret-redaction", features["secret_redaction"])

        # Update summary
        enabled_count = sum(1 for status in features.values() if self._parse_status(status))
        total_count = len(features)
        summary_text = f"{enabled_count}/{total_count} Enabled"
        self.query_one("#summary-status", Static).update(summary_text)

        # Update summary card style
        summary_card = self.query_one("#summary-card", Container)
        if enabled_count == total_count:
            summary_card.add_class("feature-enabled")
            summary_card.remove_class("feature-disabled")
        elif enabled_count == 0:
            summary_card.add_class("feature-disabled")
            summary_card.remove_class("feature-enabled")
        else:
            summary_card.remove_class("feature-enabled")
            summary_card.remove_class("feature-disabled")

        # Update features overview
        overview_text = (
            f"[green]●[/green] Enabled: {enabled_count}    "
            f"[red]●[/red] Disabled: {total_count - enabled_count}"
        )
        self.query_one("#features-overview", Static).update(overview_text)

        # Load violations
        self._load_recent_violations()

        # Generate recommendations
        self._generate_recommendations(features)

    def _parse_status(self, status) -> bool:
        """
        Parse feature status (handles bool or time-based dict).

        Args:
            status: Feature status (bool or dict with 'value' key)

        Returns:
            bool: True if enabled, False if disabled
        """
        if isinstance(status, dict):
            return status.get("value", True)
        return bool(status)

    def _update_feature_card(self, feature_id: str, status) -> None:
        """
        Update a feature card with current status.

        Args:
            feature_id: Feature identifier
            status: Feature status (bool or time-based dict)
        """
        try:
            card = self.query_one(f"#{feature_id}-card", Container)
            status_widget = self.query_one(f"#{feature_id}-status", Static)

            is_enabled = self._parse_status(status)

            if is_enabled:
                status_text = "[green]✓ Enabled[/green]"
                card.add_class("feature-enabled")
                card.remove_class("feature-disabled")
            else:
                status_text = "[red]✗ Disabled[/red]"
                card.add_class("feature-disabled")
                card.remove_class("feature-enabled")

            # Check for time-based status
            if isinstance(status, dict) and status.get("disabled_until"):
                disabled_until = status.get("disabled_until", "")
                status_text += f"\n[dim]Until: {disabled_until}[/dim]"

            status_widget.update(status_text)

        except Exception:
            pass  # Widget may not be mounted yet

    def _load_recent_violations(self) -> None:
        """Load and display recent security violations."""
        try:
            from ai_guardian.violation_logger import ViolationLogger

            logger = ViolationLogger()
            violations = logger.get_recent_violations(limit=100)

            # Filter to last 24 hours
            now = datetime.now()
            recent = []

            for v in violations:
                timestamp_str = v.get("timestamp", "")
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    hours_ago = (now - timestamp.replace(tzinfo=None)).total_seconds() / 3600

                    if hours_ago <= 24:
                        recent.append(v)
                except Exception:
                    pass  # Skip if timestamp parsing fails

            if recent:
                # Group by type
                violation_types = {}
                for v in recent:
                    reason = v.get("reason", "Unknown")
                    violation_type = self._categorize_violation(reason)
                    violation_types[violation_type] = violation_types.get(violation_type, 0) + 1

                violations_text = f"Total: {len(recent)} violations\n\n"
                for vtype, count in sorted(violation_types.items(), key=lambda x: x[1], reverse=True):
                    violations_text += f"  • {vtype}: {count}\n"

                self.query_one("#recent-violations", Static).update(violations_text.strip())
            else:
                self.query_one("#recent-violations", Static).update("[dim]No violations in last 24 hours[/dim]")

        except ImportError:
            self.query_one("#recent-violations", Static).update("[dim]Violation logging not available[/dim]")
        except Exception as e:
            self.query_one("#recent-violations", Static).update(f"[dim]Error loading violations: {e}[/dim]")

    def _categorize_violation(self, reason: str) -> str:
        """
        Categorize a violation by its reason.

        Args:
            reason: Violation reason string

        Returns:
            str: Category name
        """
        reason_lower = reason.lower()

        if "ssrf" in reason_lower:
            return "SSRF Protection"
        elif "jailbreak" in reason_lower:
            return "Jailbreak Detection"
        elif "prompt injection" in reason_lower or "injection" in reason_lower:
            return "Prompt Injection"
        elif "unicode" in reason_lower or "zero-width" in reason_lower or "homoglyph" in reason_lower:
            return "Unicode Attack"
        elif "config" in reason_lower or "claude.md" in reason_lower or "agents.md" in reason_lower:
            return "Config File Scanner"
        elif "pii" in reason_lower:
            return "PII Detection"
        elif "secret" in reason_lower or "redact" in reason_lower:
            return "Secret Redaction"
        else:
            return "Other"

    def _generate_recommendations(self, features: Dict[str, Any]) -> None:
        """
        Generate security recommendations based on current config.

        Args:
            features: Dictionary of feature statuses
        """
        recommendations = []

        # Check for disabled features
        disabled_features = [name for name, status in features.items() if not self._parse_status(status)]

        if disabled_features:
            recommendations.append(
                f"⚠ {len(disabled_features)} security feature(s) disabled. "
                "Consider enabling all Hermes features for maximum protection."
            )

        # Load violation counts for recommendations
        try:
            from ai_guardian.violation_logger import ViolationLogger

            logger = ViolationLogger()
            recent = logger.get_recent_violations(limit=1000)

            if len(recent) > 100:
                recommendations.append(
                    f"⚠ {len(recent)} total violations detected. "
                    "Review violation log to identify patterns and adjust configuration."
                )

        except Exception:
            pass

        # Add best practice recommendations
        if not recommendations:
            recommendations.append("✓ All security features enabled - good security posture!")
            recommendations.append("💡 Tip: Review the Violations tab regularly to monitor security events.")
            recommendations.append("💡 Tip: Use time-based toggles to temporarily disable features during debugging.")

        recommendations_text = "\n\n".join(recommendations)
        self.query_one("#recommendations", Static).update(recommendations_text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        button_id = event.button.id

        if button_id == "enable-all-btn":
            self.enable_all_features()
        elif button_id == "disable-all-btn":
            self.disable_all_features()
        elif button_id == "export-config-btn":
            self.export_security_config()

    def enable_all_features(self) -> None:
        """Enable all Hermes security features."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # Enable all Hermes features
            features_to_enable = [
                "ssrf_protection",
                "prompt_injection",
                "config_file_scanning",
                "secret_redaction"
            ]

            for feature in features_to_enable:
                if feature not in config:
                    config[feature] = {}
                config[feature]["enabled"] = True

            # Enable unicode detection within prompt_injection
            if "prompt_injection" not in config:
                config["prompt_injection"] = {}
            if "unicode_detection" not in config["prompt_injection"]:
                config["prompt_injection"]["unicode_detection"] = {}
            config["prompt_injection"]["unicode_detection"]["enabled"] = True

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.load_dashboard()
            self.app.notify("✓ All Hermes security features enabled", severity="success")

        except Exception as e:
            self.app.notify(f"Error enabling features: {e}", severity="error")

    def disable_all_features(self) -> None:
        """Disable all Hermes security features."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}

            # Disable all Hermes features
            features_to_disable = [
                "ssrf_protection",
                "prompt_injection",
                "config_file_scanning",
                "secret_redaction"
            ]

            for feature in features_to_disable:
                if feature not in config:
                    config[feature] = {}
                config[feature]["enabled"] = False

            # Disable unicode detection within prompt_injection
            if "prompt_injection" not in config:
                config["prompt_injection"] = {}
            if "unicode_detection" not in config["prompt_injection"]:
                config["prompt_injection"]["unicode_detection"] = {}
            config["prompt_injection"]["unicode_detection"]["enabled"] = False

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            self.load_dashboard()
            self.app.notify("⚠ All Hermes security features disabled", severity="warning")

        except Exception as e:
            self.app.notify(f"Error disabling features: {e}", severity="error")

    def export_security_config(self) -> None:
        """Export security configuration to a file."""
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            if not config_path.exists():
                self.app.notify("No configuration file found", severity="error")
                return

            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # Extract only Hermes security features
            security_config = {
                "ssrf_protection": config.get("ssrf_protection", {}),
                "prompt_injection": config.get("prompt_injection", {}),
                "config_file_scanning": config.get("config_file_scanning", {}),
                "secret_redaction": config.get("secret_redaction", {}),
            }

            # Export to file
            export_path = config_dir / f"hermes-security-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(security_config, f, indent=2)

            self.app.notify(f"✓ Security config exported to: {export_path.name}", severity="success")

        except Exception as e:
            self.app.notify(f"Error exporting config: {e}", severity="error")

    def action_refresh(self) -> None:
        """Refresh dashboard (triggered by 'r' key)."""
        self.load_dashboard()
        self.app.notify("Security dashboard refreshed", severity="information")
