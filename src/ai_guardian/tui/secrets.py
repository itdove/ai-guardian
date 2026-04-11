#!/usr/bin/env python3
"""
Secrets Tab Content

View secret detection settings and secret-related violations.
"""

from textual.app import ComposeResult
from textual.containers import Container
from textual.widgets import Static


class SecretsContent(Container):
    """Content widget for Secrets tab."""

    CSS = """
    SecretsContent {
        height: 100%;
        padding: 2;
    }

    #secrets-info {
        margin: 2;
        padding: 2;
        background: $panel;
        border: solid $primary;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the secrets tab content."""
        yield Static(
            "[bold]Secret Detection Settings[/bold]\n\n"
            "Secret scanning is handled by Gitleaks and is enabled by default.\n\n"
            "Configuration:\n"
            "  • Gitleaks config: .gitleaks.toml (project-specific)\n"
            "  • Default patterns: Built-in Gitleaks rules\n"
            "  • Pattern server: Optional enhanced detection\n\n"
            "To view secret-related violations, use the Violations tab\n"
            "and filter by 'Secrets'.\n\n"
            "[dim]Advanced secret detection settings coming soon...[/dim]",
            id="secrets-info"
        )

    def refresh_content(self) -> None:
        """Refresh content (called by parent app)."""
        pass  # Nothing to refresh yet
