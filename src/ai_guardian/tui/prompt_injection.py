#!/usr/bin/env python3
"""
Prompt Injection Tab Content

View and configure prompt injection detection settings.
"""

from textual.app import ComposeResult
from textual.containers import Container
from textual.widgets import Static


class PromptInjectionContent(Container):
    """Content widget for Prompt Injection tab."""

    CSS = """
    PromptInjectionContent {
        height: 100%;
        padding: 2;
    }

    #prompt-injection-info {
        margin: 2;
        padding: 2;
        background: $panel;
        border: solid $primary;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the prompt injection tab content."""
        yield Static(
            "[bold]Prompt Injection Detection Settings[/bold]\n\n"
            "Prompt injection detection helps protect against malicious\n"
            "prompts that try to manipulate AI behavior.\n\n"
            "Configuration:\n"
            "  • Enabled: Yes (default)\n"
            "  • Sensitivity: Medium (0.70)\n"
            "  • Allowlist patterns: Configured in ai-guardian.json\n\n"
            "To view prompt injection violations, use the Violations tab\n"
            "and filter by 'Prompt Injection'.\n\n"
            "[dim]Interactive configuration settings coming soon...[/dim]",
            id="prompt-injection-info"
        )

    def refresh_content(self) -> None:
        """Refresh content (called by parent app)."""
        pass  # Nothing to refresh yet
