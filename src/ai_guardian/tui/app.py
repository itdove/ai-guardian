#!/usr/bin/env python3
"""
Main TUI Application

Provides interactive text-based interface for AI Guardian configuration.
Tab-based interface with separate tabs for:
- Violations: All recent violations with filtering
- Skills: Skill permissions management
- MCP Servers: MCP server permissions management
- Secrets: Secret detection settings
- Prompt Injection: Prompt injection detection settings
- Config: View/export configuration
"""

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Footer, Header, TabbedContent, TabPane
from textual.binding import Binding


class AIGuardianTUI(App):
    """AI Guardian TUI Application with tab-based interface."""

    CSS = """
    Screen {
        background: $surface;
    }

    TabbedContent {
        height: 100%;
    }

    TabPane {
        padding: 1 2;
    }
    """

    TITLE = "AI Guardian Configuration"
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("ctrl+r", "refresh_current_tab", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()

        with TabbedContent():
            with TabPane("📋 Violations", id="tab-violations"):
                from ai_guardian.tui.violations import ViolationsContent
                yield ViolationsContent()

            with TabPane("🎯 Skills", id="tab-skills"):
                from ai_guardian.tui.skills import SkillsContent
                yield SkillsContent()

            with TabPane("🔌 MCP Servers", id="tab-mcp"):
                from ai_guardian.tui.mcp_servers import MCPServersContent
                yield MCPServersContent()

            with TabPane("🔒 Secrets", id="tab-secrets"):
                from ai_guardian.tui.secrets import SecretsContent
                yield SecretsContent()

            with TabPane("🛡️ Prompt Injection", id="tab-prompt-injection"):
                from ai_guardian.tui.prompt_injection import PromptInjectionContent
                yield PromptInjectionContent()

            with TabPane("📄 Config", id="tab-config"):
                from ai_guardian.tui.config_viewer import ConfigContent
                yield ConfigContent()

        yield Footer()

    def action_refresh_current_tab(self) -> None:
        """Refresh the current tab's content."""
        # Get the active tab and refresh it
        tabs = self.query_one(TabbedContent)
        active_pane = tabs.get_pane(tabs.active)
        if active_pane and hasattr(active_pane, "refresh_content"):
            active_pane.refresh_content()
            self.notify("Tab refreshed", severity="information")


def run_tui():
    """Run the AI Guardian TUI application."""
    app = AIGuardianTUI()
    app.run()
