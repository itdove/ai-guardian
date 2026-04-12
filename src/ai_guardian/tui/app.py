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
from textual.widgets import Footer, Header, TabbedContent, TabPane, Button
from textual.binding import Binding
from textual import events


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
        Binding("r", "refresh_current_tab", "Refresh"),
        # Violations tab
        Binding("1", "filter_all", "All"),
        Binding("2", "filter_tool", "Tools"),
        Binding("3", "filter_secret", "Secrets"),
        Binding("4", "filter_directory", "Dirs"),
        Binding("5", "filter_injection", "Injection"),
        # Skills tab
        Binding("a", "add_allow_pattern", "Add Allow"),
        Binding("d", "add_deny_pattern", "Add Deny"),
        # MCP / Prompt Injection / Secrets tabs
        Binding("s", "save_setting", "Save"),
        Binding("t", "test_connection", "Test"),
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
        tabs = self.query_one(TabbedContent)
        active_pane = tabs.get_pane(tabs.active)

        # Try to call the specific action method if it exists
        for child in active_pane.children:
            if hasattr(child, "action_refresh"):
                child.action_refresh()
                return

        # Fallback to refresh_content
        if hasattr(active_pane, "refresh_content"):
            active_pane.refresh_content()
            self.notify("Tab refreshed", severity="information")

    def action_filter_all(self) -> None:
        """Filter all violations (only works on Violations tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-violations":
            return
        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_filter_all"):
                child.action_filter_all()
                return

    def action_filter_tool(self) -> None:
        """Filter tool violations (only works on Violations tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-violations":
            return
        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_filter_tool"):
                child.action_filter_tool()
                return

    def action_filter_secret(self) -> None:
        """Filter secret violations (only works on Violations tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-violations":
            return
        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_filter_secret"):
                child.action_filter_secret()
                return

    def action_filter_directory(self) -> None:
        """Filter directory violations (only works on Violations tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-violations":
            return
        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_filter_directory"):
                child.action_filter_directory()
                return

    def action_filter_injection(self) -> None:
        """Filter prompt injection violations (only works on Violations tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-violations":
            return
        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_filter_injection"):
                child.action_filter_injection()
                return

    def action_add_allow_pattern(self) -> None:
        """Add allow pattern (Skills tab) or add permission (MCP/Prompt Injection tabs)."""
        tabs = self.query_one(TabbedContent)
        active_pane = tabs.get_pane(tabs.active)

        # Skills tab - add allow pattern
        if tabs.active == "tab-skills":
            for child in active_pane.children:
                if hasattr(child, "action_add_allow"):
                    child.action_add_allow()
                    return

        # MCP tab - add permission
        elif tabs.active == "tab-mcp":
            for child in active_pane.children:
                if hasattr(child, "action_add_permission"):
                    child.action_add_permission()
                    return

        # Prompt Injection tab - add pattern
        elif tabs.active == "tab-prompt-injection":
            for child in active_pane.children:
                if hasattr(child, "action_add_pattern"):
                    child.action_add_pattern()
                    return

    def action_add_deny_pattern(self) -> None:
        """Add deny pattern (only works on Skills tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-skills":
            return

        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_add_deny"):
                child.action_add_deny()
                return

    def action_save_setting(self) -> None:
        """Save setting (works on Prompt Injection tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-prompt-injection":
            return

        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_update_sensitivity"):
                child.action_update_sensitivity()
                return

    def action_test_connection(self) -> None:
        """Test connection (only works on Secrets tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-secrets":
            return

        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_test_server"):
                child.action_test_server()
                return

    def action_focus_content(self) -> None:
        """Focus first widget in active tab content (arrow down from tabs)."""
        # Just focus next - let Textual handle it
        self.screen.focus_next()

    def action_focus_tabs(self) -> None:
        """Focus back to tab bar (arrow up from content)."""
        tabs = self.query_one(TabbedContent)
        tabs.focus()

    def action_tab_left(self) -> None:
        """Switch to previous tab (left arrow)."""
        tabs = self.query_one(TabbedContent)
        tab_ids = ["tab-violations", "tab-skills", "tab-mcp", "tab-secrets", "tab-prompt-injection", "tab-config"]
        try:
            current_index = tab_ids.index(tabs.active)
            previous_index = (current_index - 1) % len(tab_ids)
            tabs.active = tab_ids[previous_index]
        except:
            pass

    def action_tab_right(self) -> None:
        """Switch to next tab (right arrow)."""
        tabs = self.query_one(TabbedContent)
        tab_ids = ["tab-violations", "tab-skills", "tab-mcp", "tab-secrets", "tab-prompt-injection", "tab-config"]
        try:
            current_index = tab_ids.index(tabs.active)
            next_index = (current_index + 1) % len(tab_ids)
            tabs.active = tab_ids[next_index]
        except:
            pass

    def on_key(self, event: events.Key) -> None:
        """Handle arrow key navigation with boundaries."""
        focused = self.focused
        tabs = self.query_one(TabbedContent)

        if event.key == "down":
            # Save current focus
            before = focused
            # Try to move down
            self.screen.focus_next()
            # If we looped back to tabs or header, restore previous focus (at bottom)
            after = self.focused
            if after == tabs or (after and after.id in ["header"]):
                before.focus()
            event.prevent_default()

        elif event.key == "up":
            # If already on main tabs, don't move up
            if focused == tabs:
                event.prevent_default()
                return

            # Try to move up
            self.screen.focus_previous()
            # If we went to header or footer, go to tabs instead
            after = self.focused
            if after and after.id in ["header", "footer"]:
                tabs.focus()
            event.prevent_default()


def run_tui():
    """Run the AI Guardian TUI application."""
    app = AIGuardianTUI()
    app.run()
