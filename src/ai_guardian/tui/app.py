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

from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Footer, Header, TabbedContent, TabPane, Button, Input
from textual.binding import Binding
from textual import events


class AIGuardianTUI(App):
    """AI Guardian TUI Application with tab-based interface."""

    # Disable command palette so ESC doesn't get consumed
    ENABLE_COMMAND_PALETTE = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._input_original_values = {}

    CSS = """
    Screen {
        background: $surface;
    }

    Footer {
        background: $panel;
        color: $text;
        dock: bottom;
    }

    TabbedContent {
        height: 100%;
    }

    TabbedContent > Tabs {
        background: $surface;
    }

    TabbedContent > Tabs > Tab {
        background: $surface;
        color: $text-muted;
    }

    TabbedContent > Tabs > Tab.-active {
        background: $primary;
        color: $background;
        text-style: bold;
    }

    TabbedContent:focus > Tabs > Tab.-active {
        background: $accent;
        color: $background;
        text-style: bold;
    }

    TabPane {
        padding: 1 2;
    }

    /* Empty states */
    .empty-state {
        color: #b0b0b0;
        text-align: center;
        padding: 2;
    }

    /* Status indicators */
    .status-ok {
        color: #76b900;
    }

    .status-warn {
        color: #d4aa00;
    }

    .status-error {
        color: #e03131;
    }

    /* Muted text */
    .muted {
        color: #b0b0b0;
    }

    /* Input fields - make them visible */
    Input {
        border: none;
        background: $surface;
        padding: 0 1;
        height: 1;
        margin: 0 1 0 0;
    }

    Input:focus {
        border-left: heavy $accent;
        text-style: bold;
        background: $surface;
    }

    /* Buttons - make them visible */
    Button {
        min-width: 10;
        height: 3;
        border: none;
        background: $panel;
        margin: 0 1 0 0;
    }

    Button:hover {
        background: $primary;
    }

    Button:focus {
        text-style: bold;
        border-left: heavy $accent;
    }

    /* Select widget */
    Select {
        border: none;
        background: $surface;
    }

    Select:focus {
        text-style: bold;
        border-left: heavy $accent;
    }


    /* Checkbox widget - no frame */
    Checkbox {
        border: none;
    }

    Checkbox:focus {
        text-style: bold;
        border-left: heavy $accent;
    }
    """

    TITLE = "AI Guardian Configuration"
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "refresh_current_tab", "Refresh"),
        # Filter shortcuts (hidden, still work via keys)
        Binding("1", "filter_all", show=False),
        Binding("2", "filter_tool", show=False),
        Binding("3", "filter_secret", show=False),
        Binding("4", "filter_directory", show=False),
        Binding("5", "filter_injection", show=False),
        # Context-specific (shown/hidden based on tab via check_action)
        Binding("a", "add_allow_pattern", "Add", show=True),
        Binding("c", "add_custom", "Custom", show=True),
        Binding("d", "add_deny_pattern", "Deny", show=True),
        Binding("s", "save_setting", "Save", show=True),
        Binding("t", "test_connection", "Test", show=True),
    ]

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        """Store original value when Input gets focus."""
        widget = event.widget
        if isinstance(widget, Input):
            self._input_original_values[widget] = widget.value

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()

        with TabbedContent(id="main-tabs"):
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

            with TabPane("📝 Logs", id="tab-logs"):
                from ai_guardian.tui.logs import LogsContent
                yield LogsContent()

        yield Footer()

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        """Control which actions are available based on current tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        current_tab = tabs.active

        # Context-specific action visibility
        tab_actions = {
            "tab-skills": ["add_allow_pattern", "add_deny_pattern"],
            "tab-mcp": ["add_allow_pattern"],
            "tab-prompt-injection": ["add_allow_pattern", "add_custom", "save_setting"],
            "tab-secrets": ["test_connection"],
        }

        # Check if current tab supports this action
        current_tab_actions = tab_actions.get(current_tab, [])
        if action in current_tab_actions:
            return True

        # Check if action is defined for ANY tab (if so, hide it)
        for actions in tab_actions.values():
            if action in actions:
                return False

        # All other actions are always available
        return True

    def action_refresh_current_tab(self) -> None:
        """Refresh the current tab's content."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        active_pane = tabs.get_pane(tabs.active)

        # Try to call the specific action method if it exists
        for child in active_pane.children:
            if hasattr(child, "action_refresh"):
                child.action_refresh()
                self.notify("Tab refreshed", severity="information")
                return
            elif hasattr(child, "refresh_content"):
                child.refresh_content()
                self.notify("Tab refreshed", severity="information")
                return

        # Notify that refresh is not available
        self.notify("No refresh method available for this tab", severity="warning")

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

        # Prompt Injection tab - add allowlist pattern
        elif tabs.active == "tab-prompt-injection":
            for child in active_pane.children:
                if hasattr(child, "action_add_pattern"):
                    child.action_add_pattern()
                    return

    def action_add_custom(self) -> None:
        """Add custom pattern (only works on Prompt Injection tab)."""
        tabs = self.query_one(TabbedContent)
        if tabs.active != "tab-prompt-injection":
            return

        active_pane = tabs.get_pane(tabs.active)
        for child in active_pane.children:
            if hasattr(child, "action_add_custom"):
                child.action_add_custom()
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
        tab_ids = ["tab-violations", "tab-skills", "tab-mcp", "tab-secrets", "tab-prompt-injection", "tab-config", "tab-logs"]
        try:
            current_index = tab_ids.index(tabs.active)
            previous_index = (current_index - 1) % len(tab_ids)
            tabs.active = tab_ids[previous_index]
        except:
            pass

    def action_tab_right(self) -> None:
        """Switch to next tab (right arrow)."""
        tabs = self.query_one(TabbedContent)
        tab_ids = ["tab-violations", "tab-skills", "tab-mcp", "tab-secrets", "tab-prompt-injection", "tab-config", "tab-logs"]
        try:
            current_index = tab_ids.index(tabs.active)
            next_index = (current_index + 1) % len(tab_ids)
            tabs.active = tab_ids[next_index]
        except:
            pass

    def on_key(self, event: events.Key) -> None:
        """Handle ESC and arrow key navigation."""
        focused = self.focused
        tabs = self.query_one("#main-tabs", TabbedContent)

        # Intercept ESC at app level
        if event.key == "escape":
            # Restore original value if we're on an Input field
            if isinstance(focused, Input) and focused in self._input_original_values:
                focused.value = self._input_original_values[focused]
                # Clean up stored value
                del self._input_original_values[focused]

            # Check current tab - if on Violations, handle sub-tabs
            if tabs.active == "tab-violations":
                try:
                    filter_tabs = self.query_one("#filter-tabs", TabbedContent)

                    # If already on filter tabs bar, go to main tabs
                    if focused == filter_tabs:
                        event.stop()
                        event.prevent_default()
                        tabs.can_focus = True
                        tabs.focus()
                        return

                    # Otherwise, we're somewhere inside violations content - go to filter tabs
                    event.stop()
                    event.prevent_default()
                    filter_tabs.can_focus = True
                    filter_tabs.focus()
                    return
                except Exception as e:
                    # If filter tabs not found, go to main tabs
                    event.stop()
                    event.prevent_default()
                    tabs.can_focus = True
                    tabs.focus()
                    return

            # For other tabs or if already on main tabs, go to main tabs
            event.stop()
            event.prevent_default()
            tabs.can_focus = True
            tabs.focus()
            return

        # Handle left/right arrows when on tabs to switch tabs
        if event.key == "left":
            if focused == tabs:
                self.action_tab_left()
                event.prevent_default()
                return
            # Also handle filter tabs
            try:
                filter_tabs = self.query_one("#filter-tabs", TabbedContent)
                if focused == filter_tabs:
                    # Switch to previous filter tab
                    filter_ids = ["filter-all", "filter-tool-permission", "filter-secret", "filter-directory", "filter-injection"]
                    try:
                        current_index = filter_ids.index(filter_tabs.active)
                        previous_index = (current_index - 1) % len(filter_ids)
                        filter_tabs.active = filter_ids[previous_index]
                        event.prevent_default()
                        return
                    except:
                        pass
            except:
                pass

        elif event.key == "right":
            if focused == tabs:
                self.action_tab_right()
                event.prevent_default()
                return
            # Also handle filter tabs
            try:
                filter_tabs = self.query_one("#filter-tabs", TabbedContent)
                if focused == filter_tabs:
                    # Switch to next filter tab
                    filter_ids = ["filter-all", "filter-tool-permission", "filter-secret", "filter-directory", "filter-injection"]
                    try:
                        current_index = filter_ids.index(filter_tabs.active)
                        next_index = (current_index + 1) % len(filter_ids)
                        filter_tabs.active = filter_ids[next_index]
                        event.prevent_default()
                        return
                    except:
                        pass
            except:
                pass

        elif event.key == "down":
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
