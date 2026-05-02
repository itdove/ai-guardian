#!/usr/bin/env python3
"""
Main TUI Application

Provides interactive text-based interface for AI Guardian configuration.
Sidebar tree navigation with grouped sections and content switching.
"""

import subprocess
import sys
from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import (
    Footer, Header, Tree, ContentSwitcher, Button, Input, Static,
)
from textual.screen import ModalScreen
from textual.binding import Binding
from textual import events


def copy_to_system_clipboard(text: str) -> bool:
    """Copy text to the system clipboard using platform-native commands.

    Returns True if the copy succeeded, False otherwise.
    """
    try:
        if sys.platform == "darwin":
            subprocess.run(
                ["pbcopy"], input=text.encode("utf-8"), check=True,
                capture_output=True, timeout=5,
            )
        elif sys.platform == "win32":
            subprocess.run(
                ["clip"], input=text.encode("utf-16le"), check=True,
                capture_output=True, timeout=5,
            )
        elif sys.platform.startswith("linux"):
            try:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text.encode("utf-8"), check=True,
                    capture_output=True, timeout=5,
                )
            except FileNotFoundError:
                subprocess.run(
                    ["xsel", "--clipboard", "--input"],
                    input=text.encode("utf-8"), check=True,
                    capture_output=True, timeout=5,
                )
        else:
            return False
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired):
        return False
    return True


NAV_GROUPS = [
    ("Security Overview", [
        ("Security Dashboard", "panel-security-dashboard"),
        ("Global Settings", "panel-global-settings"),
    ]),
    ("Monitoring", [
        ("Violations", "panel-violations"),
        ("Violation Logging", "panel-violation-logging"),
        ("Logs", "panel-logs"),
    ]),
    ("Permissions", [
        ("Skills", "panel-skills"),
        ("MCP Servers", "panel-mcp"),
        ("Permissions Discovery", "panel-permissions-discovery"),
    ]),
    ("Secrets", [
        ("Secret Scanning", "panel-secrets"),
        ("Secret Redaction", "panel-secret-redaction"),
    ]),
    ("Prompt Injection", [
        ("Detection Settings", "panel-pi-detection"),
        ("Patterns", "panel-pi-patterns"),
        ("Jailbreak", "panel-pi-jailbreak"),
        ("Unicode Detection", "panel-pi-unicode"),
    ]),
    ("Threat Detection", [
        ("SSRF Protection", "panel-ssrf"),
        ("Config Scanner", "panel-config-scanner"),
        ("PII Detection", "panel-scan-pii"),
    ]),
    ("Configuration", [
        ("Directory Protection", "panel-directory-protection"),
        ("Remote Configs", "panel-remote-configs"),
        ("Config File", "panel-config-file"),
        ("Effective Config", "panel-config-effective"),
    ]),
    ("Tools", [
        ("Regex Tester", "panel-regex-tester"),
    ]),
]


HELP_DOCS = {
    # Category-level help
    "Security Overview": (
        "[bold]Security Overview[/bold]\n\n"
        "Central hub for monitoring and configuring AI Guardian's "
        "security posture.\n\n"
        "[bold]Sections:[/bold]\n"
        "  [bold]Security Dashboard[/bold] — At-a-glance status of all "
        "security features with violation analytics\n"
        "  [bold]Global Settings[/bold] — Master toggles for permissions "
        "enforcement and secret scanning"
    ),
    "Permissions": (
        "[bold]Permissions[/bold]\n\n"
        "Control what Claude Code is allowed to do. Permissions are "
        "evaluated as allow/deny rules matched against tool names.\n\n"
        "[bold]Sections:[/bold]\n"
        "  [bold]Skills[/bold] — Manage allow/deny patterns for Claude "
        "Code skills (slash commands)\n"
        "  [bold]MCP Servers[/bold] — Manage permissions for MCP server "
        "tool invocations\n"
        "  [bold]Permissions Discovery[/bold] — Review tool calls that "
        "don't match any existing rule"
    ),
    "Threat Detection": (
        "[bold]Threat Detection[/bold]\n\n"
        "Detect and block malicious content in prompts, tool inputs, "
        "and tool outputs.\n\n"
        "[bold]Sections:[/bold]\n"
        "  [bold]Prompt Injection[/bold] — Detect jailbreak attempts, "
        "obfuscation, and Unicode attacks\n"
        "  [bold]SSRF Protection[/bold] — Block requests to private IPs, "
        "internal networks, and cloud metadata\n"
        "  [bold]Config Scanner[/bold] — Detect exfiltration of sensitive "
        "config files (CLAUDE.md, .env, etc.)"
    ),
    "Secrets": (
        "[bold]Secrets[/bold]\n\n"
        "Prevent secret leakage in AI-assisted development.\n\n"
        "[bold]Sections:[/bold]\n"
        "  [bold]Secret Scanning[/bold] — Scan tool outputs for API keys, "
        "tokens, and credentials using scanner engines\n"
        "  [bold]Secret Redaction[/bold] — Automatically redact detected "
        "secrets before they reach the AI model"
    ),
    "Monitoring": (
        "[bold]Monitoring[/bold]\n\n"
        "Track security events and review audit logs.\n\n"
        "[bold]Sections:[/bold]\n"
        "  [bold]Violations[/bold] — Browse, filter, and approve recent "
        "security violations\n"
        "  [bold]Logs[/bold] — View AI Guardian's runtime log output"
    ),
    "Configuration": (
        "[bold]Configuration[/bold]\n\n"
        "Manage AI Guardian's configuration files and directory "
        "protections.\n\n"
        "[bold]Sections:[/bold]\n"
        "  [bold]Directory Protection[/bold] — Define protected directories "
        "that Claude Code cannot access\n"
        "  [bold]Remote Configs[/bold] — Manage remote configuration "
        "sources (URLs, update schedules)\n"
        "  [bold]Config File[/bold] — View raw JSON config files\n"
        "  [bold]Effective Config[/bold] — View resolved runtime "
        "configuration"
    ),
    "Tools": (
        "[bold]Tools[/bold]\n\n"
        "Utility tools for testing and debugging AI Guardian "
        "security patterns.\n\n"
        "[bold]Sections:[/bold]\n"
        "  [bold]Regex Tester[/bold] — Interactively test regex "
        "patterns with ReDoS validation and config integration"
    ),
    # Panel-level help
    "panel-security-dashboard": (
        "[bold]Security Dashboard[/bold]\n\n"
        "Overview of all security features and their current status.\n\n"
        "[bold]Features:[/bold]\n"
        "  - Feature status cards showing enabled/disabled state\n"
        "  - Recent violation summary with counts by category\n"
        "  - Quick enable/disable toggles for each feature\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]r[/bold]  Refresh dashboard data"
    ),
    "panel-global-settings": (
        "[bold]Global Settings[/bold]\n\n"
        "Master toggles for core security features. These control "
        "whether AI Guardian enforces permissions and scans for "
        "secrets globally.\n\n"
        "[bold]Toggles:[/bold]\n"
        "  [bold]permissions_enabled[/bold] — Enable/disable tool "
        "permission enforcement\n"
        "  [bold]secret_scanning[/bold] — Enable/disable secret "
        "detection scanning\n\n"
        "Each toggle supports three modes:\n"
        "  - Permanently Enabled\n"
        "  - Permanently Disabled\n"
        "  - Temporarily Disabled (with auto re-enable timestamp)"
    ),
    "panel-skills": (
        "[bold]Skills Permissions[/bold]\n\n"
        "Manage allow and deny patterns for Claude Code skills "
        "(slash commands like /release, /review, etc.).\n\n"
        "[bold]How patterns work:[/bold]\n"
        "  - Patterns use glob matching: [bold]daf-*[/bold] matches "
        "all daf skills\n"
        "  - [bold]*[/bold] matches everything\n"
        "  - Deny rules take precedence over allow rules\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]a[/bold]  Add allow pattern\n"
        "  [bold]d[/bold]  Add deny pattern\n"
        "  [bold]r[/bold]  Refresh list"
    ),
    "panel-mcp": (
        "[bold]MCP Server Permissions[/bold]\n\n"
        "Control which MCP (Model Context Protocol) server tools "
        "Claude Code is allowed to invoke.\n\n"
        "[bold]Pattern format:[/bold]\n"
        "  [bold]mcp__servername__toolname[/bold]\n"
        "  Example: [bold]mcp__notebooklm-mcp__*[/bold] allows all "
        "NotebookLM tools\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]a[/bold]  Add permission\n"
        "  [bold]r[/bold]  Refresh list"
    ),
    "panel-permissions-discovery": (
        "[bold]Permissions Discovery[/bold]\n\n"
        "Review tool calls that were attempted but didn't match any "
        "existing allow or deny rule.\n\n"
        "Use this to discover new tools being used and decide whether "
        "to create rules for them. Each unmatched call shows:\n"
        "  - Tool name and parameters\n"
        "  - Timestamp and frequency\n"
        "  - Quick-add buttons for allow/deny rules"
    ),
    "Prompt Injection": (
        "[bold]Prompt Injection[/bold]\n\n"
        "Detect and block prompt injection attacks in tool inputs "
        "and outputs. Protects against jailbreaks, obfuscation, "
        "and Unicode-based attacks.\n\n"
        "[bold]Sections:[/bold]\n"
        "  [bold]Detection Settings[/bold] — Engine, sensitivity, "
        "action, ignore files/tools\n"
        "  [bold]Patterns[/bold] — Allowlist and custom detection "
        "patterns\n"
        "  [bold]Jailbreak[/bold] — Custom jailbreak-specific "
        "patterns\n"
        "  [bold]Unicode Detection[/bold] — Zero-width, BiDi, "
        "tag chars, homoglyphs"
    ),
    "panel-pi-detection": (
        "[bold]Detection Settings[/bold]\n\n"
        "Core prompt injection detection configuration.\n\n"
        "[bold]Settings:[/bold]\n"
        "  [bold]Detector[/bold] — heuristic (fast, local), rebuff "
        "(ML-based), llm-guard\n"
        "  [bold]Sensitivity[/bold] — low, medium, high\n"
        "  [bold]Score Threshold[/bold] — 0.0-1.0 confidence for "
        "blocking\n"
        "  [bold]Action[/bold] — block, warn, or log-only\n\n"
        "[bold]Ignore lists:[/bold]\n"
        "  Glob patterns for files and tool names to skip\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]s[/bold]  Save detector/sensitivity settings"
    ),
    "panel-pi-patterns": (
        "[bold]Allowlist & Custom Patterns[/bold]\n\n"
        "Manage patterns for prompt injection detection.\n\n"
        "[bold]Allowlist patterns:[/bold]\n"
        "  Regex patterns to ignore — use for false positive "
        "exclusions. Supports time-based expiration.\n\n"
        "[bold]Custom detection patterns:[/bold]\n"
        "  Additional regex patterns to detect as injection.\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]a[/bold]  Add allowlist pattern\n"
        "  [bold]c[/bold]  Add custom pattern"
    ),
    "panel-pi-jailbreak": (
        "[bold]Jailbreak Patterns[/bold]\n\n"
        "Manage jailbreak-specific detection patterns.\n\n"
        "[bold]Built-in detection:[/bold]\n"
        "  - Role-play attacks (DAN mode, sudo mode)\n"
        "  - Identity manipulation ('pretend you are')\n"
        "  - Constraint removal ('ignore rules')\n"
        "  - Hypothetical framing ('fictional scenario')\n"
        "  - System prompt extraction\n\n"
        "[bold]Custom patterns:[/bold]\n"
        "  Add regex patterns for additional jailbreak techniques. "
        "Matched against user prompts only."
    ),
    "panel-pi-unicode": (
        "[bold]Unicode Attack Detection[/bold]\n\n"
        "Detect Unicode-based attacks that bypass text pattern "
        "matching.\n\n"
        "[bold]Detection types:[/bold]\n"
        "  [bold]Zero-width chars[/bold] — Invisible characters "
        "(ZWSP, ZWNJ, ZWJ)\n"
        "  [bold]BiDi override[/bold] — Text direction manipulation\n"
        "  [bold]Tag characters[/bold] — Deprecated Unicode tags for "
        "hidden data\n"
        "  [bold]Homoglyphs[/bold] — Look-alike character "
        "substitution\n\n"
        "[bold]Allow settings:[/bold]\n"
        "  RTL languages — Arabic, Hebrew (safe)\n"
        "  Emoji — Standard emoji characters (safe)"
    ),
    "panel-ssrf": (
        "[bold]SSRF Protection[/bold]\n\n"
        "Block Server-Side Request Forgery attacks by preventing "
        "requests to internal networks and sensitive endpoints.\n\n"
        "[bold]What is blocked:[/bold]\n"
        "  - Private IP ranges (10.x, 172.16-31.x, 192.168.x)\n"
        "  - Localhost and loopback addresses\n"
        "  - Cloud metadata endpoints (169.254.169.254)\n"
        "  - Internal DNS names\n\n"
        "[bold]Actions:[/bold]\n"
        "  [bold]block[/bold] — Reject the request entirely\n"
        "  [bold]warn[/bold] — Allow but log a warning\n"
        "  [bold]log-only[/bold] — Silent logging\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]s[/bold]  Save settings"
    ),
    "panel-config-scanner": (
        "[bold]Config File Scanner[/bold]\n\n"
        "Detect attempts to read or exfiltrate sensitive configuration "
        "files.\n\n"
        "[bold]Protected files:[/bold]\n"
        "  - CLAUDE.md, .cursorrules, .github/copilot-*\n"
        "  - .env, .env.local, .env.production\n"
        "  - Credential files, SSH keys, cloud configs\n\n"
        "[bold]Configuration:[/bold]\n"
        "  - Additional files to protect\n"
        "  - Files to ignore (e.g., *.example.md)\n"
        "  - Custom detection patterns\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]s[/bold]  Save settings"
    ),
    "panel-scan-pii": (
        "[bold]PII Detection[/bold]\n\n"
        "Detect personally identifiable information in user prompts, "
        "file reads, and tool outputs for GDPR/CCPA compliance.\n\n"
        "[bold]PII types detected:[/bold]\n"
        "  - Social Security Numbers (XXX-XX-XXXX)\n"
        "  - Credit Card Numbers (Visa, MC, Amex, etc.)\n"
        "  - Phone Numbers (US and international)\n"
        "  - Email Addresses\n"
        "  - US Passport Numbers\n"
        "  - IBANs (International Bank Account Numbers)\n\n"
        "[bold]Actions:[/bold]\n"
        "  [bold]block[/bold] — Reject the operation entirely\n"
        "  [bold]redact[/bold] — Mask PII in output, block in input\n"
        "  [bold]warn[/bold] — Allow with warning notification\n"
        "  [bold]log-only[/bold] — Silent logging only\n\n"
        "[bold]Configuration:[/bold]\n"
        "  - Enable/disable individual PII types\n"
        "  - Ignore files via glob patterns (e.g., tests/**)"
    ),
    "panel-secrets": (
        "[bold]Secret Scanning[/bold]\n\n"
        "Scan tool outputs for leaked API keys, tokens, passwords, "
        "and other credentials.\n\n"
        "[bold]Scanner engines:[/bold]\n"
        "  - Gitleaks — Fast, regex-based secret detection\n"
        "  - BetterLeaks — Enhanced detection with fewer false positives\n"
        "  - LeakTK — Pattern server with community-maintained rules\n\n"
        "[bold]Configuration:[/bold]\n"
        "  - Pattern server URL and version\n"
        "  - Scanner selection and priority\n"
        "  - Custom allowlist for known false positives\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]t[/bold]  Test pattern server connection"
    ),
    "panel-secret-redaction": (
        "[bold]Secret Redaction[/bold]\n\n"
        "Automatically replace detected secrets with placeholder "
        "values before they reach the AI model.\n\n"
        "[bold]Redaction modes:[/bold]\n"
        "  [bold]block[/bold] — Block the entire tool output\n"
        "  [bold]log-only[/bold] — Log but don't modify output\n\n"
        "[bold]Options:[/bold]\n"
        "  - Preserve format (keep secret structure, replace chars)\n"
        "  - Log redactions for audit trail\n"
        "  - Additional custom patterns\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]s[/bold]  Save settings"
    ),
    "panel-violations": (
        "[bold]Violations Log[/bold]\n\n"
        "Browse and manage security violations detected by AI Guardian.\n\n"
        "[bold]Filter tabs:[/bold]\n"
        "  All — Every violation type\n"
        "  Tool Permission — Blocked tool/skill invocations\n"
        "  Secrets — Detected API keys, tokens, credentials\n"
        "  Secret Redaction — Redacted secrets in tool output\n"
        "  Directories — Protected directory access attempts\n"
        "  Prompt Injection — Injection/obfuscation attacks\n"
        "  Jailbreak — Jailbreak and role-play attempts\n"
        "  SSRF Blocked — Blocked requests to private IPs\n"
        "  Config Exfil — Config file exfiltration attempts\n"
        "  PII Detected — Personal identifiable information\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]1[/bold]  All  [bold]2[/bold]  Tool Permission  "
        "[bold]3[/bold]  Secrets  [bold]4[/bold]  Directories  "
        "[bold]5[/bold]  Prompt Injection\n\n"
        "[bold]Actions:[/bold]\n"
        "  - Click a violation to view full details\n"
        "  - Approve violations to add allow rules\n"
        "  - Clear violation history"
    ),
    "panel-violation-logging": (
        "[bold]Violation Logging Settings[/bold]\n\n"
        "Configure how AI Guardian logs security violations for "
        "audit and review.\n\n"
        "[bold]Settings:[/bold]\n"
        "  [bold]Max Entries[/bold] — Maximum log entries to retain "
        "(default: 1000)\n"
        "  [bold]Retention Days[/bold] — Days to keep entries "
        "(default: 30)\n\n"
        "[bold]Log Types:[/bold]\n"
        "  Enable/disable logging for each violation category:\n"
        "  tool_permission, directory_blocking, secret_detected,\n"
        "  secret_redaction, prompt_injection, jailbreak_detected,\n"
        "  ssrf_blocked, config_file_exfil, pii_detected\n\n"
        "[bold]Note:[/bold] Empty type selection logs all types."
    ),
    "panel-logs": (
        "[bold]Runtime Logs[/bold]\n\n"
        "View AI Guardian's runtime log output for debugging and "
        "monitoring.\n\n"
        "[bold]Log levels:[/bold]\n"
        "  - ERROR — Security failures and critical issues\n"
        "  - WARNING — Suspicious activity and policy violations\n"
        "  - INFO — Normal operations and status updates\n"
        "  - DEBUG — Detailed diagnostic information\n\n"
        "[bold]Features:[/bold]\n"
        "  - Auto-refresh with live log streaming\n"
        "  - Filter by log level\n"
        "  - Clear log display"
    ),
    "panel-directory-protection": (
        "[bold]Directory Protection[/bold]\n\n"
        "Define directories that Claude Code is not allowed to read "
        "from or write to.\n\n"
        "[bold]How it works:[/bold]\n"
        "  - Protected paths are checked on every file operation\n"
        "  - Both absolute and relative paths are supported\n"
        "  - Glob patterns work (e.g., /home/*/.ssh)\n\n"
        "[bold]Common protected paths:[/bold]\n"
        "  - ~/.ssh — SSH private keys\n"
        "  - ~/.aws — AWS credentials\n"
        "  - ~/.config/gcloud — GCP credentials"
    ),
    "panel-remote-configs": (
        "[bold]Remote Configurations[/bold]\n\n"
        "Load AI Guardian configuration from remote sources. Useful "
        "for team-wide policy distribution.\n\n"
        "[bold]Features:[/bold]\n"
        "  - Fetch config from URL endpoints\n"
        "  - Automatic update schedules\n"
        "  - Merge strategy (override vs. merge)\n"
        "  - Configuration validation before applying"
    ),
    "panel-config-file": (
        "[bold]Config File[/bold]\n\n"
        "View the raw JSON configuration files.\n\n"
        "[bold]Config sources:[/bold]\n"
        "  1. User global: ~/.config/ai-guardian/ai-guardian.json\n"
        "  2. Project local: .ai-guardian.json (in project root)\n\n"
        "Shows the merged JSON from all sources with file "
        "locations and existence status."
    ),
    "panel-config-effective": (
        "[bold]Effective Config[/bold]\n\n"
        "View the effective runtime configuration — equivalent to "
        "running `ai-guardian config show --all --json`.\n\n"
        "Shows the fully resolved config including:\n"
        "  - Merged settings from all sources\n"
        "  - Auto-generated directory rules\n"
        "  - Resolved SSRF blocked IPs/domains\n"
        "  - Secret redaction patterns\n"
        "  - Unicode detection settings\n"
        "  - Config file scanning rules"
    ),
    "panel-regex-tester": (
        "[bold]Regex Tester[/bold]\n\n"
        "Interactively test regex patterns against sample text "
        "with real-time match results.\n\n"
        "[bold]Features:[/bold]\n"
        "  - Enter a regex pattern and see matches instantly\n"
        "  - ReDoS safety validation via validate_regex_pattern()\n"
        "  - Match count, matched text, and positions\n"
        "  - Toggle IGNORECASE and MULTILINE flags\n"
        "  - Add tested patterns to config sections\n\n"
        "[bold]Config targets:[/bold]\n"
        "  - Prompt Injection allowlist\n"
        "  - PII Detection allowlist\n"
        "  - Secret Scanning allowlist\n\n"
        "[bold]Keyboard shortcuts:[/bold]\n"
        "  [bold]r[/bold]  Clear and reset the tester"
    ),
}


class HelpModal(ModalScreen):
    """Modal for displaying inline help documentation."""

    CSS = """
    HelpModal {
        align: center middle;
    }

    #help-container {
        width: 72;
        height: auto;
        max-height: 85%;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #help-title {
        margin: 0 0 1 0;
        text-align: center;
        text-style: bold;
        color: $accent;
    }

    #help-body {
        height: auto;
        max-height: 60;
        overflow-y: auto;
        background: $surface;
        padding: 1 2;
        margin: 1 0;
    }

    #help-footer {
        margin: 1 0 0 0;
        height: auto;
        align: center middle;
    }

    #help-footer Button {
        margin: 0 1 0 0;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
        Binding("question_mark", "dismiss", "Close", show=False),
    ]

    def __init__(self, title: str, body: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._title = title
        self._body = body

    def compose(self) -> ComposeResult:
        with Container(id="help-container"):
            yield Static(f"[bold $accent]? {self._title}[/bold $accent]", id="help-title")
            with VerticalScroll(id="help-body"):
                yield Static(self._body)
            with Horizontal(id="help-footer"):
                yield Button("Close (ESC)", id="close-help", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-help":
            self.dismiss()


class AIGuardianTUI(App):
    """AI Guardian TUI Application with sidebar navigation."""

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

    #main-layout {
        height: 100%;
    }

    #nav-tree {
        width: 28;
        dock: left;
        background: #1a1a2e;
        border-right: solid $primary;
        padding: 1 0;
    }

    #nav-tree > .tree--cursor {
        background: $primary;
        color: $background;
        text-style: bold;
    }

    #nav-tree > .tree--highlight {
        background: $accent;
    }

    #nav-tree:focus > .tree--cursor {
        background: $accent;
        color: $background;
    }

    #panels {
        height: 100%;
    }

    #panels > Container {
        padding: 1 2;
        height: 100%;
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

    /* Input fields */
    Input {
        border: none;
        background: $surface;
        padding: 0 1;
        margin: 0 1 0 0;
    }

    Input:focus {
        border-left: heavy $accent;
        text-style: bold;
        background: $surface;
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

    /* Checkbox widget */
    Checkbox {
        border: none;
    }

    Checkbox:focus {
        text-style: bold;
        border-left: heavy $accent;
    }

    /* Changed from default indicator */
    .changed-from-default {
        border-left: heavy #d4aa00;
    }

    /* Violations nested filter tabs */
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
    """

    TITLE = "AI Guardian Configuration"
    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "refresh_current_tab", "Refresh"),
        Binding("question_mark", "show_help", "Help"),
        Binding("escape", "focus_nav", "Navigation", show=False),
        Binding("1", "filter_all", show=False),
        Binding("2", "filter_tool", show=False),
        Binding("3", "filter_secret", show=False),
        Binding("4", "filter_directory", show=False),
        Binding("5", "filter_injection", show=False),
        Binding("a", "add_allow_pattern", "Add", show=True),
        Binding("c", "add_custom", "Custom", show=True),
        Binding("d", "add_deny_pattern", "Deny", show=True),
        Binding("s", "save_setting", "Save", show=True),
        Binding("t", "test_connection", "Test", show=True),
    ]

    def copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard with platform-native fallback.

        Tries native commands first (pbcopy/xclip/clip) then falls back
        to Textual's OSC 52 escape sequence for terminals that support it.
        """
        if not copy_to_system_clipboard(text):
            super().copy_to_clipboard(text)

    def on_text_selected(self, event: events.TextSelected) -> None:
        """Auto-copy selected text to clipboard."""
        selection = self.screen.get_selected_text()
        if selection:
            self.copy_to_clipboard(selection)
            self.notify("Copied to clipboard", severity="information")

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        """Store original value when Input gets focus."""
        widget = event.widget
        if isinstance(widget, Input):
            self._input_original_values[widget] = widget.value

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()

        with Horizontal(id="main-layout"):
            tree: Tree[str] = Tree("AI Guardian", id="nav-tree")
            tree.root.expand()
            for group_label, items in NAV_GROUPS:
                group_node = tree.root.add(group_label)
                group_node.expand()
                for label, panel_id in items:
                    group_node.add_leaf(label, data=panel_id)
            yield tree

            with ContentSwitcher(id="panels", initial="panel-security-dashboard"):
                with Container(id="panel-security-dashboard"):
                    from ai_guardian.tui.security_dashboard import SecurityDashboardContent
                    yield SecurityDashboardContent()

                with Container(id="panel-global-settings"):
                    from ai_guardian.tui.global_settings import GlobalSettingsContent
                    yield GlobalSettingsContent()

                with Container(id="panel-skills"):
                    from ai_guardian.tui.skills import SkillsContent
                    yield SkillsContent()

                with Container(id="panel-mcp"):
                    from ai_guardian.tui.mcp_servers import MCPServersContent
                    yield MCPServersContent()

                with Container(id="panel-permissions-discovery"):
                    from ai_guardian.tui.permissions_discovery import PermissionsDiscoveryContent
                    yield PermissionsDiscoveryContent()

                with Container(id="panel-pi-detection"):
                    from ai_guardian.tui.pi_detection import PIDetectionContent
                    yield PIDetectionContent()

                with Container(id="panel-pi-patterns"):
                    from ai_guardian.tui.pi_patterns import PIPatternsContent
                    yield PIPatternsContent()

                with Container(id="panel-pi-jailbreak"):
                    from ai_guardian.tui.pi_jailbreak import PIJailbreakContent
                    yield PIJailbreakContent()

                with Container(id="panel-pi-unicode"):
                    from ai_guardian.tui.pi_unicode import PIUnicodeContent
                    yield PIUnicodeContent()

                with Container(id="panel-ssrf"):
                    from ai_guardian.tui.ssrf import SSRFContent
                    yield SSRFContent()

                with Container(id="panel-config-scanner"):
                    from ai_guardian.tui.config_scanner import ConfigScannerContent
                    yield ConfigScannerContent()

                with Container(id="panel-scan-pii"):
                    from ai_guardian.tui.scan_pii import ScanPIIContent
                    yield ScanPIIContent()

                with Container(id="panel-secrets"):
                    from ai_guardian.tui.secrets import SecretsContent
                    yield SecretsContent()

                with Container(id="panel-secret-redaction"):
                    from ai_guardian.tui.secret_redaction import SecretRedactionContent
                    yield SecretRedactionContent()

                with Container(id="panel-violations"):
                    from ai_guardian.tui.violations import ViolationsContent
                    yield ViolationsContent()

                with Container(id="panel-violation-logging"):
                    from ai_guardian.tui.violation_logging import ViolationLoggingContent
                    yield ViolationLoggingContent()

                with Container(id="panel-logs"):
                    from ai_guardian.tui.logs import LogsContent
                    yield LogsContent()

                with Container(id="panel-directory-protection"):
                    from ai_guardian.tui.directory_protection import DirectoryProtectionContent
                    yield DirectoryProtectionContent()

                with Container(id="panel-remote-configs"):
                    from ai_guardian.tui.remote_configs import RemoteConfigsContent
                    yield RemoteConfigsContent()

                with Container(id="panel-config-file"):
                    from ai_guardian.tui.config_viewer import ConfigContent
                    yield ConfigContent()

                with Container(id="panel-config-effective"):
                    from ai_guardian.tui.config_effective import ConfigEffectiveContent
                    yield ConfigEffectiveContent()

                with Container(id="panel-regex-tester"):
                    from ai_guardian.tui.regex_tester import RegexTesterContent
                    yield RegexTesterContent()

        yield Footer()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Switch panel when a tree leaf is selected."""
        if event.node.data is not None:
            switcher = self.query_one("#panels", ContentSwitcher)
            switcher.current = event.node.data

    def _get_current_content(self):
        """Get the content widget from the currently visible panel."""
        switcher = self.query_one("#panels", ContentSwitcher)
        panel_id = switcher.current
        if panel_id is None:
            return None
        panel = self.query_one(f"#{panel_id}", Container)
        for child in panel.children:
            if hasattr(child, "refresh_content") or hasattr(child, "action_refresh"):
                return child
        return panel.children[0] if panel.children else None

    def _get_current_panel_id(self) -> Optional[str]:
        """Get the current panel ID from ContentSwitcher."""
        switcher = self.query_one("#panels", ContentSwitcher)
        return switcher.current

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        """Control which actions are available based on current panel."""
        current_panel = self._get_current_panel_id()

        tab_actions = {
            "panel-skills": ["add_allow_pattern", "add_deny_pattern"],
            "panel-mcp": ["add_allow_pattern"],
            "panel-pi-detection": ["save_setting"],
            "panel-pi-patterns": ["add_allow_pattern", "add_custom"],
            "panel-secrets": ["test_connection"],
            "panel-ssrf": ["save_setting"],
            "panel-config-scanner": ["save_setting"],
            "panel-secret-redaction": ["save_setting"],
        }

        current_tab_actions = tab_actions.get(current_panel, [])
        if action in current_tab_actions:
            return True

        for actions in tab_actions.values():
            if action in actions:
                return False

        return True

    def action_focus_nav(self) -> None:
        """Focus navigation tree (ESC handler)."""
        focused = self.focused
        if isinstance(focused, Input) and focused in self._input_original_values:
            focused.value = self._input_original_values[focused]
            del self._input_original_values[focused]
        self.query_one("#nav-tree", Tree).focus()

    def action_show_help(self) -> None:
        """Show help for the currently highlighted tree node or active panel."""
        tree = self.query_one("#nav-tree", Tree)
        cursor_node = tree.cursor_node

        if cursor_node is not None and cursor_node.data is not None:
            panel_id = cursor_node.data
            label = str(cursor_node.label)
        elif cursor_node is not None and cursor_node.data is None:
            label = str(cursor_node.label)
            if label in HELP_DOCS:
                self.push_screen(HelpModal(label, HELP_DOCS[label]))
                return
            self.notify("No help available", severity="warning")
            return
        else:
            panel_id = self._get_current_panel_id()
            if panel_id is None:
                self.notify("No help available", severity="warning")
                return
            label = panel_id

        if panel_id in HELP_DOCS:
            self.push_screen(HelpModal(label, HELP_DOCS[panel_id]))
        else:
            self.notify("No help available", severity="warning")

    def action_refresh_current_tab(self) -> None:
        """Refresh the current panel's content."""
        content = self._get_current_content()
        if content is None:
            self.notify("No panel selected", severity="warning")
            return

        if hasattr(content, "action_refresh"):
            content.action_refresh()
            self.notify("Panel refreshed", severity="information")
        elif hasattr(content, "refresh_content"):
            content.refresh_content()
            self.notify("Panel refreshed", severity="information")
        else:
            self.notify("No refresh method available for this panel", severity="warning")

    def action_filter_all(self) -> None:
        """Filter all violations (only works on Violations panel)."""
        if self._get_current_panel_id() != "panel-violations":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_filter_all"):
            content.action_filter_all()

    def action_filter_tool(self) -> None:
        """Filter tool violations (only works on Violations panel)."""
        if self._get_current_panel_id() != "panel-violations":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_filter_tool"):
            content.action_filter_tool()

    def action_filter_secret(self) -> None:
        """Filter secret violations (only works on Violations panel)."""
        if self._get_current_panel_id() != "panel-violations":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_filter_secret"):
            content.action_filter_secret()

    def action_filter_directory(self) -> None:
        """Filter directory violations (only works on Violations panel)."""
        if self._get_current_panel_id() != "panel-violations":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_filter_directory"):
            content.action_filter_directory()

    def action_filter_injection(self) -> None:
        """Filter prompt injection violations (only works on Violations panel)."""
        if self._get_current_panel_id() != "panel-violations":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_filter_injection"):
            content.action_filter_injection()

    def action_add_allow_pattern(self) -> None:
        """Add allow pattern (Skills) or add permission (MCP/Prompt Injection)."""
        panel_id = self._get_current_panel_id()
        content = self._get_current_content()
        if content is None:
            return

        if panel_id == "panel-skills" and hasattr(content, "action_add_allow"):
            content.action_add_allow()
        elif panel_id == "panel-mcp" and hasattr(content, "action_add_permission"):
            content.action_add_permission()
        elif panel_id == "panel-pi-patterns" and hasattr(content, "action_add_pattern"):
            content.action_add_pattern()

    def action_add_custom(self) -> None:
        """Add custom pattern (only works on Prompt Injection panel)."""
        if self._get_current_panel_id() != "panel-pi-patterns":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_add_custom"):
            content.action_add_custom()

    def action_add_deny_pattern(self) -> None:
        """Add deny pattern (only works on Skills panel)."""
        if self._get_current_panel_id() != "panel-skills":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_add_deny"):
            content.action_add_deny()

    def action_save_setting(self) -> None:
        """Save setting (works on Prompt Injection panel)."""
        if self._get_current_panel_id() != "panel-pi-detection":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_update_sensitivity"):
            content.action_update_sensitivity()

    def action_test_connection(self) -> None:
        """Test connection (only works on Secrets panel)."""
        if self._get_current_panel_id() != "panel-secrets":
            return
        content = self._get_current_content()
        if content and hasattr(content, "action_test_server"):
            content.action_test_server()


def run_tui():
    """Run the AI Guardian TUI application."""
    app = AIGuardianTUI()
    app.run()
