#!/usr/bin/env python3
"""
Unicode Attack Detection

Configure detection of Unicode-based attacks that bypass pattern matching:
zero-width characters, BiDi overrides, tag characters, and homoglyphs.
"""

import json

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Static, Label, Checkbox

from ai_guardian.config_utils import get_config_dir


UNICODE_SETTINGS = [
    ("detect_zero_width", "Detect Zero-Width Characters",
     "Invisible characters that break pattern matching (ZWSP, ZWNJ, ZWJ)"),
    ("detect_bidi_override", "Detect BiDi Override",
     "Text display reversal for visual deception (RLO, LRO, PDF)"),
    ("detect_tag_chars", "Detect Tag Characters",
     "Hidden data encoding in deprecated Unicode tags (U+E0001-U+E007F)"),
    ("detect_homoglyphs", "Detect Homoglyphs",
     "Look-alike character substitution (Cyrillic/Greek letters)"),
    ("allow_rtl_languages", "Allow RTL Languages",
     "Allow legitimate right-to-left text (Arabic, Hebrew, etc.)"),
    ("allow_emoji", "Allow Emoji",
     "Allow emoji characters in prompts"),
]


class PIUnicodeContent(Container):
    """Content widget for Unicode Attack Detection."""

    CSS = """
    PIUnicodeContent {
        height: 100%;
    }

    #pi-unicode-header {
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

    Checkbox:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("[bold]Prompt Injection — Unicode Detection[/bold]", id="pi-unicode-header")

        with VerticalScroll():
            with Container(classes="section"):
                yield Static("[bold]Unicode Attack Detection[/bold]", classes="section-title")
                yield Static(
                    "[dim]Detect Unicode-based attacks that bypass text pattern matching. "
                    "These attacks use invisible or look-alike characters to hide "
                    "malicious content from security scanners.[/dim]",
                    classes="section-title",
                )

                for config_key, label, description in UNICODE_SETTINGS:
                    with Horizontal(classes="setting-row"):
                        yield Checkbox(
                            label,
                            id=f"unicode-{config_key}",
                            value=True,
                        )
                    yield Static(f"[dim]    {description}[/dim]", classes="setting-row")

            with Container(classes="section"):
                yield Static("[bold]How Unicode Attacks Work[/bold]", classes="section-title")
                yield Static(
                    "[dim]Zero-width characters:\n"
                    '  "ignore\\u200Binstructions" looks like "ignoreinstructions"\n'
                    "  but the hidden character breaks pattern matching.\n\n"
                    "BiDi override:\n"
                    "  Text appears reversed visually, hiding true intent.\n"
                    "  Example: harmless-looking text actually says 'exec(cmd)'\n\n"
                    "Homoglyphs:\n"
                    "  Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)\n"
                    '  "ignore" with Cyrillic letters bypasses ASCII pattern checks.[/dim]',
                )

    def on_mount(self) -> None:
        self.load_config()

    def refresh_content(self) -> None:
        self.load_config()

    def action_refresh(self) -> None:
        self.load_config()
        self.app.notify("Unicode detection settings refreshed", severity="information")

    def load_config(self) -> None:
        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        config = {}
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except Exception as e:
                self.app.notify(f"Error loading config: {e}", severity="error")

        pi_config = config.get("prompt_injection", {})
        unicode_config = pi_config.get("unicode_detection", {})

        for config_key, _, _ in UNICODE_SETTINGS:
            try:
                cb = self.query_one(f"#unicode-{config_key}", Checkbox)
                cb.value = unicode_config.get(config_key, True)
            except Exception:
                pass

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        checkbox_id = event.checkbox.id
        if not checkbox_id or not checkbox_id.startswith("unicode-"):
            return

        config_key = checkbox_id.replace("unicode-", "")

        config_dir = get_config_dir()
        config_path = config_dir / "ai-guardian.json"

        try:
            config = {}
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

            if "prompt_injection" not in config:
                config["prompt_injection"] = {}
            if "unicode_detection" not in config["prompt_injection"]:
                config["prompt_injection"]["unicode_detection"] = {}

            config["prompt_injection"]["unicode_detection"][config_key] = event.value

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            label = config_key.replace("_", " ").title()
            self.app.notify(f"Unicode: {label} = {event.value}", severity="success")

        except Exception as e:
            self.app.notify(f"Error: {e}", severity="error")
