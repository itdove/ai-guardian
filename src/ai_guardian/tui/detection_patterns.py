"""Detection Patterns panel — read-only view of all detection rules."""

import re as re_mod
from collections import Counter

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Input, Static


CATEGORY_ORDER = [
    "secrets", "pii", "prompt_injection", "unicode",
    "ssrf", "config_exfil", "context_poisoning", "supply_chain",
    "self_protection",
]

TESTABLE_MATCH_TYPES = {"regex", "literal"}


def _test_rule_matches(rule, text):
    """Test whether a rule's pattern matches the given text."""
    if rule.match_type not in TESTABLE_MATCH_TYPES:
        return False
    try:
        if rule.match_type == "regex":
            return bool(re_mod.search(rule.pattern, text, re_mod.IGNORECASE))
        if rule.match_type == "literal":
            return rule.pattern.lower() in text.lower()
    except re_mod.error:
        return False
    return False


class DetectionPatternsContent(Container):
    """Content widget for Detection Patterns panel."""

    CSS = """
    DetectionPatternsContent {
        height: 100%;
    }

    #dp-header {
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

    #dp-filter-row {
        height: auto;
        margin: 1 0;
    }

    #dp-filter-row Button {
        margin: 0 1 0 0;
    }

    #dp-search-row {
        height: auto;
        margin: 0 0 1 0;
    }

    #dp-search-input {
        width: 40;
    }

    #dp-mode-row {
        height: auto;
        margin: 0 0 1 0;
    }

    #dp-mode-row Button {
        margin: 0 1 0 0;
    }

    Button:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._all_rules = []
        self._filter_category = None
        self._search_query = ""
        self._test_mode = False

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Detection Patterns — All Rules[/bold]",
            id="dp-header",
        )

        with VerticalScroll():
            with Container(classes="section"):
                yield Static(
                    "[bold]Filter[/bold]  "
                    "[dim]Press category buttons to filter, "
                    "or type in search box[/dim]",
                    classes="section-title",
                )

                with Horizontal(id="dp-filter-row"):
                    yield Button("All", id="dp-cat-all", variant="primary")
                    for i, cat in enumerate(CATEGORY_ORDER):
                        short = cat.replace("_", " ").title()
                        yield Button(
                            short,
                            id=f"dp-cat-{cat}",
                            variant="default",
                        )

                with Horizontal(id="dp-mode-row"):
                    yield Button(
                        "Search Rules", id="dp-mode-search",
                        variant="primary",
                    )
                    yield Button(
                        "Test Match", id="dp-mode-test",
                        variant="default",
                    )

                yield Static(
                    "", id="dp-mode-hint",
                )

                with Horizontal(id="dp-search-row"):
                    yield Input(
                        placeholder="Search by ID, description, or pattern...",
                        id="dp-search-input",
                    )
                    yield Button("Clear", id="dp-search-clear", variant="default")

            with Container(classes="section"):
                yield Static("", id="dp-summary")

            with Container(classes="section"):
                yield Static("Loading...", id="dp-table")

    def on_mount(self) -> None:
        self._load_rules()

    def refresh_content(self) -> None:
        self._load_rules()

    def _load_rules(self):
        from ai_guardian.pattern_lister import PatternLister
        self._all_rules = PatternLister().get_all_rules()
        self._render_summary()
        self._render_table()

    def _render_summary(self):
        counts = Counter(r.category for r in self._all_rules)
        parts = []
        for cat in CATEGORY_ORDER:
            if cat in counts:
                parts.append(f"[bold]{cat}[/bold]: {counts[cat]}")
        summary = (
            f"[bold]{len(self._all_rules)}[/bold] total rules  |  "
            + "  |  ".join(parts)
        )
        try:
            self.query_one("#dp-summary", Static).update(summary)
        except Exception:
            pass

    def _get_filtered_rules(self):
        rules = self._all_rules
        if self._filter_category:
            rules = [r for r in rules if r.category == self._filter_category]
        q = self._search_query.strip()
        if q:
            if self._test_mode:
                rules = [r for r in rules if _test_rule_matches(r, q)]
            else:
                ql = q.lower()
                rules = [
                    r for r in rules
                    if ql in r.id.lower()
                    or ql in r.description.lower()
                    or ql in r.pattern.lower()
                    or ql in r.category.lower()
                    or ql in r.group.lower()
                ]
        return rules

    def _render_table(self):
        rules = self._get_filtered_rules()
        q = self._search_query.strip()

        id_w = 30
        cat_w = 18
        grp_w = 18
        typ_w = 8
        pat_w = 50

        header = (
            f"  {'ID':<{id_w}s} {'Category':<{cat_w}s} {'Group':<{grp_w}s} "
            f"{'Type':<{typ_w}s} {'Pattern':<{pat_w}s} Description"
        )
        lines = [header, "  " + "-" * 140]

        for r in rules:
            pat = r.pattern
            if len(pat) > pat_w:
                pat = pat[:pat_w - 3] + "..."

            sev_color = ""
            end_color = ""
            if r.severity == "immutable":
                sev_color = "[red]"
                end_color = "[/]"
            elif r.source == "hardcoded":
                sev_color = "[yellow]"
                end_color = "[/]"

            desc = r.description
            if len(desc) > 60:
                desc = desc[:57] + "..."

            lines.append(
                f"  {sev_color}{r.id:<{id_w}s}{end_color} "
                f"{r.category:<{cat_w}s} {r.group:<{grp_w}s} "
                f"{r.match_type:<{typ_w}s} {pat:<{pat_w}s} {desc}"
            )

        if not rules:
            lines.append("  [dim]No rules match the current filter.[/dim]")

        if self._test_mode and q:
            lines.append(
                f"\n  [bold orange1]{len(rules)} rule(s) match "
                f"your test text[/bold orange1]"
            )
        else:
            lines.append(
                f"\n  Showing {len(rules)} of {len(self._all_rules)} rules"
            )

        try:
            self.query_one("#dp-table", Static).update("\n".join(lines))
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""

        if btn_id == "dp-cat-all":
            self._filter_category = None
        elif btn_id.startswith("dp-cat-"):
            cat = btn_id[7:]
            self._filter_category = (
                cat if cat != self._filter_category else None
            )
        elif btn_id == "dp-mode-search":
            self._test_mode = False
            self._update_mode_ui()
        elif btn_id == "dp-mode-test":
            self._test_mode = True
            self._update_mode_ui()
        elif btn_id == "dp-search-clear":
            self._search_query = ""
            try:
                self.query_one("#dp-search-input", Input).value = ""
            except Exception:
                pass
        else:
            return

        self._update_button_variants()
        self._render_table()

    def _update_mode_ui(self):
        try:
            s_btn = self.query_one("#dp-mode-search", Button)
            t_btn = self.query_one("#dp-mode-test", Button)
            s_btn.variant = "primary" if not self._test_mode else "default"
            t_btn.variant = "primary" if self._test_mode else "default"
        except Exception:
            pass

        try:
            hint = self.query_one("#dp-mode-hint", Static)
            if self._test_mode:
                hint.update(
                    "[dim]Test Match: enter sample text to see which "
                    "regex/literal rules detect it[/dim]"
                )
            else:
                hint.update("")
        except Exception:
            pass

        try:
            inp = self.query_one("#dp-search-input", Input)
            if self._test_mode:
                inp.placeholder = "Enter text to test against patterns..."
            else:
                inp.placeholder = "Search by ID, description, or pattern..."
        except Exception:
            pass

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "dp-search-input":
            self._search_query = event.value or ""
            self._render_table()

    def _update_button_variants(self):
        try:
            all_btn = self.query_one("#dp-cat-all", Button)
            all_btn.variant = (
                "primary" if not self._filter_category else "default"
            )
        except Exception:
            pass

        for cat in CATEGORY_ORDER:
            try:
                btn = self.query_one(f"#dp-cat-{cat}", Button)
                btn.variant = (
                    "primary" if self._filter_category == cat else "default"
                )
            except Exception:
                pass
