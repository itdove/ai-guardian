"""
Engine Tester Panel

Test strings against individual scanner engines to compare detection
across engines and debug pattern differences.
"""

import logging
import threading

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.widgets import Static, Button, Select, TextArea, Checkbox


class EngineTesterContent(ScrollableContainer):
    """Interactive engine tester for comparing scanner engine detection."""

    CSS = """
    EngineTesterContent {
        overflow-x: hidden;
    }

    #et-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    .et-section {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    .et-section-title {
        margin: 0 0 1 0;
        text-style: bold;
    }

    .et-row {
        margin: 0 0 1 0;
        height: auto;
    }

    .et-row Select {
        width: 40;
    }

    .et-label {
        width: 16;
        margin: 0 1 0 0;
    }

    #et-input-area {
        height: 10;
        margin: 0 0 1 0;
    }

    #et-run-btn {
        margin: 0 2 0 0;
    }

    #et-summary {
        margin: 0 0 1 0;
    }

    #et-details {
        margin: 0;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Engine Tester[/bold]  "
            "[dim]Test strings against scanner engines[/dim]",
            id="et-header",
        )

        with Container(id="et-input-section", classes="et-section"):
            yield Static("Input", classes="et-section-title")

            with Horizontal(classes="et-row"):
                yield Static("Engine", classes="et-label")
                yield Select(
                    [],
                    value=Select.BLANK,
                    id="et-engine-select",
                    allow_blank=True,
                    prompt="Select engine...",
                )

            yield Static(
                "[dim]Test String — paste text to scan for secrets[/dim]",
                classes="et-row",
            )
            yield TextArea(id="et-input-area")

            with Horizontal(classes="et-row"):
                yield Checkbox(
                    "Use pattern server config",
                    id="et-pattern-server",
                    value=False,
                )

            with Horizontal(classes="et-row"):
                yield Button(
                    "Test",
                    variant="primary",
                    id="et-run-btn",
                )
                yield Button(
                    "Test All Engines",
                    variant="default",
                    id="et-run-all-btn",
                )

        with Container(id="et-results-section", classes="et-section"):
            yield Static("Results", classes="et-section-title")
            yield Static("", id="et-summary")
            yield Static("", id="et-details")

    def on_mount(self) -> None:
        for widget_id in ("#et-input-section", "#et-results-section"):
            self.query_one(widget_id).styles.height = "auto"
        self.query_one("#et-results-section").display = False
        self._populate_engines()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "et-run-btn":
            self._run_single()
        elif event.button.id == "et-run-all-btn":
            self._run_all()

    def refresh_content(self) -> None:
        self._populate_engines()
        self._clear_results()

    def action_refresh(self) -> None:
        self.refresh_content()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _populate_engines(self):
        try:
            from ai_guardian.engine_tester import get_available_engines
            engines = get_available_engines()
        except Exception:
            engines = []

        select = self.query_one("#et-engine-select", Select)
        options = [(name, name) for name in engines]
        select.set_options(options)
        if engines:
            select.value = engines[0]

    def _clear_results(self):
        self.query_one("#et-results-section").display = False
        self.query_one("#et-summary", Static).update("")
        self.query_one("#et-details", Static).update("")

    def _get_input(self):
        return self.query_one("#et-input-area", TextArea).text

    def _use_pattern_server(self):
        return self.query_one("#et-pattern-server", Checkbox).value

    def _show_running(self, label: str):
        section = self.query_one("#et-results-section")
        section.display = True
        self.query_one("#et-summary", Static).update(
            f"[yellow]Running {label}...[/yellow]"
        )
        self.query_one("#et-details", Static).update("")

    def _run_single(self):
        sel = self.query_one("#et-engine-select", Select)
        engine = sel.value
        if engine is Select.BLANK:
            self._show_error("Select an engine first.")
            return

        text = self._get_input()
        if not text.strip():
            self._show_error("Enter text to test.")
            return

        self._show_running(engine)
        use_ps = self._use_pattern_server()

        def worker():
            try:
                from ai_guardian.engine_tester import test_engine
                result = test_engine(engine, text, use_pattern_server=use_ps)
                self.app.call_from_thread(self._display_single, result)
            except Exception as exc:
                self.app.call_from_thread(self._show_error, str(exc))

        threading.Thread(target=worker, daemon=True).start()

    def _run_all(self):
        text = self._get_input()
        if not text.strip():
            self._show_error("Enter text to test.")
            return

        self._show_running("all engines")
        use_ps = self._use_pattern_server()

        def worker():
            try:
                from ai_guardian.engine_tester import test_all_engines
                results = test_all_engines(text, use_pattern_server=use_ps)
                self.app.call_from_thread(self._display_comparison, results)
            except Exception as exc:
                self.app.call_from_thread(self._show_error, str(exc))

        threading.Thread(target=worker, daemon=True).start()

    def _display_single(self, result):
        section = self.query_one("#et-results-section")
        section.display = True

        if result.error and not result.found:
            self.query_one("#et-summary", Static).update(
                f"[bold]{result.engine}[/bold]: "
                f"[red]ERROR[/red] — {result.error}"
            )
            self.query_one("#et-details", Static).update("")
            return

        if result.found:
            status = f"[red]FOUND ({len(result.secrets)} secret{'s' if len(result.secrets) != 1 else ''})[/red]"
        else:
            status = "[green]NOT FOUND[/green]"

        self.query_one("#et-summary", Static).update(
            f"[bold]{result.engine}[/bold]: {status}  "
            f"[dim]({result.scan_time_ms:.0f}ms)[/dim]"
        )

        lines = []
        for s in result.secrets:
            parts = []
            if s.rule_id:
                parts.append(f"[bold]Rule:[/bold] {s.rule_id}")
            parts.append(f"[bold]Line:[/bold] {s.line_number}")
            if s.description:
                parts.append(s.description)
            lines.append("  " + "  ".join(parts))
        self.query_one("#et-details", Static).update("\n".join(lines))

    def _display_comparison(self, results):
        section = self.query_one("#et-results-section")
        section.display = True

        if not results:
            self.query_one("#et-summary", Static).update(
                "[yellow]No engines installed.[/yellow]"
            )
            self.query_one("#et-details", Static).update("")
            return

        self.query_one("#et-summary", Static).update(
            "[bold]All Engines Comparison[/bold]"
        )

        lines = []
        for r in results:
            if r.error and not r.found:
                status = f"[red]ERROR[/red] — {r.error}"
            elif r.found:
                count = len(r.secrets)
                rules = ", ".join(s.rule_id for s in r.secrets if s.rule_id)
                status = (
                    f"[red]FOUND[/red] {count} secret{'s' if count != 1 else ''}"
                    f"  [dim]{rules}[/dim]"
                )
            else:
                status = "[green]NOT FOUND[/green]"

            lines.append(
                f"  [bold]{r.engine:<14}[/bold] {status}  "
                f"[dim]({r.scan_time_ms:.0f}ms)[/dim]"
            )

        self.query_one("#et-details", Static).update("\n".join(lines))

    def _show_error(self, msg: str):
        section = self.query_one("#et-results-section")
        section.display = True
        self.query_one("#et-summary", Static).update(f"[red]{msg}[/red]")
        self.query_one("#et-details", Static).update("")
