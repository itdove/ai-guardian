#!/usr/bin/env python3
"""
Metrics Tab Content

Display violation statistics and trends from the violations log.
"""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Static


class MetricsContent(Container):
    """Content widget for Metrics panel."""

    CSS = """
    MetricsContent {
        height: 100%;
    }

    #metrics-header {
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

    #metrics-range-buttons {
        margin: 1 0;
        height: auto;
    }

    #metrics-range-buttons Button {
        margin: 0 1 0 0;
    }

    #metrics-body {
        margin: 1 0;
        padding: 1;
        background: $surface;
        min-height: 10;
    }

    Button:focus {
        border-left: heavy $accent;
        text-style: bold;
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._since_days = 30

    def compose(self) -> ComposeResult:
        yield Static("[bold]Violation Metrics[/bold]", id="metrics-header")

        with VerticalScroll():
            with Horizontal(id="metrics-range-buttons"):
                yield Button("7 days", id="metrics-7d", variant="default")
                yield Button("30 days", id="metrics-30d", variant="primary")
                yield Button("90 days", id="metrics-90d", variant="default")
                yield Button("Refresh", id="metrics-refresh", variant="success")

            with Container(classes="section"):
                yield Static("[bold]Summary[/bold]", classes="section-title")
                yield Static("Loading...", id="metrics-summary")

            with Container(classes="section"):
                yield Static("[bold]By Type[/bold]", classes="section-title")
                yield Static("", id="metrics-by-type")

            with Container(classes="section"):
                yield Static("[bold]By Severity[/bold]", classes="section-title")
                yield Static("", id="metrics-by-severity")

            with Container(classes="section"):
                yield Static("[bold]By Action[/bold]", classes="section-title")
                yield Static("", id="metrics-by-action")

            with Container(classes="section"):
                yield Static("[bold]Top Files[/bold]", classes="section-title")
                yield Static("", id="metrics-top-files")

            with Container(classes="section"):
                yield Static("[bold]Top Tools[/bold]", classes="section-title")
                yield Static("", id="metrics-top-tools")

            with Container(classes="section"):
                yield Static("[bold]Daily Trend[/bold]", classes="section-title")
                yield Static("", id="metrics-trend")

    def on_mount(self) -> None:
        self._load_metrics()

    def refresh_content(self) -> None:
        self._load_metrics()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "metrics-7d":
            self._since_days = 7
        elif btn_id == "metrics-30d":
            self._since_days = 30
        elif btn_id == "metrics-90d":
            self._since_days = 90
        elif btn_id == "metrics-refresh":
            pass
        else:
            return

        for bid in ("metrics-7d", "metrics-30d", "metrics-90d"):
            btn = self.query_one(f"#{bid}", Button)
            btn.variant = "primary" if bid == f"metrics-{self._since_days}d" else "default"

        self._load_metrics()

    def _load_metrics(self) -> None:
        try:
            from ai_guardian.metrics import MetricsComputer
            computer = MetricsComputer(since_days=self._since_days)
            report = computer.compute()
        except Exception as e:
            self.query_one("#metrics-summary", Static).update(
                f"[red]Error loading metrics: {e}[/red]"
            )
            return

        if report.total_violations == 0:
            self.query_one("#metrics-summary", Static).update(
                f"No violations in the last {self._since_days} days."
            )
            for wid in ("metrics-by-type", "metrics-by-severity",
                        "metrics-by-action", "metrics-top-files",
                        "metrics-top-tools", "metrics-trend"):
                self.query_one(f"#{wid}", Static).update("")
            return

        # Summary
        summary = (
            f"Total violations:  [bold]{report.total_violations:,}[/bold]\n"
            f"Resolved:          {report.resolved_count:,}\n"
            f"Unresolved:        {report.unresolved_count:,}\n"
            f"Unique sessions:   {report.session_count:,}"
        )
        self.query_one("#metrics-summary", Static).update(summary)

        # By type
        self._update_breakdown("metrics-by-type", report.by_type, report.total_violations)

        # By severity
        self._update_breakdown("metrics-by-severity", report.by_severity, report.total_violations)

        # By action
        self._update_breakdown("metrics-by-action", report.by_action, report.total_violations)

        # Top files
        if report.top_files:
            lines = []
            for i, (fp, count) in enumerate(report.top_files, 1):
                display = fp if len(fp) <= 50 else "..." + fp[-47:]
                lines.append(f"  {i:>2}. {display}  ({count:,})")
            self.query_one("#metrics-top-files", Static).update("\n".join(lines))
        else:
            self.query_one("#metrics-top-files", Static).update("[dim]No file data[/dim]")

        # Top tools
        if report.top_tools:
            lines = []
            for i, (tool, count) in enumerate(report.top_tools, 1):
                lines.append(f"  {i:>2}. {tool}  ({count:,})")
            self.query_one("#metrics-top-tools", Static).update("\n".join(lines))
        else:
            self.query_one("#metrics-top-tools", Static).update("[dim]No tool data[/dim]")

        # Daily trend
        if report.time_trend:
            max_count = max(t["count"] for t in report.time_trend) or 1
            bar_width = 20
            lines = []
            for entry in report.time_trend[-14:]:
                bar_len = int(entry["count"] / max_count * bar_width)
                bar = "█" * bar_len
                lines.append(f"  {entry['date']}  {entry['count']:>4,}  {bar}")
            self.query_one("#metrics-trend", Static).update("\n".join(lines))
        else:
            self.query_one("#metrics-trend", Static).update("[dim]No trend data[/dim]")

    def _update_breakdown(self, widget_id: str, data: dict, total: int) -> None:
        if data:
            lines = []
            for key, count in data.items():
                pct = (count / total * 100) if total > 0 else 0
                lines.append(f"  {key:<25s} {count:>5,}  ({pct:>5.1f}%)")
            self.query_one(f"#{widget_id}", Static).update("\n".join(lines))
        else:
            self.query_one(f"#{widget_id}", Static).update("[dim]No data[/dim]")
