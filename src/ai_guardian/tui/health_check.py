"""
Health Check (Doctor) Panel

Displays ai-guardian doctor health checks in the Console.
Reuses the Doctor class from ai_guardian.doctor.
"""

import logging

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.widgets import Static, Button, Collapsible

from ai_guardian.doctor import (
    CheckStatus,
    CheckResult,
    Doctor,
    DoctorReport,
    _CHECK_DISPLAY_NAMES,
)

logger = logging.getLogger(__name__)

_STATUS_MARKUP = {
    CheckStatus.PASS: "[green]\\[PASS][/green]",
    CheckStatus.WARN: "[yellow]\\[WARN][/yellow]",
    CheckStatus.FAIL: "[red]\\[FAIL][/red]",
    CheckStatus.SKIP: "[dim]\\[SKIP][/dim]",
}

_STATUS_ICONS = {
    CheckStatus.PASS: "[green]✅[/green]",
    CheckStatus.WARN: "[yellow]⚠️[/yellow]",
    CheckStatus.FAIL: "[red]❌[/red]",
    CheckStatus.SKIP: "[dim]➖[/dim]",
}


def format_check_status(check: CheckResult) -> str:
    """Format a single check result as a rich-text summary line."""
    icon = _STATUS_ICONS.get(check.status, "")
    label = _STATUS_MARKUP.get(check.status, str(check.status.value))
    display_name = _CHECK_DISPLAY_NAMES.get(check.name, check.name)
    return f"{icon} {label}  {display_name:<20s}  {check.message}"


def format_check_detail(check: CheckResult) -> str:
    """Format the expandable detail section for a check."""
    parts = []
    if check.detail:
        parts.append(f"[dim]Detail:[/dim]\n{check.detail}")
    if check.fix_hint:
        prefix = "[green]Fixed[/green]" if check.fixed else "[yellow]Hint[/yellow]"
        parts.append(f"{prefix}: {check.fix_hint}")
    if check.fixable and not check.fixed:
        parts.append("[dim]This issue can be auto-fixed with Fix Issues.[/dim]")
    return "\n".join(parts) if parts else "[dim]No additional details.[/dim]"


def format_summary(report: DoctorReport) -> str:
    """Format the summary line from a DoctorReport."""
    pass_count = sum(1 for c in report.checks if c.status == CheckStatus.PASS)
    warn_count = sum(1 for c in report.checks if c.status == CheckStatus.WARN)
    fail_count = sum(1 for c in report.checks if c.status == CheckStatus.FAIL)
    skip_count = sum(1 for c in report.checks if c.status == CheckStatus.SKIP)
    fixed_count = sum(1 for c in report.checks if c.fixed)

    parts = []
    if pass_count:
        parts.append(f"[green]{pass_count} passed[/green]")
    if fail_count:
        parts.append(f"[red]{fail_count} error(s)[/red]")
    if warn_count:
        parts.append(f"[yellow]{warn_count} warning(s)[/yellow]")
    if skip_count:
        parts.append(f"[dim]{skip_count} skipped[/dim]")
    if fixed_count:
        parts.append(f"[green]{fixed_count} fixed[/green]")

    return f"  {', '.join(parts)}" if parts else "  No checks ran"


class HealthCheckContent(ScrollableContainer):
    """Health check panel displaying ai-guardian doctor results."""

    CSS = """
    HealthCheckContent {
        overflow-x: hidden;
    }

    #hc-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    #hc-results {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    #hc-summary {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    .hc-check-detail {
        padding: 0 0 0 4;
        margin: 0 0 1 0;
    }

    #hc-actions {
        margin: 1 0;
        height: auto;
    }

    #hc-actions Button {
        margin: 0 2 0 0;
    }

    #hc-loading {
        margin: 1 0;
        padding: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Health Check[/bold]  "
            "[dim]System health status — ai-guardian doctor[/dim]",
            id="hc-header",
        )
        yield Static("[dim]Running health checks...[/dim]", id="hc-loading")
        yield Container(id="hc-results")
        yield Container(id="hc-summary")
        with Horizontal(id="hc-actions"):
            yield Button("Refresh", id="hc-refresh-btn", variant="primary")
            yield Button("Fix Issues", id="hc-fix-btn", variant="warning")

    def on_mount(self) -> None:
        self._run_checks()

    def refresh_content(self) -> None:
        self._run_checks()

    def action_refresh(self) -> None:
        self._run_checks()
        self.app.notify("Health checks refreshed", severity="information")

    def _run_checks(self, fix: bool = False) -> None:
        """Run doctor checks and update the display."""
        try:
            doctor = Doctor(fix=fix)
            report = doctor.run_all()
        except Exception as e:
            logger.error("Doctor checks failed: %s", e)
            report = DoctorReport()
            report.checks.append(CheckResult(
                name="doctor",
                status=CheckStatus.FAIL,
                message=f"Doctor failed to run: {e}",
            ))

        self._update_display(report, fixed=fix)

    def _update_display(self, report: DoctorReport, fixed: bool = False) -> None:
        """Rebuild the results and summary from a DoctorReport."""
        loading = self.query_one("#hc-loading", Static)
        loading.display = False

        results_container = self.query_one("#hc-results", Container)
        results_container.remove_children()

        for check in report.checks:
            has_detail = bool(check.detail or check.fix_hint or check.fixable)
            summary_line = format_check_status(check)

            if has_detail:
                detail_text = format_check_detail(check)
                collapsible = Collapsible(
                    Static(detail_text, classes="hc-check-detail"),
                    title=summary_line,
                    collapsed=True,
                )
                results_container.mount(collapsible)
            else:
                results_container.mount(Static(summary_line))

        summary_container = self.query_one("#hc-summary", Container)
        summary_container.remove_children()

        summary_text = format_summary(report)
        has_fixable = any(c.fixable and not c.fixed for c in report.checks)

        if fixed:
            fixed_count = sum(1 for c in report.checks if c.fixed)
            if fixed_count:
                summary_text += f"\n  [green]Auto-fixed {fixed_count} issue(s)[/green]"

        summary_container.mount(Static(summary_text))

        fix_btn = self.query_one("#hc-fix-btn", Button)
        fix_btn.disabled = not has_fixable

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "hc-refresh-btn":
            self.action_refresh()
        elif event.button.id == "hc-fix-btn":
            self._confirm_fix()

    def _confirm_fix(self) -> None:
        """Show confirmation before running auto-fix."""
        from textual.screen import ModalScreen
        from textual.widgets import Label
        from textual.binding import Binding

        panel = self

        class ConfirmFixScreen(ModalScreen):
            CSS = """
            ConfirmFixScreen {
                align: center middle;
            }
            #confirm-container {
                width: 60;
                height: auto;
                background: $panel;
                border: thick $primary;
                padding: 2;
            }
            #confirm-buttons {
                margin: 1 0 0 0;
                height: auto;
                align: center middle;
            }
            #confirm-buttons Button {
                margin: 0 1;
            }
            """

            BINDINGS = [
                Binding("escape", "cancel", "Cancel", show=False),
            ]

            def compose(self_inner) -> ComposeResult:
                with Container(id="confirm-container"):
                    yield Static(
                        "[bold]Fix Issues[/bold]\n\n"
                        "This will attempt to auto-fix issues that support it "
                        "(e.g., creating missing directories).\n\n"
                        "Continue?"
                    )
                    with Horizontal(id="confirm-buttons"):
                        yield Button(
                            "Fix", id="confirm-yes", variant="warning"
                        )
                        yield Button(
                            "Cancel", id="confirm-no", variant="default"
                        )

            def on_button_pressed(self_inner, event: Button.Pressed) -> None:
                if event.button.id == "confirm-yes":
                    self_inner.dismiss(True)
                else:
                    self_inner.dismiss(False)

            def action_cancel(self_inner) -> None:
                self_inner.dismiss(False)

        def on_confirm(result: bool) -> None:
            if result:
                panel._run_checks(fix=True)
                panel.app.notify(
                    "Fix completed — review results",
                    severity="information",
                )

        self.app.push_screen(ConfirmFixScreen(), on_confirm)
