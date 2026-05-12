"""
Directory Scan Panel

Scan directories for security issues (secrets, SSRF, Unicode attacks,
config file threats) with an interactive results view and export.
"""

import json
import logging
import os
import threading
import time


from pathlib import Path
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static, Button, Input, Checkbox, Label, Select


FORMAT_OPTIONS = [
    ("JSON", "json"),
    ("SARIF", "sarif"),
]


class ExportModal(ModalScreen):
    """Modal for choosing export destination and format."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    CSS = """
    ExportModal {
        align: center middle;
    }

    #export-container {
        width: 64;
        height: auto;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #export-header {
        margin: 0 0 1 0;
        text-align: center;
    }

    .export-field {
        margin: 1 0;
    }

    .export-field Input,
    .export-field Select {
        width: 100%;
    }

    #export-actions {
        margin: 1 0 0 0;
        height: auto;
    }

    #export-actions Button {
        margin: 0 1 0 0;
    }
    """

    def __init__(self, default_dir: str = ".", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._default_dir = default_dir

    def compose(self) -> ComposeResult:
        with Container(id="export-container"):
            yield Static(
                "[bold]Export Scan Results[/bold]", id="export-header"
            )

            with Container(classes="export-field"):
                yield Label("Format:")
                yield Select(
                    FORMAT_OPTIONS,
                    value="json",
                    id="export-format",
                    allow_blank=False,
                )

            with Container(classes="export-field"):
                yield Label("Destination file:")
                default_path = os.path.join(
                    self._default_dir, "scan-results.json"
                )
                yield Input(
                    value=default_path,
                    placeholder="/path/to/output-file",
                    id="export-path",
                )

            with Horizontal(id="export-actions"):
                yield Button(
                    "Export", id="do-export", variant="success"
                )
                yield Button(
                    "Cancel", id="cancel-export", variant="error"
                )

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "export-format":
            fmt = event.value
            path_input = self.query_one("#export-path", Input)
            current = path_input.value
            if fmt == "sarif" and current.endswith(".json"):
                path_input.value = current.rsplit(".json", 1)[0] + ".sarif"
            elif fmt == "json" and current.endswith(".sarif"):
                path_input.value = current.rsplit(".sarif", 1)[0] + ".json"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "do-export":
            fmt = self.query_one("#export-format", Select).value
            path = self.query_one("#export-path", Input).value.strip()
            if not path:
                self.notify("Enter a destination file path", severity="error")
                return
            self.dismiss({"format": fmt, "path": path})
        elif event.button.id == "cancel-export":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class DirectoryScanContent(ScrollableContainer):
    """Interactive directory scanner for finding security issues."""

    CSS = """
    DirectoryScanContent {
        overflow-x: hidden;
    }

    #ds-header {
        margin: 1 0;
        padding: 1;
        background: $primary;
        color: $text;
    }

    .ds-section {
        margin: 1 0;
        padding: 1;
        background: $panel;
        border: solid $primary;
    }

    .ds-section-title {
        margin: 0 0 1 0;
        text-style: bold;
    }

    .ds-row {
        margin: 0 0 1 0;
        height: auto;
    }

    #ds-path-input {
        margin: 0 0 1 0;
    }

    #ds-scan-btn {
        margin: 0 2 0 0;
    }

    #ds-summary {
        margin: 0 0 1 0;
    }

    #ds-details-scroll {
        max-height: 24;
        margin: 0 0 1 0;
    }

    #ds-details {
        margin: 0;
    }

    .ds-export-row {
        margin: 1 0 0 0;
        height: auto;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold]Directory Scan[/bold]  "
            "[dim]Scan directories for security issues[/dim]",
            id="ds-header",
        )

        with Container(id="ds-input-section", classes="ds-section"):
            yield Static("Scan Settings", classes="ds-section-title")

            yield Static(
                "[dim]Path — directory to scan for security issues[/dim]",
                classes="ds-row",
            )
            yield Input(
                value=".",
                placeholder="Directory path to scan",
                id="ds-path-input",
            )

            with Horizontal(classes="ds-row"):
                yield Checkbox(
                    "Recursive",
                    id="ds-recursive",
                    value=True,
                )
                yield Checkbox(
                    "Config files only",
                    id="ds-config-only",
                    value=False,
                )

            with Horizontal(classes="ds-row"):
                yield Button("Scan", variant="primary", id="ds-scan-btn")

        with Container(id="ds-results-section", classes="ds-section"):
            yield Static("Results", classes="ds-section-title")
            yield Static("", id="ds-summary")
            with VerticalScroll(id="ds-details-scroll"):
                yield Static("", id="ds-details")
            with Horizontal(classes="ds-export-row"):
                yield Button(
                    "Export",
                    variant="default",
                    id="ds-export-btn",
                )

    def on_mount(self) -> None:
        self.query_one("#ds-results-section").display = False
        self._findings: List[Dict[str, Any]] = []
        self._scan_path: str = "."
        self._file_count: int = 0

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ds-scan-btn":
            self._run_scan()
        elif event.button.id == "ds-export-btn":
            self._open_export_modal()

    def refresh_content(self) -> None:
        self._clear_results()

    def action_refresh(self) -> None:
        self.refresh_content()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _clear_results(self):
        self.query_one("#ds-results-section").display = False
        self.query_one("#ds-summary", Static).update("")
        self.query_one("#ds-details", Static).update("")
        self._findings = []

    def _show_running(self):
        section = self.query_one("#ds-results-section")
        section.display = True
        self.query_one("#ds-summary", Static).update(
            "[yellow]Scanning...[/yellow]"
        )
        self.query_one("#ds-details", Static).update("")

    @staticmethod
    def _suppress_logging():
        prev = logging.root.level
        logging.disable(logging.CRITICAL)
        return prev

    @staticmethod
    def _restore_logging(prev):
        logging.disable(logging.NOTSET)
        logging.root.setLevel(prev)

    def _load_config(self) -> Dict[str, Any]:
        try:
            from ai_guardian.config_utils import get_config_dir
            config_path = get_config_dir() / "ai-guardian.json"
            if not config_path.exists():
                config_path = Path.cwd() / ".ai-guardian.json"
            if not config_path.exists():
                return {}
            with open(config_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _run_scan(self):
        path = self.query_one("#ds-path-input", Input).value.strip()
        if not path:
            self._show_error("Enter a path to scan.")
            return

        resolved = Path(path).resolve()
        if not resolved.exists():
            self._show_error(f"Path does not exist: {path}")
            return

        self._scan_path = str(resolved)
        config_only = self.query_one("#ds-config-only", Checkbox).value
        self._show_running()

        def worker():
            prev = self._suppress_logging()
            try:
                from ai_guardian.scanner import FileScanner

                config = self._load_config()
                scanner = FileScanner(config=config)

                start_ms = time.monotonic_ns() // 1_000_000
                findings = scanner.scan_directory(
                    path=self._scan_path,
                    config_only=config_only,
                )
                elapsed_ms = (time.monotonic_ns() // 1_000_000) - start_ms

                file_count = len(scanner._discover_files(
                    resolved, None, None, False
                )) if resolved.is_dir() else 1

                self.app.call_from_thread(
                    self._display_results, findings, file_count, elapsed_ms
                )
            except Exception as exc:
                self.app.call_from_thread(self._show_error, str(exc))
            finally:
                self._restore_logging(prev)

        threading.Thread(target=worker, daemon=True).start()

    def _display_results(
        self,
        findings: List[Dict[str, Any]],
        file_count: int,
        elapsed_ms: int,
    ):
        self._findings = findings
        self._file_count = file_count

        section = self.query_one("#ds-results-section")
        section.display = True

        violation_count = len(findings)
        if violation_count == 0:
            self.query_one("#ds-summary", Static).update(
                f"[green]No issues found[/green]  "
                f"[dim]{file_count} files scanned ({elapsed_ms}ms)[/dim]"
            )
            self.query_one("#ds-details", Static).update("")
            return

        self.query_one("#ds-summary", Static).update(
            f"[bold]{file_count}[/bold] files scanned, "
            f"[red]{violation_count} violation"
            f"{'s' if violation_count != 1 else ''}[/red]  "
            f"[dim]({elapsed_ms}ms)[/dim]"
        )

        lines = []
        for f in findings:
            rule = f.get("rule_id", "unknown")
            msg = f.get("message", "")
            fpath = f.get("file_path", "")
            line_num = f.get("line_number")
            severity = f.get("severity", "warning")
            snippet = f.get("snippet", "")

            severity_color = "red" if severity == "error" else "yellow"
            icon = "[red]![/red]" if severity == "error" else "[yellow]![/yellow]"

            location = fpath
            if line_num:
                location += f":{line_num}"

            parts = [f"  {icon} [{severity_color}]{location}[/{severity_color}]"]
            parts.append(f"    [bold]{rule}[/bold] — {msg}")
            if snippet:
                parts.append(f"    [dim]{snippet}[/dim]")

            lines.append("\n".join(parts))

        self.query_one("#ds-details", Static).update("\n".join(lines))

    def _open_export_modal(self):
        if not self._findings:
            self.app.notify("No results to export", severity="warning")
            return

        default_dir = str(Path.cwd())
        self.app.push_screen(
            ExportModal(default_dir=default_dir), self._do_export
        )

    def _do_export(self, result: Optional[Dict]) -> None:
        if result is None:
            return

        fmt = result["format"]
        out_file = result["path"]

        try:
            parent = Path(out_file).parent
            parent.mkdir(parents=True, exist_ok=True)

            if fmt == "sarif":
                from ai_guardian import __version__
                from ai_guardian.sarif_formatter import SARIFFormatter

                formatter = SARIFFormatter(version=__version__)
                formatter.write_sarif_file(
                    self._findings, out_file, scan_path=self._scan_path
                )
            else:
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(self._findings, f, indent=2)

            self.app.notify(
                f"Exported to {out_file}",
                severity="information",
            )
        except Exception as exc:
            self.app.notify(f"Export failed: {exc}", severity="error")

    def _show_error(self, msg: str):
        section = self.query_one("#ds-results-section")
        section.display = True
        self.query_one("#ds-summary", Static).update(f"[red]{msg}[/red]")
        self.query_one("#ds-details", Static).update("")
