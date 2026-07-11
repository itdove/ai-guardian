"""About panel — version and system information."""

import platform
import sys

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

from ai_guardian import __version__


class AboutContent(VerticalScroll):
    """Displays version and system information."""

    def compose(self) -> ComposeResult:
        yield Static(
            f"[bold]AI Guardian[/bold]  v{__version__}\n\n"
            f"Python     {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}\n"
            f"Platform   {platform.platform()}\n"
            f"License    Apache-2.0\n"
        )
