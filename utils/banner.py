"""
R3CON-X startup banner — rendered with Rich for a professional look.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

VERSION   = "2.0.0"
_console  = Console(highlight=False)

_LOGO = """\
[bold red] ██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗[/bold red][bold white]      ██╗  ██╗[/bold white]
[bold red] ██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║[/bold red][bold white]      ╚██╗██╔╝[/bold white]
[bold red] ██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║[/bold red][bold white]       ╚███╔╝ [/bold white]
[bold red] ██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗██║[/bold red][bold white]       ██╔██╗ [/bold white]
[bold red] ██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║[/bold red][bold white]      ██╔╝ ██╗[/bold white]
[bold red] ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝╚═╝  ╚═══╝[/bold red][bold white]      ╚═╝  ╚═╝[/bold white]"""


def _build_info_table() -> Table:
    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column(style="bold cyan",  no_wrap=True)
    t.add_column(style="white")
    rows = [
        ("Version",  VERSION),
        ("Platform", "Linux / Kali  ·  Python 3.x"),
        ("License",  "Authorized Assessments Only"),
        ("Modules",  "PassiveRecon · ActiveScan · WebEnum · CVE · RiskAI · Report"),
    ]
    for k, v in rows:
        t.add_row(k, v)
    return t


def print_banner() -> None:
    _console.print()
    _console.print(_LOGO)
    _console.print()

    _console.print(Panel(
        _build_info_table(),
        title=f"[bold yellow] R3CON-X  v{VERSION} [/bold yellow]",
        subtitle="[dim red]!! Authorized Security Testing Only !![/dim red]",
        border_style="red",
        box=box.DOUBLE_EDGE,
        expand=True,
        padding=(0, 1),
    ))
    _console.print()
