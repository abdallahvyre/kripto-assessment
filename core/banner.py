"""Rendered output for the Krypto toolkit.

Every helper here works in two modes:

* line mode  - it prints to the Rich console and scrolls normally;
* dashboard  - a live dashboard registers itself as the sink, helpers push
  structured events into it instead of printing.

Keeping the same function signatures means the scanning modules never need
to know which renderer is active.
"""

from datetime import datetime

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markup import escape
from core.redact import display_text

from core.theme import (  
    AMBER,
    BG,
    CYAN,
    DIM,
    GREEN,
    MAGENTA,
    MUTED,
    PANEL,
    RED,
    STAGES_TOTAL,
    TEXT,
    THEME,
    VERSION,
    strip_markup,
)





_SINK = None


def set_sink(sink):
    """Route every helper into *sink* (a Dashboard) until clear_sink()."""
    global _SINK
    _SINK = sink


def clear_sink():
    global _SINK
    _SINK = None


def active_sink():
    return _SINK


def _route(level, message):
    if _SINK is None:
        return False
    _SINK.log(level, strip_markup(message))
    return True







def show_banner(console: Console, target: str = "", profile: str = "default"):
    if _SINK is not None:
        return

    brand = Text()
    brand.append("K R Y P T O", style=f"bold {CYAN}")
    brand.append("  //  ", style=DIM)
    brand.append(VERSION, style=f"bold {TEXT}")
    brand.append("\nAdversary Emulation Toolkit", style=f"bold {MAGENTA}")
    brand.append("\nSECURITY OPERATIONS CONSOLE  ::  TUI/02", style=DIM)

    status = Text()
    status.append("● ", style=GREEN)
    status.append("ENGINE / LINKED\n", style=f"bold {GREEN}")
    status.append(f"{display_text(profile.upper())} PROFILE\n", style=TEXT)
    status.append(datetime.now().strftime("LOCAL  %Y-%m-%d  %H:%M:%S"), style=MUTED)

    grid = Table.grid(expand=True, padding=0)
    grid.add_column(ratio=3)
    grid.add_column(ratio=2, justify="right")
    grid.add_row(brand, status)

    console.print(
        Panel(
            grid,
            box=box.ROUNDED,
            border_style=CYAN,
            style=f"on {PANEL}",
            padding=(0, 1),
        )
    )
    console.print(
        f"  [kw.muted]Recon · Crawl · Scan · Extract · Analyze · Correlate · Report[/]"
    )
    if target:
        console.print()
        console.print(
            Panel(
                f"[bold kw.text]TARGET[/]  {escape(display_text(target))}",
                box=box.ROUNDED,
                border_style=DIM,
                style=f"on {PANEL}",
                padding=(0, 1),
            )
        )


def section_header(console: Console, title: str, number: int = None, total: int = None):
    if _SINK is not None:
        if number is not None:
            _SINK.stage_begin(number, strip_markup(title))
        else:
            _SINK.divider(strip_markup(title))
        return

    if number is not None and total is not None:
        prefix = f"[{number:02d}/{total:02d}] "
    else:
        prefix = ""
    console.print()
    console.print(
        Panel(
            Text(f"  {prefix}{display_text(title)}  "),
            border_style=CYAN,
            box=box.ROUNDED,
            style=f"on {PANEL}",
            padding=(0, 2),
        )
    )


def stage_start(console: Console, number: int, total: int, title: str, note: str = ""):
    section_header(console, title, number=number, total=total)


def stage_end(
    console: Console,
    number: int,
    total: int,
    title: str,
    ok: bool = True,
    note: str = "",
    elapsed: float = None,
):
    if _SINK is not None:
        _SINK.stage_finish(number, ok, strip_markup(note), elapsed)
        return

    glyph = f"[kw.green]✓[/]" if ok else f"[kw.red]✗[/]"
    timing = f"  [kw.muted]({elapsed:.1f}s)[/]" if elapsed is not None else ""
    console.print(f"  {glyph}  [kw.text]{escape(display_text(title))}[/]   [kw.muted]{escape(display_text(note))}[/]{timing}")







def success(console: Console, msg: str):
    msg = escape(display_text(msg))
    if _route("OK", msg):
        return
    console.print(f"  [kw.green]✓[/]  {msg}")


def warning(console: Console, msg: str):
    msg = escape(display_text(msg))
    if _route("WARN", msg):
        return
    console.print(f"  [kw.amber]![/]  {msg}")


def error(console: Console, msg: str):
    msg = escape(display_text(msg))
    if _route("ERROR", msg):
        return
    console.print(f"  [kw.red]✗[/]  {msg}")


def info(console: Console, msg: str):
    msg = escape(display_text(msg))
    if _route("INFO", msg):
        return
    console.print(f"  [kw.cyan]•[/]  {msg}")


def found(console: Console, msg: str):
    msg = escape(display_text(msg))
    if _route("FOUND", msg):
        return
    console.print(f"  [kw.green]»[/]  {msg}")


def vuln(console: Console, msg: str):
    msg = escape(display_text(msg))
    if _route("VULN", msg):
        return
    console.print(f"  [kw.red]▸[/]  {msg}")


def critical(console: Console, msg: str):
    msg = escape(display_text(msg))
    if _route("VULN", msg):
        return
    console.print(f"  [kw.red]▲[/]  {msg}")


def log_ts(console: Console, level: str, msg: str):
    level = (level or "info").upper()
    if level in ("ERR", "FAIL"):
        level = "ERROR"
    if _route(level, msg):
        return
    color = {
        "INFO": "kw.cyan",
        "OK": "kw.green",
        "WARN": "kw.amber",
        "ERROR": "kw.red",
        "FOUND": "kw.green",
        "VULN": "kw.red",
    }.get(level, "kw.text")
    glyph = {
        "INFO": "•",
        "OK": "✓",
        "WARN": "!",
        "ERROR": "✗",
        "FOUND": "»",
        "VULN": "▸",
    }.get(level, "•")
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(f"  [kw.muted]{ts}[/]  [{color}]{glyph}[/]  {escape(display_text(msg))}")







def make_table(title: str, columns: list, rows: list, style: str = None) -> Table:
    table = Table(
        title=f"[kw.cyan]{escape(display_text(title))}[/]",
        box=box.ROUNDED,
        border_style=style or CYAN,
        header_style=f"bold {TEXT}",
        show_lines=True,
        padding=(0, 1),
        title_style=CYAN,
        style=f"on {PANEL}",
    )
    for col in columns:
        table.add_column(Text(display_text(col)), style=TEXT)
    for row in rows:
        table.add_row(*[Text(display_text(c)) for c in row])
    return table


def progress_bar(console: Console, done: int, total: int, label: str = ""):
    if _SINK is not None:
        pct = int(100 * done / total) if total else 0
        _SINK.log("INFO", f"{label} {done}/{total} ({pct}%)")
        return
    width = 30
    filled = int(width * done / total) if total else 0
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * done / total) if total else 0
    console.print(
        f"  [kw.cyan][{bar}][/]  "
        f"[kw.muted]{pct:3d}%   {done}/{total}   {escape(display_text(label))}[/]"
    )


def final_summary(console: Console, title: str, rows: list, verdict: str = None):
    if verdict == "critical":
        border, glyph = RED, "▲"
    elif verdict == "high":
        border, glyph = RED, "!"
    elif verdict == "medium":
        border, glyph = AMBER, "•"
    else:
        border, glyph = GREEN, "✓"

    table = Table(
        title=f"[kw.text]  {escape(display_text(title))}  [/]",
        box=box.DOUBLE,
        border_style=border,
        header_style=f"bold {TEXT}",
        show_lines=True,
        padding=(0, 1),
        style=f"on {PANEL}",
    )
    table.add_column("Metric", style=TEXT)
    table.add_column("Value", style=GREEN, justify="right")
    for row in rows:
        table.add_row(*[Text(display_text(c)) for c in row])
    console.print(table)

    if verdict:
        color = RED if verdict == "critical" else AMBER if verdict in ("high", "medium") else GREEN
        console.print(f"  [{color}]{glyph}  Verdict: {verdict.upper()}[/]")


STATUS = {
    "IDLE": "[kw.muted][IDLE][/]",
    "RUNNING": "[kw.cyan][RUNNING][/]",
    "COMPLETED": "[kw.green][COMPLETED][/]",
    "FAILED": "[kw.red][FAILED][/]",
    "PARTIAL": "[kw.amber][PARTIAL][/]",
}


def status_line(console: Console, status: str, msg: str = ""):
    if _SINK is not None:
        _SINK.log("INFO", f"{status}: {msg}" if msg else status)
        return
    console.print(f"  {STATUS.get(status, escape(display_text(status)))}  {escape(display_text(msg))}")
