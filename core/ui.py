"""Full-screen terminal dashboard for the Krypto toolkit.

The layout is modelled on krypto_terminal/krypto_ui.py:

    +---------------------------------------------+
    |  header: brand, engine state, clock          |
    +---------+-----------------------------------+
    | control |  metrics                          |
    |  rail   |  stage matrix                     |
    |         |  live activity  |  run profile    |
    +---------+-----------------------------------+
    |  footer: key bindings, progress             |
    +---------------------------------------------+

The scan itself runs in a worker thread; this module only renders state and
drains the event stream, so the interface never blocks on network I/O.
"""

from __future__ import annotations

import os
import select
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from io import StringIO
from typing import Optional

from rich.box import ROUNDED, SIMPLE_HEAD
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.segment import Segment
from rich.style import Style

from core import banner as banner_module
from core.redact import redact_data, redact_text, display_text
from core.stages import STAGES as STAGE_CATALOGUE
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
    TEXT,
    THEME,
    VERSION,
    strip_markup,
    GradientScreen,
)





STAGES = [(stage.name, stage.category, stage.description) for stage in STAGE_CATALOGUE]

LEVEL_COLOR = {
    "SYS": MAGENTA,
    "INFO": CYAN,
    "OK": GREEN,
    "WARN": AMBER,
    "ERROR": RED,
    "FOUND": GREEN,
    "VULN": RED,
}

GLYPH_LEVEL = (
    ("✓", "OK"),
    ("✗", "ERROR"),
    ("!", "WARN"),
    ("▸", "VULN"),
    ("▲", "VULN"),
    ("»", "FOUND"),
    ("•", "INFO"),
)

BORDER_CHARS = set("─│┌┐└┘├┤┬┴┼╭╮╰╯═║╔╗╚╝╠╣╦╩╬━┃┏┓┗┛┣┫┳┻╋-+|=_· ")


@dataclass
class StageInfo:
    number: int
    name: str
    category: str
    description: str
    state: str = "READY"
    elapsed: Optional[float] = None
    note: str = ""


@dataclass
class LogEntry:
    stamp: str
    level: str
    message: str
    divider: bool = False







class KeyReader:
    def __enter__(self):
        self._posix_state = None
        if os.name == "nt":
            import msvcrt

            self._msvcrt = msvcrt
        else:
            import termios
            import tty

            self._termios = termios
            self._posix_state = termios.tcgetattr(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
        return self

    def __exit__(self, exc_type, exc, tb):
        if os.name != "nt" and self._posix_state is not None:
            self._termios.tcsetattr(
                sys.stdin.fileno(), self._termios.TCSADRAIN, self._posix_state
            )

    def read(self) -> Optional[str]:
        if os.name == "nt":
            if not self._msvcrt.kbhit():
                return None
            char = self._msvcrt.getwch()
            if char in ("\x00", "\xe0"):
                code = self._msvcrt.getwch()
                return {"H": "up", "P": "down"}.get(code)
            return char.lower()

        ready, _, _ = select.select([sys.stdin], [], [], 0)
        if not ready:
            return None
        char = sys.stdin.read(1)
        if char != "\x1b":
            return char.lower()
        if select.select([sys.stdin], [], [], 0.005)[0]:
            second = sys.stdin.read(1)
            if second == "[" and select.select([sys.stdin], [], [], 0.005)[0]:
                third = sys.stdin.read(1)
                return {"A": "up", "B": "down"}.get(third)
        return "esc"







class ContentSurface:
    def __init__(self, content):
        self.content = content

    def __rich_console__(self, console, options):
        for line in console.render_lines(self.content, options, style=Style(bgcolor=PANEL), pad=True):
            yield from line
            yield Segment.line()


class Dashboard:
    VIEWS = ("OVERVIEW", "STAGES", "ACTIVITY", "TARGET", "FINDINGS",
             "EVIDENCE", "COVERAGE", "PLUGINS", "REPORTS")

    def __init__(
        self,
        console: Console,
        target: str,
        domain: str,
        profile: str = "default",
        rate: float = 10.0,
        threads=None,
        scope=None,
        exclude=None,
        preflight: str = "",
    ):
        self.console = console
        self.target = redact_text(target)
        self.domain = domain
        self.profile = profile
        self.rate = rate
        self.threads = threads
        self.scope = scope or "single host"
        self.exclude = exclude or []
        self.preflight = preflight
        self.limits = {}
        self.snapshot = {}
        self.row_selected = {index: 0 for index in range(4, 9)}
        self.transport = "--"
        self.runtime_provider = None

        self.stages = [
            StageInfo(index + 1, name, category, description)
            for index, (name, category, description) in enumerate(STAGES)
        ]

        self.logs: deque = deque(maxlen=600)
        self.view_index = 0
        self.selected = 0
        self.current: Optional[StageInfo] = None

        self.started_at = datetime.now()
        self.finished = False
        self.detached = False
        self.dismissed = False
        self.interrupted = False
        self.running = False
        self.state = "IDLE"
        self.status_message = "SYSTEM READY"
        self._done_seen_at: Optional[float] = None
        self._lock = threading.RLock()
        self._dirty = True
        self._last_render = 0.0

    

    def log(self, level: str, message: str):
        message = display_text(strip_markup(message or "")).strip()[:2000]
        if not message:
            return
        self.logs.append(
            LogEntry(datetime.now().strftime("%H:%M:%S"), level.upper(), message)
        )
        self._dirty = True

    def divider(self, title: str):
        self.logs.append(LogEntry("", "SYS", title, divider=True))
        self._dirty = True

    def stage_begin(self, number: int, title: str):
        with self._lock:
            index = number - 1
            if 0 <= index < len(self.stages):
                stage = self.stages[index]
                stage.state = "RUNNING"
                self.current = stage
                self.selected = index
                self.status_message = f"STAGE {number:02d} / {len(self.stages):02d}"
            self.state = "RUNNING"
        self.log("SYS", f"STAGE {number:02d} · {title}")

    def stage_finish(self, number: int, ok: bool, note: str = "", elapsed=None):
        index = number - 1
        if not (0 <= index < len(self.stages)):
            return
        stage = self.stages[index]
        stage.state = "DONE" if ok else "FAILED"
        stage.elapsed = elapsed
        stage.note = note or ""
        if self.current is stage:
            self.current = None
        self.state = "RUNNING"
        self.log("OK" if ok else "WARN", note or f"{stage.name} finished")

    def publish(self, snapshot: dict):
        """Accept a detached, redacted model; never read mutable worker results in render."""
        def literal(value):
            if isinstance(value, str):
                return display_text(value)
            if isinstance(value, dict):
                return {key: literal(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [literal(item) for item in value]
            return value
        safe = literal(redact_data(snapshot))
        with self._lock:
            self.snapshot = safe
            health = safe.get("module_health") or {}
            notes = safe.get("module_notes") or {}
            timings = safe.get("module_timings") or {}
            for catalogue, stage in zip(STAGE_CATALOGUE, self.stages):
                keys = [key for key in health if any(
                    key.startswith(pattern) if pattern.endswith("/") else key == pattern
                    for pattern in catalogue.modules)]
                if not keys:
                    continue
                states = {health[key] for key in keys}
                state = next((value for value in ("FAILED", "INCONCLUSIVE", "RUNNING", "OK")
                              if value in states), "SKIPPED")
                stage.state = {"OK": "DONE", "SKIPPED": "SKIP"}.get(state, state)
                if state == "SKIPPED" and all(notes.get(key, "").startswith("not run:") for key in keys):
                    stage.state = "NOT_RUN"
                stage.note = "; ".join(f"{key}: {notes[key]}" for key in keys if notes.get(key))[:1000]
                stage.elapsed = sum(timings.get(key, 0) for key in keys) or None
            self._dirty = True

    def finish(self, ok: bool = True):
        with self._lock:
            if self.current is not None:
                if self.current.state == "RUNNING":
                    self.current.state = "INCONCLUSIVE" if ok else "FAILED"
                self.current = None
            for stage in self.stages:
                if stage.state == "RUNNING":
                    stage.state = "INCONCLUSIVE"
                elif stage.state == "READY":
                    stage.state = "NOT_RUN"
                    stage.note = self.snapshot.get("stop_reason") or "not run before execution finished"
            self.finished = True
            interrupted = bool(self.snapshot.get("interrupted"))
            self.state = ("INTERRUPTED" if interrupted else "COMPLETE") if ok else "ERROR"
            incomplete = any(stage.state in ("FAILED", "INCONCLUSIVE", "NOT_RUN") for stage in self.stages)
            self.status_message = ("RUN FINISHED / INCOMPLETE CHECKS" if incomplete else "RUN COMPLETE") if ok else "EXECUTION ERROR"
            if ok and interrupted:
                self.status_message = ("REQUEST LIMIT REACHED / INCOMPLETE CHECKS"
                                       if (self.snapshot.get("runtime") or {}).get("budget_exhausted")
                                       else "RUN INTERRUPTED / INCOMPLETE CHECKS")
            self._dirty = True
        self.log("WARN" if ok and interrupted else "OK" if ok else "ERROR",
                 self.status_message if interrupted else "Pipeline finished" if ok else "Pipeline aborted")

    def ingest(self, text: str):
        """Turn captured console output into activity events."""
        _ingest(self, text)

    

    @property
    def done_count(self) -> int:
        return sum(1 for stage in self.stages if stage.state in ("DONE", "FAILED", "SKIP", "INCONCLUSIVE"))

    @property
    def failed_count(self) -> int:
        return sum(1 for stage in self.stages if stage.state == "FAILED")

    @property
    def progress(self) -> int:
        total = len(self.stages)
        return int(100 * self.done_count / total) if total else 0

    def uptime(self) -> str:
        elapsed = int((datetime.now() - self.started_at).total_seconds())
        return f"{elapsed // 60:02d}:{elapsed % 60:02d}"

    @staticmethod
    def _state_color(state: str) -> str:
        return {
            "READY": MUTED,
            "RUNNING": MAGENTA,
            "DONE": GREEN,
            "FAILED": RED,
            "SKIP": DIM,
            "INCONCLUSIVE": AMBER,
            "NOT_RUN": AMBER,
        }.get(state, MUTED)

    @staticmethod
    def _state_glyph(state: str) -> str:
        return {
            "READY": "·",
            "RUNNING": "●",
            "DONE": "✓",
            "FAILED": "✗",
            "SKIP": "-",
            "INCONCLUSIVE": "?",
            "NOT_RUN": "-",
        }.get(state, "·")

    @staticmethod
    def _state_label(state: str) -> str:
        return {
            "READY": "READY",
            "RUNNING": "RUN",
            "DONE": "DONE",
            "FAILED": "FAIL",
            "SKIP": "SKIP",
            "INCONCLUSIVE": "UNKNOWN",
            "NOT_RUN": "NOT RUN",
        }.get(state, "READY")

    

    def _panel(self, body, title: str = "", accent: str = DIM, height: int = None,
               panel_style: str = None) -> Panel:
        return Panel(
            body,
            title=Text(title, style=f"bold {CYAN}") if title else None,
            title_align="left",
            box=ROUNDED,
            border_style=accent,
            style=f"on {PANEL}",
            padding=(0, 1),
            height=height,
        )

    def _text(self, value: str = "", style: str = None) -> Text:
        return Text(value, style=style or TEXT, no_wrap=True, overflow="ellipsis")

    def _header(self) -> Panel:
        grid = Table.grid(expand=True, padding=0)
        grid.add_column(ratio=3)
        grid.add_column(ratio=2, justify="right")

        brand = Text(no_wrap=True, overflow="ellipsis")
        brand.append("K R I P T O", style=f"bold {CYAN}")
        brand.append("  //  ", style=DIM)
        brand.append(VERSION, style=f"bold {TEXT}")
        brand.append("\nWeb Security Assessment", style=f"bold {MAGENTA}")
        brand.append("\nSECURITY OPERATIONS CONSOLE  ::  TUI/03", style=DIM)

        state_color = {
            "IDLE": GREEN,
            "RUNNING": MAGENTA,
            "COMPLETE": GREEN,
            "ERROR": RED,
        }.get(self.state, GREEN)

        status = Text(no_wrap=True, justify="right")
        status.append("● ", style=state_color)
        status.append("ENGINE / LINKED\n", style=f"bold {state_color}")
        status.append(f"{self.status_message}\n", style=TEXT)
        status.append(datetime.now().strftime("LOCAL  %Y-%m-%d  %H:%M:%S"), style=MUTED)
        status.justify = "right"

        grid.add_row(brand, status)
        return self._panel(grid, accent=CYAN, panel_style=CYAN)

    def _sidebar(self) -> Panel:
        body_height = self.console.height - 9
        show_session = body_height >= 25
        show_selected = body_height >= 31

        content = Text(no_wrap=True, overflow="ellipsis")
        content.append("NAVIGATION\n\n", style=f"bold {MUTED}")
        for index, view in enumerate(self.VIEWS):
            active = index == self.view_index
            content.append(f" 0{index + 1} ", style=f"bold {CYAN if active else DIM}")
            content.append(
                f"{view:<10}\n",
                style=f"bold underline {CYAN}" if active else MUTED,
            )

        if show_session:
            content.append("\nSESSION\n", style=f"bold {MUTED}")
            content.append("  TARGET   ", style=DIM)
            content.append(f"{self.domain[:14]}\n", style=TEXT)
            content.append("  PROFILE  ", style=DIM)
            content.append(f"{self.profile[:14]}\n", style=TEXT)
            content.append("  RATE     ", style=DIM)
            content.append(f"{self.rate:g}/s\n", style=TEXT)
            content.append("  THREADS  ", style=DIM)
            content.append(f"{'adaptive' if self.threads is None else self.threads}\n", style=TEXT)
            content.append("  DONE     ", style=DIM)
            content.append(f"{self.done_count:02d}/{len(self.stages):02d}\n",
                           style=AMBER if self.done_count < len(self.stages) else GREEN)
            content.append("  UPTIME   ", style=DIM)
            content.append(f"{self.uptime()}\n", style=TEXT)

        if show_selected:
            content.append("\nSELECTED STAGE\n", style=f"bold {MUTED}")
            stage = self.stages[self.selected]
            content.append(f"  {stage.name}\n", style=f"bold {CYAN}")
            content.append(f"  {stage.category}\n", style=MAGENTA)
            content.append(f"  {stage.state}\n", style=self._state_color(stage.state))
        return self._panel(content, "CONTROL")

    def _footer(self) -> Panel:
        line = Text(no_wrap=True, overflow="ellipsis")
        shortcuts = [
            ("1-9", "VIEWS"),
            ("UP/DN", "SELECT"),
            ("C", "CLEAR LOG"),
            ("Q", "EXIT"),
        ]
        for index, (key, label) in enumerate(shortcuts):
            if index:
                line.append("   ")
            line.append(f" {key} ", style=f"bold underline {CYAN}")
            line.append(f" {label}", style=MUTED)

        line.append("   ")
        width = max(6, min(20, self.console.width - 4 - 63))
        filled = int(width * self.progress / 100)
        line.append("■" * filled, style=MAGENTA)
        line.append("■" * (width - filled), style=DIM)
        line.append(f" {self.progress:03d}%", style=f"bold {MAGENTA}")
        return self._panel(line, accent=DIM)

    def _metric(self, value: str, label: str, color: str) -> Panel:
        text = Text(no_wrap=True)
        text.append(value + "\n", style=f"bold {color}")
        text.append(label, style=MUTED)
        return self._panel(text, accent=DIM)

    def _metrics(self) -> Table:
        grid = Table.grid(expand=True, padding=(0, 1))
        for _ in range(4):
            grid.add_column(ratio=1)
        grid.add_row(
            self._metric(str(len(self.snapshot.get("findings") or [])), "FINDINGS", CYAN),
            self._metric(str(sum(item.get("verification") == "CONFIRMED" for item in self.snapshot.get("findings") or [])), "VERIFIED", GREEN),
            self._metric(str(len(self._evidence_rows())), "EVIDENCE REFS", MAGENTA),
            self._metric(str((self.snapshot.get("runtime") or {}).get("requests", 0)), "REQUESTS", AMBER),
        )
        return grid

    def _stage_cell(self, stage: StageInfo, selected: bool) -> Text:
        cell = Text(no_wrap=True, overflow="ellipsis")
        cell.append("> " if selected else "  ", style=f"bold {CYAN}")
        cell.append(f"{stage.number:02d} ", style=CYAN if selected else DIM)
        cell.append(stage.name, style=f"bold {CYAN}" if selected else TEXT)
        return cell

    def _stage_state(self, stage: StageInfo) -> Text:
        return Text(self._state_label(stage.state), style=self._state_color(stage.state),
                    no_wrap=True)

    def _stage_grid(self) -> Table:
        pairs = 3 if self.console.width >= 100 else 2
        rows = (len(self.stages) + pairs - 1) // pairs
        grid = Table.grid(expand=True, padding=(0, 1))
        for _ in range(pairs):
            grid.add_column(ratio=3)
            grid.add_column(ratio=1)
        for row in range(rows):
            cells = []
            for column in range(pairs):
                index = column * rows + row
                if index < len(self.stages):
                    stage = self.stages[index]
                    cells.append(self._stage_cell(stage, index == self.selected))
                    cells.append(self._stage_state(stage))
                else:
                    cells.append(Text(""))
                    cells.append(Text(""))
            grid.add_row(*cells)
        return grid

    def _stage_rows(self) -> int:
        pairs = 3 if self.console.width >= 100 else 2
        return (len(self.stages) + pairs - 1) // pairs

    def _stage_table(self) -> Table:
        wide = self.console.width >= 100
        table = Table(
            expand=True,
            show_header=True,
            header_style=f"bold {MUTED}",
            border_style=DIM,
            pad_edge=False,
            box=SIMPLE_HEAD,
            row_styles=["", f"on {BG}"],
        )
        table.add_column("", width=2)
        table.add_column("STAGE", width=20 if wide else 16)
        if wide:
            table.add_column("CLASS", width=9)
        table.add_column("STATE", width=9)
        table.add_column("TIME", width=6, justify="right")
        if wide:
            table.add_column("NOTE", ratio=1)

        rows = max(6, self.console.height - 14)
        total = len(self.stages)
        if total > rows:
            start = max(0, min(self.selected - rows // 2, total - rows))
            window = self.stages[start:start + rows]
        else:
            start = 0
            window = self.stages

        for offset, stage in enumerate(window):
            index = start + offset
            selected = index == self.selected
            cells = [
                Text(">" if selected else " ", style=f"bold {CYAN}"),
                Text(f"{stage.number:02d}  {stage.name}",
                     style=f"bold {CYAN if selected else TEXT}",
                     no_wrap=True, overflow="ellipsis"),
            ]
            if wide:
                cells.append(Text(stage.category, style=MAGENTA, no_wrap=True))
            cells.append(Text(
                f"{self._state_glyph(stage.state)} {self._state_label(stage.state)}",
                style=self._state_color(stage.state),
                no_wrap=True,
            ))
            cells.append(Text(f"{stage.elapsed:.1f}s" if stage.elapsed else "--",
                              style=MUTED, no_wrap=True))
            if wide:
                cells.append(Text(stage.note or stage.description, style=MUTED,
                                  no_wrap=True, overflow="ellipsis"))
            table.add_row(*cells)
        return table

    def _activity(self, limit: int = 7, width: int = 60) -> Text:
        output = Text(no_wrap=True, overflow="ellipsis")
        visible = list(self.logs)[-limit:]
        if not visible:
            output.append("Waiting for the first event.", style=MUTED)
        for entry in visible:
            if entry.divider:
                output.append("── ", style=DIM)
                output.append(entry.message.upper() + " ", style=f"bold {MUTED}")
                output.append("──\n", style=DIM)
                continue
            message = entry.message
            if width and len(message) > width:
                message = message[: max(0, width - 1)] + "…"
            color = LEVEL_COLOR.get(entry.level, MUTED)
            output.append(entry.stamp + "  ", style=DIM)
            output.append(f"{entry.level:<5}  ", style=f"bold {color}")
            output.append(message + "\n", style=TEXT)
        return output

    def _message_width(self, ratio: float = 0.62) -> int:
        main = self.console.width - (29 if self.console.width >= 78 else 0)
        return max(20, int(main * ratio) - 19)

    def _run_card(self) -> Text:
        stage = self.stages[self.selected]
        card = Text()
        card.append("ACTIVE SELECTION\n", style=f"bold {MUTED}")
        card.append(stage.name + "\n", style=f"bold {CYAN}")
        card.append(stage.description + "\n\n", style=TEXT)
        card.append("STAGE    ", style=DIM)
        card.append(f"{stage.number:02d} / {len(self.stages):02d}\n", style=TEXT)
        card.append("CLASS    ", style=DIM)
        card.append(stage.category + "\n", style=MAGENTA)
        card.append("STATE    ", style=DIM)
        card.append(stage.state + "\n", style=self._state_color(stage.state))
        card.append("ELAPSED  ", style=DIM)
        card.append(f"{stage.elapsed:.1f}s\n" if stage.elapsed else "--\n", style=TEXT)
        return card

    

    def _overview(self) -> Group:
        body = self.console.height - 9
        stage_height = self._stage_rows() + 2
        parts = []
        if body >= stage_height + 4:
            parts.append(self._metrics())
        parts.append(self._panel(self._stage_grid(), "STAGE MATRIX", panel_style=CYAN))
        if body >= stage_height + 4 + 12:
            lower = Table.grid(expand=True, padding=(0, 1))
            lower.add_column(ratio=3)
            lower.add_column(ratio=2)
            lower.add_row(
                self._panel(self._activity(8, self._message_width(0.62)),
                            "LIVE ACTIVITY", height=10),
                self._panel(self._run_card(), "RUN PROFILE", MAGENTA, height=10),
            )
            parts.append(lower)
        return Group(*parts)

    def _inspector(self) -> Table:
        stage = self.stages[self.selected]
        grid = Table.grid(expand=True, padding=(0, 2))
        for _ in range(3):
            grid.add_column(ratio=1)

        def cell(label, value, style=TEXT):
            text = Text(no_wrap=True, overflow="ellipsis")
            text.append(f"{label}  ", style=DIM)
            text.append(value, style=style)
            return text

        grid.add_row(
            cell("STAGE", f"{stage.number:02d} / {len(self.stages):02d}", CYAN),
            cell("CLASS", stage.category, MAGENTA),
            cell("STATE", stage.state, self._state_color(stage.state)),
        )
        grid.add_row(
            cell("NAME", stage.name, f"bold {CYAN}"),
            cell("ELAPSED", f"{stage.elapsed:.1f}s" if stage.elapsed else "--"),
            cell("NOTE", stage.note or stage.description, MUTED),
        )
        return grid

    def _stages_view(self) -> Group:
        parts = [self._panel(self._stage_table(), "REGISTERED STAGES")]
        if self.console.height >= 40:
            parts.append(self._panel(self._inspector(), "STAGE INSPECTOR", CYAN))
        return Group(*parts)

    def _activity_view(self) -> Panel:
        limit = max(8, self.console.height - 12)
        return self._panel(
            self._activity(limit, self._message_width(1.0)),
            "SESSION EVENT STREAM",
            MAGENTA,
        )

    def _target_view(self) -> Table:
        spec = Text(no_wrap=True, overflow="ellipsis")
        spec.append("SCAN CONTEXT\n\n", style=f"bold {CYAN}")
        rows = [
            ("TARGET", self.target),
            ("DOMAIN", self.domain),
            ("PROFILE", self.profile.upper()),
            ("RATE", f"{self.rate:g} req/s"),
            ("THREADS", "adaptive" if self.threads is None else str(self.threads)),
            ("SCOPE", str(self.scope)),
            ("EXCLUDE", ", ".join(self.exclude) if self.exclude else "none"),
            ("PREFLIGHT", self.preflight or "not run"),
            ("MODE", str((self.snapshot.get("settings") or {}).get("mode", "--"))),
            ("TRANSPORT", self.transport),
            ("AUTH", str((self.snapshot.get("authentication") or {}).get("summary", "configured" if (self.snapshot.get("authentication") or {}).get("authenticated") else "unauthenticated"))),
        ]
        for label, value in rows:
            spec.append(f"  {label:<10}", style=DIM)
            spec.append(f"{value}\n", style=TEXT)

        engine = Text(no_wrap=True, overflow="ellipsis")
        engine.append("ENGINE LIMITS\n\n", style=f"bold {MAGENTA}")
        limits = [
            ("ROUNDS", self.limits.get("rounds", "--")),
            ("DEPTH", self.limits.get("crawl_depth", "--")),
            ("PAGES", self.limits.get("crawl_pages", "--")),
            ("INJECTION", self.limits.get("injection_budget", "--")),
            ("BRUTEFORCE", self.limits.get("brute_budget", "--")),
            ("REQUESTS", (self.snapshot.get("runtime") or {}).get("requests", 0)),
            ("REQUEST CAP", (self.snapshot.get("runtime") or {}).get("request_budget") or "UNLIMITED"),
            ("CANCELLED", (self.snapshot.get("runtime") or {}).get("cancelled", False)),
            ("EXHAUSTED", (self.snapshot.get("runtime") or {}).get("budget_exhausted", False)),
            ("STAGES", f"{self.done_count}/{len(self.stages)} done"),
            ("STATE", self.state),
            ("UPTIME", self.uptime()),
        ]
        for label, value in limits:
            engine.append(f"  {label:<11}", style=DIM)
            engine.append(f"{value}\n", style=TEXT)

        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(ratio=3)
        grid.add_column(ratio=2)
        height = max(8, self.console.height - 9)
        grid.add_row(
            self._panel(spec, "TARGET MATRIX", height=height),
            self._panel(engine, "ENGINE", MAGENTA, height=height),
        )
        return grid

    def _view(self):
        if self.view_index == 0:
            return self._overview()
        if self.view_index == 1:
            return self._stages_view()
        if self.view_index == 2:
            return self._activity_view()
        if self.view_index == 3:
            return self._target_view()
        return (self._findings_view, self._evidence_view, self._coverage_view,
                self._plugins_view, self._reports_view)[self.view_index - 4]()

    def _window(self, rows, height=None):
        height = height or max(3, self.console.height - 20)
        selected = min(self.row_selected[self.view_index], max(0, len(rows) - 1))
        self.row_selected[self.view_index] = selected
        start = max(0, min(selected - height // 2, len(rows) - height))
        return rows[start:start + height], selected

    def _data_table(self, columns, rows):
        table = Table(expand=True, box=SIMPLE_HEAD, border_style=DIM,
                      header_style=f"bold {CYAN}", show_lines=False)
        for column in columns:
            table.add_column(column, overflow="ellipsis", no_wrap=True)
        for row in rows:
            table.add_row(*(Text(str(cell), style=TEXT, no_wrap=True, overflow="ellipsis")
                            for cell in row))
        if not rows:
            table.add_row("No records available", *("" for _ in columns[1:]))
        return table

    def _findings_view(self):
        findings = self.snapshot.get("findings") or []
        window, selected = self._window(findings, max(3, self.console.height - 33))
        rows = [(item.get("id", "--"), item.get("severity", "--"),
                 item.get("verification", "--"), item.get("status", "--"),
                 item.get("title", item.get("kind", "--"))) for item in window]
        detail = Text("Select a finding with UP/DN.", style=MUTED)
        if findings:
            item = findings[selected]
            detail = Text(style=TEXT, overflow="ellipsis")
            for label, value in (("ENDPOINT", item.get("target")), ("METHOD", item.get("method")),
                                 ("CVSS / CWE", f"{item.get('cvss_score', '--')} / {item.get('cwe', '--')}"),
                                 ("SHA-256", item.get("fingerprint")),
                                 ("EVIDENCE", item.get("evidence")),
                                 ("REPRODUCTION", item.get("reproduction", "--")),
                                 ("RETEST", item.get("reproducibility", "--")),
                                 ("HISTORY", item.get("status_history", "--")),
                                 ("REMEDIATION", item.get("remediation", "--"))):
                detail.append(f"{label}: ", style=CYAN)
                detail.append(str(value or "--")[:600] + "\n")
        return Group(self._panel(self._data_table(("ID", "SEVERITY", "VERIFICATION", "LIFECYCLE", "FINDING"), rows),
                                 f"FINDINGS / {len(findings)}"),
                     self._panel(detail, "FINDING DETAILS", MAGENTA))

    def _evidence_rows(self):
        return [(item.get("id", "--"), ref.get("sha256", "--"), ref.get("size", "--"),
                 "yes" if ref.get("redacted") else "unknown",
                 ref.get("integrity", "not checked"))
                for item in self.snapshot.get("findings") or []
                for ref in item.get("evidence_refs") or []]

    def _evidence_view(self):
        references = self._evidence_rows()
        window, selected = self._window(references)
        summary = (self.snapshot.get("lifecycle") or {}).get("summary") or {}
        counts = summary.get("by_status") or {}
        lifecycle = " | ".join(f"{key}: {value}" for key, value in counts.items() if value) or "No lifecycle records"
        note = self.snapshot.get("persistence_error") or ("Central evidence requires scan storage." if not self.snapshot.get("scan_id") else f"Scan: {self.snapshot['scan_id']}")
        return Group(self._panel(Text(lifecycle + "\n" + note, style=TEXT), "LIFECYCLE & STORAGE"),
                     self._panel(self._data_table(("FINDING", "SHA-256", "BYTES", "REDACTED", "INTEGRITY"),
                                                [(row[0], str(row[1])[:12], *row[2:]) for row in window]),
                                 f"EVIDENCE REFERENCES / {len(references)}"),
                     self._panel(Text(("SHA-256: " + str(references[selected][1]) + "\n" if references else "") +
                                      "Integrity is verified when evidence is read. Hash references alone do not certify stored content.", style=MUTED), "EVIDENCE STATUS"))

    def _coverage_view(self):
        health = self.snapshot.get("module_health") or {}
        notes = self.snapshot.get("module_notes") or {}
        times = self.snapshot.get("module_timings") or {}
        rows = [(key, state, f"{times[key]:.1f}s" if key in times else "--", notes.get(key, ""))
                for key, state in health.items()]
        window, _ = self._window(rows)
        coverage = self.snapshot.get("coverage_summary") or {}
        context = "\n".join(f"{key}: {value}" for key, value in coverage.items()) or "Coverage is populated as modules finish."
        return Group(self._panel(Text(context, style=TEXT), "API / SPA / AUTH / ADDITIONAL CHECKS"),
                     self._panel(self._data_table(("MODULE", "STATE", "TIME", "DETAIL"), window),
                                 f"ACTUAL MODULE HEALTH / {len(rows)}"))

    def _plugins_view(self):
        plugins = self.snapshot.get("plugins") or {}
        outcomes = plugins.get("plugins") or {}
        rows = [(key, item.get("state", "--"), len(item.get("findings") or []),
                 item.get("reason", item.get("error", ""))) for key, item in outcomes.items()]
        window, selected = self._window(rows)
        detail = "No plugins enabled. Discover trusted extensions with --list-plugins."
        if rows:
            item = outcomes[rows[selected][0]]
            detail = "\n".join(str(value) for value in item.get("logs") or []) or "No plugin log entries."
        errors = plugins.get("errors") or []
        if errors:
            detail += "\nDiscovery: " + str(errors)
        return Group(self._panel(self._data_table(("PLUGIN", "STATE", "FINDINGS", "DETAIL"), window), "PLUGIN EXECUTION"),
                     self._panel(Text(detail[:3000], style=TEXT), "PLUGIN LOGS", MAGENTA))

    def _reports_view(self):
        reports = self.snapshot.get("reports") or {}
        rows = list(reports.items())
        window, selected = self._window(rows)
        detail = (str(rows[selected][1]) if rows else "Reports become available after generation.")
        return Group(self._panel(self._data_table(("OUTPUT", "PATH"), window), "GENERATED REPORTS"),
                     self._panel(Text(detail, style=TEXT), "SELECTED PATH", MAGENTA),
                     self._panel(Text("Executive and technical reports share canonical findings, verification, lifecycle, evidence and incomplete checks.", style=MUTED), "REPORT CONTENT"))

    

    def render(self) -> Layout:
        with self._lock:
            if self.runtime_provider is not None:
                self.snapshot["runtime"] = self.runtime_provider()
            return GradientScreen(self._render())

    def _render(self) -> Layout:
        root = Layout()
        root.split_column(
            Layout(self._header(), size=6),
            Layout(name="body", ratio=1),
            Layout(self._footer(), size=3),
        )
        body = ContentSurface(self._view())
        if self.console.width >= 78:
            root["body"].split_row(
                Layout(self._sidebar(), size=29),
                Layout(body, ratio=1),
            )
        else:
            root["body"].update(body)
        return root

    

    def _handle_key(self, key: str):
        if key in ("q", "esc", "\x03"):
            self.running = False
            self.detached = True
            self.dismissed = True
        elif key in tuple(str(index) for index in range(1, 10)):
            self.view_index = int(key) - 1
        elif key == "up":
            if self.view_index >= 4:
                self.row_selected[self.view_index] = max(0, self.row_selected[self.view_index] - 1)
            else:
                self.selected = (self.selected - 1) % len(self.stages)
        elif key == "down":
            if self.view_index >= 4:
                self.row_selected[self.view_index] += 1
            else:
                self.selected = (self.selected + 1) % len(self.stages)
        elif key == "c":
            self.logs.clear()
            self.log("SYS", "Event stream cleared")
        self._dirty = True

    def run(self, review=False):
        """Render until the worker finishes, or until the operator presses Q."""
        banner_module.set_sink(self)
        self.running = True
        self.detached = False
        self._done_seen_at = None
        if not review:
            self.state = "RUNNING"
            self.status_message = "SCAN IN PROGRESS"
        else:
            if self.snapshot.get("interrupted"):
                reason = ("REQUEST LIMIT REACHED" if (self.snapshot.get("runtime") or {}).get("budget_exhausted")
                          else "RUN INTERRUPTED")
                self.status_message = reason + " / Q TO CLOSE"
            else:
                self.status_message = "REVIEW RESULTS / Q TO CLOSE"
        try:
            with KeyReader() as keys:
                with Live(
                    self.render(),
                    console=self.console,
                    screen=True,
                    auto_refresh=False,
                    redirect_stdout=True,
                    redirect_stderr=True,
                ) as live:
                    live.update(self.render(), refresh=True)
                    while self.running:
                        key = keys.read()
                        if key:
                            self._handle_key(key)
                        now = time.time()
                        if self._dirty or (now - self._last_render) >= 1.0:
                            live.update(self.render(), refresh=True)
                            self._dirty = False
                            self._last_render = now
                        if self.finished and not review:
                            if self._done_seen_at is None:
                                self._done_seen_at = time.time()
                            elif time.time() - self._done_seen_at >= 1.2:
                                break
                        time.sleep(0.05)
        except KeyboardInterrupt:
            self.interrupted = True
        finally:
            self.running = False
            self.detached = True
            banner_module.clear_sink()







class UIConsole:
    """Console-shaped object that feeds the dashboard instead of scrolling."""

    def __init__(self, dashboard: Dashboard, real: Console):
        self.dashboard = dashboard
        self.real = real
        self._buffer = StringIO()
        self._capture = Console(
            file=self._buffer,
            theme=THEME,
            color_system=None,
            width=80,
            highlight=False,
            emoji=False,
            legacy_windows=False,
        )

    @property
    def width(self) -> int:
        return self.real.width

    @property
    def height(self) -> int:
        return self.real.height

    def print(self, *args, **kwargs):
        if self.dashboard.detached:
            self.real.print(*args, **kwargs)
            return
        self._buffer = StringIO()
        self._capture.file = self._buffer
        self._capture.width = max(60, self.real.width - 4)
        try:
            self._capture.print(*args, **kwargs)
        except Exception:
            self._buffer.write(" ".join(str(a) for a in args))
        self.dashboard.ingest(self._buffer.getvalue())

    def clear(self):
        pass

    def rule(self, *args, **kwargs):
        title = args[0] if args else kwargs.get("title", "")
        if title:
            self.dashboard.divider(strip_markup(title))


def _ingest(dashboard: Dashboard, text: str):
    for raw in text.splitlines():
        line = raw.strip().strip("│║|").strip()
        if not line:
            continue
        if set(line) <= BORDER_CHARS:
            continue
        level = "SYS"
        message = line
        for glyph, candidate in GLYPH_LEVEL:
            if line.startswith(glyph):
                level = candidate
                message = line[len(glyph):].strip()
                break
        dashboard.log(level, message)
