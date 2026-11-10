"""Static fsociety startup artwork and an animated Krypto loading indicator.

The splash lives in the alternate screen buffer, so it disappears cleanly when
the picker or dashboard takes over. It never runs on a non-TTY, and it cannot be
skipped with a key press: only Ctrl+C aborts it.
"""

from __future__ import annotations

import math
import os
import sys
import time
from pathlib import Path

from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

from core.theme import BG, VERSION, gradient_color, gradient_text

_ART_PATH = Path(__file__).resolve().parent / "fsociety.ascii"
_DEFAULT_HOLD = 4.0
_BLANK = "\u2800"



def _blank(line: str) -> bool:
    return not line.replace(_BLANK, " ").strip()


def _trim(lines):
    """Drop visually blank edges and the common indent, then crop the sides."""
    lines = [line.rstrip() for line in lines]
    while lines and _blank(lines[-1]):
        lines.pop()
    while lines and _blank(lines[0]):
        lines.pop(0)
    if not lines:
        return []

    cols = max(len(line) for line in lines)
    padded = [line.ljust(cols) for line in lines]
    indents = [len(line) - len(line.lstrip(" " + _BLANK))
               for line in padded if not _blank(line)]
    left = min(indents) if indents else 0
    right = max(len(line.rstrip(" " + _BLANK)) for line in padded if not _blank(line))
    return [line[left:right].rstrip() for line in padded]


def _is_braille(line: str) -> bool:
    return any(0x2800 <= ord(char) <= 0x28FF for char in line)


def _is_border(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and set(stripped) <= {"X"}


def _halfblocks(rows):
    out = []
    for i in range(0, len(rows) - 1, 2):
        top, bottom = rows[i], rows[i + 1]
        out.append("".join(
            "█" if t and b else "▀" if t else "▄" if b else " "
            for t, b in zip(top, bottom)
        ).rstrip())
    return out


def _load():
    try:
        raw = _ART_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], "none"

    lines = raw.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].lstrip().startswith("$"):
        lines.pop(0)

    if any(_is_braille(line) for line in lines):
        return _trim(lines), [], "braille"

    borders = [i for i, line in enumerate(lines) if _is_border(line)]
    if borders:
        mask = [line.rstrip() for line in lines[borders[0]:borders[-1] + 1]]
        word = _trim(lines[borders[-1] + 1:])
        return mask, word, "frame"

    return _trim(lines), [], "plain"


PRIMARY, WORD, KIND = _load()

_SIL = []
_SIL_SM = []
if KIND == "frame" and PRIMARY:
    interior = [line for line in PRIMARY if not _is_border(line)]
    body = [line for line in interior if line.strip(" X")]
    if body:
        left = min(len(line) - len(line.lstrip(" X")) for line in body)
        right = max(len(line.rstrip(" X")) for line in body)
        core = [line[left:right].rstrip() for line in interior]
        cols = max((len(line) for line in core), default=0)
        grid = [[char != " " for char in line.ljust(cols)] for line in core]
        _SIL = _halfblocks(grid)
        width = max((len(line) for line in _SIL), default=0)
        padded = [line.ljust(width) for line in _SIL]
        _SIL_SM = []
        for i in range(0, len(padded) - 1, 2):
            top, bottom = padded[i], padded[i + 1]
            _SIL_SM.append("".join(
                "█" if a.strip() or b.strip() else " "
                for a, b in zip(top, bottom)
            ).rstrip())


def _style(line: str, index: int, total: int) -> Text:
    text = Text(line, no_wrap=True, overflow="crop")
    ratio = index / max(1, total - 1)
    text.stylize(f"bold {gradient_color(ratio)}")
    return text


def _block(lines):
    total = len(lines)
    return Text("\n").join(_style(line, i, total) for i, line in enumerate(lines))


def _fit(lines, avail_h: int, avail_w: int):
    """Proportionally downsample *lines* so they fit, never stretching them."""
    if not lines or avail_h < 4 or avail_w < 8:
        return []
    rows = len(lines)
    cols = max(len(line) for line in lines)
    if rows <= avail_h and cols <= avail_w:
        return lines
    factor = max(rows / avail_h, cols / avail_w)
    out_rows = max(1, int(rows / factor))
    out_cols = max(1, int(cols / factor))
    row_idx = [min(rows - 1, int(i * rows / out_rows)) for i in range(out_rows)]
    col_idx = [min(cols - 1, int(j * cols / out_cols)) for j in range(out_cols)]
    padded = {i: lines[i].ljust(cols) for i in row_idx}
    return ["".join(padded[r][c] for c in col_idx).rstrip() for r in row_idx]


def _pick_art(width: int, height: int):
    """Return (art_lines, word_lines) for the current window."""
    if width < 24 or height < 10:
        return [], []

    avail_w = width - 4
    budget = height - 7
    if budget < 4:
        return [], []

    word = list(WORD)
    with_word = budget - (len(word) + 1) if word else -1

    if KIND == "frame":
        for mask in (PRIMARY, _SIL, _SIL_SM):
            if not mask or max(len(line) for line in mask) > avail_w:
                continue
            if word and len(mask) <= with_word:
                return mask, word
            if len(mask) <= budget:
                return mask, []
        return _fit(PRIMARY, budget, avail_w), []

    if word and with_word >= 4:
        art = _fit(PRIMARY, with_word, avail_w)
        if art:
            return art, word
    return _fit(PRIMARY, budget, avail_w), []


def _frame(console: Console, elapsed: float, hold: float):
    progress = min(1.0, elapsed / hold) if hold else 1.0
    cells = max(4, min(36, console.width - 12))
    filled = min(cells, int(cells * progress))
    bar = "█" * filled + "░" * (cells - filled)
    spinner = ("◐", "◓", "◑", "◒")[int(elapsed * 8) % 4]

    details = Text(justify="center", no_wrap=True, overflow="crop")
    details.append_text(gradient_text(f"{spinner}  Krypto Loading !"))
    details.append("\n")
    details.append_text(gradient_text(bar + f"  {int(progress * 100):>3d}%"))
    details.append("\n")
    details.append_text(gradient_text("SYSTEM READY" if progress >= 1.0 else "STARTING"))

    if console.height < 10 or console.width < 24:
        return Align.center(details, vertical="middle", style=f"on {BG}")

    title = gradient_text(f"K R Y P T O  //  {VERSION}")
    title.justify = "center"
    art, word = _pick_art(console.width, console.height - 1)
    mask = _block(art + ([""] + word if word else [])) if art else title.copy()
    layout = Layout()
    layout.split_column(Layout(name="brand", size=3), Layout(name="mask"),
                        Layout(name="loading", size=4))
    layout["brand"].update(Align.center(title, vertical="middle", style=f"on {BG}"))
    layout["mask"].update(Align.center(mask, vertical="middle", style=f"on {BG}"))
    layout["loading"].update(Align.center(details, vertical="middle", style=f"on {BG}"))
    return layout


def show_splash(console: Console, hold: float | None = None) -> None:
    """Draw the splash for *hold* seconds, then restore the previous screen."""
    if not sys.stdout.isatty() or not console.is_terminal:
        return
    if hold is None:
        try:
            hold = float(os.environ.get("KRIPTO_SPLASH_HOLD", _DEFAULT_HOLD))
        except ValueError:
            hold = _DEFAULT_HOLD

    if not math.isfinite(hold) or hold <= 0:
        return

    started = time.monotonic()
    with Live(_frame(console, 0.0, hold), console=console, screen=True,
              auto_refresh=False, redirect_stdout=False,
              redirect_stderr=False) as live:
        while True:
            elapsed = min(hold, time.monotonic() - started)
            live.update(_frame(console, elapsed, hold), refresh=True)
            if elapsed >= hold:
                break
            time.sleep(min(0.05, hold - elapsed))
