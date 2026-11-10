"""Shared visual system for the Krypto interface.

The palette and the Rich theme are kept in one place so the classic
line-mode renderer and the full-screen dashboard cannot drift apart.
"""

import re

from rich.theme import Theme





BG = "#000000"
PANEL = BG
RAISED = "#160912"

CYAN = "#FF62B4"
TEAL = "#FF8065"
ELECTRIC = "#E94C9B"
GREEN = "#92E6A7"
MAGENTA = "#FF3F9E"
AMBER = "#FFAD61"
TEXT = "#F4EAF0"
MUTED = "#C4A7B6"
DIM = "#8D657B"
LIGHT_BLUE = "#FF91B8"
RED = "#FF5D70"
GRADIENT_TOP = (255, 48, 166)
GRADIENT_BOTTOM = (255, 111, 54)


def gradient_color(position: float) -> str:
    ratio = max(0.0, min(1.0, position))
    channels = (round(top + (bottom - top) * ratio)
                for top, bottom in zip(GRADIENT_TOP, GRADIENT_BOTTOM))
    return "#" + "".join(f"{channel:02X}" for channel in channels)


def gradient_text(value: str):
    from rich.text import Text
    text = Text(no_wrap=True)
    for index, char in enumerate(value):
        text.append(char, style=f"bold {gradient_color(index / max(1, len(value) - 1))}")
    return text


class GradientScreen:
    """Apply the shared vertical gradient while preserving selection contrast."""
    def __init__(self, renderable):
        self.renderable = renderable

    def __rich_console__(self, console, options):
        from rich.segment import Segment
        from rich.style import Style
        lines = console.render_lines(self.renderable, options, pad=False)
        for index, line in enumerate(lines):
            foreground = Style(color=gradient_color(index / max(1, len(lines) - 1)), bgcolor=BG, reverse=False)
            for segment in line:
                style = segment.style or Style()
                yield segment if segment.control else Segment(segment.text, style + foreground)
            yield Segment.line()

THEME = Theme(
    {
        "kw.bg": f"on {BG}",
        "kw.panel": f"on {PANEL}",
        "kw.raised": f"on {RAISED}",
        "kw.cyan": CYAN,
        "kw.teal": TEAL,
        "kw.electric": ELECTRIC,
        "kw.green": GREEN,
        "kw.magenta": MAGENTA,
        "kw.amber": AMBER,
        "kw.text": TEXT,
        "kw.muted": MUTED,
        "kw.dim": DIM,
        "kw.red": RED,
    }
)

from core import __version__ as VERSION
from core.stages import STAGES_TOTAL


def rgb(color: str):
    """Return an (r, g, b) tuple for a ``#RRGGBB`` string."""
    value = color.lstrip("#")
    return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))


def background_escape(color: str = BG) -> str:
    """OSC 11 sequence that repaints the terminal background (no black)."""
    r, g, b = rgb(color)
    return f"\x1b]11;rgb:{r:02x}/{g:02x}/{b:02x}\x07"




_TAG = re.compile(r"\[(/?)([A-Za-z][A-Za-z0-9_.:# ]*)\]")


def strip_markup(value) -> str:
    """Return *value* as plain text with Rich markup tags removed."""
    return _TAG.sub("", str(value))
