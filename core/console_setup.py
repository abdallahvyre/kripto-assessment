"""Prepare native Windows output before Rich detects terminal capabilities."""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from contextlib import contextmanager


class _Coord(ctypes.Structure):
    _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]


class _ConsoleFontInfo(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.ULONG), ("nFont", wintypes.DWORD),
                ("dwFontSize", _Coord), ("FontFamily", wintypes.UINT),
                ("FontWeight", wintypes.UINT), ("FaceName", wintypes.WCHAR * 32)]


def _kernel32():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    prototypes = {
        "GetStdHandle": ([wintypes.DWORD], wintypes.HANDLE),
        "GetConsoleMode": ([wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        "SetConsoleMode": ([wintypes.HANDLE, wintypes.DWORD], wintypes.BOOL),
        "SetConsoleCP": ([wintypes.UINT], wintypes.BOOL),
        "SetConsoleOutputCP": ([wintypes.UINT], wintypes.BOOL),
        "SetConsoleTextAttribute": ([wintypes.HANDLE, wintypes.WORD], wintypes.BOOL),
        "GetCurrentConsoleFontEx": ([wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(_ConsoleFontInfo)], wintypes.BOOL),
        "SetCurrentConsoleFontEx": ([wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(_ConsoleFontInfo)], wintypes.BOOL),
    }
    for name, (arguments, result) in prototypes.items():
        function = getattr(api, name)
        function.argtypes, function.restype = arguments, result
    return api


def configure_windows_console() -> bool:
    """Enable ANSI/UTF-8 for this console only; redirected output stays plain.

    Rich must be constructed after this function. Setting COLORTERM alone does
    not enable Windows VT output, and late initialization leaves Rich in its
    16-color legacy rendering path.
    """
    if sys.platform != "win32" or not sys.stdout.isatty():
        return False
    try:
        api = _kernel32()
        api.SetConsoleCP(65001)
        api.SetConsoleOutputCP(65001)
        enabled = False
        output = api.GetStdHandle(-11)
        for stream_id in (-11, -12):
            handle = api.GetStdHandle(stream_id)
            mode = wintypes.DWORD()
            if api.GetConsoleMode(handle, ctypes.byref(mode)):
                success = bool(api.SetConsoleMode(handle, mode.value | 0x0005))
                if stream_id == -11:
                    enabled = success
        api.SetConsoleTextAttribute(output, 0x0F)
        if os.environ.get("KRIPTO_LAUNCHER") == "1" and not os.environ.get("WT_SESSION"):
            font = _ConsoleFontInfo()
            font.cbSize = ctypes.sizeof(font)
            if api.GetCurrentConsoleFontEx(output, False, ctypes.byref(font)):
                font.FaceName = "Consolas"
                font.dwFontSize = _Coord(0, 16)
                font.FontFamily, font.FontWeight = 54, 400
                api.SetCurrentConsoleFontEx(output, False, ctypes.byref(font))
        return enabled
    except (OSError, AttributeError):
        return False


@contextmanager
def mouse_input_mode():
    """Prevent Console Host's Quick Edit from stealing the setup's clicks."""
    restore = None
    if sys.platform == "win32" and sys.stdin.isatty():
        try:
            api = _kernel32()
            handle = api.GetStdHandle(-10)
            mode = wintypes.DWORD()
            if api.GetConsoleMode(handle, ctypes.byref(mode)):
                if api.SetConsoleMode(handle, (mode.value | 0x0090) & ~0x0040):
                    restore = (api, handle, mode.value)
        except (OSError, AttributeError):
            pass
    try:
        yield
    finally:
        if restore:
            api, handle, original = restore
            api.SetConsoleMode(handle, original)
