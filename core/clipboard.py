"""Bounded Unicode clipboard access for the user's explicit paste action."""
import ctypes
import sys
import time
from ctypes import wintypes


def _clipboard_api():
    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    user.OpenClipboard.argtypes, user.OpenClipboard.restype = [wintypes.HWND], wintypes.BOOL
    user.CloseClipboard.argtypes, user.CloseClipboard.restype = [], wintypes.BOOL
    user.GetClipboardData.argtypes, user.GetClipboardData.restype = [wintypes.UINT], wintypes.HANDLE
    kernel.GlobalLock.argtypes, kernel.GlobalLock.restype = [wintypes.HANDLE], ctypes.c_void_p
    kernel.GlobalUnlock.argtypes, kernel.GlobalUnlock.restype = [wintypes.HANDLE], wintypes.BOOL
    kernel.GlobalSize.argtypes, kernel.GlobalSize.restype = [wintypes.HANDLE], ctypes.c_size_t
    return user, kernel


def read_clipboard_text() -> str:
    if sys.platform != "win32":
        return ""
    try:
        user, kernel = _clipboard_api()
        for attempt in range(3):
            if user.OpenClipboard(None):
                break
            if attempt == 2:
                return ""
            time.sleep(0.01)
        try:
            handle = user.GetClipboardData(13)  
            if not handle:
                return ""
            size = kernel.GlobalSize(handle)
            pointer = kernel.GlobalLock(handle)
            if not pointer:
                return ""
            try:
                count = min(size // ctypes.sizeof(ctypes.c_wchar), 8193)
                return ctypes.wstring_at(pointer, count).split("\0", 1)[0]
            finally:
                kernel.GlobalUnlock(handle)
        finally:
            user.CloseClipboard()
    except (OSError, AttributeError, ValueError):
        return ""
