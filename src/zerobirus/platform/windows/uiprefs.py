"""Windows preferences the interface respects, and the elevated relaunch."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_SPI_GETHIGHCONTRAST = 0x0042
_SPI_GETCLIENTAREAANIMATION = 0x1042
_HCF_HIGHCONTRASTON = 0x1
_SW_SHOWNORMAL = 1

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_user32.SystemParametersInfoW.argtypes = [
    wintypes.UINT,
    wintypes.UINT,
    ctypes.c_void_p,
    wintypes.UINT,
]
_user32.SystemParametersInfoW.restype = wintypes.BOOL
_shell32.ShellExecuteW.argtypes = [
    wintypes.HWND,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.c_int,
]
_shell32.ShellExecuteW.restype = wintypes.HINSTANCE


class _HighContrast(ctypes.Structure):
    _fields_ = (
        ("cbSize", wintypes.UINT),
        ("dwFlags", wintypes.DWORD),
        ("lpszDefaultScheme", wintypes.LPWSTR),
    )


def high_contrast_active() -> bool:
    hc = _HighContrast()
    hc.cbSize = ctypes.sizeof(_HighContrast)
    if not _user32.SystemParametersInfoW(_SPI_GETHIGHCONTRAST, hc.cbSize, ctypes.byref(hc), 0):
        return False
    return bool(hc.dwFlags & _HCF_HIGHCONTRASTON)


def animations_enabled() -> bool:
    flag = wintypes.BOOL(1)
    if not _user32.SystemParametersInfoW(_SPI_GETCLIENTAREAANIMATION, 0, ctypes.byref(flag), 0):
        return True
    return bool(flag.value)


def relaunch_elevated() -> bool:
    """Start this program again with the UAC prompt ("runas"). Returns True if Windows took it.

    The program path and arguments are our own (``sys.executable`` and ``sys.argv``), passed as
    separate strings to ShellExecuteW, never through a shell command line we build from data.
    """
    if getattr(sys, "frozen", False):
        target, args = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        target, args = (
            sys.executable,
            " ".join(f'"{a}"' for a in ["-m", "zerobirus", *sys.argv[1:]]),
        )
    result = _shell32.ShellExecuteW(None, "runas", target, args, None, _SW_SHOWNORMAL)
    return int(ctypes.cast(result, ctypes.c_void_p).value or 0) > 32
