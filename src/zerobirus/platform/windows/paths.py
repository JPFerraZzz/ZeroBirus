"""Canonical paths from the Win32 API. Read-only: files are opened for attributes only.

``core/safety`` compares strings, so the backend must hand it the path the OS itself
resolves (links, junctions, 8.3 names, case), never the raw text from a process or the
registry. Everything returned here is data and is never executed.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_FILE_SHARE_ALL = 0x1 | 0x2 | 0x4  # read, write, delete: never block other processes
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # needed to open directories
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_MAX_PATH_CHARS = 32768

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.GetFinalPathNameByHandleW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
]
_kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
_kernel32.GetShortPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
_kernel32.GetShortPathNameW.restype = wintypes.DWORD
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL


def _strip_extended_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def canonical_path(path: str) -> str:
    """Final path of ``path`` as resolved by Windows, without the ``\\\\?\\`` prefix.

    Raises ``OSError`` if the path cannot be opened. Opens with no access rights (attributes
    only) and never creates or writes anything.
    """
    handle = _kernel32.CreateFileW(
        path, 0, _FILE_SHARE_ALL, None, _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS, None
    )
    if handle is None or handle == _INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buf = ctypes.create_unicode_buffer(_MAX_PATH_CHARS)
        n = _kernel32.GetFinalPathNameByHandleW(handle, buf, _MAX_PATH_CHARS, 0)
        if n == 0 or n >= _MAX_PATH_CHARS:
            raise ctypes.WinError(ctypes.get_last_error())
        return _strip_extended_prefix(buf.value)
    finally:
        _kernel32.CloseHandle(handle)


def short_path(path: str) -> str:
    """The 8.3 form of an existing path (for diagnostics and tests). Raises ``OSError``."""
    buf = ctypes.create_unicode_buffer(_MAX_PATH_CHARS)
    n = _kernel32.GetShortPathNameW(path, buf, _MAX_PATH_CHARS)
    if n == 0 or n >= _MAX_PATH_CHARS:
        raise ctypes.WinError(ctypes.get_last_error())
    return buf.value
