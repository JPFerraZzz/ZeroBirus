"""Known folders through SHGetKnownFolderPath (OneDrive redirection, localised names)."""

from __future__ import annotations

import ctypes
import sys
import uuid
from ctypes import wintypes

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

DOCUMENTS = "FDD39AD0-238F-46AF-ADB4-6C85480369C7"
DESKTOP = "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"
PICTURES = "33E28130-4E1E-4676-835A-98395C3BC3BB"
VIDEOS = "18989B1D-99B5-455B-841C-AB7C74E4DDFC"
MUSIC = "4BD8D571-6D19-48D3-BE97-422220080E43"
PROFILE = "5E6C858F-0E22-4760-9AFE-EA3317B67173"
PROGRAM_FILES = "905E63B6-C1BF-494E-B29C-65B732D3D21A"
PROGRAM_FILES_X86 = "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E"
PROGRAM_DATA = "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97"
COMMON_STARTUP = "82A5EA35-D9CD-47C5-9629-E15D2F714E6E"


class _GUID(ctypes.Structure):
    _fields_ = (
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    )


def _guid(text: str) -> _GUID:
    u = uuid.UUID(text)
    g = _GUID()
    g.Data1, g.Data2, g.Data3 = u.time_low, u.time_mid, u.time_hi_version
    for i, byte in enumerate(u.bytes[8:]):
        g.Data4[i] = byte
    return g


_shell32 = ctypes.WinDLL("shell32")
_ole32 = ctypes.WinDLL("ole32")
_shell32.SHGetKnownFolderPath.argtypes = [
    ctypes.POINTER(_GUID),
    wintypes.DWORD,
    wintypes.HANDLE,
    ctypes.POINTER(ctypes.c_void_p),
]
_shell32.SHGetKnownFolderPath.restype = ctypes.c_long
_ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
_ole32.CoTaskMemFree.restype = None


def known_folder(folder_id: str) -> str:
    """Path of a known folder of the current user. Raises ``OSError`` on failure."""
    guid = _guid(folder_id)
    ptr = ctypes.c_void_p()
    hr = _shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(ptr))
    try:
        if hr != 0 or not ptr.value:
            raise OSError(f"SHGetKnownFolderPath failed ({hr & 0xFFFFFFFF:#x})")
        return ctypes.wstring_at(ptr.value)
    finally:
        if ptr.value:
            _ole32.CoTaskMemFree(ptr)
