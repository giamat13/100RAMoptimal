"""Shared low-level Windows API bindings and helpers used by lockdown.py and quickclean.py."""

import ctypes
import datetime
import msvcrt
import os
import sys
from ctypes import wintypes

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'focusmax_log.txt')


def log(message):
    """Appends a timestamped line to focusmax_log.txt - a durable record of what actually
    happened, so a window that closed too fast to read can still be diagnosed afterward."""
    try:
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.datetime.now().isoformat(timespec='seconds')} pid={os.getpid()} {message}\n")
    except OSError:
        pass

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
shell32 = ctypes.WinDLL('shell32', use_last_error=True)

TH32CS_SNAPPROCESS = 0x2
PROCESS_TERMINATE = 0x0001
PROCESS_SET_INFORMATION = 0x0200
PROCESS_SET_QUOTA = 0x0100
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
HIGH_PRIORITY_CLASS = 0x80
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x2


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', ctypes.c_char * 260),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ('dwLength', wintypes.DWORD),
        ('dwMemoryLoad', wintypes.DWORD),
        ('ullTotalPhys', ctypes.c_uint64),
        ('ullAvailPhys', ctypes.c_uint64),
        ('ullTotalPageFile', ctypes.c_uint64),
        ('ullAvailPageFile', ctypes.c_uint64),
        ('ullTotalVirtual', ctypes.c_uint64),
        ('ullAvailVirtual', ctypes.c_uint64),
        ('ullAvailExtendedVirtual', ctypes.c_uint64),
    ]


class LUID(ctypes.Structure):
    _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Luid', LUID), ('Attributes', wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [('PrivilegeCount', wintypes.DWORD), ('Privileges', LUID_AND_ATTRIBUTES * 1)]


kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.Process32First.restype = wintypes.BOOL
kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype = wintypes.BOOL
kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.SetPriorityClass.restype = wintypes.BOOL
kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
kernel32.SetSystemFileCacheSize.restype = wintypes.BOOL
kernel32.SetSystemFileCacheSize.argtypes = [ctypes.c_size_t, ctypes.c_size_t, wintypes.DWORD]

psapi.EmptyWorkingSet.restype = wintypes.BOOL
psapi.EmptyWorkingSet.argtypes = [wintypes.HANDLE]

ntdll.NtSetSystemInformation.restype = ctypes.c_long
ntdll.NtSetSystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong]

advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]

shell32.IsUserAnAdmin.restype = wintypes.BOOL
shell32.ShellExecuteW.restype = ctypes.c_void_p
shell32.ShellExecuteW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]

# Any process whose image is under these folders is protected (Windows core).
PROTECTED_ROOTS = [os.environ['SystemRoot']]

# Safety net: names never killed, even outside C:\Windows.
PROTECTED_NAMES = [
    'System', 'Idle', 'Registry', 'MemCompression',
    'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe',
    'smss.exe', 'svchost.exe', 'fontdrvhost.exe', 'dwm.exe', 'explorer.exe',
    'python.exe', 'pythonw.exe', 'powershell.exe', 'pwsh.exe', 'WindowsTerminal.exe', 'conhost.exe', 'cmd.exe',
    'SearchIndexer.exe', 'ctfmon.exe', 'sihost.exe', 'taskhostw.exe',
]


def pause(message):
    """Blocks for a real keypress read straight from the console (msvcrt.getch) -
    verified to actually block where both input() and a nested `cmd /c pause` did not,
    across debuggers/relaunched consoles with odd stdin wiring."""
    print(message)
    log(f'pause() entered: "{message}"')
    try:
        msvcrt.getch()
        log('pause() got a keypress, returning normally')
    except OSError as e:
        log(f'pause() msvcrt.getch() raised OSError: {e!r} - could not block, window may close now')


def enum_processes():
    """Yields (pid, parent_pid, exe_name) for every running process."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value:
        return
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if not kernel32.Process32First(snap, ctypes.byref(entry)):
            return
        while True:
            yield entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile.decode('mbcs', 'ignore')
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)


def get_process_path(pid):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        kernel32.CloseHandle(h)


def enable_privilege(name):
    """Enables a privilege (like SeProfileSingleProcessPrivilege) on our own process token -
    admin rights alone don't grant these, they still need to be switched on explicitly."""
    h_token = wintypes.HANDLE()
    advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ctypes.byref(h_token))
    try:
        luid = LUID()
        advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid))
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None)
    finally:
        kernel32.CloseHandle(h_token)


def free_and_total_mb():
    m = MEMORYSTATUSEX()
    m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
    return m.ullAvailPhys // (1024 * 1024), m.ullTotalPhys // (1024 * 1024)


def is_admin():
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin(script_path, extra_args):
    # Elevate cmd.exe /k itself (not python.exe directly) - /k keeps the console open
    # after the command finishes no matter what, so a crash can't silently vanish the window.
    inner = ' '.join(f'"{a}"' for a in [sys.executable, script_path] + extra_args)
    # cmd's /k quote parsing: with more than one quoted token it strips only the very
    # first and last quote of the whole line, corrupting it. Wrapping the whole thing
    # in one more pair of quotes gives cmd that outer pair to strip instead, leaving
    # `inner` intact. (Classic cmd.exe /C-/K quoting bug - see `cmd /?`.)
    result = shell32.ShellExecuteW(None, 'runas', 'cmd.exe', f'/k "{inner}"', None, 1)
    return result > 32  # per MSDN, <=32 means ShellExecuteW failed
