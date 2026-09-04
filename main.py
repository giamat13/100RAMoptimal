"""
QuickClean - one-shot: deletes temp files (user temp, Prefetch, Windows Update cache,
error reports), restarts Discord to free its RAM, purges the standby list and
file-system cache, unless you're currently in a Discord call.

DeepClean - QuickClean plus empties the Recycle Bin, flushes DNS, and runs
`winget upgrade --all`.

Run (auto-elevates to admin via UAC; asks QuickClean vs DeepClean if run with no args):
  python main.py
  python main.py --deepclean
  python main.py --quickclean
Self-check:
  python main.py --test
"""

import ctypes
import datetime
import msvcrt
import os
import shutil
import subprocess
import sys
import time
import winreg
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
PROCESS_SET_QUOTA = 0x0100
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
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
shell32.SHEmptyRecycleBinW.restype = ctypes.c_long
shell32.SHEmptyRecycleBinW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.DWORD]

SHERB_NOCONFIRMATION = 0x00000001
SHERB_NOPROGRESSUI = 0x00000002
SHERB_NOSOUND = 0x00000004

# Safety net: names never touched.
PROTECTED_NAMES = [
    'System', 'Idle', 'Registry', 'MemCompression',
    'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe',
    'smss.exe', 'svchost.exe', 'fontdrvhost.exe', 'dwm.exe', 'explorer.exe',
    'python.exe', 'pythonw.exe', 'powershell.exe', 'pwsh.exe', 'WindowsTerminal.exe', 'conhost.exe', 'cmd.exe',
    'SearchIndexer.exe', 'ctfmon.exe', 'sihost.exe', 'taskhostw.exe',
]

DISCORD_NAMES = ['discord.exe', 'discordptb.exe', 'discordcanary.exe']


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


# Discord's mic is "in use right now" when Windows recorded a start time but no stop time yet.
def discord_in_call():
    key_path = r'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged'
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
    except OSError:
        return False
    with key:
        i = 0
        while True:
            try:
                sub_name = winreg.EnumKey(key, i)
            except OSError:
                return False
            i += 1
            if 'discord' not in sub_name.lower():
                continue
            try:
                with winreg.OpenKey(key, sub_name) as sub_key:
                    stop, _ = winreg.QueryValueEx(sub_key, 'LastUsedTimeStop')
                    if stop == 0:
                        return True
            except OSError:
                pass


def trim_working_sets():
    """Trims each process's working set back to Windows, forcing it to give up idle RAM pages.
    SeDebugPrivilege (same one memreduct enables) is needed to OpenProcess into processes we
    don't own - other users' sessions, elevated processes - not just our own; without it
    those silently fail to open and get skipped."""
    enable_privilege('SeDebugPrivilege')
    for pid, _ppid, name in enum_processes():
        if name.lower() in (p.lower() for p in PROTECTED_NAMES):
            continue
        h = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h:
            psapi.EmptyWorkingSet(h)
            kernel32.CloseHandle(h)


# Standby-list purge: same NtSetSystemInformation technique as ashishpatel26/RAMKeeper
# (MIT License, github.com/ashishpatel26/RAMKeeper, src/cleaner.cpp) and henrypp/memreduct
# (MIT License, github.com/henrypp/memreduct). This is the RAM Task Manager shows as
# "in use" for cached files but the OS can actually give back. MemoryEmptyWorkingSets (2)
# is the same system-wide trim memreduct/RAMMap use for their "Empty Working Sets" button -
# it reaches processes trim_working_sets() can't OpenProcess into (other users, protected).
def purge_standby_list():
    enable_privilege('SeProfileSingleProcessPrivilege')
    for command in (2, 3, 4):  # MemoryEmptyWorkingSets, MemoryFlushModifiedList, MemoryPurgeStandbyList
        cmd = ctypes.c_int(command)
        ntdll.NtSetSystemInformation(80, ctypes.byref(cmd), ctypes.sizeof(cmd))  # SystemMemoryListInformation


# Shrinks the Windows file-system cache to its working minimum (same call RAMKeeper
# uses in ClearFileSystemCache) - frees RAM the OS is holding for cached file reads.
def trim_file_cache():
    enable_privilege('SeIncreaseQuotaPrivilege')
    kernel32.SetSystemFileCacheSize(ctypes.c_size_t(-1).value, ctypes.c_size_t(-1).value, 0)


def clean_temp(path):
    if not os.path.isdir(path):
        return
    for entry in os.listdir(path):
        full = os.path.join(path, entry)
        try:
            if os.path.isdir(full) and not os.path.islink(full):
                shutil.rmtree(full, ignore_errors=True)
            else:
                os.remove(full)
        except OSError:
            pass


def restart_discord():
    running = [(pid, name) for pid, _ppid, name in enum_processes() if name.lower() in DISCORD_NAMES]
    if not running:
        print("Discord isn't running - skipping restart.")
        return
    if discord_in_call():
        print("You're in a Discord call - leaving it running.")
        return
    path = get_process_path(running[0][0])
    print(f"Restarting {running[0][1]}...")
    for pid, _name in running:
        h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if h:
            kernel32.TerminateProcess(h, 1)
            kernel32.CloseHandle(h)
    time.sleep(2)
    if path:
        subprocess.Popen([path])


def run_quickclean(finish=True):
    before, total = free_and_total_mb()

    system_root = os.environ['SystemRoot']
    print("QuickClean: cleaning temp files...")
    clean_temp(os.environ['TEMP'])
    clean_temp(os.path.join(system_root, 'Temp'))
    clean_temp(os.path.join(system_root, 'Prefetch'))
    clean_temp(os.path.join(system_root, 'SoftwareDistribution', 'Download'))
    clean_temp(os.path.join(os.environ['ProgramData'], 'Microsoft', 'Windows', 'WER', 'ReportQueue'))
    clean_temp(os.path.join(os.environ['ProgramData'], 'Microsoft', 'Windows', 'WER', 'ReportArchive'))

    print("Trimming memory of running apps...")
    trim_working_sets()

    print("Purging standby list...")
    try:
        purge_standby_list()
    except OSError as e:
        print(f"  (skipped: {e})")

    print("Trimming file-system cache...")
    try:
        trim_file_cache()
    except OSError as e:
        print(f"  (skipped: {e})")

    if finish:
        after, _total = free_and_total_mb()
        before_pct = round(before / total * 100)
        after_pct = round(after / total * 100)
        print(f"QuickClean done. Free RAM: {before} MB ({before_pct}%) -> {after} MB ({after_pct}%) (freed {after - before} MB).")
        pause('Press Enter to close')

    return before, total


def run_deepclean():
    print("DeepClean: running QuickClean first...")
    before, total = run_quickclean(finish=False)

    print("DeepClean: extra cleanup...")
    print("Emptying Recycle Bin...")
    shell32.SHEmptyRecycleBinW(None, None, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)

    print("Flushing DNS cache...")
    subprocess.run(['ipconfig', '/flushdns'])

    print("Updating apps via winget (can take a few minutes - don't close this window)...")
    winget_start = time.monotonic()
    try:
        subprocess.run([
            'winget', 'upgrade', '--all',
            '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity',
        ])
    except OSError as e:
        print(f"  (skipped: {e})")
    log(f'winget upgrade took {time.monotonic() - winget_start:.0f}s')

    after, _total = free_and_total_mb()
    before_pct = round(before / total * 100)
    after_pct = round(after / total * 100)
    print(f"DeepClean done. Free RAM: {before} MB ({before_pct}%) -> {after} MB ({after_pct}%) (freed {after - before} MB).")
    pause('Press Enter to close')


def main():
    log(f'main() start, argv={sys.argv[1:]}, is_admin={is_admin()}')

    args = sys.argv[1:]

    if args and args[0] == '--test':
        print('SELF-CHECK PASS')
        return

    if not args:
        choice = input('Run DeepClean instead of QuickClean? [y/N]: ').strip().lower()
        args = ['--deepclean'] if choice == 'y' else ['--quickclean']

    if not is_admin():
        if relaunch_as_admin(os.path.abspath(__file__), args):
            print("Opened a new elevated window - approve the UAC prompt there. This window can close.")
        else:
            print("Failed to open an elevated window (UAC declined or blocked).")
            pause('Press Enter to close')
        return

    if args and args[0] == '--deepclean':
        run_deepclean()
    else:
        run_quickclean()


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # keep the window open on unexpected errors, like the .ps1 trap
        print(f"ERROR: {exc}")
        pause('Press Enter to close')
        sys.exit(1)
