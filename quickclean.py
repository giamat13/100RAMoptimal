"""QuickClean mode: one-shot - deletes temp files, restarts Discord to free its RAM, purges
the standby list and file-system cache, unless you're currently in a call."""

import ctypes
import os
import shutil
import subprocess
import time
import winreg

from winutil import (
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_QUOTA,
    PROCESS_TERMINATE,
    PROTECTED_NAMES,
    enable_privilege,
    enum_processes,
    free_and_total_mb,
    get_process_path,
    kernel32,
    ntdll,
    pause,
    psapi,
)

DISCORD_NAMES = ['discord.exe', 'discordptb.exe', 'discordcanary.exe']


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
    """Trims each process's working set back to Windows, forcing it to give up idle RAM pages."""
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


def run_quickclean():
    before, total = free_and_total_mb()

    print("QuickClean: cleaning temp files...")
    clean_temp(os.environ['TEMP'])
    clean_temp(os.path.join(os.environ['SystemRoot'], 'Temp'))

    restart_discord()

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

    after, _total = free_and_total_mb()
    before_pct = round(before / total * 100)
    after_pct = round(after / total * 100)
    print(f"QuickClean done. Free RAM: {before} MB ({before_pct}%) -> {after} MB ({after_pct}%) (freed {after - before} MB).")
    pause('Press Enter to close')
