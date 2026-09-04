"""Lockdown mode: closes every process that is NOT approved, except Windows core processes.
Gives the approved apps maximum performance (High priority + High Performance power plan).
Keeps running until you press Ctrl+C."""

import os
import subprocess
import time

from winutil import (
    HIGH_PRIORITY_CLASS,
    PROCESS_SET_INFORMATION,
    PROCESS_TERMINATE,
    PROTECTED_NAMES,
    PROTECTED_ROOTS,
    enum_processes,
    get_process_path,
    kernel32,
    pause,
)


def test_allowed(name, path, allowed):
    if not name:
        return True  # unknown -> leave alone
    if name.lower() in (p.lower() for p in PROTECTED_NAMES):
        return True
    if name.lower() in (a.lower() for a in allowed):
        return True
    if path:
        for root in PROTECTED_ROOTS:
            if path.lower().startswith(root.lower()):
                return True
    return False


def run_lockdown(allowed, dry_run):
    print(f"FocusMax running. Approved: {', '.join(allowed)}. Ctrl+C to stop.")
    if dry_run:
        print("DRY RUN - nothing will be killed.")

    subprocess.run(['powercfg', '/setactive', 'SCHEME_MIN'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Protect this script itself and its parent chain (Python/Terminal running it)
    parent_map = {pid: ppid for pid, ppid, _name in enum_processes()}
    self_pids = set()
    pid = os.getpid()
    while pid and pid != 0:
        self_pids.add(pid)
        pid = parent_map.get(pid, 0)

    allowed_lower = [a.lower() for a in allowed]
    try:
        while True:
            for pid, _ppid, name in enum_processes():
                if pid in self_pids:
                    continue
                path = get_process_path(pid)
                if test_allowed(name, path, allowed):
                    if name.lower() in allowed_lower:
                        h = kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
                        if h:
                            kernel32.SetPriorityClass(h, HIGH_PRIORITY_CLASS)
                            kernel32.CloseHandle(h)
                    continue
                if dry_run:
                    print(f"[DRYRUN] would kill: {name} (pid {pid}) {path or ''}")
                else:
                    h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
                    if h:
                        kernel32.TerminateProcess(h, 1)
                        kernel32.CloseHandle(h)
                        print(f"[BLOCKED] {name}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    pause('Stopped. Press Enter to close')
