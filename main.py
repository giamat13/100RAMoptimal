"""
FocusMax - two modes:
  Lockdown   - closes every process that is NOT approved, except Windows core processes.
               Gives the approved apps maximum performance (High priority + High Performance power plan).
               Keeps running until you press Ctrl+C.
  QuickClean - one-shot: deletes temp files, restarts Discord to free its RAM, purges the
               standby list and file-system cache, unless you're currently in a call.

Run (auto-elevates to admin via UAC, asks mode - and for Lockdown, allowed apps - if not given):
  python main.py
  python main.py --mode Lockdown --allowed-apps "discord.exe,cities.exe"
  python main.py --mode QuickClean
Dry run (Lockdown mode only - prints what would be killed, kills nothing - run this FIRST):
  python main.py --mode Lockdown --dry-run
Self-check:
  python main.py --test
Stop (Lockdown mode): Ctrl+C.   Restore power plan: powercfg /setactive SCHEME_BALANCED
"""

import argparse
import os
import sys

from lockdown import run_lockdown, test_allowed
from quickclean import run_quickclean
from winutil import is_admin, log, pause, relaunch_as_admin


def self_check():
    ok = 0
    if test_allowed('game.exe', r'D:\x\game.exe', ['game.exe']):
        ok += 1                                                    # approved
    if not test_allowed('evil.exe', r'D:\x\evil.exe', ['game.exe']):
        ok += 1                                                    # blocked
    if test_allowed('notepad.exe', os.environ['SystemRoot'] + r'\System32\notepad.exe', ['game.exe']):
        ok += 1                                                    # Windows protected
    if test_allowed('lsass.exe', r'C:\weird\lsass.exe', ['game.exe']):
        ok += 1                                                    # protected name
    if ok == 4:
        print('SELF-CHECK PASS')
    else:
        raise SystemExit(f'SELF-CHECK FAIL ({ok}/4)')


def main():
    log(f'main() start, argv={sys.argv[1:]}, is_admin={is_admin()}')
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['Lockdown', 'QuickClean'])
    parser.add_argument('--allowed-apps', default='')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()

    if args.test:
        self_check()
        return

    mode = args.mode
    if not mode:
        print("Choose mode:")
        print("  1. Lockdown   - kills everything except approved apps, keeps running, max performance")
        print("  2. QuickClean - one-shot: deletes temp files, restarts Discord to free RAM, then exits")
        mode = 'QuickClean' if input("Enter 1 or 2: ").strip() == '2' else 'Lockdown'

    allowed_apps = args.allowed_apps
    if mode == 'Lockdown' and not allowed_apps:
        allowed_apps = input(
            "Which apps are allowed to keep running? (exe names, comma separated, e.g. discord.exe,cities.exe): "
        )

    if not is_admin():
        relaunch_args = ['--mode', mode]
        if allowed_apps:
            relaunch_args += ['--allowed-apps', allowed_apps]
        if args.dry_run:
            relaunch_args.append('--dry-run')
        if relaunch_as_admin(os.path.abspath(__file__), relaunch_args):
            print("Opened a new elevated window - approve the UAC prompt there. This window can close.")
        else:
            print("Failed to open an elevated window (UAC declined or blocked).")
            pause('Press Enter to close')
        return

    if mode == 'QuickClean':
        run_quickclean()
        return

    allowed = [a.strip() for a in allowed_apps.split(',') if a.strip()]
    run_lockdown(allowed, args.dry_run)


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # keep the window open on unexpected errors, like the .ps1 trap
        print(f"ERROR: {exc}")
        pause('Press Enter to close')
        sys.exit(1)
