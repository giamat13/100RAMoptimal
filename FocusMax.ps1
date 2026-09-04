<#
FocusMax - two modes:
  Lockdown   - closes every process that is NOT approved, except Windows core processes.
               Gives the approved apps maximum performance (High priority + High Performance power plan).
               Keeps running until you press Ctrl+C.
  QuickClean - one-shot: deletes temp files and restarts Discord to free its RAM,
               unless you're currently in a call. Finishes in seconds, no ongoing monitoring.

Run (auto-elevates to admin via UAC, asks mode - and for Lockdown, allowed apps - if not given):
  powershell -ExecutionPolicy Bypass -File FocusMax.ps1
  powershell -ExecutionPolicy Bypass -File FocusMax.ps1 -Mode Lockdown -AllowedApps "discord.exe,cities.exe"
  powershell -ExecutionPolicy Bypass -File FocusMax.ps1 -Mode QuickClean
Dry run (Lockdown mode only - prints what would be killed, kills nothing - run this FIRST):
  powershell -ExecutionPolicy Bypass -File FocusMax.ps1 -Mode Lockdown -DryRun
Self-check:
  powershell -ExecutionPolicy Bypass -File FocusMax.ps1 -Test
Stop (Lockdown mode): Ctrl+C.   Restore power plan: powercfg /setactive SCHEME_BALANCED
#>

param([ValidateSet('Lockdown', 'QuickClean')][string]$Mode, [string]$AllowedApps, [switch]$DryRun, [switch]$Test)

# Keep the window open if a terminating error happens (instead of closing instantly)
trap { Write-Host "ERROR: $_" -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }

if (-not $Test -and -not $Mode) {
    Write-Host "Choose mode:"
    Write-Host "  1. Lockdown   - kills everything except approved apps, keeps running, max performance"
    Write-Host "  2. QuickClean - one-shot: deletes temp files, restarts Discord to free RAM, then exits"
    $Mode = if ((Read-Host "Enter 1 or 2") -eq '2') { 'QuickClean' } else { 'Lockdown' }
}

if ($Mode -eq 'Lockdown' -and -not $Test -and -not $AllowedApps) {
    $AllowedApps = Read-Host "Which apps are allowed to keep running? (exe names, comma separated, e.g. discord.exe,cities.exe)"
}

# Auto-elevate: if not admin, relaunch this script as admin (UAC prompt)
if (-not $Test -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $a = @('-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-Mode',$Mode,'-AllowedApps',"`"$AllowedApps`"")
    if ($DryRun) { $a += '-DryRun' }
    Start-Process powershell -Verb RunAs -ArgumentList $a
    exit
}

# Apps you approve to run (exe name only, no path) - asked for at the start of every run.
$Allowed = @($AllowedApps -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# Any process whose image is under these folders is protected (Windows core).
$ProtectedRoots = @("$env:SystemRoot")            # C:\Windows and everything under it

# Safety net: names never killed, even outside C:\Windows.
$ProtectedNames = @(
    'System','Idle','Registry','MemCompression',
    'csrss.exe','wininit.exe','winlogon.exe','services.exe','lsass.exe',
    'smss.exe','svchost.exe','fontdrvhost.exe','dwm.exe','explorer.exe',
    'powershell.exe','pwsh.exe','WindowsTerminal.exe','conhost.exe',
    'SearchIndexer.exe','ctfmon.exe','sihost.exe','taskhostw.exe'
)

function Test-Allowed {
    param([string]$Name, [string]$Path)
    if (-not $Name) { return $true }                       # unknown -> leave alone
    if ($ProtectedNames -contains $Name) { return $true }  # -contains is case-insensitive
    if ($Allowed -contains $Name) { return $true }
    if ($Path) {
        foreach ($root in $ProtectedRoots) {
            if ($Path -like "$root*") { return $true }
        }
    }
    return $false
}

# Discord's mic is "in use right now" when Windows recorded a start time but no stop time yet.
function Test-DiscordInCall {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged'
    $inCall = $false
    Get-ChildItem $key -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'Discord' } | ForEach-Object {
        if ((Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).LastUsedTimeStop -eq 0) { $inCall = $true }
    }
    $inCall
}

$DiscordNames = @('Discord', 'DiscordPTB', 'DiscordCanary')

# Trims each process's working set back to Windows, forcing it to give up idle RAM pages.
function Invoke-TrimWorkingSets {
    if (-not ([System.Management.Automation.PSTypeName]'PInvoke.Win32').Type) {
        Add-Type -Name Win32 -Namespace PInvoke -MemberDefinition @'
[DllImport("psapi.dll")]
public static extern bool EmptyWorkingSet(IntPtr hProcess);
'@
    }
    foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
        if ($ProtectedNames -contains "$($proc.Name).exe") { continue }
        try { [PInvoke.Win32]::EmptyWorkingSet($proc.Handle) | Out-Null } catch {}
    }
}

if (-not ([System.Management.Automation.PSTypeName]'PInvoke.NtMem').Type) {
    Add-Type -Namespace PInvoke -Name NtMem -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, byte[] NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
[DllImport("ntdll.dll")]
public static extern int NtSetSystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetSystemFileCacheSize(IntPtr MinimumFileCacheSize, IntPtr MaximumFileCacheSize, int Flags);
'@
}

# Enables a privilege (like SeProfileSingleProcessPrivilege) on our own process token -
# admin rights alone don't grant these, they still need to be switched on explicitly.
function Enable-Privilege {
    param([string]$Privilege)
    $hToken = [IntPtr]::Zero
    [void][PInvoke.NtMem]::OpenProcessToken((Get-Process -Id $PID).Handle, 0x28, [ref]$hToken) # QUERY|ADJUST
    $luid = 0L
    [void][PInvoke.NtMem]::LookupPrivilegeValue($null, $Privilege, [ref]$luid)
    # TOKEN_PRIVILEGES: PrivilegeCount(4) + LUID(8) + Attributes(4), SE_PRIVILEGE_ENABLED=2
    $tp = New-Object byte[] 16
    [BitConverter]::GetBytes([int]1).CopyTo($tp, 0)
    [BitConverter]::GetBytes([long]$luid).CopyTo($tp, 4)
    [BitConverter]::GetBytes([int]2).CopyTo($tp, 12)
    [void][PInvoke.NtMem]::AdjustTokenPrivileges($hToken, $false, $tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
}

# Standby-list purge: same NtSetSystemInformation technique as ashishpatel26/RAMKeeper
# (MIT License, github.com/ashishpatel26/RAMKeeper, src/cleaner.cpp). This is the RAM
# Task Manager shows as "in use" for cached files but the OS can actually give back.
function Invoke-PurgeStandbyList {
    Enable-Privilege 'SeProfileSingleProcessPrivilege'
    $mem = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt32($mem, 3)  # MemoryFlushModifiedList
        [PInvoke.NtMem]::NtSetSystemInformation(80, $mem, 4) | Out-Null  # SystemMemoryListInformation
        [Runtime.InteropServices.Marshal]::WriteInt32($mem, 4)  # MemoryPurgeStandbyList
        [PInvoke.NtMem]::NtSetSystemInformation(80, $mem, 4) | Out-Null
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($mem)
    }
}

# Shrinks the Windows file-system cache to its working minimum (same call RAMKeeper
# uses in ClearFileSystemCache) - frees RAM the OS is holding for cached file reads.
function Invoke-TrimFileCache {
    Enable-Privilege 'SeIncreaseQuotaPrivilege'
    [void][PInvoke.NtMem]::SetSystemFileCacheSize([IntPtr]-1, [IntPtr]-1, 0)
}

function Invoke-QuickClean {
    $before = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory   # KB

    Write-Host "QuickClean: cleaning temp files..." -ForegroundColor Cyan
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

    $discord = Get-Process -Name $DiscordNames -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $discord) {
        Write-Host "Discord isn't running - skipping restart." -ForegroundColor Yellow
    } elseif (Test-DiscordInCall) {
        Write-Host "You're in a Discord call - leaving it running." -ForegroundColor Yellow
    } else {
        $path = $discord.Path
        Write-Host "Restarting $($discord.Name)..." -ForegroundColor Cyan
        Get-Process -Name $DiscordNames -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        if ($path) { Start-Process $path }
    }

    Write-Host "Trimming memory of running apps..." -ForegroundColor Cyan
    Invoke-TrimWorkingSets

    Write-Host "Purging standby list..." -ForegroundColor Cyan
    try { Invoke-PurgeStandbyList } catch { Write-Host "  (skipped: $_)" -ForegroundColor DarkYellow }

    Write-Host "Trimming file-system cache..." -ForegroundColor Cyan
    try { Invoke-TrimFileCache } catch { Write-Host "  (skipped: $_)" -ForegroundColor DarkYellow }

    $after = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory    # KB
    $totalKB = (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize
    $beforeMB = [math]::Round($before / 1024)
    $afterMB = [math]::Round($after / 1024)
    $beforePct = [math]::Round($before / $totalKB * 100)
    $afterPct = [math]::Round($after / $totalKB * 100)
    Write-Host "QuickClean done. Free RAM: $beforeMB MB ($beforePct%) -> $afterMB MB ($afterPct%) (freed $($afterMB - $beforeMB) MB)." -ForegroundColor Green
}

if ($Test) {
    $Allowed = @('game.exe'); $ok = 0
    if (Test-Allowed 'game.exe' 'D:\x\game.exe') { $ok++ }                              # approved
    if (-not (Test-Allowed 'evil.exe' 'D:\x\evil.exe')) { $ok++ }                       # blocked
    if (Test-Allowed 'notepad.exe' "$env:SystemRoot\System32\notepad.exe") { $ok++ }    # Windows protected
    if (Test-Allowed 'lsass.exe' 'C:\weird\lsass.exe') { $ok++ }                        # protected name
    if ($ok -eq 4) { 'SELF-CHECK PASS' } else { throw "SELF-CHECK FAIL ($ok/4)" }
    return
}

if ($Mode -eq 'QuickClean') {
    Invoke-QuickClean
    Read-Host 'Press Enter to close'
    return
}

Write-Host "FocusMax running. Approved: $($Allowed -join ', '). Ctrl+C to stop." -ForegroundColor Cyan
if ($DryRun) { Write-Host "DRY RUN - nothing will be killed." -ForegroundColor Yellow }

powercfg /setactive SCHEME_MIN 2>$null   # power plan: High Performance

# Protect this script itself and its parent chain (PowerShell/Terminal running it)
$Self = @(); $q = $PID
while ($q -and $q -ne 0) {
    $Self += $q
    $q = (Get-CimInstance Win32_Process -Filter "ProcessId=$q" -ErrorAction SilentlyContinue).ParentProcessId
}

while ($true) {
    foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
        if ($Self -contains $p.ProcessId) { continue }   # never kill self
        if (Test-Allowed $p.Name $p.ExecutablePath) {
            if ($Allowed -contains $p.Name) {
                try { (Get-Process -Id $p.ProcessId -ErrorAction Stop).PriorityClass = 'High' } catch {}
            }
            continue
        }
        if ($DryRun) {
            Write-Host "[DRYRUN] would kill: $($p.Name) (pid $($p.ProcessId)) $($p.ExecutablePath)" -ForegroundColor Yellow
        } else {
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
                  Write-Host "[BLOCKED] $($p.Name)" -ForegroundColor Red } catch {}
        }
    }
    Start-Sleep -Milliseconds 500
}
