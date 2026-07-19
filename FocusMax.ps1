<#
FocusMax - closes every process that is NOT approved, except Windows core processes.
Gives the approved apps maximum performance (High priority + High Performance power plan).

Run (auto-elevates to admin via UAC):
  powershell -ExecutionPolicy Bypass -File FocusMax.ps1
Dry run (prints what would be killed, kills nothing - run this FIRST):
  powershell -ExecutionPolicy Bypass -File FocusMax.ps1 -DryRun
Self-check:
  powershell -ExecutionPolicy Bypass -File FocusMax.ps1 -Test
Stop: Ctrl+C.   Restore power plan: powercfg /setactive SCHEME_BALANCED
#>

param([switch]$DryRun, [switch]$Test)

# Keep the window open if a terminating error happens (instead of closing instantly)
trap { Write-Host "ERROR: $_" -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }

# Auto-elevate: if not admin, relaunch this script as admin (UAC prompt)
if (-not $Test -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $a = @('-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    if ($DryRun) { $a += '-DryRun' }
    Start-Process powershell -Verb RunAs -ArgumentList $a
    exit
}

# ==== CONFIG: apps you approve to run (exe name only, no path). Edit this. ====
$Allowed = @(
    'javaw.exe', 'gamingservices.exe', 'gamingservicesnet.exe'
)

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

if ($Test) {
    $Allowed = @('game.exe'); $ok = 0
    if (Test-Allowed 'game.exe' 'D:\x\game.exe') { $ok++ }                              # approved
    if (-not (Test-Allowed 'evil.exe' 'D:\x\evil.exe')) { $ok++ }                       # blocked
    if (Test-Allowed 'notepad.exe' "$env:SystemRoot\System32\notepad.exe") { $ok++ }    # Windows protected
    if (Test-Allowed 'lsass.exe' 'C:\weird\lsass.exe') { $ok++ }                        # protected name
    if ($ok -eq 4) { 'SELF-CHECK PASS' } else { throw "SELF-CHECK FAIL ($ok/4)" }
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
