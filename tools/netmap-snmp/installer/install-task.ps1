# RackTrace: register the start-at-boot scheduled task (runs as SYSTEM, no sign-in needed) and start it now.
# Called by the installer; can also be run by hand as administrator:
#   powershell -ExecutionPolicy Bypass -File install-task.ps1 -Exe "C:\Program Files\RackTrace\netmap.exe"
param([Parameter(Mandatory=$true)][string]$Exe, [switch]$Remove)
$ErrorActionPreference = 'Stop'
$name = 'RackTrace'
if ($Remove) {
  try { Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue } catch {}
  try { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue } catch {}
  exit 0
}

$a = New-ScheduledTaskAction -Execute $Exe -Argument '--service --machine' -WorkingDirectory (Split-Path $Exe)
$t = New-ScheduledTaskTrigger -AtStartup
# No execution time limit (default stops after 3 days), retry on failure, ignore battery state
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) `
     -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $name -Action $a -Trigger $t -Settings $s -Principal $p -Description 'RackTrace monitoring service (starts at boot)' -Force | Out-Null
Start-ScheduledTask -TaskName $name
Write-Output "Registered and started scheduled task: $name"
