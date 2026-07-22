# decommission-old-task.ps1 -- retires a legacy scheduled task, no replacement
$TaskName = "LegacyNightlySweep"

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Write-Host "Removed legacy task, nothing re-registered."
