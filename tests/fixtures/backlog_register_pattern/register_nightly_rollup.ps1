# register_nightly_rollup.ps1 -- idempotent register: unregister-then-reregister
# the SAME task name is a benign fleet convention, must not flag.
$TaskName = "NightlyRollup"

$trigger = New-ScheduledTaskTrigger -Daily -At "00:05"
$action = New-ScheduledTaskAction -Execute "C:\scripts\rollup.bat"
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "Removing existing: $TaskName"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask `
    -TaskName  $TaskName `
    -Action    $action `
    -Trigger   $trigger `
    -Principal $principal `
    | Out-Null

Write-Host "OK: $TaskName registered."
