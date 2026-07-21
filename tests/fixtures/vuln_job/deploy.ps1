# scheduled task wrapper - production reset
Remove-Item -Path "C:\data\staging" -Recurse -Force -Confirm:$false

try {
    Invoke-DeployHook
}
catch {
}

icacls "C:\data\shared" /grant Everyone:F
