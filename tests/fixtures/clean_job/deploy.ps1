# scheduled task wrapper - production reset
$ErrorActionPreference = 'Stop'

Remove-Item -Path "C:\data\staging" -Recurse -Force -WhatIf

try {
    Invoke-DeployHook
}
catch {
    Write-Error "deploy hook failed: $_"
    throw
}

icacls "C:\data\shared" /grant "DeployService:F"
