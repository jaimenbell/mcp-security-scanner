# deploy.ps1 -- empty catch, but downstream verifies success before continuing
try {
    $ok = Invoke-DeployHook
}
catch {
}

if (-not $ok) {
    throw "deploy hook failed silently"
}

Write-Host "deploy verified ok"
