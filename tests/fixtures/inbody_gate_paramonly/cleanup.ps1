# release-cleanup scheduled task
param([switch]$Force)

Write-Host "force mode requested: $Force"
Remove-Item -Path "C:\data\staging" -Recurse -Force
