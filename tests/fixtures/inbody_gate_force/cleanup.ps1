# release-cleanup scheduled task
param([switch]$Force)

if (-not $Force) {
    throw "refusing to run: pass -Force to actually delete the staging tree"
}

Remove-Item -Path "C:\data\staging" -Recurse -Force
