# block-dangerous-git guard: documents the patterns it BLOCKS
# Remove-Item -Recurse -Force <root> is blocked by this guard
# patterns (rm -rf / rm -fr) aimed at project roots are rejected
Write-Host "registering task"
