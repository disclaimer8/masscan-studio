$ErrorActionPreference = 'Stop'
Set-Location C:\Users\lab\src\rmasscan-920dd25
git init -q
git add -A
Set-Location rmasscan
cargo test --locked --workspace --all-targets --no-fail-fast
exit $LASTEXITCODE
