$ErrorActionPreference='Continue'
$d='C:\Users\lab\src\full-931f69f'
if (Test-Path $d) { Remove-Item -Recurse -Force $d }
New-Item -ItemType Directory -Path $d | Out-Null
tar -xf C:\Users\lab\src\full-931f69f.tar -C $d
"tar exit $LASTEXITCODE; tar sha " + (Get-FileHash C:\Users\lab\src\full-931f69f.tar -Algorithm SHA256).Hash
Set-Location $d\rmasscan
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
$env:NO_COLOR='1'
cargo clippy --locked --workspace --all-targets -- -D warnings 2>&1 | Out-File C:\Users\lab\src\clippyF-931f69f.log -Encoding utf8
"CLIPPY_EXIT=$LASTEXITCODE"
Get-Content C:\Users\lab\src\clippyF-931f69f.log | Select-Object -Last 6
cargo test --locked --workspace --all-targets 2>&1 | Out-File C:\Users\lab\src\testF-931f69f.log -Encoding utf8
"TEST_EXIT=$LASTEXITCODE"
Select-String -Path C:\Users\lab\src\testF-931f69f.log -Pattern '^test result|^error|FAILED$' | ForEach-Object { $_.Line }
