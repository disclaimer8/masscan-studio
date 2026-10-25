$ErrorActionPreference='Continue'
Set-Location C:\Users\lab\src\full-931f69f\rmasscan
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
$env:NO_COLOR='1'
cargo test --locked --no-fail-fast -p rmasscan-lab --lib --bins --examples --test capture --test oracle_util --test process_group --test windows_evidence 2>&1 | Out-File C:\Users\lab\src\testF2-931f69f.log -Encoding utf8
"TEST_EXIT=$LASTEXITCODE"
Select-String -Path C:\Users\lab\src\testF2-931f69f.log -Pattern '^test result|FAILED$|^error' | ForEach-Object { $_.Line }
