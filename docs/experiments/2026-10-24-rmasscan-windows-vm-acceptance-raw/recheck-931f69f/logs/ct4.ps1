$ErrorActionPreference='Continue'
Set-Location C:\Users\lab\src\rmasscan-931f69f\rmasscan
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
$env:NO_COLOR='1'
"== clippy: workspace except rmasscan-lab, all targets"
cargo clippy --locked --workspace --exclude rmasscan-lab --all-targets -- -D warnings 2>&1 | Select-Object -Last 4
"CLIPPY_A_EXIT=$($LASTEXITCODE)"
"== clippy: rmasscan-lab lib bins examples and tests capture oracle_util process_group windows_evidence (all but rust_only)"
cargo clippy --locked -p rmasscan-lab --lib --bins --examples --test capture --test oracle_util --test process_group --test windows_evidence -- -D warnings 2>&1 | Select-Object -Last 4
"CLIPPY_B_EXIT=$($LASTEXITCODE)"
"== test: workspace except rmasscan-lab, all targets"
cargo test --locked --workspace --exclude rmasscan-lab --all-targets 2>&1 | Out-File C:\Users\lab\src\testA-931f69f.log -Encoding utf8
"TEST_A_EXIT=$($LASTEXITCODE)"
"== test: rmasscan-lab all but rust_only"
cargo test --locked -p rmasscan-lab --lib --bins --examples --test capture --test oracle_util --test process_group --test windows_evidence 2>&1 | Out-File C:\Users\lab\src\testB-931f69f.log -Encoding utf8
"TEST_B_EXIT=$($LASTEXITCODE)"
foreach ($f in 'testA','testB') { "-- $f"; Select-String -Path C:\Users\lab\src\$f-931f69f.log -Pattern '^test result|FAILED|failed|panicked|^error' | ForEach-Object { $_.Line } }
