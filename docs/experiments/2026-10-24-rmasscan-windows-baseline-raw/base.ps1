$ErrorActionPreference='Continue'
$L='C:\Users\lab\base'; Remove-Item -Recurse -Force $L -ErrorAction SilentlyContinue; New-Item -ItemType Directory $L | Out-Null
Set-Location C:\Users\lab\src\rmasscan-31a729f\rmasscan
$codes=[ordered]@{}
function Run($name,[scriptblock]$sb){
  $sw=[Diagnostics.Stopwatch]::StartNew()
  & $sb *> "$L\$name.log"
  $codes[$name]=$LASTEXITCODE
  "$name exit=$($LASTEXITCODE) secs=$([int]$sw.Elapsed.TotalSeconds)"
}
Run fmt { cargo fmt --all --check }
Run clippy { cargo clippy --locked --workspace --all-targets -- -D warnings }
Run test { cargo test --locked --workspace }
Run no_c_guard { cargo test --locked -p rmasscan-core --test no_c_in_build }
Run verify_wire_selftest { python scripts/verify-wire.py --self-test }
Run wire_suite_selftest { python scripts/wire_suite.py --self-test }
Run wire_scan_build { cargo build --locked --release -p rmasscan-net --example wire_scan }
Run deny { cargo deny check bans licenses sources }
Run cli_echo { cargo run --locked -q -p rmasscan-cli -- --echo 10.0.0.0/24 -p80 --seed 1 }
$codes | ConvertTo-Json | Set-Content "$L\codes.json"
