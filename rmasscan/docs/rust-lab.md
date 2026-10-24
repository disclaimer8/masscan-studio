# Rust laboratory tools

Build once on each host architecture:

```sh
cargo build --locked --release -p rmasscan-lab
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

`rmasscan-lab` contains the portable evidence verifier, packet comparator,
Linux capture and peer tools, VM isolation manager, Linux/Windows suites and
independent C-oracle collection. Python is not a build, test or run dependency.
The Windows PowerShell files remain system-integration wrappers. Bash entry
points invoke the Rust tools and OS utilities; they contain no embedded Python.

```sh
target/release/rmasscan-lab verify-wire --self-test
target/release/rmasscan-lab windows-verify --dir PATH_TO_EVIDENCE
target/release/rmasscan-lab windows-suite --list --plan failure
target/release/rmasscan-lab vm-lab plan --run-id n2 --manifest lab.json
```

The `verify-wire` comparator accepts `--expected`, repeated `--actual` (pause
legs in order), optional `--expected-meta` and one `--actual-meta` per leg.
Its exit codes remain 0 PASS, 1 FAIL, 2 INVALID. Windows evidence verification
also represents missing evidence as NOT RUN; a missing file never produces PASS.

For Linux oracle captures, set `RMASSCAN_LAB_BIN` to the **Linux-built** binary
and use `scripts/wire-lab.sh`. Remote Windows-suite orchestration requires an
explicit `--remote-lab /absolute/path/to/linux/rmasscan-lab`. A Mac executable
must not be copied to the Linux host as if it were interchangeable.

VM verification uses a unique nonce and a new report path per invocation.
Failed guest verification aborts before opening a scan. `record-guest` checks
the report's actual verification time and expected nonce; copying an old report
does not make it fresh. Guest and host clocks must agree within the accepted
window; fix clock drift rather than relaxing freshness.

Archived experiment scripts and their hashes document historical runs. They
are not current tool entry points and must not be rewritten to pretend the
old measurements came from the new implementation. Replaying saved packets
validates the verifier; it does not constitute a new live network acceptance.
