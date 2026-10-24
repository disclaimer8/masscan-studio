# Rust laboratory tools

Build once on each host architecture:

```sh
cargo build --locked --release -p rmasscan-lab
```

For evidence runs, build with the commit embedded: `RMASSCAN_LAB_BUILD_COMMIT=$(git rev-parse HEAD) cargo build --locked --release -p rmasscan-lab`.
The manifest and preflight records then carry `build_commit` (the commit the binary was compiled from, or `unknown` when the
variable was not set) apart from `git_commit` and `git_dirty`, which describe the `--repo` checkout the binary is run against
and may differ from it. The binary sha256 is the authoritative identity; `windows-verify` prints all three and warns when
`build_commit` is `unknown` or differs from the commit under test.

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

`rmasscan-lab` contains the portable evidence verifier, packet comparator,
Linux capture and peer tools, VM isolation manager, Linux/Windows suites and
independent C-oracle collection. No script interpreter is a build, test or run dependency; `scripts/language-guard.sh` (workflow `language-guard.yml`, no path filter) and `tests/rust_only.rs` enforce it for the whole repository.
The Windows PowerShell files remain system-integration wrappers. Bash entry
points invoke the Rust tools and OS utilities.

Capture on Linux is witnessed by the independent `tcpdump` (`capture dump`, `-U
--immediate-mode`): a capture is valid only if the start marker is in the pcap before the
scanner starts, the veth counters went quiet, three end markers follow, tcpdump reports no
kernel or interface drops, and captured == received == pcap frames == the rx+tx counter
window. The lab sends frames and listens through the same `open_explicit` adapter the product
uses; the only `unsafe` the lab needs is in `rmasscan-net`'s non-default `lab` feature (a
`sigaction` stop flag and one backlog-0 listener). There is no CLI self-test: the comparator and
suite cases are `cargo test -p rmasscan-lab`.

Perf caveat (not yet measured live): `-U --immediate-mode` makes tcpdump flush per packet. At
100k pps (307,200 probes per cell) that may cost kernel drops, which marks the cell INVALID (it
fails closed and blocks the perf gate; nothing is relaxed). Every perf row in `results.json`
records `<impl>_capture_kernel_drops_per_run` and `<impl>_capture_invalid_reasons`, so an
INVALID 100k cell shows whether the witness (capture) or the scanner lost frames. Run
`wire-lab.sh --suite perf --reps 1` once on the Linux host before the 5-rep run to see this.

```sh
# working directory: rmasscan/ (the cargo workspace). The live-run commands in the deployment section
# below run from the repository root instead and say so.
cargo test --locked -p rmasscan-lab   # comparator and suite regression cases (no CLI self-test)
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

## Deployment for the live Windows rerun

Everything below is the procedure; none of it runs implicitly. The suite refuses to start a raw
run unless the preflights in step 5 pass, so a skipped step ends in exit 2 (`NOT RUN`) and not in
a run with unknown provenance. The expected evidence directories and the order of the reruns are
the last two items.

1. **Toolchain on home-pc, user-local.** No root, no distro packages beyond a C linker (`cc`):

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
   . ~/.cargo/env        # rust-toolchain.toml in the archive selects 1.99.1 on first use
   ```

2. **Build the exact commit from `git archive`** (never a working tree, never a branch name).
   Run on the Mac from a clean checkout; `COMMIT` is the full 40-hex SHA that you will also pass
   to `--commit`:

   ```sh
   COMMIT=$(git rev-parse HEAD)
   git archive --format=tar "$COMMIT" rmasscan \
     | ssh home-pc "rm -rf ~/winvm/build/$COMMIT && mkdir -p ~/winvm/build/$COMMIT && tar -x -C ~/winvm/build/$COMMIT"
   ssh home-pc ". ~/.cargo/env && cd ~/winvm/build/$COMMIT/rmasscan && RMASSCAN_LAB_BUILD_COMMIT=$COMMIT cargo build --locked --release -p rmasscan-lab"
   ```

3. **Install it and record the deploy manifest.** The old `~/winvm/lab/windows-vm-lab.py` is
   retired; the Rust `vm-lab` reads the existing `~/winvm/lab/n2.json` unchanged (same `names`
   keys, alias and marker format).

   ```sh
   ssh home-pc "mkdir -p ~/winvm/lab/bin && install -m 0755 ~/winvm/build/$COMMIT/rmasscan/target/release/rmasscan-lab ~/winvm/lab/bin/rmasscan-lab"
   ssh home-pc ". ~/.cargo/env && ~/winvm/lab/bin/rmasscan-lab deploy-manifest --commit $COMMIT \
       --binary \$HOME/winvm/lab/bin/rmasscan-lab --out \$HOME/winvm/lab/deploy-manifest.json \
       --toolchain \"\$(rustc --version)\""
   scp home-pc:winvm/lab/deploy-manifest.json ./deploy-manifest.json   # the trust anchor lives on the Mac
   ssh home-pc 'sha256sum ~/winvm/lab/bin/rmasscan-lab'                 # cross-check against the manifest
   ```

   The manifest records `commit`, the installed path and the binary's `sha256` and size. Rebuild
   and re-record whenever the commit changes: a manifest for another commit is refused.

4. **Guest.** Build `wire_scan.exe` on the guest from the same commit (`git archive`,
   `RMASSCAN_SOURCE_COMMIT=$COMMIT`, release, static CRT); `run.json`'s `source_commit` is checked
   against `--commit`. Do not copy any guest script by hand: the suite deploys all seven
   (`windows-vm-lab.ps1` to `C:\Users\lab\`, the `windows_wire_*` files to `C:\Users\lab\t4\`).
   The suite creates `~/winvm/t4-ev` on home-pc itself; `C:\Users\lab\t4` must already exist on the
   guest because the script copy targets it before `windows_wire_prepare.ps1` runs.

5. **Run the suite.** Run it from the REPOSITORY ROOT of a clean checkout of `$COMMIT` (not from
   `rmasscan/`): every relative path below, including `--out`, `--fixtures`, `--repo .` and
   `./deploy-manifest.json` from step 3, is relative to that directory. Build the Mac binary from the
   same checkout first, `(cd rmasscan && RMASSCAN_LAB_BUILD_COMMIT=$(git rev-parse HEAD) cargo build --locked --release -p rmasscan-lab)`, which puts it
   at `rmasscan/target/release/rmasscan-lab`. The suite records that binary's sha256, the commit and a
   dirty flag of `--repo` (the orchestrator build) in the manifest and each preflight record, and
   `windows-verify` reports it; it refuses to start when it cannot establish them. `--repo` is a
   checkout that contains `--commit`. Before the first remote mutation the suite

   - refuses a missing `--deploy-manifest`, a manifest for another commit or another
     `--remote-lab` path;
   - reads the seven guest scripts with `git show COMMIT:rmasscan/scripts/...` (not from a
     compile-time path), stages them under `<out>/deploy/guest-scripts/` and records their hashes;
   - hashes the remote binary with `sha256sum` and refuses it unless that value is listed in the
     manifest; nothing has been swept, copied or started at that point;
   - after copying, hashes every script again on the guest and refuses on any difference;
   - reads both clocks (`date -u +%s.%N` on home-pc before and after the guest reading, so the
     round trip is part of the margin) and refuses unless the guest is at most 5 s ahead of and at
     most 60 s behind home-pc. These are the limits `record-guest` enforces on the Verify report, so
     the first gate would fail anyway; fix time sync, do not relax the limits.

   ```sh
   rmasscan/target/release/rmasscan-lab windows-suite \
     --out docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional-r2 \
     --suite functional-r2 --plan functional --commit $COMMIT --repo . \
     --guest-exe 'C:\Users\lab\t4\wire_scan.exe' \
     --fixtures docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional/fixtures \
     --remote-lab /home/a1/winvm/lab/bin/rmasscan-lab --deploy-manifest ./deploy-manifest.json
   ```

   Evidence of the preflights is written into the output directory: `deploy/deploy-manifest.json`
   (a copy), `deploy/guest-scripts/*` (the exact bytes sent) and `deploy/preflight-<run>.json`
   (commit, manifest hash, remote binary hash, script hashes, the measured clock offset and its
   uncertainty). A rerun into the same directory adds one more preflight file.

6. **sudoers: nothing to configure.** On 2026-10-24 the user `a1` on home-pc had `NOPASSWD: ALL`,
   so `sudo -n <rmasscan-lab> vm-lab ...`, `sudo -n ip netns exec wvp-n2 <rmasscan-lab> peer ...`,
   `sudo -n tcpdump`, `sudo -n kill` and the dead-man `sudo -n sh -c 'exec timeout ...'` the suite
   issues all work without a rule. If the grant is ever narrowed, those command shapes are the
   ones to allow; the suite fails closed (exit 2 or 10) when `sudo -n` asks for a password.

7. **Fixtures are reused.** Both parts use `functional/fixtures` of the acceptance directory
   (original pinned masscan `8e6b3b0`, binding identical for the Windows runs and the C oracle),
   passed with `--fixtures`. The suite copies them to `<out>/fixtures/` so each new directory is
   self-contained; do not re-capture the oracle for a rerun.

8. **Evidence layout** (all under `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/`):

   ```
   functional/           part A, first run (capture_schema 1); kept unchanged
   functional-r1-smoke/  one smoke run of the round 1 orchestrator; kept unchanged
   functional-r2/        part A rerun:  --suite functional-r2 --plan functional   (24 runs)
   failure-r1/           part B:        --suite failure-r1    --plan failure      (18 runs)
     manifest.json  fixtures/  runs/<tag>/  runs_discarded/  deploy/  verdict.json
     README.md      MANIFEST.sha256
   verification/         build and test logs of the commit under test
   ```

   Write `verdict.json` with `rmasscan-lab windows-verify --dir DIR --out DIR/verdict.json`, then
   `README.md` (commit, hashes from the deploy manifest, verdict counts, anything INVALID and why)
   and finally `MANIFEST.sha256` (`shasum -a 256` over every file of the directory). Replace
   personal paths in text files with `$HOME`/`$REPO`; do not touch pcaps.

   Caveat for part A in `functional/`: its runs predate the nonce chain, so the guest Verify leg of
   its raw-run gate is unproven per run (the verifier treats them as capture_schema 1). Only
   `functional-r2/` and `failure-r1/` carry the proof (capture_schema 3).

Cleanup after an aborted suite: `rmasscan-lab windows-suite --cleanup --suite ID` stops every
recorded remote process (pid and start time must match) and removes the suite's scratch directory.
