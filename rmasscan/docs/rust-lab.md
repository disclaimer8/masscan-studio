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
target/release/rmasscan-lab windows-suite --list --plan failure   # or functional, or perf
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

9. **Part C: performance (`--plan perf`).** Twenty runs: the rates 100, 1000, 10000 and 100000 pps,
   five repetitions each, ordered repetition by repetition (`perf.<rate>.r<rep>`, so slow drift of the
   VM spreads over the rates). Every cell scans only `198.18.0.2` with the functional binding and
   listeners, source port 40000, seed 1, wait 3, retries 0, ports `1-N` sized for about 5 s of
   sending: `1-500`, `1-5000`, `1-50000`, `1-65535` (the last is 0.66 s nominal; the VM may not reach
   it, which is what is measured). Each cell goes through the same raw-run gate as parts A and B
   (guest Verify with nonce, `record-guest`, full status, `raw_run_allowed`), peer and eno1 captures
   and capture schema 3; there is no fast mode. `--suite` is mandatory for this plan.

   ```sh
   rmasscan/target/release/rmasscan-lab windows-suite --list --plan perf   # the 20 tags, no remote action
   rmasscan/target/release/rmasscan-lab windows-suite \
     --out docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/perf-r1 \
     --suite perf-r1 --plan perf --commit $COMMIT --repo . \
     --guest-exe 'C:\Users\lab\t4\wire_scan.exe' \
     --fixtures docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional/fixtures \
     --remote-lab /home/a1/winvm/lab/bin/rmasscan-lab --deploy-manifest ./deploy-manifest.json
   ```

   Expected wall time: about 75 to 90 minutes. functional-r2 took 87 minutes for 24 runs, about
   3.6 minutes per run, almost all of it gate, setup and capture quiescence; 20 runs are about 72
   minutes, plus the sending (5 s at most per run), waits and the larger pcap transfers of the two
   fast rates. A failed or INVALID cell can be rerun alone with `--rerun --only perf.<rate>.r<rep>`
   (only if it is discardable, as for the other plans).

   The per-run timeout and the dead-man bound of the captures follow the cell: at least twice the
   nominal time (probes / rate + wait) plus 60 s of fixed overhead, never below `--run-timeout`
   (default 240 s).

   `windows-verify` gives each cell its own verdict and adds a `perf_summary` to `verdict.json`:

   - INVALID: any capture-completeness rule (tcpdump drops, captured != received, lab0 counter
     window, end marker, schema).
   - FAIL: a gate leg failed; eno1 saw a lab frame; a scanner SYN to anything but 198.18.0.2 or from the
     wrong MAC, IP or source port; on a proven-complete capture, SYNs on the wire != `tx_sent` or a
     Completed run with a probe missing or duplicated on the wire (on an incomplete capture these two
     are INVALID, not FAIL); a SYN after the outcome; an outcome other than `Completed` or
     `Failed(RxLoss)`; `Failed(RxLoss)` with zero or unknown kernel drops; `Completed` with
     non-zero or unknown kernel drops; or Completed results that differ from the listener truth.
     A gate-leg failure is FAIL here and therefore not rerunnable, while the same failure in part A or B
     is INVALID and rerunnable; in practice only status-post can reach it (a failed pre-run leg aborts the
     suite before the scanner starts, which leaves a discardable NOT RUN cell).
   - PASS otherwise. `Failed(RxLoss)` with measured drops above zero is a PASS (`rx_loss: true`):
     honest measured loss. Its results are not compared with the full listener truth, but they must be
     genuine (a subset of it, no foreign or duplicate entries), with the drop count consistent with
     `rx_health` and guest exit 3, the same check as the `rxloss` run of part B.

   `perf_summary.rows` has one row per rate: PASS/FAIL/INVALID/NOT RUN/rx_loss counts and the
   medians over the Completed PASS cells (every probe went out) of `steady_pps_wire` (from peer-pcap SYN timestamps),
   `steady_pps_inprocess`, `cpu_user_ms`, `cpu_kernel_ms`, `peak_working_set_bytes`, `join_ms` and
   `drain_s`. `rate_gate` is MET when the median wire rate is within 20 percent of the requested
   rate, OPEN otherwise, NOT RUN with fewer than 3 Completed PASS cells or no measured median. RxLoss PASS
   cells are counted (`rx_loss`) and reported separately (`rxloss_cells`, `rxloss_steady_pps_wire_median`);
   they never enter a median or the gate. It is a measurement of the VM, not of
   a physical NIC, and may stay OPEN until 2B-sendqueue; it never changes `overall`, which is PASS
   only if the manifest and all 20 cells are PASS. Per-cell metrics (`notes.perf` of each run in the
   verdict) also carry `transmitted_wire`, `tx_sent`, `rx_packets`, `kernel_drops`, received and
   peer-wire reply counts and `capture_valid`. Stop latency under load is not remeasured here: it is
   in the `stop_*` runs of `failure-r1`, and per-Npcap-call latency in the spike evidence
   `docs/experiments/2026-10-24-rmasscan-stage2b-windows-spike-raw`.

   Pcaps: the suite keeps every perf pcap in the evidence directory and never compresses or deletes a
   VALID one; size, frame count and sha256 are taken on home-pc before the copy. The 10000 and 100000
   pps cells have the largest pcaps (several MB each). For the repository copy, gzip the big ones
   afterwards (`gzip -9 -n runs/<tag>/peer.pcap`, the same as `failure-r1`) and say so in the
   README; to verify such a copy, work on a scratch copy and run `gunzip -k runs/*/peer.pcap.gz` there
   first, because the verifier reads `peer.pcap` and the recorded sha256 is that of the uncompressed file.

Cleanup after an aborted suite: `rmasscan-lab windows-suite --cleanup --suite ID` stops every
recorded remote process (pid and start time must match) and removes the suite's scratch directories except runs that still carry the keep marker (see below); those are reported.

### Exit codes of `windows-suite`

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | reserved |
| 2 | NOT RUN: refused before any remote change (bad option, lock held, preflight) |
| 10 | aborted (including an unreadable or unmeasured eno1 capture) |
| 11 | an ordinary rerun refused (the run is not discardable) |
| 12 | directory capture schema too old |
| 13 | isolation breach: a lab frame on eno1 (live interlock or abort path), or a safety finding in `--out` (start and `--rerun` refused) |
| 130 | interrupted (Ctrl-C / SIGTERM) |

### Safety findings, aborted runs, Ctrl-C and the suite lock

**Safety checks (final review I-1).** The verifier has a class of check that no other finding can
hide: an eno1 capture with any lab frame; any SYN that is not from the bound MAC and IP or not to
198.18.0.2; any scanner SYN during a refusal or restricted-token run. They need nothing but the two
pcaps, so they run before the meta, capture and run files are looked at. A tripped one makes the
run FAIL whatever else is INVALID or NOT RUN (a failed status-post, a lab0 drop, an incomplete
capture), so the run is never discardable, and `verdict.json` lists it in `safety_trips` and sets
`overall` to FAIL even when the run sits in `runs_discarded/` or `runs_aborted/`. `windows-suite`
refuses to start or `--rerun` in an `--out` that holds such a run (exit 13, the run is named); use
a new directory.

**Aborted runs (I-2).** When a run fails after the guest runner was invoked, the suite stops the
captures, reads the eno1 frame count on home-pc and judges it with the live interlock: a lab frame
exits 13, an unreadable or unmeasured capture exits 10 with the reason, a clean one leaves the run
NOT RUN (discardable). The interlock requires the eno1 tcpdump counters `received` and
`dropped_kernel` to be measured and zero as well as the frame count. The scratch is copied to
`runs_aborted/<tag>.<run id>/` after its sha256 sums were recorded on home-pc
(`abort-hashes-on-home-pc.txt`); the remote scratch stays and carries a `.abort-uncopied` marker
until the copy matches. The marker is written when the run's scratch is created, before anything can be
sent, so an orchestrator that dies or an ssh that fails after the send leaves the evidence marked too. A
successful run removes its scratch (marker included) after its copies were hash-checked; an aborted run
clears the marker only after the hash match, and not while the scratch holds a sub-directory. The
start-of-suite sweep and `--cleanup` never remove a marked run. A start that finds one deletes nothing and
starts no run: exit 13 when its `eno1.pcap` shows a lab frame, else exit 10 naming the run. Recovery: on
home-pc inspect the directory (`ls -l`, `tcpdump -nr eno1.pcap`), copy it home with
`scp -r home-pc:DIR OUT/runs_aborted/NAME`, compare `sha256sum` on both sides, `rm DIR/.abort-uncopied`,
start again. `--cleanup` keeps marked runs and lists them. An unproven eno1 (unreadable, unmeasured, kernel
drops) exits 10 even when the operator stopped the suite, so it is never reported as a plain interrupt (130). The verifier evaluates the safety checks on every `eno1.pcap` and `peer.pcap`
under `runs_aborted/`; an aborted run without pcaps changes nothing.

**Ctrl-C (M-1).** SIGINT and SIGTERM only raise a flag. The ssh children sit in their own process
group, so the terminal does not signal them. The suite then stops the run's remote tools through
an exec path that ignores the flag (otherwise it would kill its own cleanup), copies the evidence
as for any abort, TERMs every recorded process of the suite, waits 12 s (a TERMed link-loss tool needs
up to 10 s to put lab0 back up) and KILLs what is left. The exit code is 130 (10 or 13 when the eno1 evidence is unproven or shows a lab frame). The cleanup is about
20 ssh round trips plus the 12 s grace, one to three minutes over the jump chain: wait for it, a second
Ctrl-C does nothing and `kill -9` leaves the tools to their dead-man bounds. If the link is still
down afterwards (`vm-lab status` shows `raw_run_allowed` false and the next Verify fails closed),
bring it up by hand with any QMP client on home-pc, for example
`printf '{"execute":"qmp_capabilities"}\n{"execute":"set_link","arguments":{"name":"lab0","up":true}}\n' | socat - UNIX-CONNECT:$HOME/winvm/qmp.sock`.
The Linux `wire-suite` records an interrupted perf run as `partial: true` (never as a complete
matrix) and sends its stop-path signals without going through the helper that the stop flag kills.

**One suite at a time (M-3).** Every `windows-suite` invocation, `--cleanup` included, holds
`flock -n` on `~/winvm/t4-ev/.suite.lock` on home-pc for its whole run, through one ssh session whose
stdin stays open (a dead orchestrator closes it, so the lock cannot outlive it). A second invocation
(a smoke test during a long part, a retry from another terminal) is refused with exit 2 before it
changes anything. Without the lock its start-of-suite sweep would TERM and KILL the other run's captures,
listener and link-loss tool.

The lock session uses `ServerAliveInterval=15` and `ServerAliveCountMax=4`, so a dropped link is noticed
within a minute. A missing `flock` on home-pc exits 10 with its own message. If the lock is reported busy
and no suite is running, find the holder on home-pc with `fuser -v ~/winvm/t4-ev/.suite.lock` (or
`ps -eo pid,etime,args | grep '[.]suite.lock'`); it is a `sh` with a `cat` child left by a half-open ssh
session. Kill that `sh` (and the `cat`) and start again. Never kill the holder while a suite is running.
**Options (M-5).** Each subcommand accepts only its own options. An unknown option (`--pla perf`) or a
repeated one (`--only a --only b`; give all tags after one `--only`) exits 2 and names the option. The
commands in this document are parsed against the same lists by a unit test.

Known gap (M-6, deferred to the next Linux acceptance): `oracle-fixtures` still stages the scripts that sit
next to the checkout that built the binary (`CARGO_MANIFEST_DIR` at compile time). Build it from the
checkout under test, in a private target directory.
