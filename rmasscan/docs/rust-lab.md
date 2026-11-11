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
   against `--commit`. Set `RUSTFLAGS='-C target-feature=+crt-static -C link-arg=/DEPENDENTLOADFLAG:0x800'`:
   a `RUSTFLAGS` variable replaces the DLL-search hardening in `rmasscan/.cargo/config.toml`, so it must
   repeat the link-arg (see `windows-wire-lab.md`, DLL search hardening). Check the built EXE with
   `dumpbin /loadconfig wire_scan.exe` (Dependent Load Flag `0x800`) and record the result. Do not copy any guest script by hand: the suite deploys all seven
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
     --remote-lab /home/<LAB_ACCOUNT>/winvm/lab/bin/rmasscan-lab --deploy-manifest ./deploy-manifest.json
   ```

   Evidence of the preflights is written into the output directory: `deploy/deploy-manifest.json`
   (a copy), `deploy/guest-scripts/*` (the exact bytes sent) and `deploy/preflight-<run>.json`
   (commit, manifest hash, remote binary hash, script hashes, the measured clock offset and its
   uncertainty). A rerun into the same directory adds one more preflight file.

6. **sudoers: nothing to configure.** On 2026-10-24 the user `<LAB_ACCOUNT>` on home-pc had `NOPASSWD: ALL`,
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
     --remote-lab /home/<LAB_ACCOUNT>/winvm/lab/bin/rmasscan-lab --deploy-manifest ./deploy-manifest.json
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
   a physical NIC: the VM ceiling with sendqueue is an OPEN finding for the physical NIC stage, never a FAIL; it never changes `overall`, which is PASS
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

### Part C with sendqueue

The Windows adapter sends through `pcap_sendqueue_transmit` in batches of at most `TX_BATCH_FRAMES`
(64) frames, one transmit per engine batch. Part C is rerun on that code into a new directory,
`perf-r2`, with the same twenty cells as `perf-r1` (rep-major, same ports, same fixtures), so the two
compare row by row. `--tx-mode sendqueue|single` (default `sendqueue`) is the TX path the verifier
must find in `identity.tx_mode`; it only records `tx_mode_expected` in `manifest.json` and does not
change what runs on the guest. A directory keeps the mode it was started with.

```sh
rmasscan/target/release/rmasscan-lab windows-suite \
  --out docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance-raw/perf-r2 \
  --suite perf-r2 --plan perf --tx-mode sendqueue --commit $COMMIT --repo . \
  --guest-exe 'C:\Users\lab\t4\wire_scan.exe' \
  --fixtures docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional/fixtures \
  --remote-lab /home/<LAB_ACCOUNT>/winvm/lab/bin/rmasscan-lab --deploy-manifest ./deploy-manifest.json
```

New `windows-verify` checks, all FAIL (behaviour) and applied only when the manifest has
`tx_mode_expected` (older directories such as `perf-r1` and `failure-r1` get no new check and keep
their verdicts) and only to scan reports (`status` ok with a `net` block):

- `identity.tx_mode` is present (absent: "harness predates sendqueue") and equals `tx_mode_expected`.
- `net.tx_over_budget == 0`, else "call budget breached". The counter counts driver calls over the 50 ms
  contract (`MAX_IO_TIMEOUT`), not over the 42 ms `IO_BUDGET`. It is measured by the Windows adapter; a `single` run does not measure it, so zero there is not evidence and is not asked for.
- For `perf.<rate>` cells with `rate >= 10000` under sendqueue: `net.tx_batches > 0` and
  `net.tx_batch_max <= identity.tx_batch_cap`, else "sendqueue claimed but no batch was transmitted".
- Wire sequence (perf cells, offline on the kept full pcaps): the SYNs in capture order must equal, byte for
  byte and in order, the frames of the cell's plan ("wire SYN sequence equals the plan's probe sequence").
  The expected sequence is generated with `rmasscan-core`'s `ProbeCursor` from the cell's own arguments
  (ports, targets, seed, source port, MACs, IPs and the same `--rate`, because the probe order rotates by
  the rate: `xXx = i + r * rate`). A Completed cell must match in full; a cell that ended early (RxLoss)
  must match a prefix. A difference is a behaviour FAIL; a missing or incomplete capture makes it INVALID.
  A directory without `tx_mode_expected` gets the result only as `notes.perf.wire_order_matches_plan`
  (report-only; `perf-r1` matches on every cell whose pcap is plain). This is the GO evidence that the
  batched sendqueue path neither reorders, drops, duplicates nor alters a frame. The rate-100 functional
  cases form only one-frame batches (no batch forms before about the 139th frame of a scan), so they do
  not exercise the batched path: perf proves the batching path, the functional cases against the C
  fixtures prove the bytes (and the order) of the generator.
- Unchanged: `tx_sent` equals the SYN count on the wire, order equals the fixture, exactly once.
  On a run with `tx_uncertain > 0` the wire rule is `tx_sent <= SYN on wire <= tx_sent + tx_uncertain`.

JSON fields: `identity.tx_mode`, `identity.tx_batch_cap`, `net.tx_batches`, `net.tx_batch_max`,
`net.tx_over_budget` in `run.json`; `notes.perf` of each cell carries `tx_batches`, `tx_batch_max`,
`tx_batch_cap`, `tx_over_budget`; `perf_summary.rows[].median` adds `tx_batch_max`.

GO rule for throughput (VM): `rate_gate` MET at 100, 1000 and 10000 pps, and the 100000 row recorded
as measured. The VM ceiling with sendqueue (about 16k to 37k pps in the spike, two VM speed modes)
does not reach 100k; that is an OPEN finding for the physical NIC stage, never a FAIL, and it never
changes `overall`.

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

## Autodetect suite

Приёмка живого скана CLI с автоопределением адаптера и шлюза идёт на тех же трёх запечатанных стендах, что и прежние
приёмки. Кейсы, их argv и ожидания определены в одном месте, в таблице верификатора (`autodetect_verify.rs`,
`CaseSpec`): suite пишет `argv.json` из `CaseSpec::argv()` и `expect.json` из `CaseSpec::expect()` как есть и своих
кейсов не определяет. Вердикт выносит офлайн `autodetect-verify` (без сети и процессов). INVALID и NOT RUN никогда не
повышаются. Кадр лаборатории на uplink/`eno1` или чужой SYN делает FAIL весь каталог. `windows-verify` отдаёт каталог,
манифест которого несёт ключ `autodetect` (или `plan: autodetect`), `autodetect-verify` целиком: вердикт,
`safety_trips`, отчёт и rc те же. Прежние каталоги (`functional-r3`, `perf-r1` и другие) этих ключей не имеют и
судятся прежним верификатором с прежними вердиктами.

**Пути и учётная запись.** `--out` (на Mac и место бинарников) — нейтральный путь без имени учётной записи, например
`mktemp -d /private/tmp/rmasscan-ad.XXXXXX` на Mac и `mktemp -d /tmp/rmasscan-ad.XXXXXX` на minipc; не scratch агента
(`/private/tmp/claude-<uid>/-Users-<имя>/…`) и не `$TMPDIR` (`/var/folders/…`). Первое окно macOS на `6c87e94` писало
`--out` в такой scratch, и имя попало в каждый `capture.json` (путь `-w` в `.work`). Теперь каждый suite (Linux,
macOS пользовательский и root, Windows) одним общим помощником (`capture::Scrubber`) пишет во всё, что попадает в
evidence (записи прогонов, `capture.json`, манифест, статусы, записи `deploy/`; на Linux ещё `suite.log`), свой
`--out` как `$OUT`, рабочий каталог как `$WORK` (Linux; на macOS и Windows это `$OUT/.work`), домашний каталог как
`$HOME`, а учётную запись, взятую один раз при старте (`$SUDO_USER`, если задан и не `root`, иначе `$USER`; `root` не
заменяется), как `$USER`. `autodetect-verify` в любом текстовом файле evidence находит, кроме `/Users/ИМЯ`,
`/home/ИМЯ`, `\Users\ИМЯ`, ещё формы через дефис `-Users-ИМЯ`, `-home-ИМЯ` (в начале имени: `on-home-pc` не путь) и
корни scratch одного пользователя `claude-<цифры>` и `/var/folders/` (в том числе `/private/var/folders/`): INVALID
с именем файла. `$OUT`, `$WORK`, `$HOME`, `$USER` и нейтральные абсолютные пути (`/private/tmp/rmasscan-ad.<x>/…`)
он принимает.

**Прерванные попытки.** Попытка, не ставшая прогоном, остаётся как `runs_aborted/<tag>.<run id>/` (прерванный
прогон; на Windows и NOT RUN preflight). `autodetect-verify` перечисляет каждую запись `runs_aborted/` в `aborted`
вердикта (тег, кейс, вид, файлы). Кейс прогоняется в один `--out` один раз, поэтому кейс с такой попыткой не бывает
PASS: прогон рядом с ней — INVALID (он не единственный прогон кейса), без прогона кейс NOT RUN. Запись, которая не
`<плановый тег>.<run id>`, делает каталог INVALID. Захваты попыток судит `safety_scan`, как и прежде. Все три suite
отказывают (NOT RUN, до любого изменения стенда и любого удалённого шага) кейсу, у которого в `--out` уже есть
`runs/<tag>` или `runs_aborted/<tag>.*`; повтор идёт в новый `--out`.

| Стенд | Команда | Кейсы |
| --- | --- | --- |
| Linux netns (minipc) | `scripts/wire-lab.sh --suite autodetect` запускает внутри `autodetect-suite linux` | `l01`–`l12` |
| Windows VM `n2` (home-pc) | `windows-suite --plan autodetect` | `w01`–`w08b` |
| macOS `feth` (Mac) | `autodetect-suite macos`, `--root-case` | `m01`–`m07`, `m10`–`m11`; см. `macos-feth-lab.md`, «Autodetect window» |

**Linux.** `wire-lab.sh --suite autodetect` поднимает прежний стенд из двух netns и делает в нём одно
контролируемое изменение, только внутри netns сканера: IPv4 `198.18.0.1/24` на `veth-a`, маршрут по умолчанию
`via 198.18.0.2 dev veth-a` и постоянные соседские записи `198.18.0.2–.5 → 02:aa:00:00:00:02`. Seal-проверки и
`capture isolation --mode autodetect` подтверждают ровно это до каждого прогона и после него (`isolation.json` и
`isolation-post.json` прогона, верификатор судит оба). Отмена: cleanup скрипта удаляет обе netns и записывает это в
`OUT/teardown.json` (`lab_id`, `namespaces_deleted`, `namespaces_left`; netns считаются по точному имени).
`lab_id` — id лаборатории: скрипт берёт его при старте из `/proc/sys/kernel/random/uuid` и передаёт suite
(`--lab-id`, suite пишет его в `manifest.json`). `autodetect-verify` требует запись в каталоге Linux: нет записи,
она не читается, netns осталась или её `lab_id` не равен `lab_id` манифеста — INVALID (запись чужой лаборатории не
закрывает эти прогоны). Если suite не смог скопировать прогон в каталог evidence, он оставляет рабочий каталог
прогона и метку `OUT/.work/work-kept.txt`, и cleanup тогда `OUT/.work` не удаляет. `OUT`, где уже есть вывод
прежней лаборатории (`manifest.json`, `runs/`, `runs_aborted/`, `teardown.json`, `.work/`), скрипт не принимает
(FATAL, rc 2): каждая лаборатория идёт в новый `--out`.
Скрипт сам перезапускает себя через `sudo -n`; suite `sudo` не вызывает. `--out` всегда вне репозитория, в
нейтральном каталоге без имени учётной записи (см. «Пути и учётная запись»), в репозиторий каталог попадает только
шагом «Evidence в репозиторий» ниже. Из каталога `rmasscan/` экспорта коммита на minipc:

```sh
cargo build --locked --release -p rmasscan-lab -p rmasscan-cli
OUT=$(mktemp -d /tmp/rmasscan-ad.XXXXXX)/autodetect-out/linux-r1
RMASSCAN_LAB_BIN=$PWD/target/release/rmasscan-lab bash scripts/wire-lab.sh --suite autodetect \
  --oracle "$HOME/rmasscan-oracle/masscan/bin/masscan" --rmasscan target/release/rmasscan --out "$OUT"
target/release/rmasscan-lab autodetect-verify --dir "$OUT" --out "$OUT/verdict.json"
```

**Windows.** `rmasscan.exe` собирается на госте так же, как `wire_scan.exe` в шаге 4 раздела «Deployment»: тот же
`git archive` коммита, release, статический CRT, тот же `RUSTFLAGS` с `/DEPENDENTLOADFLAG:0x800`. Отличие одно:
`cargo build --locked --release -p rmasscan-cli` вместо `-p rmasscan-net --example wire_scan`. Затем `dumpbin /loadconfig rmasscan.exe`
(флаг `0x800`) и копия в `C:\Users\lab\t4\rmasscan.exe`. Шаги 1–3 и 5 те же. `--out` — вне репозитория, в
нейтральном каталоге без имени учётной записи (там же `.work` оркестратора: после аварии в нём может остаться
полный гостевой `--iflist`). Команды из корня репозитория:

```sh
OUT=$(mktemp -d /private/tmp/rmasscan-ad.XXXXXX)/autodetect-out/windows-r1
rmasscan/target/release/rmasscan-lab windows-suite --list --plan autodetect   # девять кейсов, ничего не запускает
rmasscan/target/release/rmasscan-lab windows-suite \
  --out "$OUT" \
  --suite windows-r1 --plan autodetect --commit $COMMIT --repo . \
  --guest-exe 'C:\Users\lab\t4\rmasscan.exe' \
  --remote-lab /home/<LAB_ACCOUNT>/winvm/lab/bin/rmasscan-lab --deploy-manifest ./deploy-manifest.json
rmasscan/target/release/rmasscan-lab windows-verify --dir "$OUT" --out "$OUT/verdict.json"
```

План `autodetect` проходит каждый кейс через прежние шаги wire_scan-планов:

- ворота: гостевой Verify с nonce, `record-guest`, `status-pre.json`;
- слушатели пира `80,443,8000-8007`, молчащий `8099`;
- захваты `lab0` (пир) и `eno1` (интерлок, код 13);
- тот же гостевой runner: `windows_wire_run.ps1`, для `w08a` и `w08b` `windows_wire_runas.cmd` под ограниченным
  токеном (два отдельных запуска runner: `--iflist` и скан);
- `status-post.json`, хэши pcap на home-pc до копирования.

Своё у плана:

- `--guest-exe` обязан называть `rmasscan.exe`, `--suite` обязателен. `--fixtures` не нужен: если он дан, он не
  читается и не копируется. `--rerun` и `--tx-mode` отклоняются (NOT RUN): кейс прогоняется в один `--out` один раз,
  повтор идёт в новый `--out`.
- runner получает `rmasscan.exe` и argv кейса из таблицы (`runner-argv.json` в каталоге прогона). Опций `wire_scan`
  нет, `run.json` из JSON-строки stdout не строится (у `rmasscan` её нет).
- Перед `w01` и `w06` после ворот тем же runner идёт preflight `rmasscan --offline` с теми же целями
  (`runner-preflight-argv.json`, `preflight.txt`). Живой кейс идёт, только если preflight показал
  `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`. Иначе кейс NOT RUN (код 2), и ни слушатель, ни
  захват, ни скан не запускаются. Это не прерванный прогон: удалённый scratch (отчёт ворот и маркер, захвата нет)
  удаляется на home-pc, а не копируется домой, и маркер в evidence не попадает. Записи ворот и `preflight.txt`
  остаются в `runs_aborted/<tag>.<run id>/work/`; каталог — NOT RUN, не INVALID. Если удалить scratch не удалось,
  маркер остаётся, и следующий старт отказывает. Повторный `--only <tag>` в тот же `--out` отклоняется (NOT RUN до
  любого удалённого шага), а прогон кейса рядом с такой попыткой верификатор считает INVALID.
- Гостевые файлы переносятся как `guest-stdout.txt`, `guest-stderr.txt`, `guest-exit.txt`. Код ограниченного
  runner переносится как `guest-runner-rc.txt` (`.rc` не входит в allowlist). `detected.json` — разбор
  `guest-stderr.txt` парсером верификатора.
- `w07` и `w08a` (`--iflist`): гостевой `stdout.txt` (полный список интерфейсов гостя) копируется в рабочий
  каталог оркестратора `<out>/.work/<tag>.<run id>/`, а не в каталог прогона. Там он редуцируется в `iflist.json`
  (`rc`, число строк, sha256, строка `Ethernet 2`) тем же правилом, что у Linux и macOS, и сразу удаляется.
  `guest-stdout.txt` не создаётся.
- `capture.json`: запись suite плюс поля `capture dump` (`valid`, `invalid_reasons`, `pcap_sha256`, `pcap_frames`).
  Их считает правило полноты свидетеля (`dump::problems`): маркеры, статистика tcpdump, дельта дропов `lab0`, окно
  счётчиков, тишина, выход tcpdump.
- Прогон пишется в `<out>/.work/` и попадает в `runs/<tag>` только целиком, через `hashes-before-copy.txt` и
  проверку копии правилом верификатора. Прерванный прогон: удалённый scratch уходит в
  `runs_aborted/<tag>.<run id>/` (прежний путь, с маркером и pid-файлами: каталог после этого INVALID), часть
  оркестратора — туда же в `work/`. Непустой `.work` останавливает следующий старт; что не удалось удалить из
  `.work`, suite называет строкой `WARN`.
- Манифест: `"autodetect": "windows"`, `exe.build` `Rust static CRT rmasscan CLI from code_commit`, `binding` по
  кейсу (ожидаемое обнаружение из `expect.json`). Полей `oracle`, `pause`, `tx_mode_expected` нет. Скрипты гостя
  проходят только через `.work`, их хэши записаны в `deploy/preflight-<run>.json`. Пути под домашним каталогом в
  манифесте, статусах, `capture.json` и `deploy/` заменены на `$HOME`, `--out` на `$OUT`, учётная запись оркестратора
  на `$USER`. Поэтому копия `deploy/deploy-manifest.json`
  уже не совпадает с исходным файлом: в `deploy/preflight-<run>.json` `deploy_manifest_sha256` — хэш исходного
  `--deploy-manifest` на этой машине, `deploy_manifest_copy.sha256` — хэш копии в каталоге. В каждом прогоне
  `guest-runner.json` обязан назвать `--guest-exe` (`exe`) и sha256 из манифеста (`exe_sha256`); продолжение
  каталога с другим `rmasscan.exe` отклоняется.

**Каталог прогона** `runs/<tag>/`:

| Стенд | Файлы |
| --- | --- |
| все | `argv.json`, `expect.json`, `peer.pcap`, `capture.json`, `hashes-before-copy.txt`; скан и отказ: `detected.json`; `--iflist`: `iflist.json` вместо stdout |
| Linux | `stdout.txt`, `stderr.txt`, `exit.txt`, `peer.err`, `isolation.json`, `isolation-post.json`; `l11_parity`: `oracle/{stdout,stderr,exit}.txt`, `oracle.pcap`, `oracle-capture.json`, `oracle.err`; `l12_iflist`: `oracle/iflist.json` |
| Windows | `guest-stdout.txt` (не у `w07`, `w08a`), `guest-stderr.txt`, `guest-exit.txt`, `eno1.pcap`, `eno1.err`, `peer.err`, `status-pre.json`, `status-post.json`, `guest-verify*.json`/`.txt`, `listeners.json`, `runner-argv.json`, `guest-runner.json`, `nic.json`, `meta.json`, `pcap-hashes-on-home-pc.txt`, `run-artifacts.json`; `w01`, `w06`: `preflight.txt`, `runner-preflight-argv.json`; `w08a`, `w08b`: `guest-runner.log`, `guest-runner-rc.txt` |
| macOS | `stdout.txt`, `stderr.txt`, `exit.txt`, `peer.err`, `uplink.pcap`, `uplink.err`, `status-pre.json`, `status-post.json`, `alf.txt`, `listeners.json`; `m05`: `preflight.txt`, `preflight-argv.json` |

В корне каталога Linux ещё `teardown.json` (отмена стенда, см. выше). Файлы evidence несут только расширения
`json pcap txt log err sha256 md`. Полный вывод `--iflist` не хранится нигде, ни у `rmasscan`, ни у оракула (masscan
печатает список на stderr; `l12_iflist` с `oracle/stdout.txt` или `oracle/stderr.txt` — INVALID). `oracle/iflist.json`
редуцируется так же, как у `rmasscan`, со строкой стенда в форме masscan (` N  veth-a \t(…)`); её нет или она не
называет `veth-a` — INVALID, к ней те же правила приватности, что к строке `rmasscan`. Кадр на захвате
стенда (пир, оракул) с MAC, который не равен ни MAC сканера, ни MAC пира стенда (маркеры не в счёт), — FAIL
безопасности в любом кейсе. На macOS `capture.json` обязан сводить `privacy_filter` с захватом: `frames_kept` равно
числу кадров `peer.pcap`, `frames_kept + frames_dropped` — `unfiltered.pcap_frames`, иначе INVALID.

**Evidence в репозиторий** (план, задача 7, «Evidence»). Каталог из `$SCRATCH` копируется в
`docs/experiments/2026-10-27-rmasscan-autodetect-acceptance-raw/<linux-r1|windows-r1|macos-r1|macos-root-r1>` только
так, на Mac из корня репозитория. Каталог Linux сначала забирается с minipc; путь на minipc пишется целиком (`$OUT`
и `$SCRATCH` Mac — не пути minipc), и `.work` проверяется там, до копии:

```sh
LINUX_OUT=/home/<LAB_ACCOUNT>/<scratch>/autodetect-out/linux-r1   # --out на minipc, буквально
ssh minipc "test ! -e '$LINUX_OUT/.work'" || echo "STOP: minipc kept $LINUX_OUT/.work (an unfinished copy)"
rsync -a minipc:"$LINUX_OUT"/ "$SCRATCH/autodetect-out/linux-r1"/
```

Затем для каждого каталога (`NAMES` — имена хостов и учётных записей всех машин, через которые каталог прошёл, без
учётной записи гостя `lab`, которая разрешена):

```sh
names() { tr -d '\r' | grep -vx lab | paste -sd'|' -; }
NAMES=$( { hostname -s; id -un; } | names )   # Mac: macos-r1, macos-root-r1
# linux-r1:   NAMES="$NAMES|$(ssh minipc 'hostname -s; id -un' | names)"
# windows-r1: NAMES="$NAMES|$( { ssh home-pc 'hostname -s; id -un'; ssh -J home-pc -p 2222 lab@127.0.0.1 hostname; } | names )"
SRC=$SCRATCH/autodetect-out/windows-r1   # каталог --out (linux-r1: забранная копия)
DST=docs/experiments/2026-10-27-rmasscan-autodetect-acceptance-raw/windows-r1
test ! -e "$SRC/.work" || test -z "$(ls -A "$SRC/.work")" || echo "STOP: $SRC/.work is not empty (an unfinished copy)"
for d in "$SRC"/runs/*/ "$SRC"/runs_aborted/*/; do
  [ ! -d "$d" ] || (cd "$d" && shasum -a 256 -c --quiet hashes-before-copy.txt) || echo "STOP: $d"
done
grep -ralwE "$NAMES|_tcp\.local|_udp\.local" "$SRC" && echo "STOP: privacy"   # каждый файл, pcap тоже (-a): 0 совпадений
mkdir -p "$DST" && rsync -a --exclude .work "$SRC"/ "$DST"/
for d in "$DST"/runs/*/ "$DST"/runs_aborted/*/; do
  [ ! -d "$d" ] || (cd "$d" && shasum -a 256 -c --quiet hashes-before-copy.txt) || echo "STOP: $d"
done
rmasscan/target/release/rmasscan-lab autodetect-verify --dir "$DST" --out "$DST/verdict.json"   # тот же вердикт
```

Любой `STOP` — копия не делается или удаляется. Совпадение privacy-скана смотрят глазами: настоящее имя — копии нет;
случайное совпадение короткого имени (`<LAB_ACCOUNT>`) в байтах pcap записывается в `README.md` каталога. Дальше `MANIFEST.sha256`, `README.md` каталога и `verification/`,
как в плане. `.work` в репозиторий не попадает никогда (он не в `.gitignore`).

**Коды.** `autodetect-verify --dir DIR [--out FILE]` (и `windows-verify` для такого каталога): 0 PASS, 1 FAIL,
2 INVALID или NOT RUN. `autodetect-suite`: 0 все выбранные прогоны выполнены, 2 NOT RUN, 10 ABORT, 13 ISOLATION
BREACH, 130 INTERRUPTED. `windows-suite --plan autodetect` — коды `windows-suite` из таблицы «Exit codes of
`windows-suite`» выше; NOT RUN (2) ещё и у preflight, который не показал ожидаемое обнаружение. Код suite говорит только о том, выполнены ли прогоны.
PASS или FAIL выносит верификатор.

**`RMASSCAN_EXPECT_DEFAULT_ROUTE`.** Офлайн-тесты `cargo test --locked --workspace` читают настоящую таблицу маршрутов
(`rmasscan-cli/tests/detect_readonly.rs`, только чтение, без кадров). С `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` ожидания
строгие: первый маршрут по умолчанию обязан идти через шлюз, у `8.8.8.8` обязан быть маршрут, и `--offline` не может
отказать с `NoRoute`. Так запускают на хостах с известным маршрутом по умолчанию: dev Mac без VPN, minipc, гость Windows. Без переменной (CI)
тесты терпимы к хосту без такого маршрута. Строгий режим на Mac предполагает, что маршрут по умолчанию не идёт через
VPN `utun`.

**Строка статуса.** С этапа форматов вывода живой скан CLI пишет в stderr строку статуса masscan (`rate:…\r`, в конце
77 пробелов и `\r` перед `[+] finished`; после первого Ctrl-C — `waiting several seconds to exit...` и 44 пробела).
`autodetect-verify` читает stderr так, как его показывает терминал: видимый текст строки — то, что после её последнего
`\r`; каждый фрагмент перед `\r` обязан быть формой статуса по собственной копии грамматики лаборатории
(`autodetect_verify.rs`, `screen`), иначе это ошибка разбора, а не пропущенная строка. Вердикты закоммиченных
каталогов autodetect от этого не меняются.

## Output suite

Живой паритет форматов вывода (спека `2026-11-06-rmasscan-output-formats-design.md` §6.2) идёт на том же стенде Linux,
что и autodetect: `wire-lab.sh --suite output` поднимает его так же (печать, `lab_id`, `teardown.json`, отказ от
`--out` прежней лаборатории) и запускает внутри `output-suite linux`. Кейсы `o01`–`o17` с argv и ожиданиями — одна
таблица верификатора (`output_verify.rs`, `OutputCase`); C-оракул идёт на кейсах с `oracle` (все форматы, `--show`,
`-oL -`, `--interactive`, `--readscan`), только rmasscan — `o12_nostatus` (с `--nostatus` masscan `8e6b3b0` висит
вечно, не дойдя до принудительного выхода: первая итерация цикла ожидания ждёт поток передачи, `main.c:1530`, а тот
крутится до `is_rx_done`, `main.c:470`, который выставили бы только вторая итерация, `main.c:1490–1491`, или ветка
статуса, `main.c:1518`), `o13_open_fail` и прерывания `o14`–`o16` (SIGINT процессу rmasscan через ~2 с,
30 с на выход, затем SIGKILL; время сигнала в `interrupt.json`). Каждый сканер работает в своём каталоге внутри
рабочего каталога прогона, поэтому файлы вывода в argv — относительные имена (`-oL output.txt`), а в evidence они
лежат байт в байт под нейтральными именами `output.txt`/`output.bin` (оракул — в `oracle/`). `o17_readscan` читает
оба `-oB` из `runs/o06_binary` того же `--out` (без него suite отказывает до запуска). Вердикт выносит офлайн
`output-verify` (0 PASS, 1 FAIL, 2 INVALID или NOT RUN): записи C и rmasscan равны после маски времени, заголовки —
после маски часов, время записей и часы заголовков в окне захвата, записи равны ответам стенда и ответам на проводе,
структура каждого формата, молчание stdout, строка статуса по грамматике, `sent` равен SYN на проводе, ноль кадров
сканера при отказе открытия файла и при `--readscan`; privacy — как у autodetect, плюс разбор `-oB` по записям.

**Подвал оракула.** masscan `8e6b3b0` не завершает ни один живой скан на этом стенде: его поток приёма не возвращается
на тихом линке, после окна ожидания он печатает `[-] Passed the wait window but still running, forcing exit...` и
выходит с 0 (main.c:1489–1496), не дойдя до `output_destroy`, поэтому в файлах оракула нет подвала (у JSON нет `]`).
С этой строкой в stderr оракула нехватка подвала ожидаема (`oracle_forced_exit` в заметках прогона), без неё — INVALID;
подвал, который оракул всё же записал, сравнивается. Подвал rmasscan обязан быть подвалом своего формата, построенным
из его же записей (XML `<hosts up down total>` по его open и closed). Байтовый паритет подвалов с C доказан офлайн
эталонами `--readscan` (`tests/golden/formats`).

```sh
cargo build --locked --release -p rmasscan-lab -p rmasscan-cli
OUT=$(mktemp -d /tmp/rmasscan-out.XXXXXX)/output-out/linux-output-r1
RMASSCAN_LAB_BIN=$PWD/target/release/rmasscan-lab bash scripts/wire-lab.sh --suite output \
  --oracle "$HOME/rmasscan-oracle/masscan/bin/masscan" --rmasscan target/release/rmasscan --out "$OUT"
target/release/rmasscan-lab output-verify --dir "$OUT" --out "$OUT/verdict.json"
```

## Scan-control suite

Живой паритет управления сканом (спека `2026-11-08-rmasscan-scan-control-design.md` §6.2) идёт на стенде autodetect:
`wire-lab.sh --suite scan-control` поднимает его так же, как `--suite output` (печать, `lab_id`, `teardown.json`, отказ от
`--out` прежней лаборатории, ловушка очистки на EXIT/INT/TERM, которая удаляет оба netns) и запускает внутри
`scan-control-suite linux`. Шесть кейсов `sc01`–`sc06` и их шаги (один запуск сканера каждый) с argv и ожиданиями это
одна таблица верификатора (`scan_control_verify.rs`, `steps`); у шага свой каталог `runs/<tag>/<шаг>/` с `argv.json`,
`stdout.txt stderr.txt exit.txt`, файлами сканера под нейтральными именами (`output.txt`, `output.json`, `paused.txt` это
его `paused.conf`, `scanner.pcap` это его `--pcap`), захватом пира (`peer.pcap capture.json peer.err`) и, у прерванного
шага, `interrupt.json`; на уровне кейса `expect.json`, `isolation.json`, `isolation-post.json`, `hashes-before-copy.txt`.
Шаги одной группы работают в одном рабочем каталоге (`--resume` находит `paused.conf` и файл вывода прерванного запуска),
остальные в разных. Вердикт выносит офлайн `scan-control-verify` (0 PASS, 1 FAIL, 2 INVALID или NOT RUN).

| Кейс | Шаги | Что доказывает | C-оракул |
|---|---|---|---|
| `sc01_shards_union` | `shard1`, `shard2`, `oracle` | `--shard 1/2` и `2/2` с одним `--seed` вместе шлют ровно все 12 SYN без пересечений, их находки вместе равны находкам одиночного прогона C, а порядок SYN оракула это два шарда вперемешку (`start = one - 1`, `increment = of`) | да, один полный прогон |
| `sc02_pause_wait_resume` | `pause`, `resume` | SIGINT через 3 с, строка Ctrl-C, `saving resume file to: paused.conf` до первого тика `waiting N-secs`, файл на диске в первую секунду, фаза `--wait 2` принимает поздний ответ (netem держит ответы пира 1 с, ответ после SIGINT попадает в `-oJ`), подвал `]` закрыт; `resume-index` равен числу отправленных SYN; `--resume paused.conf` шлёт ровно остаток плана (один адаптер: точное мультимножество, ничего не потеряно и не отправлено дважды), файл дописан (`output-append`), оба документа вместе равны ответам стенда на все 80 зондов | нет: netem нужен для окна позднего ответа, а C не завершает живой скан на этом стенде |
| `sc03_retries` | `retries`, `oracle` | `--retries 2` шлёт каждый зонд `(2+1)^2 = 9` раз (три прохода индекса по три отправки, `main.c:421–431`), SYN совпадают с планом, мультимножество зондов равно оракулу, находки схлопнуты дедупликацией и равны оракулу | да |
| `sc04_packet_mods_and_pcap` | `mods`, `badsum` | `--ttl 42 --tcp-sackok --tcp-wscale 7`: в каждом SYN из захвата пира TTL 42, опции MSS 1460, SACK-permitted, wscale 7 с нулевым паддингом, верные чексуммы и длина; отдельный `--badsum`: L4-чексумма каждого SYN неверна при верной чексумме IPv4, пир не отвечает; файл `--pcap` самого сканера: точный заголовок, длины записей равны и не больше 1514, только кадры на наш ip:порт от пира, каждый кадр есть в захвате пира байт в байт, и в нём есть ответ от каждого адреса и порта, который ответил | нет: `--badsum` в C заглушка, опции TCP сверены с C офлайн-векторами |
| `sc05_infinite_interrupt` | `run` | `--infinite` шлёт больше одного полного прохода (каждый зонд минимум дважды, каждый полный проход это перестановка 12 зондов, первый проход равен плану), строка статуса формы `*` (`syn/s ack/s tcb-rate`), SIGINT: код 0, без `paused.conf`, файл вывода закрыт | нет: C не завершает живой скан на этом стенде |
| `sc06_dual_veth` | `dual`, `dual_pause`, `dual_resume` | `--adapter[0]` на `veth-a` и `--adapter[1]` на `veth-a2`: полный прогон это точное разбиение плана по чётным и нечётным индексам (каждый зонд один раз, ответы второго адаптера вернулись по второму линку); пауза и `--resume` по спеке §4.3: `resume-index` это минимум баз адаптеров (`2 x` отправленных на линк), **без потерь, дубли ограничены** (каждый зонд отправлен не более двух раз, адаптер, ушедший дальше минимума, повторяет только свои зонды; точное мультимножество не требуется), находки двух документов вместе равны ответам стенда на все 80 зондов | нет: C на втором линке не запускается |

**Второй линк.** Для `--adapter[1]` `wire-lab.sh --suite scan-control` создаёт внутри тех же двух запечатанных netns
вторую пару veth (`veth-a2` в netns сканера, `veth-b2` сразу в netns пира; MAC `02:aa:00:00:00:03` и `:04`): без адреса
на любом конце, с маршрутом `/32` на `198.18.0.6` и постоянным соседом только на конце пира (`198.18.0.6` назначен
никакому интерфейсу, rmasscan берёт его через `--adapter-ip[1]`), tx-offload выключен, IPv6 выключен. Обе пары исчезают с
двумя netns в той же ловушке очистки; интерфейс хоста не создаётся, не меняется и не перечисляется. Печать
(`capture isolation --mode scan-control`) судит основной стенд как раньше, затем требует ровно `lo` и две veth в каждом
netns, второй линк без мастера, без маршрутов на конце сканера и с единственным маршрутом `198.18.0.6/32` на конце пира;
запись несёт `mode: scan-control` и `second_link`, и на неё опираются suite и верификатор. У каждого шага с двумя
линками два свидетеля (`peer.pcap` на `veth-b`, `peer2.pcap` на `veth-b2`, у каждого свой стартовый маркер со стороны
сканера и свои конечные).

**Окно позднего ответа (`sc02`).** Ядро пира отвечает SYN-ACK мгновенно, поэтому на шаге `pause` suite ставит в netns
пира `tc qdisc add dev veth-b root netem delay 1000ms` (меньше `--wait 2`) и снимает задержку после остановки свидетеля;
`netem.json` хранит факт. Ответы на SYN последней секунды перед SIGINT приходят уже в фазе ожидания, и верификатор
требует, чтобы хотя бы один такой ответ (по времени на проводе позже SIGINT) был в файле, а весь файл равен ответам на
все отправленные SYN. Если `tc` или модуль netem недоступны, suite отказывает (NOT RUN) до запуска сканера. `paused.conf`
«до ожидания»: suite опрашивает каталог сканера каждые 50 мс после сигнала и пишет первый момент, когда файл появился,
в `interrupt.json`; верификатор требует не позже секунды после сигнала при ожидании в 2 с и порядок строк в stderr.

**Подвал оракула.** Как у output suite: C не завершает живой скан (`[-] Passed the wait window but still running, forcing
exit...`, код 0), поэтому в файле оракула нет подвала; с этой строкой в его stderr это ожидаемо (`oracle_forced_exit` в
заметках), без неё INVALID. Сравнение с оракулом идёт по множествам находок и по порядку и мультимножеству зондов на
проводе, не по подвалу.

**Охранные правила** (код suite, как у output suite): только root внутри `wire-lab.sh`; стенд фиксирован (`--iface-a
veth-a`, `--iface-b veth-b`, MAC стенда, `--ns-a` и `--ns-b` безопасные и разные, `--lab-id`); `isolation.json`
`wire-lab.sh` обязан подтверждать запечатанный стенд scan-control (режим, маршрут по умолчанию только через пира, вторая
пара); любая цель из argv таблицы вне `198.18.0.0/24` это отказ до запуска; печать перед каждым кейсом и после него
(после него провал это ABORT, прогон остаётся в `runs_aborted/`); бинарники не меняются между кейсами; кейс идёт один
раз в один `--out`; SIGINT уходит процессу rmasscan, а не группе suite; оболочка выполняет одну постоянную строку
(`cd "$0" && exec "$@"`). Privacy: тот же разбор, что у autodetect и output (адреса, MAC, имена хостов, домашние пути,
имена интерфейсов только `veth-a`, `veth-a2`, `veth-b`, `veth-b2`), попадание это INVALID.

```sh
cargo build --locked --release -p rmasscan-lab -p rmasscan-cli
OUT=$(mktemp -d /tmp/rmasscan-out.XXXXXX)/scan-control-out/linux-scan-control-r1
RMASSCAN_LAB_BIN=$PWD/target/release/rmasscan-lab bash scripts/wire-lab.sh --suite scan-control \
  --oracle "$HOME/rmasscan-oracle/masscan/bin/masscan" --rmasscan target/release/rmasscan --out "$OUT"
target/release/rmasscan-lab scan-control-verify --dir "$OUT" --out "$OUT/verdict.json"
```

## Protocols suite

Живой паритет протоколов IPv4 (спека `2026-11-08-rmasscan-protocols-ipv4-design.md` §6.2) идёт на стенде autodetect:
`wire-lab.sh --suite protocols` поднимает его так же, как `--suite scan-control` (печать, `lab_id`, `teardown.json`, отказ от
`--out` прежней лаборатории, ловушка очистки на EXIT/INT/TERM) и запускает внутри `protocols-suite linux`. Нужен
`--rmasscan`. Пять кейсов `p01`–`p05` и их шаги это одна таблица верификатора (`protocols_verify.rs`, `CASES` и `steps`):
на каждый выходной документ кейса один шаг rmasscan и один шаг C-оракула с тем же argv, у каждого свой захват пира
(`peer.pcap`) и свой перезапущенный ответчик. Argv всех кейсов: `198.18.0.2-198.18.0.5 <флаги> [<-oX> <файл>] [--show open,closed]
--seed 1 --rate 100 --wait 3 --source-port 40000`; фиксированный порт источника делает зонды двух сканеров побайтно
сравнимыми (cookie нагрузки UDP, initiate tag SCTP, id ICMP и `ip_id` зависят от него). Вердикт выносит офлайн
`protocols-verify --dir DIR [--out FILE]` (0 PASS, 1 FAIL, 2 INVALID или NOT RUN).

| Кейс | Флаги | Документы | Что доказывает |
|---|---|---|---|
| `p01_ping` | `--ping` | `-oL` | Echo Request обоих сканеров побайтно равны плану и друг другу, найдены все четыре пира, у каждого Echo Reply код 0 |
| `p02_udp_payloads_and_closed` | `-sU -p53,161,500,59999` | `-oJ`, `-oB` | встроенные нагрузки DNS (53), SNMP (161), ISAKMP (500) и 0 байт на 59999 равны плану и зондам оракула; UDP 53 и 161 `open`, 500 и 59999 `closed` по ICMP 3/3 |
| `p03_sctp_init_ack_abort` | `-sZ -p2905,2906` | `-oB`, `-oL` | INIT побайтно равны плану и оракулу (CRC-32C); INIT-ACK на 2905 `open`, ABORT на 2906 `closed` |
| `p04_arp_scan` | `--arp` | интерактивный stdout, `-oB` (тип 8) | четыре 42-байтовых who-has и ни одного ARP к шлюзу, `[+] router-mac = ff-ff-ff-ff-ff-ff (given)`, все соседи с MAC пира |
| `p05_mixed_protos` | `-pT:80,U:53,S:2905,I:0` | `-oJ` | одна выборка с записями tcp, udp, sctp и icmp |

**Как отвечают пиры.** TCP 80 и 8080 открыты (слушатели ответчика), остальные порты закрыты; Echo и ARP отвечает ядро
пира. UDP 53 и 161 отвечает ответчик лаборатории (`capture responder --udp-ports P,.. --udp-ips A,..`): по сокету на адрес
пира и порт (сокет на `0.0.0.0` отвечал бы с первичного адреса), один ответ `UDP_REPLY` на датаграмму. Закрытый порт
UDP получает ICMP 3/3 ядра пира; Linux ограничивает такие ответы (по умолчанию `icmp_ratemask` 6168), поэтому
`wire-lab.sh --suite protocols` ставит `net.ipv4.icmp_ratemask=0` только в netns пира (запись в `commands.txt`, значение
умирает вместе с netns, хост не меняется). SCTP: в ядре minipc модуль SCTP не загружен, SCTP-инструментов нет, поэтому
INIT на линке пира отвечает ответчик лаборатории (`--sctp-iface IF --sctp-open P,..`, один поток, `protocols_verify::sctp_reply`):
INIT-ACK на 2905 и ABORT на остальных портах в форме Linux (RFC 9260 §8.4: бит T 0, initiate tag INIT как verification
tag, CRC-32C), только для целого INIT на свой MAC. Это не стек ядра. Ядро пира без SCTP шлёт ещё ICMP 3/2 на каждый INIT,
оба сканера его игнорируют. Модуль не загружается и не выгружается нигде. Если в ядре хоста SCTP есть, ядро ответило бы
ABORT рядом с ответчиком: suite отказывает до запуска чего-либо (NOT RUN), p03 и p05 не выполняются; остальные кейсы
выбирает `--only` у `protocols-suite`. `peer-stack.json` кейса хранит `icmp_ratemask`, `icmp_echo_ignore_all`,
`sctp_in_kernel` и аргументы ответчика; значения не стенда делают кейс INVALID.

**Что судит верификатор.** Зонды rmasscan равны плану продукта (`ReadyPlan` и курсор, по порядку, по разу); зонды
оракула равны зондам rmasscan того же документа побайтно и по порядку (перестановка BlackRock). Стенд на каждый зонд
отвечает ровно тем одним ответом, которого требует его форма; иначе INVALID для обоих сканеров, не FAIL. Документ
разбирается в байтовых формах C (`-oL`, `-oJ`, `-oB` типов 6, 7 и 8, интерактивные строки) и сравнивается с записями
своего провода. stderr rmasscan: код 0, молчащий stdout при файле, только строки `[+]` и формы строки статуса,
`[+] finished: Completed, sent N, replies R, open O` равно числу зондов и различных ответов на проводе. Файл оракула
может быть без подвала только при строке `[-] Passed the wait window but still running, forcing exit...` в его stderr (так
было в каждом шаге r3 и r4), файл rmasscan обязан быть целым.

**Порядок записей (поправка П9 спеки).** Зонд за зондом порядок побайтно тот же, что у C. Стенд не может дать двум
прогонам один порядок ответов: оба сканера шлют на `--rate 100` по несколько зондов подряд, и внутри такой пачки ответчик
(поток на каждый сокет UDP и на линк SCTP) и ядро пира отвечают в порядке, который меняется от прогона к прогону. Поэтому
документ каждого сканера судится по порядку ответов своего провода, а записи rmasscan равны записям C как мультимножество,
поле в поле без времени (`notes.record_order_vs_c`: «те же записи в том же порядке», «в другом порядке» или «другие
записи»). Внутри своего провода действует окно `REPLY_REORDER_WINDOW_US` = 50 мкс: пару записей, ответы которых сняты на
линке пира не дальше 50 мкс друг от друга, документ может записать в любом порядке. Промежуток меряется по захвату и
округляется до микросекунды; ровно 50 мкс внутри окна, 51 мкс уже нет (граничный тест
`the_reply_order_window_is_50_us_and_a_pair_exactly_50_us_apart_is_inside`). Окно покрывает гонку двух CPU: ответ
ответчика и ответ ядра пира в микросекундах друг от друга доходят до сокета сканера в любом порядке (живые r2 и r3 на
прежнем окне: 5 и 7 мкс). Соседние зонды пачки уходят до около 0,25 мс друг от друга, поэтому окно в 50 мкс требует
порядок ответов и внутри пачки, кроме таких гонок. До итогового ревью этапа окно было 1 мс и внутри пачки на практике
допускало почти любую перестановку. Пара дальше окна проваливает шаг rmasscan (FAIL) и делает INVALID шаг оракула, с
промежутком в микросекундах в деталях. `notes.reply_order_swaps` шага: `pairs`, сколько пар записано в обратном порядке
внутри окна, и `largest_gap_us`, наибольший промежуток среди них (`null` без таких пар). Сверка с C точная: запись,
которую документ rmasscan потерял или записал дважды, проваливает ровно сверку со своим проводом и сверку с C этого
документа (тест `the_stands_reply_order_may_differ_between_the_two_runs_of_a_document`), а другой TTL одного ответа,
записанный так, как он пришёл, проваливает одну сверку с C. Порядок записей в писателях rmasscan закреплён и офлайн-тестами.
В r4 (код `82f0483`) ни один из 16 шагов не записал такую пару в другом порядке (`pairs` 0 везде), хотя на линке пира
в 13 шагах есть соседние ответы не дальше 50 мкс друг от друга (32 пары, ближайшие 4 мкс).

**Кадры стороны сканера.** Каждый кадр с MAC сканера, не являющийся зондом, обязан быть из четырёх названных классов
(`SCANNER_CLASSES`) и не превышать границу числа кадров на шаг; иначе проверка проваливает шаг rmasscan и делает INVALID
шаг оракула (в деталях `<класс> N of at most M`, границы в `notes.scanner_frames.<шаг>.at_most`):
- `next_hop_who_has`: 60-байтовый ARP who-has `198.18.0.2` от резолвера, только в сканах не ARP; не больше 10 у rmasscan
  (`ARP_TIMEOUT / ARP_INTERVAL`) и 12 у C (`stack-arpv4.c:175-187`);
- `rst_to_syn_ack`: RST без других флагов на SYN-ACK пира; не больше одного на кадр SYN-ACK стенда у rmasscan (RST шлёт
  только ядро netns сканера, своего пути RST у rmasscan нет), у C ещё по одному на различный SYN-ACK: собственный
  `tcp_send_RST` C идёт только после его дедупликации (`main.c:1067–1068`, затем `main.c:1095`), повтор SYN-ACK получает
  сброс одного ядра. До итогового ревью этапа граница C была два на кадр SYN-ACK и пропускала второй сброс C на повтор;
- `port_unreachable_to_udp_reply`: ICMP 3/3 ядра сканера на ответ UDP пира, не больше одного на ответ;
- `protocol_unreachable_to_sctp_reply`: ICMP 3/2 ядра сканера на INIT-ACK или ABORT пира, не больше одного на ответ.
Любой другой кадр (`unexplained`) тоже проваливает шаг.

**Названные отклонения.** Отличия rmasscan от C применяются по имени, а не мягким сравнением; у каждого своя проверка
провода («стенд не мог задействовать»), число случаев идёт в `notes.deviations`: `udp-checksum-ffff` (П6, пары зондов,
равных только по этому правилу, при верной сумме `0xFFFF`), `icmp-echo-code-0` и `rx-checksum-verify` (П5: у всех Echo
Reply код 0 и у всех ответов верные суммы), `non-tcp-dedup` (повторы UDP и SCTP у C схлопываются перед сравнением,
никогда не TCP, Echo и ARP), `sctp-tcp-fallthrough` (флаги чанка SCTP ни SYN-ACK, ни RST, `main.c:920–922`),
`arp-mac-ethernet-source` (MAC записи ARP это Ethernet-источник, `proto-arp.c:39`). В r3 и r4 все шесть условий выполнены
и ни одно отклонение не сработало: живое окно показывает, что эти пути не изменили сравнение, но не упражняет дедупликацию
повторов, отбрасывание Echo с кодом не 0 и неверных сумм у rmasscan (это покрыто офлайн-тестами).

**`responder.json`.** Каждый шаг пишет его в момент окончания сканера:
`{"exited_with": null, "killed_by_signal": null, "state_unknown": null, "stderr": ""}`, если ответчик работал. Иначе
заполнено ровно одно из трёх полей: код выхода, сигнал, который его завершил, или почему его состояние не прочитано (у suite
нет его дескриптора; `try_wait` вернул ошибку, с её текстом). До итогового ревью этапа все три случая писались одним
`exited_with: -1`. Такой ответчик называется в вердикте (INVALID, «the peer responder was not seen running when the
scanner ended (it exited with N | it was killed by signal N | its state is unknown (...)): <stderr>»); ответчик, не
ставший готовым, называется в причине NOT RUN теми же словами. Отдельно: упавший ответчик
завершает всех своих рабочих сразу, ошибка уходит в `responder.err.txt` шага.

**Охранные правила** как у scan-control: только root внутри `wire-lab.sh`, стенд фиксирован, любая цель вне `198.18.0.0/24`
это отказ до запуска, печать до и после каждого кейса, кейс идёт один раз в один `--out`; проверяются `foreign_syns`,
`no_foreign_frame` и `foreign_probes` (любой кадр TCP, UDP, ICMP, SCTP или ARP who-has сканера вне стенда, в том числе в
захватах прерванных попыток). Privacy: как у autodetect, имена тегов кейсов маскируются перед разбором (`p02_udp_…`
иначе читается как метка DNS-SD `_udp`), адреса записей `-oB` обязаны быть адресами стенда.

```sh
cargo build --locked --release -p rmasscan-lab -p rmasscan-cli
OUT=$(mktemp -d /tmp/rmasscan-out.XXXXXX)/protocols-out/linux-protocols-r1
RMASSCAN_LAB_BIN=$PWD/target/release/rmasscan-lab bash scripts/wire-lab.sh --suite protocols \
  --oracle "$HOME/rmasscan-oracle/masscan/bin/masscan" --rmasscan target/release/rmasscan --out "$OUT"
target/release/rmasscan-lab protocols-verify --dir "$OUT" --out "$OUT/verdict.json"
```

## IPv6 suite

TCP SYN поверх IPv6 (Р3: только TCP) на стенде autodetect; код и офлайн-тесты есть, живого окна ещё не было (7b).
`wire-lab.sh --suite ipv6` сначала выключает IPv6 везде, как для прочих наборов (строки `disable_ipv6=1` общие и не
менялись), затем только для этого набора включает его на `veth-a`, `veth-b` и `lo` двух netns: без DAD, без RS/RA,
без форвардинга, link-local по EUI-64 (`IPV6_SETTINGS` = `capture::IPV6_SYSCTLS`). Сканер `fd00:198:18::1/64`, пиры
`fd00:198:18::2`-`::5/64`, IPv6-маршрут сканера по умолчанию через link-local пира `fe80::aa:ff:fe00:2` (NS rmasscan
идёт с глобального адреса на link-local роутера), постоянные соседи IPv6 с обеих сторон, затем ожидание 3 с.
Печать `capture isolation --mode ipv6`; ответчик слушает 80 и 8080 и на IPv6 (`capture responder --tcp6-ips`); suite
читает IPv6 сторон перед стартом и перед каждым кейсом (`ipv6-stack.json`), адрес tentative это NOT RUN.

Ожидается, подтвердить в 7b: ядра сторон во время шага не шлют NS (их предотвращают постоянные соседи; NS ядра
сканера отличался бы целью и временем и назван `scanner_ns_for_peer`), отчёты MLD о новых группах кончаются за
3 с ожидания, пир отвечает на NS ровно одним NA формы Linux (S|O, TLLA), C принимает argv и шлёт те же SYN.

| Кейс | Документы | Что доказывает |
|---|---|---|
| `v01_ndp_and_tcp6_syn` | `-oJ`, `-oB` | 1-10 NS резолвера (столько, сколько в `(ndp: N requests`) для `fe80::aa:ff:fe00:2`, SYN равны плану и C |
| `v02_mixed_v4_v6` | `-oB` (6, 7, 10, 11), `-oL` | ARP и NDP; инвариант v4: байты IPv4-зондов равны плану только IPv4, IPv6 в нижних перемешанных индексах |
| `v03_explicit_router_mac_ipv6` | `-oJ` | `--router-mac-ipv6`: ни одного NS, зонды на заданный MAC |

Argv оракула это argv rmasscan плюс `--adapter-ip fd00:198:18::1` (C не берёт ULA источником) и
`--router-mac-ipv6 02-aa-00-00-00-02` (C ищет роутер RS/RA, Linux-пир RA не шлёт); цели IPv6 в скобках.
`ipv6-verify --dir DIR` (0 PASS, 1 FAIL, 2 INVALID или NOT RUN) судит по правилам протоколов (R4) общим кодом
`pair_verify.rs`: классы кадров сканера с границами (`SCANNER_CLASSES`), шум ядер `STAND_NOISE` с границей 0 (INVALID,
даже с MAC сканера), отклонения по имени (`ndp-ns-not-rs`, `oracle-source-given`, `ipv6-ttl-not-compared`,
`families-one-interface`, их условие проверяется на стороне оракула), TTL записей IPv6 с C не сравнивается.

```sh
OUT=$(mktemp -d /tmp/rmasscan-out.XXXXXX)/ipv6-out/linux-ipv6-r1
RMASSCAN_LAB_BIN=$PWD/target/release/rmasscan-lab bash scripts/wire-lab.sh --suite ipv6 \
  --oracle "$HOME/rmasscan-oracle/masscan/bin/masscan" --rmasscan target/release/rmasscan --out "$OUT"
target/release/rmasscan-lab ipv6-verify --dir "$OUT" --out "$OUT/verdict.json"
```

## Privacy scan before committing evidence

`rmasscan-lab privacy-scan --dir DIR [--forbid TOKEN]...` is a **mandatory step before any evidence directory is copied into
the repository**. It stands outside every verdict, so the verifiers' rules and the committed verdicts do not change. It
parses every `.pcap` and `.pcapng` under DIR and reports any mDNS (UDP 5353), LLMNR (5355) or NBNS (137) frame: a guest
OS announces its own host name on the lab NIC with them, and the pcap rules of `autodetect-verify` allow OS frames.
The names are decoded from DNS wire form (length-prefixed labels, compression pointers, names inside PTR/CNAME/NS/SRV
data, NetBIOS names) and printed masked (first three characters and an ellipsis) with the file and the frame number; a
text search for `_tcp.local` cannot find them. Every other file is searched as text, and every capture as raw bytes,
for the tokens given with `--forbid` (repeatable; the operator passes the real host names and accounts on the command
line, so no real name lives in the repository). A `--forbid` token shorter than 4 bytes is refused with exit 2 and a
message that does not print the token: a token that short matches unrelated bytes, such as pcap timestamps. In a
capture the raw-bytes search covers frame data only: pcap record headers are skipped; for pcapng it covers the
packet-block data plus every non-packet block (section and interface blocks, comments, interface names). A capture
that does not parse is searched whole. A hit prints the file, the line (`bytes` in a capture) and the token's number,
never the token. Exit codes: 0 without a hit, 1 on any hit, 2 on a refused argument. Run it on the pulled directory,
fix the stand or re-run on a hit, and copy only after a clean exit:

```sh
target/release/rmasscan-lab privacy-scan --dir "$OUT" --forbid "$(hostname -s)" --forbid "$USER" --forbid "$LABHOST"
```

## macOS (`feth` stand)

Build as above on the Mac. `macos-lab`, `macos-suite` and the live peer-side tools exist on macOS only (on
other systems `macos-suite` and `macos-lab` answer "macOS-only", rc 2). `macos-verify` is portable and works
on any host on a copied evidence directory.

| Command | What it does | Exit codes |
| --- | --- | --- |
| `macos-lab plan\|up\|status\|bpf-access\|link\|down` | the sealed `feth4201`/`feth4202` stand (the user runs the root ones) | see `macos-feth-lab.md` |
| `macos-suite --out DIR --suite ID --plan functional\|failure\|perf --commit SHA --repo PATH --wire-scan PATH --fixtures DIR [--run-id m1] [--manifest LAB_MANIFEST] [--reps N] [--rates CSV] [--only TAG ...] [--rerun] [--list] [--run-timeout S] [--remove-stale-lock]` | gated live runs, evidence per run in `DIR/runs/<tag>.<nonce>/` | 0 done, 2 NOT RUN, 10 abort, 11 rerun refused, 12 schema, 13 lab frame on the uplink, 130 interrupted |
| `macos-verify --dir DIR [--out FILE]` | offline verdict per run, per pause/resume group and for the directory | 0 PASS, 1 FAIL, 2 INVALID or NOT RUN |
| `oracle-fixtures --out DIR --peer-mac MAC [--src-mac MAC] --remote-lab /abs/path --host minipc` | independent pinned C oracle on minipc; `--src-mac` (default the Windows VM adapter MAC) sets the binding, `02:ac:00:00:00:01` for the Mac | 0 all valid |

Plans: `functional` (part A, same cases as Windows), `failure` (part B: the two `perm_denied` runs need
BPF denied and come first, the other 15 need it granted) and `perf` (part C: 100, 1000, 10000 and 100000
pps, five repetitions each, repetition-major; `--reps` and `--rates` select a subset and the rest of the
plan is then NOT RUN). The exact order of the commands is in `macos-feth-lab.md`.

Verdicts follow the Windows verifier: an incomplete capture is INVALID, a missing result is NOT RUN, a lab
frame on the uplink or a foreign SYN is a FAIL of the whole directory that no rerun discards, and the
evidence (`macos_capture_schema` 1, per run `capture_schema`) must carry the hashes taken before the copy.
`perf_summary` reports `rate_gate` MET (median within 20 percent), OPEN, or NOT RUN (fewer than three
Completed PASS cells); on `feth` this measures the kernel pair, not a physical NIC, and a 100k pps witness
that loses frames makes its cells INVALID rather than relaxing the gate.
