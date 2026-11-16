# Benchmarks

## Stage 1 exit criterion: offline generation >= 80% of C

Result: **parity, about 0.96-0.99 loop for loop; the >= 80% criterion is met.**
Against the manifest figure (C wall clock, 2,843,897 pps) the Rust median of the
latest measurement is 2,882,526 pps (1.014), but that compares a bare loop with a
whole process, so the loop-for-loop ratio is the honest one (see below).

### Oracle (C masscan)

`tests/golden/manifest.json` -> `offline_gen_pps` = 2,843,897, from
`offline_gen_bench`: 2^28 targets in 94.39 s wall clock (whole process: start, exit and fixed sleeps).

```
masscan 0.0.0.0/4 -p80 --rate 100000000 --offline --interface lo \
  --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 \
  --router-mac 66-55-44-33-22-11 --source-port 40000 --seed 1 --wait 0
```

### Hardware

Bench host: Intel Pentium Silver N6005 @ 2.00 GHz, 4 cores, Ubuntu 26.04 (Linux
7.0.0-38, x86_64). Same machine as the oracle. rustc/cargo 1.99.1 installed via
rustup (minimal profile, `--no-modify-path`) under `~/.cargo`.

### Rust measurement

Method: `tests/offline_gen.rs::offline_generation_meets_80pct_of_oracle`
(`#[ignore]`, release only). It builds `0.0.0.0/4`, port 80 (2^28 packets), then
times `generate()` from `tests/common/offline_gen.rs`:

- `Throttler` (`SystemClock`, rate 1e8) driven like main.c:289: `next_batch` when
  the batch is exhausted, one decrement per packet;
- `transmit_scan` (index, BlackRock shuffle with seed 1 / 14 rounds, pick);
- `syn_cookie_ipv4` per packet, then `TcpSynTemplate::build_syn` into a reused `Vec`;
- no send step (offline `rawsock_send_packet` is a no-op).

Timing covers only the generation loop (not process start or target setup).
The C wall clock carries fixed overhead that the Rust figure does not: the 1 s
sleep at `transmit_thread` start (main.c:231), a 100 ms sleep (:1395), the 750 ms
end-of-scan poll (:1440), the 250 ms wait-loop sleep (:1513) and the post-loop
drain of 1000 x `usleep(100)` (:470-492). A two-point fit by the reviewer (2^28
vs 2^24 targets) puts the fixed overhead at 2.3-3.1 s, i.e. 2.4-3.3% of 94 s.
Removing it makes C about 2.91-2.94 M pps loop-only (2^28/(94.39-2.3) = 2,914,925
at the low end), so Rust is at parity.

Commands (the paired G-bench procedure; `$BENCH_HOST` is the ssh name of the
bench host, `A` and `B` are the two commits compared, `A = B` for a noise check).
Each tree is shipped with `git archive` into its own directory and built into its
own target directory; runs alternate A B A B A B, and before every run the
one-minute load average must be below 0.3:

```
for t in a b; do   # c = A for a, B for b
  git archive "$c:rmasscan" | ssh "$BENCH_HOST" "rm -rf ~/rmasscan-bench-$t && mkdir ~/rmasscan-bench-$t && tar -x -C ~/rmasscan-bench-$t"
  ssh -n "$BENCH_HOST" "cd ~/rmasscan-bench-$t && CARGO_TARGET_DIR=~/rmasscan-bench-$t-target ~/.cargo/bin/cargo test --locked --release -p rmasscan-core --test offline_gen --no-run"
done
# run i = 1..3, for t in a b, after the load check:
ssh -n "$BENCH_HOST" "uptime; cd ~/rmasscan-bench-$t && CARGO_TARGET_DIR=~/rmasscan-bench-$t-target ~/.cargo/bin/cargo test --locked --release \
  -p rmasscan-core --test offline_gen -- --ignored --nocapture --test-threads=1; uptime"
```

Each run prints `OFFLINE_GEN` (the 2^28 loop above) and `OFFLINE_CURSOR` (the same
2^28 workload through `ProbeCursor`: `preload(64)`, `advance_sent_n`, no throttler).
Per row: medians `mA`, `mB`, the ratio `mB/mA` and the three paired ratios
`B_i/A_i`; the `sink` values of A and B must be equal. `cargo bench --locked -p
rmasscan-core` adds the rows `offline_gen`, `cursor_1port`, `cursor_16port` and
`cursor_mapped` (`/10` x port 80, 4,194,304 probes, or `10.0.0.0/16` x `1-64` with a
65,536-entry destination map), three runs each, for the Mac ranking (G-mac).

The test refuses to run in debug and skips with a message if `/proc/cpuinfo`
reports a CPU different from the manifest's `offline_gen_bench.cpu_model`.

All runs (2^28 packets, bench host):

| Run | Measured code | Seconds | pps | vs manifest |
|-----|---------------|---------|-----|-------------|
| implementer 1 | c398f75 (rsync of working tree) | 93.544 | 2,869,619 | 1.009 |
| implementer 2 | c398f75 | 92.734 | 2,894,668 | 1.018 |
| implementer 3 | c398f75 | 92.748 | 2,894,249 | 1.018 |
| fix round 1 | 4dd24c8 (git archive), load 0.3-1.2 | 94.053 | 2,854,083 | 1.004 |
| fix round 2 | 4dd24c8 | 93.125 | 2,882,526 | 1.014 |
| fix round 3 | 4dd24c8 | 93.053 | 2,884,761 | 1.014 |
| reviewer, Rust | c398f75 (load 1.35-1.79) | 96.409 | 2,784,336 | 0.979 |
| reviewer, C | oracle binary, same window | 95.14 wall (92.26 user) | 2,821,478 | 0.987 Rust/C |

Median of the three 4dd24c8 runs: 2,882,526 pps. 4dd24c8 adds a per-packet
`black_box(&frame)` (the previous two-byte read did not keep stores alive under
LTO) and a no-op `on_target` hook; throughput did not drop. Runs vary by a few
percent with machine load. Wall clock against wall clock the ratios are 0.98-0.99
(reviewer, loaded window) and 1.01 (manifest). The conservative loop-for-loop
reading compares the reviewer's C user time (92.26 s) with the Rust loop time
(96.409 s) and gives about 0.955-0.963, which is consistent with the headline
"about 0.96-0.99".

### Other

- `cargo bench -p rmasscan-core` runs a plain timed loop (3 runs of `/10`, 2^22
  packets), not criterion: criterion =0.8.2 pulls `alloca` -> `cc` into the dev
  graph (`cargo tree -e normal,build,dev -p rmasscan-core`), which breaks the
  no-C rule. The /10 workload is not comparable to the oracle; on an Apple
  arm64 Mac it gives about 5.7 M pps (informational only, different hardware).
- The ordinary `cargo test` runs only `small_workload_generates_every_target`
  (/24, 256 packets) to keep the pipeline compiled and correct.

### Native-Rust phase 1, rmasscan-core

Paired measurements on the bench host, one row per task (method above). `A` is the
last accepted code commit, `B` the commit under test; load average is the lowest
and highest one-minute value in the logs; Mac medians are the medians of nine
`cargo bench` runs per loop (offline_gen / cursor_1port / cursor_16port /
cursor_mapped).

| task | A | B | OFFLINE_GEN mA / mB | ratio (pairs) | OFFLINE_CURSOR mA / mB | ratio (pairs) | load avg | sinks | Mac medians (4 loops) | decision |
|------|---|---|---------------------|---------------|------------------------|---------------|----------|-------|-----------------------|----------|
| 2 (base, A/A) | 280f5c42 | 280f5c42 | 2,788,995 / 2,753,925 | 0.987 (0.971, 1.028, 1.002) | 2,307,003 / 2,279,264 | 0.988 (0.988, 0.977, 1.008) | 0.23-1.76 (before runs 0.23-0.29) | equal (gen 34223905032, cursor 576472068694419045) | 8,784,776 / 7,455,047 / 6,904,995 / 5,451,513 pps | A/A noise exceeds 1 % |
