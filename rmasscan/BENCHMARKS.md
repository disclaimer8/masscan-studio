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
bench host, `A` and `B` are the two commits compared, `A = B` for a noise check;
`$LOG` is a scratch directory). Each tree is shipped with `git archive` into its
own directory and built into its own target directory. Five pairs run in ABBA
order (a.1 b.1, b.2 a.2, a.3 b.3, b.4 a.4, a.5 b.5; pair i is a.i and b.i), each
run pinned to one core with `taskset -c 3`, and before every run the one-minute
load average must be below 0.3 (waiting at most 30 minutes):

```
for t in a b; do
  if [ "$t" = a ]; then c=$A; else c=$B; fi
  git archive "$c:rmasscan" | ssh "$BENCH_HOST" "rm -rf ~/rmasscan-bench-$t && mkdir ~/rmasscan-bench-$t && tar -x -C ~/rmasscan-bench-$t"
  ssh -n "$BENCH_HOST" "cd ~/rmasscan-bench-$t && CARGO_TARGET_DIR=~/rmasscan-bench-$t-target ~/.cargo/bin/cargo test --locked --release -p rmasscan-core --test offline_gen --no-run"
done
for pair in '1 a b' '2 b a' '3 a b' '4 b a' '5 a b'; do
  set -- $pair; i=$1
  for t in $2 $3; do
    ssh -n "$BENCH_HOST" 'for n in $(seq 180); do awk "{exit !(\$1 < 0.3)}" /proc/loadavg && exit 0; sleep 10; done; exit 1'
    ssh -n "$BENCH_HOST" "uptime; cd ~/rmasscan-bench-$t && CARGO_TARGET_DIR=~/rmasscan-bench-$t-target taskset -c 3 ~/.cargo/bin/cargo test --locked --release -p rmasscan-core --test offline_gen -- --ignored --nocapture --test-threads=1; s=\$?; uptime; exit \$s" > "$LOG/$t.$i.log" 2>&1
  done
done
```

The reference implementation of this loop, with all failure checks, is the
`bench-gate.sh` script of the native-core plan (G-bench).

Each run prints `OFFLINE_GEN` (the 2^28 loop above) and `OFFLINE_CURSOR` (the same
2^28 workload through `ProbeCursor`: `preload(64)`, `advance_sent_n`, no throttler).
Per row: medians `mA`, `mB` of the five runs, the ratio `mB/mA` and the five paired
ratios `B_i/A_i`; the `sink` values of A and B must be equal. `cargo bench --locked -p
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

- `cargo bench --locked -p rmasscan-core` runs plain timed loops, not criterion (four loops, three
  runs each: `offline_gen`, `cursor_1port`, `cursor_16port`, `cursor_mapped`):
  criterion =0.8.2 pulls `alloca` -> `cc` into the dev
  graph (`cargo tree -e normal,build,dev -p rmasscan-core`), which breaks the
  no-C rule. The workloads are not comparable to the oracle; on an Apple
  arm64 Mac `offline_gen` gives about 5.7 M pps in earlier measurements (informational only,
  different hardware).
- The ordinary `cargo test` runs only `small_workload_generates_every_target` and
  `small_cursor_workload_covers_every_target` (/24, 256 packets each) to keep the pipelines compiled and correct.

### Native-Rust phase 1, rmasscan-core

Paired measurements on the bench host, one row per task (method above). `A` is the
last accepted code commit, `B` the commit under test; load average is the lowest
and highest one-minute value in the logs; Mac medians are the medians of nine
`cargo bench` runs per loop (offline_gen / cursor_1port / cursor_16port /
cursor_mapped).

| task | A | B | OFFLINE_GEN mA / mB | ratio (pairs) | OFFLINE_CURSOR mA / mB | ratio (pairs) | load avg | sinks | Mac medians (4 loops) | decision |
|------|---|---|---------------------|---------------|------------------------|---------------|----------|-------|-----------------------|----------|
| 2 (base, A/A) | dcacd335 | dcacd335 | 2,820,742 / 2,824,016 | 1.001 (1.011, 1.002, 1.005, 1.000, 0.995) | 2,297,714 / 2,306,204 | 1.004 (1.064, 1.002, 1.005, 0.995, 1.006) | 0.24-1.62 (before runs 0.24-0.42) | equal (gen 34223905032, cursor 576472178750522997) | 8,228,928 / 6,989,610 / 6,543,468 / 5,123,407 pps | 5-pair ABBA, taskset -c 3: median ratios within 1.5 %, one pair (cursor pair 1, 1.064) outside 0.97-1.03 |
| 2 (base, A/A, 3-pair, superseded) | 280f5c42 | 280f5c42 | 2,788,995 / 2,753,925 | 0.987 (0.971, 1.028, 1.002) | 2,307,003 / 2,279,264 | 0.988 (0.988, 0.977, 1.008) | 0.23-1.76 (before runs 0.23-0.29) | equal (gen 34223905032, cursor 576472068694419045) | 8,784,776 / 7,455,047 / 6,904,995 / 5,451,513 pps | A/A noise exceeds 1 % |
| 3 (BlackRock round mask) | dcacd335 | c7a5bdf2 | 2,833,915 / 2,895,265 | 1.022 (1.021, 1.024, 1.017, 1.023, 1.027; B faster in 5 of 5) | 2,299,627 / 2,354,378 | 1.024 (1.030, 1.017, 1.033, 1.011, 1.031; B faster in 5 of 5) | 0.24-1.56 | equal (gen 34223905032, cursor 576472178750522997) | 8,140,773 / 6,492,735 / 6,298,843 / 4,983,702 pps | принято (правило пользователя от 2026-11-16: 5/5 пар и ≥ 1,5 %) |
| 4 (BlackRock, 8 lanes in transmit and -sL) | 78708334 | 1d42d281 | 2,902,783 / 4,138,287 | 1.426 (1.425, 1.423, 1.426, 1.426, 1.427; B faster in 5 of 5) | 2,358,896 / 2,337,374 | 0.991 (0.992, 0.989, 0.991, 0.987, 0.991; B faster in 0 of 5) | 0.23-1.60 (before runs 0.23-0.43) | equal (gen 34223905032, cursor 576472178750522997) | 24,415,410 / 6,802,696 / 6,258,419 / 5,027,618 pps | принято (5/5 пар и mB/mA ≥ 1,03; CURSOR без регрессии ≥ 0,97, ProbeCursor не менялся; первый прогон ворот оборвался перед b.5 на сбросе ssh и повторён целиком) |
| 5 (ProbeCursor on the shuffled stream with lookahead) | 1d42d281 | 22796d29 | 4,118,288 / 4,028,330 | 0.978 (0.992, 0.964, 0.978, 1.002, 1.002; B faster in 2 of 5) | 2,318,355 / 3,159,177 | 1.363 (1.363, 1.362, 1.365, 1.339, 1.363; B faster in 5 of 5) | 0.24-1.91 (before runs 0.24-0.81) | equal (gen 34223905032, cursor 576472178750522997) | 24,092,636 / 14,313,596 / 13,358,071 / 8,114,255 pps | принято (CURSOR: 5/5 пар и mB/mA ≥ 1,03; GEN без регрессии ≥ 0,97, пара 2 0,964 при load 0,81 перед b.2) |
| 6a (ProbeCursor reuses probe buffers) | 22796d29 | f7c82137 | 4,116,946 / 4,166,895 | 1.012 (1.059, 1.008, 0.795, 1.003, 1.013; B faster in 4 of 5) | 3,076,896 / 3,712,251 | 1.206 (1.174, 1.174, 1.223, 1.218, 1.202; B faster in 5 of 5) | 0.24-0.29 before runs (3.08 after b.3) | equal (gen 34223905032, cursor 576472178750522997) | 24,188,070 / 18,610,127 / 15,931,286 / 9,414,841 pps | принято (CURSOR: 5/5 пар и mB/mA ≥ 1,03; GEN без регрессии ≥ 0,97, пара 3 0,795: b.3 шёл при скачке нагрузки хоста, uptime после прогона 3,08; OFFLINE_GEN у A 22796d29 равен 4,12 M, а не 4,03 M) |
| 6b (sorted delivery table, `MODE=bench`, per-log median of three runs; loops offline_gen / cursor_1port / cursor_16port / cursor_mapped) | f7c82137 | 033c4e2a | 4,159,624 / 4,153,365; 3,678,797 / 3,666,602; 3,351,866 / 3,357,495; 2,646,297 / 2,643,735 | 0.998; 0.997; 1.002; cursor_mapped 0.999 (1.078, 0.999, 0.999, 0.964, 0.995; B faster in 1 of 5) | see left | см. слева | 0.25-0.72 before runs (1.23 highest in logs) | equal (offline_gen 534795568, 1port 9004079510931757, 16port 9009884609496714, mapped 9005616079306503) | 24,310,367 / 18,567,757 / 15,934,897 / 8,257,636 pps | отклонено (cursor_mapped 0,999 < 1,015; откат `git revert`) |
| 7 (IPv4 header checksum over a slice) | f7c82137 | 89ca3f7a | 4,161,160 / 4,130,700 | 0.993 (0.965, 1.005, 0.993, 1.001, 0.985; B faster in 2 of 5) | 3,715,345 / 3,696,015 | 0.995 (0.986, 1.001, 1.015, 0.993, 0.994; B faster in 2 of 5) | 0.24-1.80 (all uptime lines in the logs; each run waited for under 0.3 first) | equal (gen 34223905032, cursor 576472178750522997) | 24,438,723 / 18,892,726 / 16,170,922 / 9,524,463 pps (median of 27 runs per loop) | нейтрально — оставлено как идиома (без ускорения) |
