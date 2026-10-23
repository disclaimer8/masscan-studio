# Benchmarks

## Stage 1 exit criterion: offline generation >= 80% of C

Result: **met**. Rust median 2,894,249 pps vs C oracle 2,843,897 pps, ratio **1.018**
(threshold 0.80).

### Oracle (C masscan)

`tests/golden/manifest.json` -> `offline_gen_pps` = 2,843,897, from
`offline_gen_bench`: 2^28 targets in 94.39 s wall clock (includes process start,
exit and the 1 s receive-thread wait at `transmit_thread` start, main.c:224).

```
masscan 0.0.0.0/4 -p80 --rate 100000000 --offline --interface lo \
  --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 \
  --router-mac 66-55-44-33-22-11 --source-port 40000 --seed 1 --wait 0
```

### Hardware

minipc: Intel Pentium Silver N6005 @ 2.00 GHz, 4 cores, Ubuntu 26.04 (Linux
7.0.0-38, x86_64). Same machine as the oracle. rustc/cargo 1.99.1 installed via
rustup (minimal profile, `--no-modify-path`) under `~/.cargo`.

### Rust measurement

Method: `tests/offline_gen.rs::offline_generation_meets_80pct_of_oracle`
(`#[ignore]`, release only). It builds `0.0.0.0/4`, port 80 (2^28 packets), then
times `generate()` from `tests/common/offline_gen.rs`:

- `Throttler` (`SystemClock`, rate 1e8) driven like main.c:292: `next_batch` when
  the batch is exhausted, one decrement per packet;
- `transmit_scan` (index, BlackRock shuffle with seed 1 / 14 rounds, pick);
- `syn_cookie_ipv4` per packet, then `TcpSynTemplate::build_syn` into a reused `Vec`;
- no send step (offline `rawsock_send_packet` is a no-op).

Timing covers only the generation loop (not process start or target setup), so it
is slightly favourable to Rust (about 1 s of startup in the C figure, about 1%);
the 80% threshold is far from that effect.

Commands (from the repo root):

```
rsync -a --delete --exclude target rmasscan/ minipc:rmasscan-bench/
ssh minipc 'cd ~/rmasscan-bench && ~/.cargo/bin/cargo test --release \
  -p rmasscan-core --test offline_gen -- --ignored --nocapture'
```

| Run | Seconds | pps | Ratio vs oracle |
|-----|---------|-----------|-----|
| 1 | 93.544 | 2,869,619 | 1.009 |
| 2 | 92.734 | 2,894,668 | 1.018 |
| 3 | 92.748 | 2,894,249 | 1.018 |
| median | 92.748 | 2,894,249 | 1.018 |

### Other

- `cargo bench -p rmasscan-core` runs a plain timed loop (3 runs of `/10`, 2^22
  packets), not criterion: criterion =0.8.2 pulls `alloca` -> `cc` into the dev
  graph (`cargo tree -e normal,build,dev -p rmasscan-core`), which breaks the
  no-C rule. The /10 workload is not comparable to the oracle; on an Apple
  arm64 Mac it gives about 5.7 M pps (informational only, different hardware).
- The ordinary `cargo test` runs only `small_workload_generates_every_target`
  (/24, 256 packets) to keep the pipeline compiled and correct.
