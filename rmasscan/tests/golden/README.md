# Golden fixtures from the pinned C masscan oracle

Source of truth: masscan commit `8e6b3b0c07a81e8ea61d557c06134a21a6881614`
(version 1.3.9-integration), built on Ubuntu 26.04.1 x86_64 (see `manifest.json`).

Regenerate: copy `rmasscan/scripts/build-oracle.sh` to the oracle host and run
`bash ~/rmasscan-oracle/build-oracle.sh`, then copy the results back with the exact command below.
This README is hand-written and not generated, so the copy-back must exclude it:

    rsync -a --delete --exclude README.md minipc:rmasscan-oracle/golden/ rmasscan/tests/golden/

The script refuses to run if HEAD differs from the pin, and runs every masscan
invocation inside a fresh network namespace (`unshare -rn`, or `sudo unshare -n` when
AppArmor blocks user namespaces). No packet can leave the host.

Layout
- `manifest.json`: provenance and one record per fixture (`file`, `mode`, `args`,
  `line_count`, `sha256`, `truncated`, ...). `args` are the exact masscan arguments.
- `listscan/`: `-sL` stdout. Each case was run twice and the output hashes matched. Includes edge cases
  for tiny ranges (blackrock_init special-cases ranges 0-8): `single_ip_p80_seed1` (1 target),
  `slash31_p80_seed1` (2), `range3_p80_seed1` (3), and `ipv6_slash126_p80-443_seed1`
  (`[addr]:port` format). The 65,536-port edge case is `slash30_allports_seed1`
  (262,144 lines, truncated).
- `echo/`: `--echo` and `--echo-all` stdout (`<case>.conf`, `<case>.all.conf`). Every case
  pins `--seed`: without it masscan prints a random seed.
- `paused/`: real `paused.conf` files written on SIGINT from `--offline` runs.
  The `resume-index` is timing dependent: parse and compare fields, do not hash-compare.

Truncated fixtures: outputs over 1 MiB are stored as `<case>.head.txt` (first 2000 lines).
Compare the first 2000 lines directly, and `line_count` plus `sha256` (of the full stdout)
by streaming the Rust output.

Offline caveat: at the pinned commit `--offline` fails on Linux ("bad packet template":
the offline adapter has link type 0, the IPv6 template writes AF_INET6=10, the parser
accepts only 24/28/30). The `paused/` captures and `offline_gen_pps` therefore come from a
copy with a one-line patch (offline adapter link type = Ethernet), recorded as
`offline_binary_sha256`. `-sL` and `--echo` use the unpatched pinned binary.

`offline_gen_pps` is wall-clock based (`/usr/bin/time -v`, 2^28 targets) on the CPU in
`offline_gen_bench.cpu_model`; compare Rust only on the same hardware.

Binary hashes: `binary_sha256` and `offline_binary_sha256` identify the build artifacts
produced on the oracle host and are not reproducible (`__DATE__`/`__TIME__` are embedded by
print_version, main-conf.c:101). Provenance is the pinned git HEAD; the hash only ties the
fixtures to the exact binary that made them. Each manifest case has a `binary` field
(`pinned` or `offline-patched`) and all records share one key set (absent values are null).
