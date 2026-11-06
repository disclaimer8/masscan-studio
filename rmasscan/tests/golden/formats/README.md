# Output-format goldens from the pinned C masscan oracle

Offline parity for `-oL -oJ -oD -oG -oX -oB -oH -oU` (design §6.1,
`docs/superpowers/specs/2026-11-06-rmasscan-output-formats-design.md`). The C oracle
(masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`, binary sha256 in `manifest.json`, the
same build as `../manifest.json`) converted each input with `--readscan`; the test
`crates/rmasscan-cli/tests/formats_golden.rs` replays every case through `rmasscan_cli::run`
on the three CI operating systems.

## Regenerate

1. Inputs: `cargo run -p rmasscan-cli --example format_inputs -- DIR` (deterministic; the test
   fails if the generator and `inputs/` drift apart).
2. On the oracle host, in a fresh `mktemp -d /tmp/rmasscan-out.XXXXXX`, with DIR and
   `scripts/build-format-goldens.sh` copied there:
   `TMPDIR=$W bash build-format-goldens.sh --oracle <pinned masscan> --inputs DIR --out $W/golden`.
   The script checks the oracle sha256, refuses `/etc/masscan/masscan.conf`, runs every masscan
   invocation in `sudo -n unshare -n` (only a DOWN loopback), runs each case twice and requires both
   runs to agree after masking.
3. Copy `$W/golden/{manifest.json,services.txt,outputs}` here, keep `inputs/` and this README
   (hand-written), run the privacy grep over this directory, then delete `$W` on the host.

## Layout

- `inputs/*.scan.bin`: the `-oB` inputs, written by the rmasscan binary writer
  (`examples/format_inputs.rs`). `basic` (8 records: open/closed on 10.0.0.1, 10.0.0.2, 10.0.0.3,
  192.0.2.7, ports 80/443/8080/22), `edge` (ports 0, 65535 and 47001, TTL 0 and 255, flags 0, 0x04,
  0x12, 0x14, 0xFF, addresses 0.0.0.1 and 255.255.255.255, times on a single-digit day at the day
  boundaries), `empty` (header and footer only). `many` (70 000 records, 1 MiB) is not committed.
- `outputs/<case>.out`: what C wrote to the `-o?` file, byte for byte.
- `services.txt`: `getent services <port>/tcp` on the oracle host for every port of the inputs
  (`getservbyport`, `out-tcp-services.c`); the test loads it with `ServiceNames::parse`.
- `manifest.json`: oracle pin, host (OS and kernel only), `inputs` (`sha256`, `records`, `stored`)
  and one record per case: `args` (masscan argv, `@INPUT@` and `@OUTPUT@` stand for the two
  paths), `output` (`null` when not stored), `sha256` of the raw output, `masked_sha256`, `masks`,
  and C's `stdout` and `stderr` with the input path replaced by `@INPUT@`.

Cases: for each input, with and without `--show open,closed`, every format plus `-oX --webxml`
(`<stem>.<open|open-closed>.<format>`), and two filter cases on `basic`:
`--range 10.0.0.0/31 -p80 --readscan basic -oL|-oG out` (`filter.open.*`; targets and ports go
before `--readscan`, C takes every following argument without `-` as a file, `main-conf.c:3266–3278`).

File names use `.bin`, `.out` and `.txt`: the repository language guard
(`scripts/language-guard.sh`, `allowed_name`) accepts no `.scan`, `.xml` or extensionless data file.

## Masks

C takes these fields from the clock when it writes them; each mask must hit exactly one line of a
non-empty output (in the capture script and in the test), the rest of the bytes is compared exactly:

| kind | line | masked |
| --- | --- | --- |
| `xml_start` | `<nmaprun scanner="masscan" start="N" …` | `N` (time of the first record write) |
| `xml_finished` | `<finished time="N" timestr="T" elapsed="E" />` | `N`, `T` (local time), `E` |
| `grepable_done` | `# Masscan done at …` | the date (GMT at close) |

The script masks with `sed -E`, the test with the same rules in Rust; for every stored case the test
checks that both give `masked_sha256`. `many` cases (input over `store_max_bytes`) are compared by
`masked_sha256` only: the test regenerates `many.scan.bin` with the example code and checks its
sha256 against `inputs` first.

## C behaviour recorded here

- `empty` (header and footer, no record): every format, `-oB` included, leaves a 0-byte file (the
  file is opened and truncated, the header is lazy, no footer without a record); stderr is just
  `[+] --readscan FILE`, stdout is empty, exit 0.
- Without `-p` the grepable header lists no ports: `# Ports scanned: TCP(0;) UDP(0;) SCTP(0;)
  PROTOCOLS(0;)`; with `-p80` before `--readscan` it is `TCP(1;80-80)`.
- `# Masscan 1.3.9-integration scan initiated …` is the time of the first record in the file (GMT,
  `%c` of the C locale): `Tue Nov 14 22:13:20 2023`, and with a single-digit day `Fri Dec  1 00:00:00
  2023` (`%e` pads with a space).
- `-oB` with `--show open,closed` rewrites `basic` and `edge` byte for byte (`s:` = first record time).
- XML `<hosts up= down=>` counts only the records shown: without `--show` `down="0"`. `elapsed` was 0.
- With a file format stdout is silent. The progress line is printed every 65 536 records, after
  the `[+] --readscan` line: `[+] FILE:    65536\r` (`%8`, no newline), so `many` has one.
- Ports 0, 65535 and 47001 have no services entry: `unknown` in `-oG` and `-oU`; flags 0 give
  reason `none`, 0xFF `fin-syn-rst-psh-ack-urg-ece-cwr`.

## Differences from C

None in these cases: rmasscan matches every case, so the test skips none (its `SKIPS` list is empty;
a skip would have to name the case and its design decision). The goldens were taken on Linux; the
same expected bytes on macOS and Windows are design decision Р12 (C on Windows writes `\r\n`, XML
`\r\r\n`). Service names come from `services.txt`, not from the host file (Р10 is the host-file
reader itself, tested in `output::services`).
