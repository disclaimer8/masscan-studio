# Output-format goldens from the pinned C masscan oracle

Offline parity for `-oL -oJ -oD -oG -oX -oB -oH -oU` (design §6.1,
`docs/superpowers/specs/2026-11-06-rmasscan-output-formats-design.md`), and for banner records in `--readscan`
(types 9/13 and the legacy 3/4/5), `--output-format certs`, the default format and `--banner-types` (banners
sub-stage 4a, `docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md` A5, C2-C3.1). The C oracle
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
3. Copy `$W/golden/{manifest.json,services.txt,protocols.txt,outputs}` here (`outputs/` holds `*.stdout.out` too),
   keep `inputs/` and this README (hand-written), run the privacy grep over this directory, then delete `$W` on the
   host.

Extending (how the `protocols`, then the `ipv6` and then the two banner inputs were added): run the script on all
inputs as above, check that every earlier case reproduces (`masked_sha256`, `stdout`, `stderr`), and copy only the
new cases: their outputs, their manifest entries and input, `services.txt` and `protocols.txt`; the earlier entries
and outputs stay as committed (the raw `sha256` of the outputs with a clock mask differs in the new capture, in the
masked fields only: 26 of 94 earlier cases at the `ipv6` capture, 35 of 119 at the banner capture; `masked_sha256`,
`stdout` and `stderr` of every earlier case reproduced, so none of them was touched), and `extended` in
`manifest.json` records the later capture (time, host, its cases). The script walks the records of an input by type
and length (`walk_records`: varint type and length, `in-binary.c:546-570`; status types 6/7 of 15 bytes and 10/11 of
28, banner types 9 and 13, legacy 3/4/5 with the extra byte of type 4) instead of assuming 15 bytes. The `extended`
block and the new case entries were merged into the committed `manifest.json` by hand with `jq`:
`build-format-goldens.sh` alone regenerates the case entries of a whole new manifest, but never writes `extended`.

## Layout

- `inputs/*.scan.bin`: the `-oB` inputs, written by the rmasscan binary writer
  (`examples/format_inputs.rs`). `basic` (8 records: open/closed on 10.0.0.1, 10.0.0.2, 10.0.0.3,
  192.0.2.7, ports 80/443/8080/22), `edge` (ports 0, 65535 and 47001, TTL 0 and 255, flags 0, 0x04,
  0x12, 0x14, 0xFF, addresses 0.0.0.1 and 255.255.255.255, times on a single-digit day at the day
  boundaries), `empty` (header and footer only), `protocols` (12 records of types 6/7 with `ip_proto` 1, 6,
  17 and 132: UDP open on 53, 123 and 59999, UDP closed from ICMP 3/3 on 161 and 500, SCTP open 2905 and
  closed 2906, ICMP Echo open on two hosts, TCP open/closed by flags and TCP closed from ICMP 3/3 with
  reason 0; addresses from RFC 5737). `ipv6` (18 records: 14 of types 10/11, 28 bytes, written as
  `binary_out_status_ipv6` does, `out-binary.c:103-149`, mixed with 4 IPv4 records of types 6/7 so that the file
  order is pinned; RFC 3849 addresses with every `ipv6address_fmt` case, `massip-addr.c:33-109`: the first zero run
  is compressed, not the longest (`2001:db8:0:1:0:0:0:1` is `2001:db8::1:0:0:0:1` in C), `::`, `::1`, `fe80::1`,
  `ffff:...:ffff`, `::ffff:192.0.2.1` as `::ffff:c000:201`, `2001:db8::`; TCP open and closed, UDP, SCTP and ICMP,
  ports 0 and 65535, TTL 0 and 255, and `2a03:9060:0:400::2` on 443 and 22). `many` (70 000 records, 1 MiB) is not committed. ARP (type 8) has
  no input here: C cannot read it (`in-binary.c:583`), the `readscan` unit tests cover it.
  `banners` (61 records, written by the rmasscan `-oB` writer, `Formatter::banner`): 56 banner records of types 9
  (IPv4) and 13 (IPv6) mixed with 5 status records (types 6/7/10, the first record is a status record); application ids
  0..=37 and 65535 (`(37)`, `(65535)`), `ip_proto` 0, 1, 6, 17, 132 and 99 (`arp`, `icmp`, `tcp`, `udp`, `sctp`,
  `err`), every byte 0..=255 as a payload (IPv4 and IPv6), `< > & " ' \` in a title, `cert:MIIB…` and a bare
  `cert:` (5 bytes, not stripped by certs), empty payloads, the one/two-byte `-oB` length boundary (113/114 bytes
  IPv4, 100/101 IPv6), a 16 369-byte payload (the longest IPv4 `-oB` banner; text cut at 8190 with holes, JSON cut at
  the 65 536 buffer), dns-ver (app 6) over TCP (XML `syn-ack`), TTL 0 and 255; ports 80 and 443 carry only TCP records.
  `banners-legacy` (10 records): the legacy banner types C reads but never writes, as raw bytes (type 3: time,
  address, port, app, payload, always TCP; types 4 and 5: time, address, protocol, port, app, payload; type 4's
  length is one less than its body, C reads the last byte separately, `in-binary.c:595-602`, and with a 12-byte
  length that byte is the low byte of the app), including an empty type 3, a 120-byte type 5 (two-byte length) and
  `ip_proto` 99, plus one status record (type 6) and one type 9 banner for the filter case.
- `outputs/<case>.out`: what C wrote to the `-o?` file, byte for byte.
- `outputs/<case>.stdout.out`: C's stdout, byte for byte, for the cases whose stdout carries the result: certs (the
  PEM blocks, raw payload bytes) and the default format (`Discovered` and `Banner on port` lines).
- `services.txt`: `getent services <port>/tcp` for every TCP record port and `<port>/udp` for every UDP
  record port of the inputs on the oracle host (`getservbyport`, `out-tcp-services.c:34-99`); the test
  loads it with `ServiceNames::parse`.
- `protocols.txt`: `getent protocols <n>` for the other `ip_proto` of the records (1 and 132;
  `getprotobynumber`, `out-tcp-services.c:101-118`, the service name `-oG` prints for ICMP and SCTP);
  the test adds it with `ServiceNames::with_protocols`.
- `manifest.json`: oracle pin, host (OS and kernel only), `inputs` (`sha256`, `records`, `stored`)
  and one record per case: `args` (masscan argv, `@INPUT@` and `@OUTPUT@` stand for the two
  paths), `output` (`null` when not stored), `sha256` of the raw output, `masked_sha256`, `masks`,
  and C's `stdout` and `stderr` with the input path replaced by `@INPUT@`. A case whose stdout is kept as a file has
  `stdout: null`, `stdout_output` and `stdout_sha256`; a case without a file (the default format, no `@OUTPUT@` in
  `args`) also has `output`, `sha256`, `masked_sha256` and `size_bytes` null.

Cases: for each input, with and without `--show open,closed`, every format plus `-oX --webxml`
(`<stem>.<open|open-closed>.<format>`), and two filter cases on `basic`:
`--range 10.0.0.0/31 -p80 --readscan basic -oL|-oG out` (`filter.open.*`; targets and ports go
before `--readscan`, C takes every following argument without `-` as a file, `main-conf.c:3266–3278`),
and two on `protocols`: `--range 192.0.2.0/28 --readscan protocols -oL|-oG out` (`filter.protocols.*`),
and seven on `ipv6` (`filter.ipv6.*`, `-oL` and `-oG` unless noted): `mixed`
(`--range 2001:db8::/48,192.0.2.0/24`), `only4` (`--range 192.0.2.0/24`), `port` (`-p443,22`) and `mixedport`
(`-oL` only: `--range 2001:db8::/120,192.0.2.0/30 -p22,80`; with a port the IPv6 range must stay under 63 bits,
see below).
A `-p` filter over non-TCP records is not captured: C compares the record's unshifted port with the
shifted port ranges (`in-filter.c:14–17`), rmasscan compares `(ip_proto, port)`, a named difference
(design `2026-11-08-rmasscan-protocols-ipv4` Р5); an address filter means the same in both.

Banner cases: both banner inputs also have `<stem>.open.certs` (`--output-format certs --output-filename F`: the
file and stdout), `<stem>.open.default` and `<stem>.open-closed.default` (no `-o`: stdout only); on `banners`,
`banner-types.dns-ver.<list|grepable|binary>` (`--banner-types dns-ver`) and `banner-types.ssl-http.<…>`
(`--banner-types ssl --banner-types http`), and `filter.banners.<list|grepable>` (`--range
192.0.2.0/24,2001:db8::/120 -p80,443`: ports 80 and 443 carry only TCP records there, so the port filter means the
same in C and rmasscan); on `banners-legacy`, `filter.banners-legacy.list` (`--range 10.0.0.0/8 -p22 --banner-types
ssh`: every legacy record passes, the type 9 and the status record do not).

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
- Non-TCP records (`protocols`): every format names the protocol (`udp`, `sctp`, `icmp`); `-oG` names a
  UDP record's service by `/udp` (`59999` is `unknown`) and an ICMP or SCTP record's by its protocol
  (`icmp`, `sctp`); `-oU` writes a non-TCP record in the grepable form without a service; reason 0 is
  `none`; XML keeps `<scaninfo type="syn" protocol="tcp" />` and counts only TCP records in
  `<hosts up= down=>` (`up="1" down="2"` with `--show open,closed`); with no `-p` the grepable header
  lists no port of any protocol.

## Banner records (types 3, 4, 5, 9 and 13)

- `--readscan` turns banners on (`main-conf.c:3266-3272`): every format prints the banner records next to the status
  records, in file order; banners ignore `--show` and are not counted in XML `<hosts up= down=>`. The default format
  prints `Banner on port P/proto on IP: [app] text` padded to 79 columns, after `Discovered` lines (`output.c:903-923`).
- `--banner-types NAME` (and `--banner-type`, `--banner-apps`, `--banner-app`, `main-conf.c:2683-2697`) takes one
  `masscan_string_to_app` name per option (case-sensitive; `ssh` is 3, `vnc-old` 23, `x509` 15). With any name every
  status record is skipped unparsed (`in-binary.c:584-623`, so a status record before the first banner does not set
  the scan start: `-oB` `s:` is the first banner's time) and types 9/13 pass only with a listed app; types 3/4/5 pass
  every filter (no `readscan_filter_pass`). A bad name (measured on the oracle with `ssl,http`, `HTTP`, `unknown` and
  `error`): stderr `FAIL: bad banner app: NAME\nerr\n`, exit 1, no output file; rmasscan prints the same.
- `-oB` rewrites types 3/4/5 as type 9 (TTL 0, type 3 always TCP) and keeps types 9/13 byte for byte.
- certs writes `{finished: 1}` to the file and one PEM block per banner, any app, on stdout (72-byte lines, each cut at
  its first NUL byte by `%.*s`); `cert:` is stripped only when the payload is longer than 5 bytes.
- XML says `reason="syn-ack"` for app 6 (dns-ver) whatever the protocol, `response` otherwise (`out-xml.c:106-109`),
  and writes ` />` with a space; `-oU` prints nothing for a banner (header and footer still come); `-oH` prints one
  more address line per banner.
- Unit tests only (`readscan.rs`), measured on the oracle with the same isolation but not stored as goldens: a type 4
  record cut before its extra byte prints `[-] read() error`, exits 1 and leaves the output without its footer (C calls
  `exit(1)`); type 5 shorter than 13 bytes and type 9 shorter than 14 are skipped silently and set no scan start; type
  13 with a version other than 6, or too short to hold it, prints `[-] corrupt record` and the read goes on; type 13
  with version 6 but shorter than 27 bytes prints nothing yet sets the scan start (`in-binary.c:304-305, 318-319`);
  with `--banner-types` a type 10 with version 4, a type 6 with `ip_proto` 47 and types 1 and 2 are skipped without a
  message. C and rmasscan gave the same bytes, stderr and exit code in every one of them. A type 3 shorter than 12
  bytes is not fed to C (it reads about 4 GiB past its buffer, `in-binary.c:363`).

## IPv6 records (types 10 and 11)

- C reads them (`in-binary.c:228-276`, `parse_status6`) and writes them (`out-binary.c:103-149`); the body is
  `[ts BE4, ip_proto, port BE2, reason, ttl, version = 6, hi BE8, lo BE8]` after `[type 10|11, length 26]`.
  Type 12 (`Out_Arp6`) is written but has no `case` in the reader: `file corrupt: unknown type 12`.
- Every format prints the address with `ipaddress_fmt` (`massip-addr.c:191-199` calls `ipv6address_fmt`): no
  brackets anywhere; XML says `addrtype="ipv6"` (`out-xml.c:75-83`, `name_from_ip_version`, `output.c:89-96`).
  `-oG` and `-oU` print the same address in `Host:` / `from`.
- A mixed file keeps the file order; an IPv4 record is 15 bytes and an IPv6 one 28 in `-oB` output too.
- The read filter tests the address only when the filter has an IPv4 range (`filter->count_ipv4s`,
  `in-binary.c:132, 254`, `in-filter.c:10`), then `massip_has_ip` picks the IPv4 or IPv6 list by the record's
  version (`massip.c:45-51`). So `--range 2001:db8::/32 --readscan` (IPv6 ranges only) filters nothing in C, every IPv4 and
  IPv6 record passes (measured on the oracle). rmasscan filters it (ruling R14, a named difference like the protocols
  stage's Р5): only records inside the IPv6 ranges stay, IPv4 records are outside the target set. No golden pins that
  case, goldens exist only where C and rmasscan agree. `--range 192.0.2.0/24` drops every IPv6 record (`only4`); a
  list with both matches IPv6 records against the IPv6 ranges (`mixed`). `-p` applies to both versions (`port`).
- C checks the 63-bit scan range for `--readscan` too (`main.c:1698-1704`): `--range 2001:db8::/64 -p22 --readscan`
  exits 1 with `scan range too large`. That case has no golden (the capture script expects exit 0); the unit test
  `readscan_accepts_an_ipv6_filter` covers it.
- A type 10/11 body with version other than 6, or too short to hold the version byte (fewer than 10 bytes), prints
  `[-] corrupt record` on stderr (no file name) and the record is skipped, the read goes on; a body cut inside the
  address reads the missing 8-byte halves as `0xFFFF…`. These are unit tests (`readscan.rs`), not goldens: the
  inputs are not files `-oB` can write.

## Differences from C

None in these cases: rmasscan matches every case, so the test skips none (its `SKIPS` list is empty;
a skip would have to name the case and its design decision). The goldens were taken on Linux; the
same expected bytes on macOS and Windows are design decision Р12 (C on Windows writes `\r\n`, XML
`\r\r\n`). Service names come from `services.txt`, not from the host file (Р10 is the host-file
reader itself, tested in `output::services`).

Named differences outside the goldens (unit tests in `readscan.rs`): a type 10/11 record with an `ip_proto` other
than 1, 6, 17 and 132 is an error (`unsupported record protocol N`, design decision Р13, as for types 6/7), C prints
`err` for it; type 12 stays `Unsupported` (C: `unknown type 12`, both stop the read); the legacy status types 1 and 2
stay `Unsupported` (C reads them, guessing the protocol from the port, `in-binary.c:41-98`) except with
`--banner-types`, where both skip them unparsed. Banner records: a type 3 body shorter than 12 bytes is `[-] file
corrupt` (exit 1, output closed with its footer; banners design Р2: C reads about 4 GiB past its buffer); a `-p`
filter compares a banner record's `(ip_proto, port)` with the shifted ranges like a status record (Р5; a protocol
without its own port space, not 1/6/17/132, never passes a `-p` filter), C compares the unshifted port, so
`-p53` keeps a UDP banner on 53 in C and not in rmasscan; an IPv6-only address filter filters banner records too
(R14).
