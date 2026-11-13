# UDP banner goldens from the pinned C masscan parsers

Offline parity of `rmasscan_proto::handle_udp` (`crates/rmasscan-proto/src/udp/`) with masscan's `handle_udp`
(`src/proto-udp.c:54-132`, masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`) for DNS (53), NTP (123), NetBIOS name
service (137), SNMP (161) and ports without a parser (the `default` branch: first 64 bytes plus the raw datagram).
Banners sub-stage 4a, task 4 (`docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md` B0-B4,
C1; design R1, R2, R14). Task 5 adds 500, 5683, 11211 and the ZeroAccess ports to the same set. The test
`crates/rmasscan-proto/tests/udp_golden.rs` replays every section of every case through `handle_udp`.

## The oracle

`udp-oracle` is a small C driver linked with the real sources of the pinned commit: `proto-udp.c`, `proto-dns.c`,
`proto-ntp.c`, `proto-netbios.c`, `proto-snmp.c`, `proto-memcached.c`, `proto-coap.c`, `proto-isakmp.c`,
`proto-zeroaccess.c` and their helpers (`proto-banout.c`, `smack1.c`, `smackqueue.c`, `util-*.c`, `massip-addr.c`,
`pixie-timer.c`; the list and every file's sha256 are in `manifest.json`). It replaces only:

- `output_report_status` and `output_report_banner`: they record into memory; the banner stub keeps the `is_banner`
  gate of `src/output.c:898-899`;
- `syn_cookie`: it returns the case's cookie. The parsers only ever use `(unsigned)syn_cookie(ip_them, port_them |
  Templ_UDP, ip_me, port_me, entropy)` (`src/proto-dns.c:369`, `src/proto-netbios.c:125`, `src/proto-snmp.c:567`), so a
  case states that 32-bit value instead of addresses and entropy; the parsers apply their own masks (`& 0xFFFF`,
  `& 0x7FFFFFFF`).

C is not allowed in this repository (`crates/rmasscan-lab/tests/rust_only.rs`), so the driver, its build script and
the runner live off the repository next to the oracle's masscan clone (R14). `manifest.json` records their sha256,
the sha256 of the four binaries, the compiler and the masscan commit; the build script refuses a clone that is not at
the pin or is dirty and copies the sources before compiling (the clone is never modified).

Each case runs in two framings of the same datagram, each in its own heap buffer:

- `payload`: the "frame" is the UDP payload alone (`app_offset` 0, frame length = datagram length). C's absolute frame
  offsets (DNS compression pointers, `rr_offset[]`) then coincide with offsets in the datagram, and nothing outside
  the datagram is addressable without reading out of bounds;
- `eth`: Ethernet II + IPv4 + UDP + payload, zero-padded to the 60-byte Ethernet minimum, `app_offset` 42, frame length
  including the padding, as `src/main.c:915` passes a captured frame. Addresses are RFC 5737 documentation addresses.

and in five builds of the same sources: `default` (`-g -O2`, masscan's Makefile flags), the same with stack painting
(the 64 KiB of stack below the caller filled with 0x00, 0xFF, the cookie's low 16 bits as 32-bit words, or the 16-bit
words 12 and 50 before every `handle_udp` call), `zero` and `pattern` (`-ftrivial-auto-var-init`), and `asan`
(`-fsanitize=address,undefined`, exactly sized buffers, `halt_on_error=0`, `suppress_equal_pcs=0`).

**Expected output** (`cases/<case>.out`) is the `pattern` build in the `payload` framing. That is C with the two
decisions rmasscan takes where C is out of bounds or non-deterministic (R1 classes a and c, R2): offsets are relative
to the datagram, and an uninitialised `id` or `rr_offset[]` is absent (the 0xFE fill never equals a 16-bit id and
points past every datagram here). For every input where C neither reads outside the datagram nor reads uninitialised
memory, this is byte for byte what C prints in a real frame; `manifest.json` shows per case where that does not hold.

## Regenerate

1. Inputs: `cargo run -p rmasscan-proto --example udp_golden_inputs -- DIR` writes `DIR/cases/<case>.bin` and
   `DIR/cases.tsv` (name, port, cookie, rawudp, mode, description). The test fails if the generator and `cases/*.bin`
   drift apart.
2. On the oracle host: `build.sh` (four binaries and `BUILDINFO` from the pinned clone), then
   `run-goldens.sh DIR OUT` in a fresh `mktemp -d /tmp/rmasscan-udp.XXXXXX`: every case through every variant, both
   framings, then `OUT/golden/{manifest.json,cases/*.out,cases/*.eth.out}`.
3. Copy `OUT/golden` here together with `DIR/cases/*.bin`, check the input and output sha256 in the manifest, run the
   privacy grep over this directory (host names, user names, local paths, LAN addresses), delete the host's temporary
   directory.

## Layout and format

- `cases/<case>.bin`: the UDP payload (the datagram after the UDP header).
- `cases/<case>.out`: the expected output, `udp-oracle-pattern` in the `payload` framing:

  ```
  udp-oracle port=P cookie=0xXXXXXXXX rawudp=R mode=M sections=S framing=payload
  section len=N                    (mode sweep:OFF: "section len=N byte[OFF]=K")
  status open count=1              (handle_udp's status record; the engine writes it, not the parsers)
  banner APP LEN BYTES             (one line per output_report_banner call, in C's order)
  ```

  `mode` is `whole` (one section, the whole datagram), `prefixes` (one section per prefix length `0..=n`: every
  truncation) or `sweep:OFF` (256 sections, the byte at `OFF` set to `0..=255`). `BYTES` is `-` for an empty banner,
  `=datagram` when the `LEN` bytes equal the first `LEN` bytes of the section's datagram (the oracle checks that with
  `memcmp`), and otherwise the bytes in double quotes: 0x20-0x7E as they are except `"` and `\`, every other byte as
  `\xNN`.
- `cases/<case>.eth.out`: the same `pattern` build in the `eth` framing, present only when it differs from `.out`.
- `manifest.json`: the oracle block above, `host` (OS and kernel only), `captured_at`, and per case: `about` (what the
  case covers, from the generator), `port`, `cookie`, `rawudp`, `mode`, input and output sha256, `sections`, and the
  observations:
  - `eth_raw_past_datagram`: sections where the `eth` output differs only in the content of the final raw banner
    (same application, same length): C's fallback reads `app_length` bytes starting `app_offset` bytes past the
    datagram on 11211 and on ports without a parser (`src/proto-udp.c:97-101, 108-112, 129`; C1.1). These bytes are
    whatever follows the frame in the capture buffer, so the test compares only presence and length; rmasscan reports
    the datagram;
  - `eth_frame`: sections where the `eth` output differs otherwise (listed in `FRAME_DEPENDENT` of the test);
  - `c_uninit_sections`: sections whose output differs between the `default` build with and without stack painting
    and the `zero`/`pattern` builds, in either framing: C's result there depends on uninitialised stack;
  - `sanitizer`: AddressSanitizer and UBSan reports by framing, kind, first masscan frame and sections.

Section lists are ranges (`len=0..11`).

## What the goldens show (C at 8e6b3b0)

125 cases, 3 962 sections: DNS 40 cases, NTP 20, NBNS 24, SNMP 35, ports without a parser 6 (ports 7, 19, 0, 65535,
9999). They cover success, every early exit of B1-B4, wrong cookies, `--rawudp`, every truncation of one reply per
protocol, byte sweeps (DNS and NBNS flag bytes, every NTP header byte the parser reads, every NetBIOS name byte, SNMP PDU
and value tags, OID bytes), the C self-test vector (`src/proto-snmp.c:630-644`) and the MIB name table.

Named differences (each named in `crates/rmasscan-proto/src/udp/mod.rs`; the rmasscan README lists them with the
other banner differences):

- Raw banner past the datagram on ports without a parser (`default-*`, C1.1, R2): rmasscan reports the datagram.
- DNS compression pointers address the captured frame in C (`src/proto-dns.c:69`): `dns-pointer-to-id` and
  `dns-pointer-chain-5` validate in C through bytes of the Ethernet and IP headers and print `dns-ver`; rmasscan
  resolves pointers in the DNS message (R1 class a: outside the datagram; class c: the headers change from frame to
  frame), the name is invalid and the raw banner follows.
- Uninitialised `id` (datagram shorter than 12 bytes) and `rr_offset[1]` / `rr_offset[qdcount]` (C1.16): stack painting
  makes C print a raw banner for an 11-byte DNS or NBNS datagram (`dns-short-11`, `nbns-short-11`, `dns-empty`,
  `nbns-empty`, the first 12 truncations of `dns-chaos-txt` and `nbns-nbstat`), a `dns-ver` text for a reply with one
  record (`dns-qd0-one-answer`) and an `nbtstat` text for a reply whose question does not parse
  (`nbns-question-bad-class`). rmasscan treats a short datagram as a cookie mismatch and a missing record as absent.
- Not visible in the goldens: C reads the TXT text and the NBSTAT MAC against the frame length, not the datagram length
  (`src/proto-dns.c:420-434`, `src/proto-netbios.c:145-166`). Ethernet padding cannot change the result (a record
  starts at frame byte 54 or later and `offset + 10 >= length` trips first), but a trailer the capture keeps after the
  IP datagram (an FCS) ends up in `dns-ver` and in the NBSTAT MAC; rmasscan stops at the datagram.

C memory errors under AddressSanitizer (no crash in a normal build, nothing in rmasscan):

- `dns_extract_name` heap over-read (`src/proto-dns.c:164`, called at `:318`) on DNS and NBNS replies without records
  (`dns-header-only`, `dns-formerr-header-only`, `nbns-header-only`): `rr_offset[0]` is uninitialised there and the
  name copy follows it. Its result is never read; rmasscan does not port it.
- `asn1_integer` reads the tag byte without a bounds check (`src/proto-snmp.c:151`): one byte past the datagram on
  truncated SNMP replies (`snmp-selftest`, `snmp-sysdescr-sysname`, `snmp-reqid-21-bytes`, `snmp-length-over-0x10000`,
  `snmp-length-indefinite`). The result does not depend on that byte.
- The raw fallback past the datagram on ports without a parser (`proto-udp.c:121`, all `default-*` cases).
