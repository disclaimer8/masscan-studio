# UDP banner goldens from the pinned C masscan parsers

Offline parity of `rmasscan_proto::handle_udp` (`crates/rmasscan-proto/src/udp/`) with masscan's `handle_udp`
(`src/proto-udp.c:54-132`, masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`) for DNS (53), NTP (123), NetBIOS name
service (137), SNMP (161), ISAKMP (500), CoAP (5683), memcached (11211), ZeroAccess (16464, 16465, 16470, 16471) and
ports without a parser (the `default` branch: first 64 bytes plus the raw datagram). Banners sub-stage 4a, tasks 4
and 5 (`docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md` B0-B8, C1; design R1, R2, R14).
The test `crates/rmasscan-proto/tests/udp_golden.rs` replays every section of every case through `handle_udp`.

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

At startup the driver calls `snmp_init()` (the MIB matcher, as `main.c` does) and `banner_memcached.init` on a zeroed
`struct Banner1`: the UDP memcached parser runs `memcached_tcp_parse`, which needs the matchers that the static
`memcached_init` builds (`src/proto-memcached.c:227-293`); masscan reaches it the same way from `banner1_create`
(`src/proto-banner1.c:617`), which runs whenever `--banners` or `--rawudp` is set (`src/main.c:605-620`,
`src/main-conf.c:1126-1128`).

Every `handle_udp` call runs in a forked child with a 2-second alarm (and, without AddressSanitizer, a 4 GiB address
space limit) and returns its records through a shared mapping. A child that does not return prints `hang` instead of
its records, a child killed by another signal `crash signal=N`. C does not return from some ISAKMP replies (an endless
loop, see below) and, in the builds where the uninitialised `max_length` of ZeroAccess's banner is 0, from every valid
ZeroAccess reply.

C is not allowed in this repository (`crates/rmasscan-lab/tests/rust_only.rs`), so the driver, its build script and
the runner live off the repository next to the oracle's masscan clone (R14). `manifest.json` records their sha256,
the sha256 of the four binaries, the compiler and the masscan commit; the build script refuses a clone that is not at
the pin or is dirty and copies the sources before compiling (the clone is never modified).

Each case runs in five framings of the same datagram, each in its own heap buffer, with the frame length (including
padding) passed to `handle_udp` as `src/main.c:915` passes a captured frame:

- `payload`: the "frame" is the UDP payload alone (`app_offset` 0, frame length = datagram length). C's absolute frame
  offsets (DNS compression pointers, `rr_offset[]`) then coincide with offsets in the datagram, and nothing outside
  the datagram is addressable without reading out of bounds;
- `eth`: Ethernet II + IPv4 + UDP, zero-padded to the 60-byte Ethernet minimum, `app_offset` 42;
- `eth6`: Ethernet II + IPv6 + UDP, `app_offset` 62;
- `vlan`: Ethernet II + 802.1Q tag (VLAN 100) + IPv4 + UDP, zero-padded to 60, `app_offset` 46;
- `rawip`: IPv4 + UDP without a link header (a raw-IP link type), `app_offset` 28.

Addresses are documentation addresses (RFC 5737, RFC 3849): the reply comes from 192.0.2.1 / 2001:db8::1 to
198.51.100.1 / 2001:db8::2, port 40000; the IPv4 header has id 0x1234, DF, TTL 64.

and in five builds of the same sources: `default` (`-g -O2`, masscan's Makefile flags), the same with stack painting
(the 64 KiB of stack below the caller filled with 0x00, 0xFF, the cookie's low 16 bits as 32-bit words, or the 16-bit
words 12 and 50 before every `handle_udp` call), `zero` and `pattern` (`-ftrivial-auto-var-init`), and `asan`
(`-fsanitize=address,undefined`, exactly sized buffers, `halt_on_error=0`, `suppress_equal_pcs=0`, `symbolize=0`;
the runner symbolizes the frames afterwards with `addr2line -a -f -i`). In the builds without AddressSanitizer every
buffer is followed by 4096 filler bytes, 0xEE by default, so that a read past the frame is visible.

**Expected output** (`cases/<case>.out`) is the `pattern` build in the `payload` framing with filler 0x00. That is C
with the three decisions rmasscan takes where C is out of bounds or non-deterministic (R1 classes a and c, R2):
offsets are relative to the datagram; an uninitialised `id` or `rr_offset[]` is absent (the 0xFE fill never equals a
16-bit id and points past every datagram here); and a byte past the end of the datagram reads as 0x00 (only ISAKMP
reads there in a way that changes the output, see below; for every other case the filler makes no difference, which
the runner checks). For every input where C neither reads outside the datagram nor reads uninitialised memory, this is
byte for byte what C prints in a real frame; `manifest.json` shows per case and framing where that does not hold.

## Regenerate

1. Inputs: `cargo run -p rmasscan-proto --example udp_golden_inputs -- DIR` writes `DIR/cases/<case>.bin` and
   `DIR/cases.tsv` (name, port, cookie, rawudp, mode, description). The test fails if the generator and `cases/*.bin`
   drift apart.
2. On the oracle host: `build.sh` (four binaries and `BUILDINFO` from the pinned clone), then
   `run-goldens.sh DIR OUT` in a fresh `mktemp -d /tmp/rmasscan-udp.XXXXXX`: every case through every variant and
   every framing, then `OUT/golden/{manifest.json,cases/*.out}` (`cases/<case>.<framing>.out` and
   `cases/<case>.ee.out` included). About 25 minutes on four cores; AddressSanitizer is most of it.
3. Copy `OUT/golden` here together with `DIR/cases/*.bin`, check the input and output sha256 in the manifest, run the
   privacy grep over this directory (host names, user names, local paths, LAN addresses), delete the host's temporary
   directory.

## Layout and format

- `cases/<case>.bin`: the UDP payload (the datagram after the UDP header).
- `cases/<case>.out`: the expected output, `udp-oracle-pattern` with filler 0x00 in the `payload` framing:

  ```
  udp-oracle port=P cookie=0xXXXXXXXX rawudp=R mode=M sections=S framing=payload
  section len=N                    (mode sweep:OFF: "section len=N byte[OFF]=K")
  status open count=1              (handle_udp's status record; the engine writes it, not the parsers)
  banner APP LEN BYTES             (one line per output_report_banner call, in C's order)
  ```

  or, in place of the status and banner lines, `hang` (C did not return within 2 s) or `crash signal=N`.

  `mode` is `whole` (one section, the whole datagram), `prefixes` (one section per prefix length `0..=n`: every
  truncation) or `sweep:OFF` (256 sections, the byte at `OFF` set to `0..=255`). `BYTES` is `-` for an empty banner,
  `=datagram` when the `LEN` bytes equal the first `LEN` bytes of the section's datagram (the oracle checks that with
  `memcmp`), and otherwise the bytes in double quotes: 0x20-0x7E as they are except `"` and `\`, every other byte as
  `\xNN`.
- `cases/<case>.ee.out`: the `pattern` build in the `payload` framing with the default filler 0xEE, present only when
  it differs from `.out`: its differing sections are the ones where C's output depends on the bytes after the
  datagram. The test requires that only ISAKMP cases have one.
- `cases/<case>.<framing>.out` (`eth`, `eth6`, `vlan`, `rawip`): the `pattern` build (filler 0xEE) in that framing,
  present only when it differs from `.out`.
- `manifest.json`: the oracle block above, the framings, `host` (OS and kernel only), `captured_at`, and per case:
  `about` (what the case covers, from the generator), `port`, `cookie`, `rawudp`, `mode`, input and output sha256,
  `sections`, and the observations:
  - `frames.<framing>.output`: the `.<framing>.out` file or `null`;
  - `frames.<framing>.raw_past_datagram`: sections where that framing's output differs only in the content of the final
    raw banner (same application, same length): C's fallback reads `app_length` bytes starting `app_offset` bytes past
    the datagram on 11211 and on ports without a parser (`src/proto-udp.c:97-101, 108-112, 129`; C1.1). These bytes
    are whatever follows the frame in the capture buffer, so the test compares only presence and length; rmasscan
    reports the datagram;
  - `frames.<framing>.frame`: sections where it differs otherwise. The test (`FRAME_DIFFS`) names the kind of every
    such difference per case and framing and checks it in every section. These two lists compare each framing with
    the `payload` framing of the same run (filler 0xEE); a frame section that differs from `.out` only because of the
    filler is one of the `filler_ee` sections, and the test accepts it when it equals the `.ee.out` section;
  - `filler_ee`: the `.ee.out` file or `null`, and the sections where it differs from `.out`;
  - `c_hang_sections`, `c_crash_sections`: sections where the expected run did not return or crashed;
  - `c_uninit_sections`: sections whose output differs between the `default` build with and without stack painting
    and the `zero`/`pattern` builds, in any framing (a `hang` in one of them included): C's result there depends on
    uninitialised stack;
  - `asan_exit`, `asan_hang_sections`: the AddressSanitizer run's exit code and the sections where it did not return;
  - `sanitizer`: AddressSanitizer and UBSan reports by framing, kind, first masscan frame and sections.

Section lists are ranges (`len=0..11`).

## What the goldens show (C at 8e6b3b0)

203 cases, 9 247 sections (the test asserts the total).

Task 4: 125 cases, 3 962 sections: DNS 40 cases, NTP 20, NBNS 24, SNMP 35, ports without a parser 6 (ports 7, 19, 0,
65535, 9999). They cover success, every early exit of B1-B4, wrong cookies, `--rawudp`, every truncation of one reply
per protocol, byte sweeps (DNS and NBNS flag bytes, every NTP header byte the parser reads, every NetBIOS name byte,
SNMP PDU and value tags, OID bytes), the C self-test vector (`src/proto-snmp.c:630-644`) and the MIB name table.

Task 5: 78 cases, 5 285 sections on the other parser ports: memcached 21 cases (979 sections), CoAP 17 (1 184), ISAKMP
25 (2 812), ZeroAccess 15 (310). They cover the B5-B8 paths: the `stats` reply and every truncation, the soft cookies
(` IP-MISMATCH`), the header limits of memcached (sequence 100 and 101, 0 and 101 datagrams, reserved 1 and 0x100) and
every line rule of `memcached_tcp_parse` (case folding, the line skipped after `STAT\n` or any other reply, the empty
pattern, unknown names that stop the parse, `END`, the separator and `isspace` sets by byte sweeps); CoAP's
self-test packet, the version/type/TKL byte, every code, every option byte, the option names and extended lengths,
every Content-Format value, and the link parser (quoted parameters, the `offset == ';'` bug at datagram offset 59 next
to the same reply at 58); the four ISAKMP self-test samples with every truncation (`sample2`..`sample4` with the high
32 bits of the initiator cookie cleared, else no 32-bit cookie matches), sweeps of the header, situation, protocol,
transform and attribute bytes, the attribute table, the vendor ids, the DOIs and the endless loops; ZeroAccess
`retL` on all four ports, every truncation, a CRC sweep, the getL probe and self-test vector, the count limits, an
unaligned length, banners just under and over 200 bytes and a datagram over 2048 bytes.

C behaviour reproduced as it is (deterministic, R1): the CoAP token is built from the header bytes `px[0..TKL]` and
printed as `0x<decimal>`, ` text-plain` without a Content-Format option, a Content-Format longer than 4 bytes keeps its
low 32 bits, option length 15 is taken literally, up to three ` PARSE_ERR` for one option, and the `offset == ';'`
comparison (`coap-link-param-at-59` loses the second link, `-58` keeps it); every memcached line rule above; ISAKMP's
`e_next_*` all-ones values past `max` (a 16-byte reply prints `v15.15 xchg=255 ENCRYPTED `), `PSK` for auth methods 1
and 5, the SPI not skipped, vendor ids by exact length.

Named differences (each named in `crates/rmasscan-proto/src/udp/mod.rs`; the rmasscan README lists them with the
other banner differences):

- Raw banner past the datagram on 11211 and on ports without a parser (`memcached-*`, `default-*`, C1.1, R2):
  rmasscan reports the datagram.
- ISAKMP reads past the datagram (R1 class a): a nested payload's end comes from its length field
  (`src/proto-isakmp.c:49`), `e_next_*` checks only that end and the vendor id comparison reads with `memcmp`
  (`src/proto-isakmp.c:246`), so on a truncated reply C reads whatever follows the datagram. rmasscan reads zeros
  there (what C reads from the zero padding of a short Ethernet frame). The sections where it matters are the
  `.ee.out` ones: `isakmp-sample1` `len=32..77`, `isakmp-sample2` `len=32..80`, `isakmp-sample3` `len=203`, `len=223`,
  `isakmp-payload-past-datagram`. In the frame framings C reads the same 0xEE filler after the frame as in the
  `.ee.out` run, and the test checks exactly that.
- ISAKMP endless loops (R1 class b, R2): a payload, proposal or transform of length 0 with a non-zero next payload
  (`src/proto-isakmp.c:372-373, 191, 146`) and a transform whose attributes leave one byte before its end
  (`e_next_short16` does not advance, `src/proto-isakmp.c:68-70`) make C repeat one step forever, in every build and
  framing (`hang`: `isakmp-zero-length-payload`, `-proposal`, `-transform`, `isakmp-odd-attribute-tail`; a reply can
  stop C's receive thread). rmasscan runs a step that did not advance once and leaves that loop; its output for these
  sections is in `C_HANGS` in the test. `isakmp-zero-length-last` (length 0, no next payload) ends in C too.
- ZeroAccess over 2048 bytes (R1 class a): C decrypts into `unsigned char buf[2048]` and computes the CRC over the
  whole datagram length (`src/proto-zeroaccess.c:176, 208`), past the buffer into the stack (`zeroaccess-over-2048`,
  AddressSanitizer: stack-buffer-overflow in `crc_calc`); the CRC then does not match and C prints only the raw
  banner. rmasscan treats such a datagram as not ZeroAccess, with the same output.
- ZeroAccess's banner buffer has no `max_length` (`src/proto-zeroaccess.c:183-185`, C1.17, R1 classes a and c): with
  0 there C loops in `banout_expand` forever, so every valid ZeroAccess section is a `hang` in the `zero` build, with
  stack painting 0x00 and under AddressSanitizer (`c_uninit_sections`, `asan_hang_sections`); with a large value C
  appends in place past `banner[200]` (`zeroaccess-13-addresses`, 206 bytes, prints correctly in the `pattern` build by
  luck). rmasscan builds the banner like any other.
- DNS and NBNS compression pointers address the captured frame in C, not the DNS message (`src/proto-dns.c:69`, `px`
  is the frame; the name check follows the pointer into link and IP header bytes). rmasscan resolves them in the
  message (R1 class a: C reads outside the datagram; class c: the result depends on the link type, the address family,
  a VLAN tag, the IP header and the addresses, not on the reply). Measured, by framing:
  - `eth` (Ethernet + IPv4): the usual `c0 0c` lands on frame byte 12, the EtherType high byte 0x08, an 8-byte "label"
    ending at frame byte 21 (the fragment offset's low byte, 0), so the name passes by accident and C agrees with
    rmasscan on every ordinary reply. Other pointer targets differ: `dns-pointer-to-id` and `dns-pointer-chain-5`
    validate in C through header bytes and print `dns-ver`, rmasscan finds the name invalid and prints the raw banner;
  - `eth6` (Ethernet + IPv6) and `vlan` (802.1Q): frame byte 12 is 0x86 or 0x81, `& 0xC0 == 0x80`, an error
    (`src/proto-dns.c:61-62`). **Wherever rmasscan prints `dns-ver` or `nbtstat` for a reply whose answer name is
    compressed (the usual successful reply), C prints only the raw `unknown` banner** (rmasscan: the parser text and,
    where C has one, the raw banner): 12 cases (`dns-chaos-txt` and its variants, the flag sweeps, the TXT cases,
    `dns-edns-ext-rcode`, `dns-many-answers`, `nbns-nbstat-with-question`). A reply with RCODE 1-9 is printed before
    the answer name is checked, so there C prints the RCODE string and the raw banner exactly as rmasscan does. In
    `dns-edns-ext-rcode-nxdomain` the rejected answer stops C's parse before the EDNS0 OPT record, so C prints
    `3:NXDOMAIN` and the raw banner where rmasscan (RCODE 19, no string) prints the TXT text. `dns-pointer-to-id`,
    `dns-pointer-chain-5` and `dns-pointer-loop` go the other way: the pointers land in IPv6 address or header bytes
    and validate, so C prints `dns-ver` where rmasscan prints the raw banner;
  - `rawip` (no link header): frame byte 12 is the first byte of the IPv4 source address (192 here, `& 0xC0 == 0xC0`,
    a pointer to frame byte 0x00, the version byte 0x45: an error), so the same 13 cases differ the same way, plus
    `dns-pointer-chain-4` (raw banner only in C). `dns-pointer-to-id`, `dns-pointer-chain-5` and `dns-pointer-loop` do
    **not** differ in `rawip`: there C prints only the raw banner, as rmasscan does. By code reading, another source address changes the
    outcome again (a first byte below 0x40 is read as a label length); other link types (Linux cooked capture,
    loopback) put other bytes at offset 12 and are not measured here.
  Replies with uncompressed names (`nbns-nbstat`, `dns-txt-uncompressed-name`) agree in every framing.
- Uninitialised `id` (datagram shorter than 12 bytes) and `rr_offset[1]` / `rr_offset[qdcount]` (C1.16): stack painting
  makes C print a raw banner for an 11-byte DNS or NBNS datagram (`dns-short-11`, `nbns-short-11`, `dns-empty`,
  `nbns-empty`, the first 12 truncations of `dns-chaos-txt` and `nbns-nbstat`), a `dns-ver` text for a reply with one
  record (`dns-qd0-one-answer`) and an `nbtstat` text for a reply whose question does not parse
  (`nbns-question-bad-class`). rmasscan treats a short datagram as a cookie mismatch and a missing record as absent.
- Not visible in the goldens: C reads the TXT text and the NBSTAT MAC against the frame length, not the datagram length
  (`src/proto-dns.c:420-434`, `src/proto-netbios.c:145-166`). Ethernet padding cannot change the result (in the padded
  framings a record starts at frame byte 54 or later and `offset + 10 >= length` trips first), but a trailer the
  capture keeps after the IP datagram (an FCS) ends up in `dns-ver` and in the NBSTAT MAC (measured off the goldens with
  a 4-byte trailer: `9.18.24\xfc\xfc\xfc\xfc`, `FC-FC-FC-FC-`); rmasscan stops at the datagram.

C memory errors under AddressSanitizer (no crash in a normal build, nothing in rmasscan):

- `dns_extract_name` heap over-read (`src/proto-dns.c:164`, called at `:318`) on DNS and NBNS replies without records
  (`dns-header-only`, `dns-formerr-header-only`, `nbns-header-only`): `rr_offset[0]` is uninitialised there and the
  name copy follows it. Its result is never read; rmasscan does not port it.
- `asn1_integer` reads the tag byte without a bounds check (`src/proto-snmp.c:151`): one byte past the datagram on
  truncated SNMP replies (`snmp-selftest`, `snmp-sysdescr-sysname`, `snmp-reqid-21-bytes`, `snmp-length-over-0x10000`,
  `snmp-length-indefinite`; every framing). The result does not depend on that byte.
- The raw fallback past the datagram on 11211 and on ports without a parser (`proto-udp.c:121`, all `memcached-*` and
  `default-*` cases, every frame framing).
- `memcached_tcp_parse` reads `px[length]` in the skip-to-end-of-line state (`src/proto-memcached.c:165`,
  `memcached-stats` `len=18..22`, every framing). The state is not used after the UDP call, so the output does not
  depend on it; rmasscan does not read it. (For TCP in 4b the state survives into the next segment.)
- ISAKMP's reads past the datagram (above): `e_next_byte`, `e_next_short16`, `e_next_int32` (`src/util-extract.c:9,
  22, 38-39`) and `_payload_vendor_id` (`src/proto-isakmp.c:246`).
- `zadecrypt` reads up to three bytes past a datagram whose length is not a multiple of 4
  (`src/proto-zeroaccess.c:121-123`; `zeroaccess-retl` truncations, `zeroaccess-unaligned`); the CRC and the addresses
  use only the first `len` bytes, so the output does not depend on them.
- ZeroAccess over 2048 bytes (above): stack-buffer-overflow READ in `crc_calc` (`src/proto-zeroaccess.c:98`).
- UBSan, signed left shifts (undefined behaviour, R1 class a, no effect on the output with gcc): `e_next_long64`
  (`src/util-extract.c:58, 60`) on every ISAKMP reply whose cookie bytes have the top bit set (the value is discarded:
  the cookies are only skipped), and `buf[3]<<24` in ZeroAccess's stored CRC (`src/proto-zeroaccess.c:206`; rmasscan
  reads it as an unsigned little-endian value).
