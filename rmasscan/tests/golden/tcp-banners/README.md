# TCP banner framework goldens from the pinned C masscan

Offline parity of `rmasscan_proto::banner_stream` (`crates/rmasscan-proto/src/banner1/`) with masscan's
`banner1_parse` (`src/proto-banner1.c:113-325`, masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`) for one TCP
connection: the classifier (`patterns[]`, `src/proto-banner1.c:34-106`, compiled by smack, `src/smack1.c`), the HEUR
record and its replay, the banner buffers (`src/proto-banout.c`) and the hello table of `banner1_create`. Banners
sub-stage 4b, task 8 (`docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tcp.md` B1-B6, C2, C3, E2.1,
E2.2, E4; design R5, R13, R14). The test `crates/rmasscan-proto/tests/tcp_golden.rs` replays every case; unit tests in
`banner1/classify.rs`, `banner1/hello.rs` and `banner1/banout.rs` read `patterns.out`, `hellos.out` and
`banout.{in.txt,out}`.

## The oracle

`tcp-oracle` is a small C driver linked with the unmodified sources of the pinned commit: `proto-banner1.c`,
`proto-banout.c`, `smack1.c`, `smackqueue.c`, the 4b parsers (`proto-{http,ftp,smtp,pop3,imap4,ssh,vnc,tcp-telnet,
tcp-rdp,memcached,mc}.c`), `crypto-base64.c` and the units `banner1_create` and `banner1_parse` reference (TLS, X.509,
SMB, NTLMSSP, versioning, scripting, their helpers; the list and every file's sha256 are in `manifest.json`). It
replaces only:

- `tcpapi_send` and `tcpapi_close`, the only stack calls the parsers make: they record `action send` / `action close`
  in call order (the other `tcpapi_*` record too, and no parser calls them);
- `output_report_banner`, `syn_cookie`, `default_udp_parse` (the UDP memcached path), `pcapfile_*` and
  `preprocess_frame` (`banner1_test`): never reached from `banner1_parse`, they abort if called.

For one case it does what masscan does for one connection (`src/stack-tcp-core.c:1043-1049`, `src/stack-tcp-app.c:126`):
`banner1_create` once, a zeroed `StreamState` with the case's port, `banout_init`, `banner1_parse` per piece of the
server stream, then the records `banner_flush` reports (list order, `length && protocol`, app `protocol & 0x0FFFFFFF`,
`src/stack-tcp-core.c:810-823`) and the final `app_proto`. Three runs per case, each in a forked child with a
2-second alarm: `whole` (one call with the whole stream: **the reference**, R13), `bytewise` (one call per byte) and,
for a case with more than one segment, `given` (one call per segment). The last two are evidence of how C depends on
the split (reference E2); rmasscan must give the `whole` result in every split.

Every case also runs under an AddressSanitizer build of the same sources; `manifest.json` records per case whether
its output equals the default build's and how many sanitizer reports it printed (all equal, none).

C is not allowed in this repository (`crates/rmasscan-lab/tests/rust_only.rs`), so the driver, its build script and
the runner live off the repository next to the oracle host's masscan clone (R14). `manifest.json` records their
sha256, the sha256 of both binaries, the compiler and the masscan commit; the build script refuses a clone that is not
at the pin or is dirty and copies the sources before compiling (the clone is never modified).

## Regenerate

1. Inputs: `RMASSCAN_TCP_BANNERS_INPUTS=DIR cargo test -p rmasscan-proto --test tcp_golden inputs_match_generator`
   writes `DIR/cases/<case>.in.txt` and `DIR/cases.tsv` (name, expectation, declared rule, description) from
   `crates/rmasscan-proto/tests/tcp_golden/inputs.rs`; copy `banout.in.txt` from here into `DIR`. Without the variable
   the test fails if the generator and `cases/*.in.txt` drift apart.
2. On the oracle host: `build.sh` (both binaries and `BUILDINFO` from the pinned clone), then `run-goldens.sh DIR OUT`
   with a fresh `mktemp -d` under the oracle's directory as `OUT`: every case through both builds, then the tables,
   then `OUT/golden/{manifest.json,patterns.out,hellos.out,banout.in.txt,banout.out,cases/*}`. About 15 seconds.
3. Copy `OUT/golden` here, check the sha256 in the manifest, run the privacy scan over this directory (host names,
   user names, local paths, LAN addresses), delete the host's temporary directory.

## Layout and format

- `cases/<case>.in.txt`: the oracle input, one directive per line (`#` lines are comments):

  ```
  tcp-banner-input v1
  port N
  capture none|html
  segment HEX | segment repeat=N:HEX
  ```

  The server stream is the concatenation of the segments; `repeat=N:HEX` is `HEX` repeated and cut to `N` bytes.
  Every stream is synthetic (names only `*.test` and `lab`, no addresses).
- `cases/<case>.out`: `tcp-oracle v1 port=P capture=C segments=K bytes=N`, then per run `run whole|bytewise|given
  calls=N`, `app_proto N`, the actions (`action send flags=F LEN BYTES`, `action close`) in call order, the records
  (`record APP LEN BYTES`) in list order and `end`; or `hang` / `crash ...` in place of the run's lines. `BYTES` is `-`
  for nothing, `=stream` when the `LEN` bytes equal the first `LEN` bytes of the stream (checked with `memcmp`), else
  the bytes in double quotes: 0x20-0x7E as they are except `"` and `\`, every other byte as `\xNN`.
- `patterns.out`: `patterns[]` as `banner1_create` passes them to smack: `pattern I app=N flags=0xF extra=E len=L HEX`
  (flags 0x1 anchored, 0x9 anchored with wildcards).
- `hellos.out`: every port with a `payloads.tcp[]` stream after `banner1_create`: `hello port=P name=NAME flags=0xF
  next=0|1 len=L HEX`. The bytes are printed only for the streams 4b sends (`http`, `telnet`, `rdp`, `memcached`,
  `mc`); the others print `withheld` (TLS ClientHello is 4c, SMB 4d, and the nmap-service-probes hellos are never
  ported, R3: their bytes stay out of this repository).
- `banout.in.txt`, `banout.out`: direct `banout_append` scripts (`append APP LEN SEED`, byte `k` is
  `(SEED + 131 * k) & 0xFF`) and per script the node list (`node protocol=0xP length=L`, head first) and the records.
- `manifest.json`: the oracle block above, `host` (OS and kernel only), `captured_at`, the three tables and per case
  `about`, `expect`, `declared`, `port`, `capture`, `segments`, `bytes`, input and output sha256, C's `app_proto` of each
  run, and the AddressSanitizer result.

## Expectations

Each case names how rmasscan is compared with C's `whole` run, in every split the test makes (whole, byte by byte, the
given segments and 8 random splits):

- `records` (20 cases): records in C's order, each C record cut at 65 536 bytes (R5), and `app_proto`; the actions too
  on the whole stream. In task 8 these are the streams no ported parser handles: no match, 70 000 bytes without a
  match, a byte before an anchored pattern, the SMB `*` with 0x7B or 0xFF, and an SSL3 record first.
- `classification` (59 cases): only `app_proto`. Every non-SMB, non-SSL3 pattern (VNC versions, the 15 unanchored and
  6 anchored Telnet patterns, both RDP prefixes, `"220 "` on 25 and 587 against other ports), upper and lower case, a
  match in the second segment. C's parsers ran and their records are kept as evidence; the parser tasks turn their
  cases into `records`.
- `declared-4b` (11 cases): the named 4b rule and C's `app_proto`. `unknown-stream`: SMB is not ported in 4b
  (reference B6), so the whole stream is one `unknown` record (app 1) and no action, while C ran its SMB parser.

## What the goldens show (C at 8e6b3b0)

90 cases. The classifier: patterns are anchored at stream offset 0 and partial anchored matches continue across
segments; any leading byte that does not continue an anchored pattern ends anchoring for the rest of the stream; case
matters only for A-Z; the first match by earliest end wins; the SMB `*` matches every byte except the first byte of an
unanchored pattern, 0x7B (`{`) and 0xFF (`smb-star-7b-*`, `smb-star-ff-*`; `00 00 7b 22` is Minecraft); `"220 "` on 25
and 587 is SMTP (`src/proto-banner1.c:147-153`) and on any other port FTP, `"220-"` FTP everywhere (E3.3).

C depends on the split here, and rmasscan follows the whole stream:

- E2.1: a match in the second segment (`http-split-after-2`, `smb-split`) or byte by byte leaves C an extra `unknown`
  record with the bytes before the match; rmasscan replays them into the parser and keeps no such record.
- E2.2: after a rejected SSL3 record (`ssl3-then-mc`, `ssl3-then-iac`) C keeps searching and its later segments match
  Minecraft or Telnet; on the whole stream the SSL3 match is the first and the stream is `unknown`, as in rmasscan.
- R5: C keeps 70 000 bytes in one record (`no-match-70000`); rmasscan keeps the first 65 536.
