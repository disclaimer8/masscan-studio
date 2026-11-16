# TCP banner framework goldens from the pinned C masscan

Offline parity of `rmasscan_proto::banner_stream` (`crates/rmasscan-proto/src/banner1/`) with masscan's
`banner1_parse` (`src/proto-banner1.c:113-325`, masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`) for one TCP
connection: the classifier (`patterns[]`, `src/proto-banner1.c:34-106`, compiled by smack, `src/smack1.c`), the HEUR
record and its replay, the banner buffers (`src/proto-banout.c`) and the hello table of `banner1_create`. Banners
sub-stage 4b, task 8, the FTP, SMTP, POP3 and IMAP4 parsers of task 9 (`src/proto-{ftp,smtp,pop3,imap4}.c`),
HTTP responses and request editing of task 10 (`src/proto-http.c`), the SSH, Telnet, VNC and RDP parsers of
task 11 (`src/proto-{ssh,tcp-telnet,vnc,tcp-rdp}.c`), and memcached over TCP and Minecraft of task 12
(`src/proto-memcached.c`, `src/proto-mc.c`)
(`docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tcp.md` B1-B6, C2, C3, D2-D5, E2.1, E2.2, E3.3, E3.4,
E4; design R1, R5, R13, R14). The test `crates/rmasscan-proto/tests/tcp_golden.rs` replays every case; unit tests in
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

Every response case also runs under an AddressSanitizer build of the same sources; `manifest.json` records per case
whether its output equals the default build's and how many sanitizer reports it printed (all equal, none). Request
editing has its own `http_requests` section and sanitizer findings below.

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
  ported, R3: their bytes stay out of this repository). The `starttls-unknown` case outputs are not in conflict with
  that: they show C's `action send` of the masscan-authored `ssl_hello_template` (`src/proto-ssl.c:1077`, AGPL like
  the rest of the port, not NPSL), because C's text parser sends it at the go-ahead and the cases are C evidence;
  `hellos.out` is about the hellos rmasscan 4b sends from the port table, and it does not send this one.
- `banout.in.txt`, `banout.out`: direct `banout_append` scripts (`append APP LEN SEED`, byte `k` is
  `(SEED + 131 * k) & 0xFF`) and per script the node list (`node protocol=0xP length=L`, head first) and the records.
- `tls-hellos.out` (4c task 2): the eight ClientHello dumps of oracle mode `tls-hellos` — the two registered
  streams, the three vuln templates raw, and the three built hellos (`ssl_hello()` dynamicization with
  `time()` fixed at the `now` of the first line, plus the POODLE SCSV) as `tls-hello kind=K len=L HEX`.
  Provenance is in the file's `#` header; the default and AddressSanitizer builds agreed byte for byte.
  Read by the unit tests in `banner1/tls_hello.rs`.
- `manifest.json`: the oracle block above, `host` (OS and kernel only), `captured_at`, the three tables and per case
  `about`, `expect`, `declared`, `port`, `capture`, `segments`, `bytes`, input and output sha256, C's `app_proto` of each
  run, and the AddressSanitizer result.

## Expectations

Each case names how rmasscan is compared with C's `whole` run, in every split the test makes (whole, byte by byte, the
given segments and 8 random splits):

- `records` (208 cases): records in C's order, each C record cut at 65 536 bytes (R5), and `app_proto`; the actions too
  on the whole stream. From task 8 the streams no ported parser handles: no match, 70 000 bytes without a match, a
  byte before an anchored pattern, the SMB `*` with 0x7B or 0xFF, and an SSL3 record first. From task 9 the FTP, SMTP,
  POP3 and IMAP4 streams: the 11 classification cases of these parsers from task 8 (`ftp-220-dash-21`,
  `ftp-220-space-21`, `ftp-220-space-2525`, `ftp-220-dash-25`, `smtp-220-space-25`, `smtp-220-space-587`, `smtp-521`,
  `pop3`, `pop3-lowercase`, `imap4`, `imap4-lowercase`) and 50 new ones (greeting lines, the reply to
  `AUTH TLS`, EHLO and STARTTLS, CAPA and STLS, TAB, NUL and other bytes outside `isprint`, a line without a code,
  `"220-"` on 25, a 70 004-byte FTP greeting line, IMAP `* OK` and streams that only look like IMAP).
- The `classification` kind of tasks 8-11 (only `app_proto`, while a parser was still a stub) is retired: with
  task 12 every 4b parser is ported, so each former classification case is a `records` case now. Its C output file
  never changed in those upgrades; only the expected comparison grew.
- `declared-4b` (18 cases): the named 4b rule and C's `app_proto`.
  - `unknown-stream` (11): SMB is not ported in 4b (reference B6), so the whole stream is one `unknown` record (app 1)
    and no action, while C ran its SMB parser.
  - `starttls-unknown` (7): the server agrees to STARTTLS (FTP 234, SMTP 220, POP3 `+OK`). The first segment of the
    case ends with that line. Expected: the text parser's record and the actions before the TLS hello of C's run over
    that segment (the `given` run when the case has a second segment, else `whole`), no TLS hello, and the bytes of
    the second segment as one `unknown` record, in banout list order: after the parser record while that is under
    200 bytes (all these cases), before it from 200 bytes on (C moves the list head, B3; pinned by a unit test, not a
    case); `app_proto` is C's, 9. C sends `banner_ssl.hello`
    (`src/proto-ftp.c:103`, `src/proto-smtp.c:149`, `src/proto-pop3.c:131`; its bytes are in these outputs as an
    `action send`) and parses what follows as TLS, which is 4c.

## What the goldens show (C at 8e6b3b0)

226 response cases and 27 request cases. The classifier: patterns are anchored at stream offset 0 and partial anchored matches continue across
segments; any leading byte that does not continue an anchored pattern ends anchoring for the rest of the stream; case
matters only for A-Z; the first match by earliest end wins; the SMB `*` matches every byte except the first byte of an
unanchored pattern, 0x7B (`{`) and 0xFF (`smb-star-7b-*`, `smb-star-ff-*`; `00 00 7b 22` is Minecraft); `"220 "` on 25
and 587 is SMTP (`src/proto-banner1.c:147-153`) and on any other port FTP, `"220-"` FTP everywhere (E3.3).

C depends on the split here, and rmasscan follows the whole stream:

- E2.1: a match in the second segment (`http-split-after-2`, `smb-split`) or byte by byte leaves C an extra `unknown`
  record with the bytes before the match; rmasscan replays them into the parser and keeps no such record.
- E2.2: after a rejected SSL3 record (`ssl3-then-mc`, `ssl3-then-iac`) C keeps searching and its later segments match
  Minecraft or Telnet; on the whole stream the SSL3 match is the first and the stream is `unknown`, as in rmasscan.
- E2.3: a failed HTTP version (`http-failure-given`) gives no record on the whole stream, but C already recorded
  `HTTP/1.` when cut there. Rust holds the raw header in a bounded, budgeted Banout until the blank line or session
  flush; failure releases it without recording. This also preserves the whole-stream record order: Server values
  first, then the raw header append, then body/title. The staged record transfers its logical length and truncation
  flag without charging or releasing its reservation twice. Incomplete headers are emitted once at session flush.
- R5: C keeps 70 000 bytes in one record (`no-match-70000`); rmasscan keeps the first 65 536.
- STARTTLS: after the go-ahead line C keeps running the text parser over the rest of that segment from state 0
  (`src/proto-ftp.c:101`, `src/proto-smtp.c:147`, `src/proto-pop3.c:129`; the loop goes on). On the whole stream a
  tail is a new greeting with a second `AUTH TLS`, `EHLO` or `CAPA` (`ftp-auth-234-dash-25-tail`,
  `smtp-starttls-220-tail`, `pop3-stls-ok-tail`); split at the go-ahead or byte by byte it goes to the TLS parser,
  which records nothing for it. Reference E2 lists FTP, SMTP and POP3 as split-invariant in C; they are not here.
  rmasscan records every byte after the go-ahead as `unknown` in any split (`starttls-unknown`).

The text parsers (task 9), as C does on the whole stream:

- FTP and SMTP lines: three digits, `' '` (last line) or `'-'`, text; CR is skipped only inside the text, so CR or any
  other non-digit where a code digit is due closes; TAB, NUL and bytes outside 0x20-0x7E in the text close without
  being recorded; the reply to `AUTH TLS` or `STARTTLS` is read up to its first LF, which is not recorded. `"220-"`
  on 25 and `"220 "` on 2525 get `AUTH TLS` (E3.3); SMTP sends `STARTTLS` after the last EHLO line whatever the code.
- POP3: CR is skipped everywhere and every other byte is recorded, with no `isprint` check; `+OK` is compared with
  case, so `+ok` closes after `+o`; `-` to CAPA records the line and closes without `STLS`; the CAPA list ends only
  at a line holding one dot.
- IMAP4: every classified stream is `* OK` and two closes, nothing sent (`src/proto-imap4.c:49-66`, E3.4); `* ok`
  gives `* o`. `*  OK`, `* BYE` and `* OK` followed by CRLF do not match `"* OK "` and stay `unknown`.

## HTTP task 10

The 30 new response cases and three upgraded task-8 HTTP cases cover `HTTP/1.0 302`, `Server: gws`, repeated and
spaced Server names, `<title>`, `<TITLE id=x>`, `<titlex>`, no title, a title without a closing `<`, multiple titles,
full HTML on/off, failed/incomplete status and fields, 2,000 version digits, bare LF, CR inside a field name and
banout order around 199/200 bytes. Every response is compared with C whole in all splits (whole, bytewise, given,
eight seeded random splits); actions on whole too. When task 10 captured them, every response case then in the set
and the three tables gave identical normal and sanitizer output, with zero reports.

`requests/<name>.in.txt` lists edits in the C3 application order: `payload HEX` (including Content-Length),
`User-Agent: HEX`, `Host: HEX`, `method HEX`, `url HEX`, `version HEX`, `header NAMEHEX VALUEHEX`, `Cookie: HEX`.
Empty hex means an empty value; field names are C strings (NUL truncates the name), values have explicit lengths.
`requests/<name>.out` is the exact request bytes, including NUL, CR and LF. The Rust unit fixture generator is
`http_request.rs::tests::cases`; `RMASSCAN_HTTP_INPUTS=DIR cargo test -p rmasscan-proto --lib
http_request_golden_matches_c` writes independent oracle inputs. Its ordinary run compares each generated input
and result with these files. The shared manifest test (`manifest_hashes_match_files`,
`crates/rmasscan-proto/tests/tcp_golden.rs`) verifies the hash of every file in the manifest: input and output of
each response case, the two banout scenario files, the two tables and input and output of each request case; it also
asserts that count.

The request adapter, kept off repository, includes the unchanged TCP oracle with renamed main, creates Banner1,
copies the default hello, then calls the real `http_change_requestline`/`http_change_field` in C3 order. The pinned
source hashes are in the main oracle section; `http_requests.oracle` records request adapter, build script, runner,
compiler and both binary hashes. Task 10 captured locally with Apple clang; prior TCP outputs and table bytes stayed
identical. The original oracle artifacts were preserved; no remote machine or scan was used.

The 27 request cases cover default and individual options, a combined case, case-insensitive replacement and
respelling, a name without colon, CRLF/bare LF, whitespace/empty values, empty method, URL with space, explicit
binary values and repeated cookies. Sanitizer metadata is evidence, not an alternate expected request:

- Eight request runs report a C memory defect. `combined`, `user_agent-13`, `user_agent-14`, `user_agent-15` have the
  known replace over-read (`src/proto-http.c:362-364`, E1.7); `method-2`, `url-6`, `version-8`, `version-9` expose
  shrinking before tail movement (`:110-114`, E1.17). Each has one report; the other 19 have none.
- `method-2` (empty method), `version-8` (empty version) and `version-9` (version `a\r\nb`) have corrupted visible tails
  under ASan; the other 24 outputs agree. Rust uses a safe logical splice preserving the full old tail, matching the
  ordinary captures here and never copying allocator/redzone bytes. That agreement does not prove defined C
  behavior. Short/empty values remain accepted. These class-a fixes are also in the binding reference and README.
- The retained off-repository sanitizer diagnostics and stdout hashes in the manifest identify the failing C
  evidence; those invalid bytes are not fixture expectations.

## Tasks 11 and 12

Task 11 added the SSH, Telnet, VNC and RDP streams (SSH ident and KEX fallthrough, Telnet negotiation and
subnegotiation, the VNC 3.3/3.7/3.8 security handshakes and error path, RDP TPKT/COTP/CC including the whole-stream
`unknown` of E2.5) and upgraded 41 task-8 classification cases to `records`. Task 12 adds memcached over TCP and
Minecraft: `STAT` lines (kept stats, unknown stat, bare `STAT`, `ERROR`, `END`), the split-keyword and
past-segment cases (`memcached-split-keyword`, `memcached-tcp-past-segment`: C loses a command keyword cut at a
segment boundary, E2.6, and reads `px[length]` in the skip-line state, E1.4), and Minecraft JSON (balanced, with
favicon, unbalanced, extra closes, braces inside strings, `{"` unanchored on any port). C's split runs stay as
evidence for E2.4-E2.7 and E2.9, pinned by `c_split_evidence_matches_the_reference`; rmasscan gives the whole-stream
records in every split (Minecraft: the raw stream at flush when the brace count ends `<= 0`, favicon kept, E2.7).
The task-12 recapture regenerated all 226 cases locally with the same oracle builds: every prior case file and
table stayed byte-identical, and normal and sanitizer outputs agree with zero reports.
