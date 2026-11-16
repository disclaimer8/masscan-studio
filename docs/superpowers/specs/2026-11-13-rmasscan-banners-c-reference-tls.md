# rmasscan banners 4c: C reference for TLS and X.509 (upstream masscan @ 8e6b3b0)

Scope: substage 4c of the banners stage (stage spec §3, plan 2026-11-13-rmasscan-banners-4c.md task 0). Every
claim below was re-read in the C source at `8e6b3b0` on 2026-11-15; line numbers are that tree (`src/file.c:NNN`).
This document supersedes the TLS half of
[the TLS/SMB reference](2026-11-13-rmasscan-banners-c-reference-tls-smb.md) where they differ (§G lists every
correction); the SMB half is untouched and will be re-checked by 4d. Sections: A streams and hellos, B record
layer, C X.509 observable semantics, D stack mechanics, E options and modes, F differences (E1 fixes, E2 split
dependence, E3 kept quirks), G corrections to the TLS/SMB reference.

## A. Streams and ClientHellos

### A1. Registration and ports
- `banner_ssl` {name "ssl", port 443, hello=`ssl_hello_template`, hello_length=`sizeof-1`, flags=`SF__close`,
  parse=`ssl_parse_record`, next=`&banner_ssl_12`} (`src/proto-ssl.c:1442-1451`); `banner_ssl_12` is the same
  with `ssl_12_hello_template`, flags 0, next 0 (`:1435-1440`). Neither stream has `SF__nowait_hello`, so the
  hello waits for the 2-second hello timeout like every other stream (TCP reference B5).
- `SF__close` means `App_SendFirst` queues a FIN right after the hello (`src/stack-tcp-app.c:187-192`; the FIN
  leaves a tick later, TCP reference A5). Only the first stream has it.
- Exactly 23 ports are pre-wired to `&banner_ssl` in `banner1_create` (`src/proto-banner1.c:527-595`): 322, 443,
  465, 636, 637, 990, 991, 992, 993, 994, 995, 2083, 2087, 2096, 2376, 3269, 5061, 8140, 8443, 8531, 9050, 11712,
  49955. This matches the 4b TCP reference B4 row for TLS. Ports 2379/2380 are `docker` (NPSL), 563 is nothing.
- `--hello ssl` and each vuln mode assign `&banner_ssl` to ports 0..65534 (`for (i=0; i<65535; i++)`,
  `src/stack-tcp-core.c:501-507,546-549,562-565,584-587`); port 65535 keeps its previous stream (E3.6 of 4b).
- `--hello-string[PORT]` copies the port's current stream struct and replaces only `hello`/`hello_length`
  (`src/stack-tcp-core.c:595-616`), so on a TLS port (or under `--hello ssl` / a vuln mode) the copy keeps
  `SF__close` and `next=&banner_ssl_12` (E3.5 of 4b, closed by 4c).
- The classifier has eight anchored SSL3 patterns `\x16\x03\x00..\x03` and `\x15\x03\x00..\x03`
  (`src/proto-banner1.c:56-63`), and an SSL3 match is rejected unless our TLS hello was sent on this connection
  (`!(proto==PROTO_SSL3 && !is_sent_sslhello)`, `:137-138`). `is_sent_sslhello` is set only by
  `banner_set_sslhello` in `App_SendFirst` when the stream is exactly `&banner_ssl` or `&banner_ssl_12`
  (`src/stack-tcp-app.c:157-163`) and by the STARTTLS hand-offs (§A4). A copied `--hello-string` stream on a TLS
  port is neither pointer, so it does not set the flag (its parser is still `ssl_parse_record` once classified
  by port stream, but a server-first SSL3-classified stream stays rejected).

### A2. The five templates; dynamicization only in vuln modes
Record framing `16 <ver16> <len16>`, handshake `01 <len24> <client_version16> <random32> …`. Sizes are
`ssl_hello_size` = record length + 5 (`src/proto-ssl.c:1211-1220`), not `sizeof` (the registered
`hello_length = sizeof(template)-1` agrees for the two static templates).

| kind | source | record ver | client ver | total | session id | cipher suites | extensions |
|---|---|---|---|---|---|---|---|
| default | `ssl_hello_template` `src/proto-ssl.c:1076-1105` | 03 01 | 03 03 | 198 | empty | 30 (list `:1089-1092`) | 000b, 000a, 0023, 0016, 0017, 000d |
| tls13 (`_12`) | `ssl_12_hello_template` `:1114-1120` | 03 01 | 03 03 | 287 | 32 bytes fixed | 31 incl. 1301/1302/1303 | default set + 002b, 002d, 0033 |
| heartbeat | `ssl_hello_heartbeat_template` `src/vulncheck-heartbleed.c:33-66` | 03 02 | 03 02 | 225 | empty | 51 (102 bytes) | 000b, 000a, 0023, 000f data `01` |
| ticketbleed | `ssl_hello_ticketbleed_template` `src/vulncheck-heartbleed.c:4-27` | 03 01 | 03 03 | 361 | 16 bytes `ff6fbfbc…` | 13 | 0000 SNI `www.ancestry.com`, 0005, 000a, 000b, 0023 (194-byte ticket), 000d, ff01 |
| sslv3 | `sslv3_hello` `src/vulncheck-sslv3.c:6-17` | 03 00 | 03 00 | 72 (+2 with SCSV) | empty | 12 incl. `feff` | none (no extensions block) |

- **In Normal mode the two hellos go on the wire as the static template bytes** (fixed random). `ssl_hello()`
  is called only in the three vuln branches of `tcpcon_set_parameter` (`src/stack-tcp-core.c:542,558,578`), and
  `banner_ssl.hello` is assigned nowhere else. `banner_ssl_12.hello` is never replaced: in a vuln mode the
  second connection still sends the static TLS 1.3 template.
- `ssl_hello(templ)` (`src/proto-ssl.c:1224-1254`): copies `ssl_hello_size` bytes, writes `time(0)` big-endian
  at bytes 11..14, then for `i` in 4..32 writes byte 11+i = low byte of
  `siphash24(&val, sizeof(val), key={0,0})` where `val` is C `unsigned` (4 bytes, host order) holding `i + now`.
  On the little-endian hosts masscan runs on, the hashed bytes are `(i + now)` as u32 LE. Bytes 11..42 are the
  32-byte random (4 time + 28 siphash). The buffer is built once per scan (one `banner_ssl.hello`), so every
  vuln-mode hello of a scan is identical.
- Poodle: `px = ssl_hello(sslv3_template)`, then `ssl_add_cipherspec(px, 0x5600, append=1)`
  (`src/stack-tcp-core.c:578-580`). `ssl_add_cipherspec` dispatches on the record version and only supports
  0x0300, else prints `internal error` to stderr and returns the template unchanged (`src/proto-ssl.c:1182-1206`;
  also when byte 0 is not 0x16). The SSLv3 variant (`:1123-1178`) finds the cipher list at fixed offset 43 plus
  the session-id length byte there, inserts 2 bytes at the end of the list, and adds 2 to all three length
  fields (cipher-list, handshake, record).
- rmasscan already has the hash: `rmasscan_core::cookie::siphash24(data, k0, k1)` (crate `siphasher`, vectors
  pinned against `src/crypto-siphash24.c:150-244`). No new implementation is needed in 4c.

### A3. SendFirst kludges and the small window
- On first send (`src/stack-tcp-app.c:154-195`): if the stream pointer is `&banner_ssl`/`&banner_ssl_12`,
  `banner_set_sslhello(socket, true)`; if `banner_is_heartbleed(socket)` (the scan mode flag, any stream),
  `banner_set_small_window(socket, true)` sets `tcb->is_small_window` (`src/stack-tcp-core.c:1556-1563`).
- While `is_small_window`, **every** frame from `tcpcon_send_packet` (SYN, ACK, data, FIN, RST) has its window
  rewritten to 600 by `tcp_set_window(px, len, 600)` after the frame is built (`src/stack-tcp-core.c:1163-1164`).
- `tcp_set_window` (`src/templ-pkt.c:374-414`) re-parses the finished frame as Ethernet (`preprocess_frame(..., 1)`)
  and recomputes the TCP checksum with `tcp_checksum2` (`:211-232`), whose pseudo-header always reads the four
  address words at IPv4 offsets `ip+12..ip+19`. On an IPv6 frame that is the middle of the source address, so
  the recomputed checksum is wrong: class (г) broken frames, §F E1. Our frame builder writes the window before
  checksumming per family, so rmasscan frames are correct by construction; the window value 600 is the parity
  surface. (On non-Ethernet templates the C parse can also simply not find TCP and leave the window at 1200.)

### A4. STARTTLS sends the current `banner_ssl.hello`
FTP (`src/proto-ftp.c:93-104`), SMTP (`src/proto-smtp.c:139-150`), POP3 (`src/proto-pop3.c:122-133`) and the
unreachable IMAP4 path (`src/proto-imap4.c:181`) `memset` the stream state, set `app_proto=PROTO_SSL3` and
`is_sent_sslhello=1`, restore the port, and `tcpapi_send(banner_ssl.hello, banner_ssl.hello_length)`. In a vuln
mode that is the mode's hello. What C does with the rest of the go-ahead segment is E2 (§F); 4c replaces the 4b
E2.8 rule as decided in the plan.

## B. Record layer (`ssl_parse_record` and below)

State lives in `StreamState` (`src/proto-banner1.h:77-98,253`): record state/remaining in `pstate`, plus
`ssl.type`, `ssl.handshake.{state,type,remaining}`, and one union `ssl.x` shared by `server_hello`,
`server_cert` and `server_alert` (all start with `state`). Alert and heartbeat reuse `ssl.handshake.state` and
`ssl.handshake.remaining` as their own. Observable consequences are noted where they matter.

### B1. Record framing and resets (`src/proto-ssl.c:892-1053`)
- States START → VERSION_MAJOR → VERSION_MINOR → LENGTH0 → LENGTH1 → CONTENTS, 5-byte header
  `type|ver_mjr|ver_mnr|len16`. START: type byte with high bit set → UNKNOWN (terminal: the rest of the stream
  is consumed and ignored). VERSION_MAJOR must be exactly 3, else UNKNOWN. VERSION_MINOR is stored unchecked
  (record version itself is never reported; the ServerHello version is).
- `ssl->handshake.state` is reset to 0 in two places: in START when the record type differs from the previous
  record's (`:933-938`), and on the LENGTH1→CONTENTS fallthrough (`:968-971`, only when the length's last byte
  is not the last byte of the segment — the `DROPDOWN` break skips the reset, which is harmless because the
  next call enters CONTENTS with the sub-parser untouched since the header). Net effect: **each record starts
  its handshake sub-parser at state 0**. A handshake message fragmented across two TLS records is therefore
  re-entered at START on the second record (its first payload byte is read as a new handshake type) — kept
  quirk E3, distinct from TCP segmentation, which the machine is invariant to.
- CONTENTS dispatches by record type over `min(segment_left, record_remaining)`: 20 ignored, 21 `parse_alert`,
  22 `parse_handshake`, 23 ignored, 24 `parse_heartbeat`, any other type ignored (no default error). Record
  types above 24 with the high bit clear are skipped whole.
- A zero-length record goes LENGTH1 → CONTENTS with `len=0` (inner parser called with an empty slice for
  types 21/22/24) and immediately back to START.

### B2. Handshake framing (`:522-652`)
- States START → LENGTH0..2 → CONTENTS. START: type byte with high bit set → UNKNOWN for this handshake
  machine (the record layer keeps framing subsequent records, and B1 resets the handshake state per record, so
  a later record can parse again). On START, `ssl->x.all.state = 0` resets the shared sub-parser state.
- At the end of LENGTH2, if `handshake.type == 2` (ServerHello — the comment says "server done", the code says
  2) and `is_heartbleed`, the 15-byte probe `15 03 02 00 02 01 80 18 03 02 00 03 01 40 00` is sent with
  `tcpapi_send(..., 0)` (`:583-588`). This fires once per ServerHello header, before its contents are parsed,
  and also on a zero-length ServerHello. Live-stack caveat (task 10): on the first connection the hello went
  out with `SF__close`, so by parse time the TCB is in FIN_WAIT1_SEND/FIN_WAIT1_RECV/FIN_WAIT2 and
  `tcpapi_send` refuses ("wrong state", `stack-tcp-core.c:1758-1778`; `seg_send` would also refuse past the
  queued FIN) — at the pin the probe only reaches the wire on the reconnect connection (`banner_ssl_12`, no
  `SF__close`) when the ServerHello is parsed after the hello was acked (ESTABLISHED_RECV). The parser action
  itself is observable offline (oracle cases) and kept as is.
- CONTENTS dispatches only type 2 → `parse_server_hello` and type 11 → `parse_server_cert`; all other types
  are skipped by length. When the handshake length is exhausted the state returns to START (another handshake
  message may follow in the same record).

### B3. ServerHello (`:127-339`), emission order
1. VERSION_MINOR byte: `BANNER_VERSION` appends the version token to `ssl` (`"SSLv3 "`, `"TLS/1.0 "`,
   `"TLS/1.1 "`, `"TLS/1.2 "`, `"TLS/1.3 "`, else `"SSLver[%u,%u] "`, `:90-118`). For version 0x0300 it **also**
   appends `"SSL[v3] "` to `vuln` (`:98`), in every mode.
2. Same byte, if `is_poodle_sslv3`: `" POODLE "` appended to `vuln` (`:180-182`) — before the sanity check:
   `version_major > 3 || version_minor > 4` → UNKNOWN (`:183-186`), but the two appends above have already
   happened (only reachable with major ≠ the record's, since this is the handshake's own version field).
3. 4-byte time skipped into an unused `timestamp`, 28-byte random skipped.
4. SESSION_LENGTH byte: if `is_ticketbleed && remaining > 16` → `vuln` gets `"SSL[ticketbleed] "` (17 bytes
   hardcoded, `:226-228`). Fires on the declared length alone.
5. Session id skipped; 2-byte cipher → `BANNER_CIPHER` appends `"cipher:0x%x"` to `ssl` with no trailing space
   (`:70-86`), so names from the certificate follow as `", name"` items, and an alert later appears glued as
   `"cipher:0x88 ALERT(...)"` modulo the alert's own leading space (B5).
6. Compression byte stored; 2-byte extensions total; then `tag16|len16|data` walk bounded by that total
   (`remaining`): fewer than 4 bytes left at EXT_TAG0 → UNKNOWN. Extension `0x000f` (heartbeat): the **first**
   data byte, if nonzero, appends `"SSL[heartbeat] "` (15 bytes hardcoded) to `vuln` (`:313-328`); further data
   bytes are skipped as EXT_DATA. An extension length running past the extensions total ends via
   `remaining == 0` → UNKNOWN. Bytes of the ServerHello beyond the extensions block are not consumed by this
   parser (the handshake layer skips them).

### B4. Certificate framing (`:370-495`) and banout completion
- 3-byte total length, then per certificate a 3-byte length and the DER body. First certificate (states
  CLEN*/CERT) → `PROTO_X509_CERT` (15), the rest (CALEN*/CACERT) → `PROTO_X509_CACERT` (16).
- At each certificate start: `banout_init_base64` if capturing, the X.509 state is zeroed and re-initialised
  with this certificate's length, and `x509.count` becomes previous count + 1 (`:432-437`; `count` is
  `unsigned char` in `CertDecode`, wraps after 255).
- Body fragments go to both consumers in order: base64 append (if `is_capture_cert`), then `x509_decode`
  (`:451-458`). At `cert_remaining == 0`: finalize base64, then `banout_end(proto)` (`:465-474`). The
  commented-out close at `:475-481` does nothing.
- `banout_end` sets `0x80000000` on the node's protocol (`src/proto-banout.c:163-171`), and only if the node
  exists and is non-empty. `banout_find_proto` compares the **full** protocol word (`:54-59`), so the next
  append for the same proto does not find the ended node and creates a new one: **a chain of three
  certificates yields one `X509` record and two `X509CA` records** at flush (`banner_flush` emits each node
  with `protocol & 0x0FFFFFFF`, `src/stack-tcp-core.c:799-830`). A zero-length certificate produces no capture
  record (finalize with state 0 appends nothing; `banout_end` finds no node).
- The streaming base64 (`src/proto-banout.c:376-442`) emits 4 chars per completed 3-byte group with carry in
  `pstate->base64` (one encoder per connection, shared with heartbleed capture); finalize emits the partial
  group with `=`/`==`. No line wrapping, no PEM header in the record.
- Total/cert lengths are `unsigned` from the wire (24-bit); `len` is clamped by both remainings. If the total
  runs out mid-certificate, whatever was captured stays unfinalized (no padding) and whatever names were
  decoded stay in `ssl`.

### B5. Alert (`:788-867`)
- Two bytes `level|description`, read via the shared handshake state (one alert per record at most: after
  DESCRIPTION the state drops to UNKNOWN and the rest of the record is skipped by the record layer).
- Non-poodle, or poodle with `level != 2`: `ssl` gets `" ALERT(0x%02x%02x) "`.
- Poodle with `level == 2`: description 86 → `safe` gets `"poodle[TLS_FALLBACK_SCSV] "` unless `safe` already
  contains `"TLS_FALLBACK_SCSV"`; description 40 → `safe` gets `"poodle[no-SSLv3] "` under the **same**
  contains-check (it checks for the SCSV string, not its own — after an 86, a following 40 is suppressed; two
  40s across two records are not suppressed by each other); any other description → `safe` gets
  `"poodle[no-SSLv3] "` unconditionally **and** `ssl` gets the ALERT text (`:822-856`).

### B6. Heartbeat (`:668-775`)
- Type byte must be 1 or 2, else UNKNOWN. At LENGTH1, for type 2: if the **declared** length ≥ 16 → `vuln`
  gets `"SSL[HEARTBLEED] "` (16 bytes hardcoded) whether or not those bytes ever arrive; if
  `is_capture_heartbleed`, the base64 encoder is initialised and an empty append creates the `heartbleed`
  node (`:719-732`) — a capture record exists even if zero payload bytes follow.
- Payload bytes are base64-appended while the declared length lasts; at its end the state goes UNKNOWN
  (padding skipped by the record layer). **`banout_finalize_base64` is never called for heartbleed capture**
  (its only call site is certificate framing): a captured bleed whose length is not a multiple of 3 loses the
  last partial group and never gets `=` padding. Deterministic output — kept quirk E3.

## C. X.509 observable semantics (`src/proto-x509.c`, `src/proto-x509.h`)

The Rust implementation is a native incremental DER walk (plan decision), so this section pins what is
observable — which bytes reach the `ssl` banner, and what stops parsing — not the ~130 C states. Anything C
does that is not observable in the banner or in stopping is explicitly marked dead.

### C1. The walk is positional, not a generic DER tree
Fields are expected in one fixed order (state enum `:439-476`, `kludge_next` patch table `:485-526`):
outer SEQUENCE → TBS SEQUENCE → version [0] then INTEGER → serial INTEGER → signature SEQUENCE + OID →
issuer SEQUENCE (RDN loop: SET → SEQUENCE → OID → string) → validity SEQUENCE (two times) → subject SEQUENCE
(same RDN loop) → subjectPublicKeyInfo SEQUENCE (contents skipped) → extensions [3] → extensions SEQUENCE →
per extension SEQUENCE (OID → optional critical → OCTET STRING → inner SEQUENCE → GeneralName list) → outer
signatureAlgorithm SEQUENCE + OID → signature BIT STRING (contents skipped). There is **no path for
issuerUniqueID [1] or subjectUniqueID [2]**: after the public-key field the machine demands the extensions tag
`0xa3`, and anything else is a hard tag error (C2). A v1 certificate (no version [0]) fails at the version tag
demand `0xa0`.

### C2. Tag checks: hard vs soft
- Hard (mismatch → state ERROR): every SEQUENCE position demands `0x30`, version [0] demands `0xa0`, INTEGER
  (version, serial) demands `0x02`, every OID position demands `0x06`, extensions [3] demands `0xa3`, the
  final BIT STRING demands `0x03` (`:582-652,755-780`). ERROR drains the current field via `ASN1_skip` and the
  pop at the top of the byte loop resumes at the stacked brother state, so a hard error stops the current
  field, not necessarily the certificate; where the brother is PADDING the rest of the parent is dead bytes.
- Soft (mismatch only skips the decoration, parsing continues at the length): RDN SET `0x31`, name strings
  `0x13`/`0x0c` (bracket append in capture modes only), validity times `0x17` — the timestamp digits are then
  still consumed positionally into the dead validity computation (`:589-625,944-1022`).
- `EXTVALUE_TAG` (the byte after an extension OID): `0x04` proceeds to the value length; `0x02` and every
  other byte go to PADDING, i.e. **an extension with a critical BOOLEAN (`0x01`) is skipped whole** and its
  value never parsed (`:811-822`). SAN (`0x55 0x1d 0x11` below) is normally non-critical, so this rarely bites.

### C3. Lengths and the push limits
- Length byte < 0x80 is the length. With the high bit set, `length_of_length = byte & 0x7f` length bytes
  follow, accumulated into an `unsigned short` (`u.tag.remaining`, `src/proto-x509.h` union): forms 0x81/0x82
  are the sane ones; 0x83+ wraps the u16, and 0x80 (indefinite) makes `length_of_length` underflow its
  `unsigned char` to 255 after the first length byte (`:865-942`). Both are deterministic garbage lengths, not
  crashes; §F E2 leaves their treatment to the oracle data of task 3.
- `is_der_failure` is set for non-minimal lengths and leading zeros (`:917-932`) and **never read** anywhere.
- `ASN1_push` (`:304-374`): a length > 0xFFFF, stack depth ≥ 9, or a child length greater than the parent's
  remaining sets `x->state = 0xFFFFFFFF` and returns without pushing (and prints to stderr for the first two).
  The failure is sticky **across calls** (the save at `:1058-1059` does not overwrite it) but not within one:
  the local `state` in the running `x509_decode` call is untouched, so the rest of that call keeps parsing
  without the frame (parent remaining also not reduced). C's result on such input therefore depends on how
  the stream is split into calls (task 3 oracle case `google-trunc-half`: whole emits the CN, bytewise
  nothing); per Р13 the golden is the whole-stream run, and the Rust walk reproduces it in every split by
  simply not pushing on failure. Only the very first push (certificate length in `x509_decode_init`) has no
  "within the call" life after it, so a certificate over 64 KiB is never parsed. On a successful push, the
  child's length is subtracted from the parent's remaining; the pop-at-zero at the top of the byte loop
  (`:567-571`) then walks back up.
- `x509_decode_init(x, length)` zeroes the state and pushes the certificate length with next-state
  `0xFFFFFFFF` (`:1378-1383`), so a certificate length > 0xFFFF makes the certificate unparseable (nothing is
  emitted) while capture still records its bytes (B4 runs independently).
- PADDING consumes bytes without interpreting them until the enclosing field's remaining hits zero
  (`:1024-1041`, ASN1-CHILD-UNDERFLOW) — unknown and trailing material is silently swallowed at every level
  whose brother state is PADDING (`kludge_next` default).

### C4. OID matching and name emission
- OIDs are matched by an Aho-Corasick (smack) over the OID **value bytes**, anchored at the first byte, with
  `SMACK_SNMP_HACK` (a 0x80 self-loop, so zero-prefixed sub-identifiers still match), built from `mib[]`
  (`:124-170,250-280`). Patterns are typed in the "43/85" first-byte-merged text form, so `85.4.3` is the
  value bytes `55 04 03` (2.5.4.3 commonName) and `85.29.17` is `55 1d 11` (2.5.29.17 subjectAltName). Only
  these two carry id `Subject_Common`; every other table entry (SNMP MIB names, signature algorithms, other
  RDN types) only sets `subject.type` to a non-emitting value — including the per-arc intermediate matches:
  `subject.type` is overwritten on **each** arc boundary where smack reports a pattern (`:687-746`), so e.g.
  `55 04` (2.5.4) matches mid-OID before `55 04 03` completes; only the final value at OID end matters for the
  following string. An OID unknown to the table leaves `subject.type` at whatever the last matched prefix set.
- CN: when a subject OID finishes with type `Subject_Common` and `x->count <= 1` (first certificate), `", "` is
  appended to `ssl` immediately at the last OID byte; if `count > 1`, `subject.type` is forced to 0 so the
  string that follows is not emitted either (`:719-727`). The string bytes are then appended one by one in
  SUBJECTNAME_CONTENTS for as long as `subject.type == Subject_Common` (`:660-668`) — any string tag (C2 soft),
  any bytes including NUL. A subject with two CN RDNs emits `", a, b"`.
- SAN: when an extension OID finishes with type `Subject_Common`, each GeneralName with tag `0x82` (dNSName)
  appends `", "` at its tag byte and its bytes in EXT_DNSNAME_CONTENTS (`:795-809,660-668`); other
  GeneralName tags go to PADDING for the rest of that name structure. **As written, the SAN path has no
  `count` gate** — the suppression in `:724-726` runs only inside SUBJECTID_CONTENTS1. Whether a chain
  certificate's SANs reach the banner must be probed against the oracle (task 3, case "chain with SAN"); the
  TLS/SMB reference's blanket "only the first cert" is not what the code says for extensions (§G).
- `subject.type` is reset at each RDN SET (`:609-617`) but not between extensions except through OID matching;
  an extension whose OID never matches a `mib[]` pattern inherits the previous type.
- Issuer names are never emitted on the live path: ISSUERNAME_CONTENTS emits only under `is_capture_issuer`,
  and the SUBJECTNAME/EXT_DNSNAME bracket form `" subject[" … "]"` only under `is_capture_subject`
  (`:589-608,653-668`). Both flags are zero in the live SSL path (state is memset per certificate, B4) and
  the only place setting them is dead readscan code (§E4).

### C5. Dead paths (do not port)
Validity times are decoded digit-by-digit into a `struct tm`, `mktime`d and stored; the day count print is
commented out (`:944-1022`). Version and serial integers are accumulated into `u.num` and never used.
`spnego_decode` in the same file (`:1061-1390`) belongs to SMB (4d), not 4c.

## D. Stack mechanics for 4c

### D1. Reconnect (`src/stack-tcp-core.c:1603-1700,1781-1794`)
- Trigger: `App_Connect` on APP_CONNECTED, if `stream->next`, calls `tcpapi_reconnect(socket, stream->next,
  App_Connect)` before arming the hello timeout (`src/stack-tcp-app.c:56-80`). The original connection
  proceeds normally; both connections live independently.
- `_next_IP_port` (`:1603-1644`): `port = first + (port - first + 1)`; if that reaches `>= last`, wrap to
  `first` and advance the source IP the same way inside its range (wrap to its first). The port range is the
  stack source range (`stack->src`), whose `last` behaves as exclusive in this arithmetic. The IPv6 branch is
  marked "TODO: this code is untested, yolo" and subtracts/adds 128-bit addresses (`:1627-1638`).
- If the next (ip, port) equals the current one (single source port and address), C prints
  `[-] ERR: There must be multiple source ports/addresses for reconnection` but **still calls create**;
  `ERRMSG` deduplicates by format-string pointer (`src/util-errormsg.c:40-64`), so this prints once per run.
- `tcpcon_create_tcb` with an existing 4-tuple returns the existing TCB unchanged (`:1000-1004`), after which
  `_do_reconnect` writes `new_tcb->app_state = App_Connect` onto it (`:1699`). In the same-4-tuple case that
  writes the *original* connection's app state back to App_Connect moments before `application_event` moves
  it to ReceiveHello — no observable effect. With a different port whose 4-tuple happens to already be live
  (e.g. the original SYN used that port for another target), the same overwrite hits that foreign connection:
  kept quirk E3, in practice unreachable in the lab.
- New TCB: state SYN_SENT (memset 0), `seqno_me = syn_cookie(their ip/port, my new ip/port, entropy) + 1`,
  `seqno_them = 0`, `ttl = 255` placeholder, `when_created = global_now` at reconnect time, stream = the
  `next` stream, first timeout scheduled at `secs+1` (`:1045-1052`, `TICKS_FROM_TV(secs+1, usecs)` — the same
  +1s first tick every TCB gets; the 4b timer model governs rmasscan's equivalent, Р6).

### D2. SYN_SENT (`:2003-2030` plus the common prologue)
- On TIMEOUT: `syns_sent++` and a SYN (`0x02`) is sent via `tcpcon_send_packet`, which puts
  `seqno_me - is_syn` on the wire (`:1155`) — i.e. exactly the cookie. This repeats on every tick until a
  SYN-ACK arrives or the lifetime check (`when_created + timeout_connection < secs`, checked on TIMEOUT
  before the state switch, `:1970-1980`) sends RST and destroys the TCB. A SYN_SENT connection that never
  establishes therefore still ends with a lifetime RST (seq = `seqno_me`, ack = 0), like C.
- On SYNACK: seq/ack fields are adopted from the segment, ACK sent, state → ESTABLISHED_RECV, APP_CONNECTED
  delivered (which for `banner_ssl_12` finds `next == 0` and arms the hello timeout). The engine only ever
  hands the stack a SYN-ACK whose cookie `parse_reply` verified (4b task 4 contract), which is why the stack
  must compute the same cookie from the table seed.
- Any other event in SYN_SENT logs an UNHANDLED EVENT `ERRMSGip` (also deduplicated once).

### D3. Records from the second connection
The second connection is an ordinary TCB: its banners flush as its own connection-banner set, its `open`
status was already written by the SYN-spew path's first SYN-ACK. Its banner records carry the TTL logic of 4b
(task 7 of 4b: TTL of the SYN-ACK that created the TCB); the placeholder `ttl=255` is overwritten by the
normal create-on-SYNACK fields in C when the reply is processed (`stack_incoming_tcp` create path, TCP
reference A3) — the lab verifier in task 12 confirms the record TTL against the oracle.

## E. Options and modes

### E1. Capture flags (`src/main-conf.c:1132-1178`, table `:2402-2403`)
- `--capture cert|servername|html|heartbleed|ticketbleed` and `--nocapture`/`--no-capture` set the five
  `Masscan.is_capture_*` bits by `EQUALS` on the value; unknown value prints `FAIL: %s: unknown capture type`
  (or `nocapture`) and returns CONF_ERR. Defaults at startup: only cert on (`src/main.c:1610`).
- `is_capture_servername` has no consumer anywhere (it is copied into `Banner1` by
  `tcpcon_set_banner_flags`, `src/stack-tcp-core.c:623-636`, and never read). The flags are copied once at
  scanner start (`src/main.c:638-643`); parser code reads `banner1->is_capture_*` only.
- Echo: `SET_capture` in echo mode prints, for cert and servername when off, and for html/heartbleed/
  ticketbleed when on, `capture = X` or `nocapture = X` — already ported in 4a; 4c does not change it.

### E2. The three vuln modes (`src/main-conf.c:2810-2819,2929-2941`)
- `--heartbleed` (name): `is_heartbleed=1`, then parameters `no-capture=cert`, `no-capture=heartbleed`,
  `banners=true` — in argv order, so a later `--capture cert` re-enables capture. `--ticketbleed` is the same
  with `no-capture=ticketbleed`. There is no `--poodle` or `--sslv3` option *name*; poodle is reached only as
  `--vuln poodle` or `--vuln sslv3` (value by EQUALS): `is_poodle_sslv3=1`, `no-capture=cert`, `banners=true`.
- `--vuln heartbleed|ticketbleed` forwards to the same two name branches. Any other `--vuln` value goes to
  `vulncheck_lookup` (`src/vulncheck.c:7-13`), which knows only `ntp-monlist` (a Lua script check); unknown
  values print `FAIL: vuln check '%s' does not exist` + hint and `exit(1)`. A second different script check
  prints `FAIL: only one vuln check supported at a time` + hint and `exit(1)`. Script checks (Lua) are a stage
  non-goal (spec §2); in 4c only the four TLS values are ported and everything else keeps C's fatal text —
  including `ntp-monlist`, which in rmasscan must fail the same way instead of running (named difference,
  task 9).
- The three mode bits are independent booleans on `Masscan` (`src/masscan.h:201-203`). At start they are
  applied to the stack in the fixed order smbv1, http, ssl, heartbleed, ticketbleed, sslv3
  (`src/main.c:645-654`): each `tcpcon_set_parameter` call reassigns all ports to `&banner_ssl` and replaces
  `banner_ssl.hello`, so with several modes set the **last in that fixed order wins the hello**, while the
  `banner1->is_*` parser flags accumulate (heartbleed probe + ticketbleed length check + poodle alert logic
  can all be armed at once, with the sslv3 hello on the wire).
- The mode bits have no `SET_` table entries: they are not printed by `--echo` and not written to
  `paused.conf` beyond their side effects (`banners = true` and the nocapture lines). A resumed scan
  therefore continues in Normal TLS mode — kept quirk, named in the README by task 10.

### E3. What the modes do to the wire, summary
| mode | hello (all ports <65535) | parser flag | extra wire behavior |
|---|---|---|---|
| heartbleed | heartbeat template via `ssl_hello()` | `is_heartbleed` | small window 600 (§A3); probe on ServerHello (B2) |
| ticketbleed | ticketbleed template via `ssl_hello()` | `is_ticketbleed` | — |
| poodle/sslv3 | sslv3 template via `ssl_hello()` + SCSV | `is_poodle_sslv3` | — |

### E4. readscan and the `certs` format
- `readscan_report()` in `src/in-report.c:337-381` would base64-decode `X509` records, re-run `x509_decode`
  with `is_capture_subject=is_capture_issuer=1`, and annotate `vuln` records — but its only call site is
  commented out (`src/in-binary.c:444`). Shipped `--readscan` therefore does **no** re-decode: TLS banner
  records convert between formats byte-wise like any other banner (stage spec §5). Do not port the dead path.
- `--output-format certs` (`src/out-certs.c`): `cert_out_banner` ignores its `fp` and `proto` and `printf`s
  **every** banner record to stdout as PEM: strips a leading `"cert:"` if present (length > 5), prints
  `-----BEGIN CERTIFICATE-----`, the record bytes in 72-column lines, `-----END CERTIFICATE-----`. Close
  prints `{finished: 1}` to the output file. Status records print nothing.

## F. Differences for 4c

### F1. E1 — fixes (class а–г of Р1; each becomes a README line)
- **E1.1 small-window checksum on IPv6.** `tcp_set_window` recomputes with an IPv4 pseudo-header (§A3), so
  C's heartbleed-mode IPv6 frames carry a wrong TCP checksum (class г). Ours are computed per family.
- **E1.2 length forms beyond 0x82 in X.509.** C wraps a u16 for 0x83+ and underflows `length_of_length` for
  0x80 (C3), producing deterministic garbage field boundaries. If the Rust walk instead fails the field
  closed on `length_of_length == 0 || > 2`, the difference is named here and decided on oracle cases in
  task 3 (default: fail closed — the wrapped lengths read sibling bytes as the wrong fields but stay inside
  the certificate buffer, so this is a fidelity question, not safety).
- No TLS/X.509 memory-safety defect was found re-reading 4c scope (consistent with the TLS/SMB reference §7:
  the confirmed OOBs are SMB/NTLMSSP, 4d). The record and handshake layers clamp every dispatch by the two
  remainings; the X.509 stack cannot walk past the certificate because every byte decrements
  `stack.remainings[0]` first.

### F2. E2 — split dependence
- TLS record layer, all sub-parsers and X.509 are invariant to TCP segmentation in C (state persists across
  calls; TLS/SMB reference §7 verified chunk sizes 1..400). Р13 therefore needs no unsplit-stream exception
  inside TLS itself.
- **E2.8′ (replaces 4b E2.8).** After a STARTTLS go-ahead C keeps parsing the rest of that segment as a new
  text greeting and only the next segment reaches the TLS parser (TCP reference B6/E2.8). As decided in the
  plan, rmasscan sends the remaining bytes of the go-ahead segment to the TLS parser too, making the hand-off
  split-invariant. On the wire C additionally sends a second `AUTH TLS`/`EHLO`/`CAPA` in the unsplit case;
  rmasscan never does.
- Handshake-across-records re-entry (B1) is a *record*-fragmentation quirk, reproduced as written; the lab
  scenarios use one handshake message per record like real servers.
- **E2.9 (4c) X.509 push failures.** An `ASN1_push` failure (C3) makes C's own result depend on the split into
  `x509_decode` calls: sticky across calls, invisible within one. Р13 golden = whole-stream run; the Rust
  walk gives that result in every split. Task 3 evidence: case `google-trunc-half` (C whole emits the CN,
  C bytewise emits nothing) and a 240-case mutation differential with zero mismatches against the whole run.
- **E2.10 (4c) `ssl` vs `X509*` record order under capture.** `parse_server_cert` appends a chunk's base64
  before feeding the same chunk to X.509, and chunks are bounded by the segment, so when the certificate
  record is the banout head and crosses the 200-byte head move while the first name is still ahead in the
  same chunk, C's flush order of `ssl` and `X509` records flips between whole and bytewise runs (task 4 case
  `cert-early-subject`). Р13 golden = whole-stream order; rmasscan buffers each record's Certificate body and
  processes it at the record boundary (record boundaries are a property of the stream, not of segmentation),
  giving the whole-stream order in every split. Record contents are identical either way.

### F3. E3 — kept quirks (deterministic, reproduced)
- SSLv3 ServerHello emits `vuln "SSL[v3] "` in every mode (B3 step 1).
- Poodle emission happens before the ServerHello version sanity check (B3 step 2); alert dedup checks the
  SCSV string for the `no-SSLv3` append and not at all in the default branch (B5).
- Heartbleed `vuln` fires on the declared heartbeat length, and heartbleed capture is never base64-finalized
  (B6). Ticketbleed fires on the declared session-id length (B3 step 4).
- Normal-mode ClientHellos are byte-identical constants including their baked-in random (§A2).
- Reconnect with no other source port prints its ERRMSG once and otherwise does nothing (D1); the foreign-TCB
  `app_state` overwrite on a tuple collision is inherited unreachable-in-the-lab behavior.
- Resumed scans lose the vuln mode (E2 last bullet).

## G. Corrections to the TLS/SMB reference (TLS half)
1. §0.3/§1.4: a version token of `SSLv3` also appends `vuln "SSL[v3] "` (B3); the reference listed version
   tokens only into `ssl`.
2. §1.1: the port list had "?" entries and wrong guesses (563, 2379, 2380). Exact list of 23 in §A1.
3. §1.3: `ssl_hello()` dynamicization runs only for the three vuln templates; the default and TLS 1.3 hellos
   are sent as static template bytes (§A2). The siphash input is the 4-byte host-order `unsigned` `i + now`.
4. §1.4: the handshake sub-parser state is reset on entering each record's CONTENTS (and on record-type
   change), so handshake messages do not survive record fragmentation (B1). Alert and heartbeat share the
   handshake state variables; server-hello/cert/alert share the `ssl.x` union.
5. §1.4 (alert): the dedup guard exists only on descriptions 86 and 40, and both test for the string
   `"TLS_FALLBACK_SCSV"`; the default branch appends unguarded (B5).
6. §1.4 (heartbeat): capture is never base64-finalized; an empty capture record is created at the length field
   (B6).
7. §2.3: "only the first cert in the chain contributes names" is enforced in code only for the CN path; the
   SAN path has no `count` check as written (C4) — oracle probe assigned to task 3.
8. §1.6/§2.3: the readscan subject/issuer re-decode is dead code (call site commented out), so the bracket
   forms are unreachable in shipped behavior (E4).
9. §1.7: `certs` wraps **every** banner record in PEM, not only certificate records, and writes to stdout
   regardless of the output file (E4).
10. §1.1: `--hello ssl` and the modes reassign ports `0..65534`, i.e. 65535 ports, not "all 65535 ports" as a
    count including 65535 itself (§A1).
