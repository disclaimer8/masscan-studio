# rmasscan banner-grabbing recon: TLS/SSL, X.509, SMB/NTLMSSP (upstream masscan @ 8e6b3b0)

Scope: stage 4 `--banners` for TLS, X.509, SMB. All paths under `src/`. `L`/`:NNN` = line.
Strings/bytes quoted verbatim (C escapes unexpanded). "Inferred" = not read directly.
Facts tagged "VERIFIED" were confirmed by compiling the C modules offline against the in-tree
test vectors and crafted inputs under ASan+UBSan (clang, arm64); see §7.

Upstream masscan is **AGPL-3.0** (`LICENSE`, `README.md:603-617`). Every file in this note carries
no per-file header except where noted; they inherit AGPL. Exceptions found: `crypto-siphash24.c:1-13`
(SipHash reference, CC0 / public domain). `crypto-base64.c` has no license banner (treat as AGPL).
**There is no cryptography anywhere in the banner path** — no key exchange, no decryption, no hashing of
payloads. masscan sends a fixed ClientHello and *reads cleartext handshake bytes only*; once the server
would switch to encrypted records (type 23 app-data, type 20 change-cipher-spec) masscan parses nothing.
siphash24 is used only to fill the ClientHello random with a masscan-detectable pattern (§1.3).

---

## 0. Banner plumbing shared by all parsers

### 0.1 BannerOutput (proto-banout.c/.h) — the append-only sink every parser writes to
- `struct BannerOutput { next; protocol; length; max_length; unsigned char banner[200]; }` (proto-banout.h:15-21). A linked list; **one node per `protocol` id**. First node inline (200 bytes); `banout_expand` doubles via MALLOC/memcpy and relinks (proto-banout.c:258-286). `banout_append` finds-or-creates the proto node, expands while `length+len >= max_length`, memcpy, `length += len` (L328-363).
- `banout_new_proto` **prepends** new proto nodes after head (L250-251), so emission order ≠ list order (matters only for test asserts, not output).
- `protocol` high bits are flags: `banout_end` sets `0x80000000` ("this banner is complete", e.g. one finished certificate) (L163-171); readers mask with `& 0x0FFFFFFF` (stack-tcp-core.c:817) or `&0xFFFF` (banout_string L61). `banout_string`/`_length` select by proto (L58-68, 135-145).
- `AUTO_LEN == (size_t)~0` → `strlen` (proto-banout.h:60, used everywhere as the "nul-terminated literal" sentinel).
- `banout_append_unicode` (L202-231): emits a UTF-16 code unit as 1–4 UTF-8 bytes. Used by SMB/NTLMSSP for unicode strings. `banout_append_hexint` (L185-197): fixed-width lowercase hex (used for SMBv2 GUID).
- **Base64 streaming encoder** (L376-442): `banout_init_base64` → repeated `banout_append_base64` (3-byte groups, 2-bit `state`+24-bit `temp` carry across fragments) → `banout_finalize_base64` (emits `=`/`==` padding). Table `b64` = `A-Za-z0-9+/` (L367-371). No line wrapping, no `-----BEGIN-----`. VERIFIED against proto-banout.c:463-540 selftest vectors ("eA==", "YmM=", "bW5v", "c3R1dg==", "ZmdoaWo=").
- `struct BannerBase64 { state:2; temp:24; }` lives in `StreamState` (proto-banner1.h:47-51, 250) — one encoder per connection, so cert-capture and heartbleed-capture cannot run truly concurrently on one stream (they don't overlap in practice).

### 0.2 App-protocol ids (masscan-app.h:8-49, strings masscan-app.c)
Relevant: `PROTO_HEUR=1`("unknown"), `PROTO_SSL3=9`("ssl"), `PROTO_SMB=10`("smb"), `PROTO_X509_CERT=15`("X509"), `PROTO_X509_CACERT=16`("X509CA"), `PROTO_VULN=20`("vuln"), `PROTO_HEARTBLEED=21`("heartbleed"), `PROTO_TICKETBLEED=22`("ticketbleed"), `PROTO_SAFE=24`("safe"). **These numbers are serialized into masscan's binary output files** (masscan-app.h:4-6) — a Rust port that wants file compat must keep them.
- Reporting (stack-tcp-core.c `banner_flush` L799-830): on FIN/close, walks the banout list and for each node with `length && protocol` calls `report_banner(out, now, ip, 6/*TCP*/, port, protocol & 0x0FFFFFFF, ttl, banner, length)`. So **each proto id becomes its own banner record**: e.g. one TCP:443 result emits separate `ssl`, `X509`, `X509CA`, `vuln` banners.

### 0.3 TLS output text format (what the ssl/x509 parsers actually produce) — VERIFIED
Concatenated into the single `PROTO_SSL3`("ssl") banner, space-separated, in parse order:
- Version token: `"SSLv3 "`,`"TLS/1.0 "`,`"TLS/1.1 "`,`"TLS/1.2 "`,`"TLS/1.3 "`, else `"SSLver[%u,%u] "` (proto-ssl.c:96-117).
- Cipher: `"cipher:0x%x"` (no trailing space) of the 16-bit suite (proto-ssl.c:70-86). Note: the commented-out table means **no human cipher name**, just the hex.
- Then X.509 leaf subject CNs/SANs, each prefixed `", "` (proto-x509.c). Full observed banner e.g.:
  `TLS/1.2 cipher:0xc007, *.google.com, *.google.com, *.android.com, ...` (case1 vector) and
  `TLS/1.0 cipher:0x88, ubuntu.localdomain, puppet, puppet.localdomain, ubuntu.localdomain` (case3).
- Alerts: `" ALERT(0x%02x%02x) "` (level,desc) → `PROTO_SSL3` (proto-ssl.c:850-855).
Vuln findings go to **separate** proto nodes: `PROTO_VULN`("vuln"), `PROTO_SAFE`("safe"), `PROTO_HEARTBLEED`, `PROTO_TICKETBLEED`. See §1.5–1.6.

---

## 1. TLS/SSL (proto-ssl.c 1451 L, proto-ssl.h, vulncheck-heartbleed.c, vulncheck-sslv3.c)

### 1.1 Registration & port surface
- `banner_ssl` = {name "ssl", port 443, hello=`ssl_hello_template`, hello_length=`sizeof-1`, flags=`SF__close` (send FIN after hello), selftest=`ssl_selftest`, init=`ssl_init`(no-op), parse=`ssl_parse_record`, next=`&banner_ssl_12`} (proto-ssl.c:1442-1451).
- `banner_ssl_12` = same but `ssl_12_hello_template`, flags=0, next=0 (L1435-1440). The `next` chain means: on SYN-ACK masscan opens a second connection with the *other* hello (TLS1.3-capable) — `tcpapi_reconnect(socket, stream->next, ...)` in stack-tcp-app.c:61-63. So each SSL port is probed with **two** ClientHellos on two connections (default 1.2 hello first, then the 1.3 hello).
- Ports pre-wired to `banner_ssl` (proto-banner1.c:527-595): 443,465,563?(no),636,637,990,991,992,993,994,995,2083,2087,2096,2376,2379?(docker),2380?(docker),3269,5061,8140,8443,8531,9050,11712,49955,322,8531. `--hello ssl` or `--heartbleed`/`--ticketbleed`/`--vuln poodle` reassigns **all 65535 ports** to `banner_ssl` (stack-tcp-core.c:500-507,537-588).
- TLS is also reached heuristically: SMACK patterns `\x16\x03\x00..\x03`, `\x15\x03\x00..\x03` → `PROTO_SSL3` (proto-banner1.c:56-63). But note the guard: a heuristic SSL match is **ignored unless we already sent our own hello** (`!(proto==PROTO_SSL3 && !is_sent_sslhello)`, proto-banner1.c:137-138) — prevents treating an unsolicited server ServerHello as a reason to re-dispatch.

### 1.2 ClientHello templates (exact decoded bytes) — VERIFIED (decoded from source escapes)
Record framing is `16 03 01 <len16>`; inner handshake `01 <len24> <client_version16> <random32> <sid_len><sid> <cipherlen16><ciphers> <complen8><comp> <extlen16><exts>`.

| template | src | rec ver | client_ver | total | sid | ciphers (count) | extensions |
|---|---|---|---|---|---|---|---|
| **default** `ssl_hello_template` | proto-ssl.c:1076-1105 | 03 01 | 03 03 (TLS1.2) | 198 B | empty | 30 suites (c02b cca9 c02c c009 c00a c023 c024 c02f cca8 c030 c013 c014 c027 c028 009e ccaa 009f 0033 0039 0067 006b 009c 009d 003c 003d 002f 0035 000a 0005 00ff) | ec_point_formats(b), supported_groups(a), session_ticket(23), encrypt_then_mac(16), extended_master_secret(17), signature_algorithms(d) |
| **1.3** `ssl_12_hello_template` | proto-ssl.c:1114-1120 | 03 01 | 03 03 | 287 B | 32 B nonzero | 31 suites incl. 1302/1303/1301 (TLS1.3) | +supported_versions(2b: 0304 0303 0302 0301), psk_key_exchange_modes(2d:01 01), key_share(33: group 001d x25519, 32 B key) |
| **heartbeat** `ssl_hello_heartbeat_templatex` | vulncheck-heartbleed.c:33-66 | 03 02 (TLS1.1) | 03 02 | 225 B | empty | 51 suites | ec_point_formats, supported_groups, session_ticket, **heartbeat(000f, data `01`)** |
| **ticketbleed** `ssl_hello_ticketbleed_templatex` | vulncheck-heartbleed.c:4-27 | 03 01 | 03 03 | 361 B | **16 B** `ff6fbfbc...` | 13 suites | server_name "www.ancestry.com", status_request, supported_groups, ec_point_formats, **session_ticket(23) 194-byte blob**, signature_algorithms, renegotiation_info |
| **sslv3/poodle** `sslv3_hello` | vulncheck-sslv3.c:6-17 | **03 00 (SSLv3)** | 03 00 | 72 B | empty | 12 suites (0039 0038 0035 0033 0032 0004 0005 002f 0016 0013 **feff** 000a) — **no extensions block at all** | none |

Selection (stack-tcp-core.c `tcpcon_set_parameter`): `--heartbleed` → `banner_ssl.hello = ssl_hello(ssl_hello_heartbeat_template)` + `is_heartbleed=1` (L534-548); `--ticketbleed` → ticketbleed template + `is_ticketbleed=1` (L552-566); `--vuln poodle`/`--sslv3` → `ssl_add_cipherspec(ssl_hello(sslv3_template), 0x5600, is_append=1)` **appends TLS_FALLBACK_SCSV (0x5600)** to the cipher list + `is_poodle_sslv3=1` (L570-585). These also force SSL on all ports and `no-capture cert` (main-conf.c:2810-2819,2936-2940).

### 1.3 Hello dynamicization `ssl_hello()` (proto-ssl.c:1224-1254)
MALLOCs a copy of the template, then **overwrites bytes 11-14 with `time(0)` big-endian** (the TLS gmt_unix_time) and **bytes 11+4..11+31 (28 bytes) with siphash24(i+now, key={0,0})** low byte per index (L1239-1251). Purpose: make the random field a masscan fingerprint, re-randomized per process start (not per packet — one shared `banner_ssl.hello` buffer). `ssl_hello_size` reads `(px[3]<<8|px[4])+5` (L1211-1220). `ssl_add_cipherspec_sslv3` (L1123-1178) reallocs +2, inserts a cipher at list start (prepend) or end (append), fixing the three length fields (record, handshake, cipherlist). Only SSLv3 (`0x0300`) templates supported; other versions print "internal error" and return unchanged (L1198-1205) — **so SCSV-append only works with the sslv3 template**.

### 1.4 Record/handshake state machine (`ssl_parse_record` proto-ssl.c:892-1053)
Streaming, **no reassembly** — `state`+`remaining` persist across TCP segments (header comment L32-46). Outer record = 5-byte `type|ver_mjr|ver_mnr|len16`:
- START: `type` high bit set → UNKNOWN; else store `ssl->type`, reset handshake.state on type change (L928-939).
- VERSION_MAJOR must be `3` else UNKNOWN (L944-948); any 0x03xx accepted. VERSION_MINOR stored raw.
- CONTENTS: computes `len = min(seg_remaining, record_remaining)`, dispatches by record type, `i += len-1`, loops records (L983-1042). Dispatch: 20 change-cipher-spec (ignored), 21 `parse_alert`, 22 `parse_handshake`, 23 app-data (ignored — "encrypted, always"), 24 `parse_heartbeat`.
- **Handshake sub-parser** (`parse_handshake` L522-652): 4-byte `type|len24`. On **type 2 (server done)** — wait, type 2 = ServerHello; **server-done is type 14**; the heartbleed send trigger is at LENGTH2 `if (ssl->handshake.type == 2 && is_heartbleed)` (L583-588) i.e. after a ServerHello's length is known it injects the heartbleed request `"\x15\x03\x02\x00\x02\x01\x80" "\x18\x03\x02\x00\x03\x01" "\x40\x00"` via `tcpapi_send` (VERIFIED: fires on ServerHello). CONTENTS dispatch: type 2 → `parse_server_hello`, type 11 → `parse_server_cert`, all others skipped (L603-635).
- **ServerHello parser** (`parse_server_hello` L127-339): enum states VERSION_MAJOR..EXT_DATA_HEARTBEAT. Emits version banner (BANNER_VERSION), skips 4-byte time + 28-byte random (`remaining=28` skip), reads session-id (len byte then skip), reads 2-byte cipher → `BANNER_CIPHER`, compression byte, then walks extensions `tag16|len16`; **ext 0x000f (heartbeat) with a nonzero data byte → `banout_append(PROTO_VULN,"SSL[heartbeat] ",15)`** (L293-328). `version_major>3 || version_minor>4` → UNKNOWN (L183-186). **ticketbleed heuristic**: at SESSION_LENGTH, `if (is_ticketbleed && remaining>16) → PROTO_VULN "SSL[ticketbleed] "` (session-id echoed longer than our 16 → L226-228, VERIFIED). **POODLE**: at VERSION_MINOR, `if (is_poodle_sslv3) → PROTO_VULN " POODLE "` (L180-182).
- **Alert parser** (`parse_alert` L788-867): `level|description`. If `is_poodle_sslv3 && level==2(fatal)`: desc 86 (inappropriate_fallback) → `PROTO_SAFE "poodle[TLS_FALLBACK_SCSV] "`; desc 40 (handshake_failure) → `PROTO_SAFE "poodle[no-SSLv3] "`; other → `PROTO_SAFE "poodle[no-SSLv3] "` + `PROTO_SSL3 " ALERT(0x..) "` (dedup-guarded by `banout_is_contains`). Non-poodle: always `PROTO_SSL3 " ALERT(0x%02x%02x) "`. VERIFIED all three poodle branches.
- **Heartbeat parser** (`parse_heartbeat` L668-775): `type|len16`. On type 2 (response): **`if remaining>=16 → PROTO_VULN "SSL[HEARTBLEED] "`** (the bleed succeeded — server returned more than it should) (L719-724). If `is_capture_heartbleed`, base64-captures the bled bytes into `PROTO_HEARTBLEED` (L728-731,748-753). VERIFIED: crafted type-24 record with 0x4000 length yields both `vuln: SSL[heartbeat] SSL[HEARTBLEED] ` and `heartbleed` base64 node.

### 1.5 Certificate framing (`parse_server_cert` proto-ssl.c:370-495)
3-byte `total_len`, then per-cert 3-byte `cert_len` + DER body, passed incrementally to `x509_decode`. States CLEN0.. (first cert) vs CALEN0.. (subsequent) decide proto id: **first cert → `PROTO_X509_CERT`(15), rest of chain → `PROTO_X509_CACERT`(16)** (L444). On each new cert: `memset(&data->x509,0)`, `x509_decode_init(&x509, cert_remaining)`, `x509.count = (prev count)+1` (L432-437) — the count gates which cert's names are reported (§2). If `is_capture_cert`: `banout_init_base64` then streaming `banout_append_base64(proto, px+i, len)` of the raw DER, finalized + `banout_end` at cert end (L427-473). VERIFIED: case3 leaf → `X509`(15) base64 1916 B, CA → `X509CA`(16) base64 1808 B.
- **No cert size cap inside this parser** beyond the X.509 state machine's own 16-bit length ceiling (§2). `cert_remaining`/`remaining` are `unsigned`; lengths come straight from the wire.
- At cert end with `remaining==0`: a commented-out `tcpapi_close` (L475-481) — masscan does **not** close here (relies on server FIN / its own `SF__close`).

### 1.6 `--capture` flags and where they live
`struct Banner1` bits (proto-banner1.h:31-38): `is_capture_html, is_capture_cert, is_capture_servername, is_capture_heartbleed, is_capture_ticketbleed, is_heartbleed, is_ticketbleed, is_poodle_sslv3`. **`is_capture_cert` defaults ON** (main.c:1610). CLI `--capture cert|servername|html|heartbleed|ticketbleed` and `--nocapture …` (main-conf.c:1132-1178, SET_capture). Flags copied into the live parser by `tcpcon_set_banner_flags` (stack-tcp-core.c:623-636). `is_capture_subject`/`is_capture_issuer` are **X.509-level** bits (proto-x509.h:29-30), set per decode: live SSL path leaves them 0 for ServerHello cert (so SAN-via-`Subject_Common` path, not the "subject[…]" bracket path, §2); the `--readscan` re-decode sets **both** (in-report.c:350-351).

### 1.7 `--capture cert` output (`out-certs.c`, Output_Certs / `-oD cert`?)
`certs_output` (out-certs.c:84-91). `cert_out_banner` (L50-80): strips a leading `"cert:"` if present, then prints to **stdout** `-----BEGIN CERTIFICATE-----\n`, the base64 wrapped at **72 cols**, `-----END CERTIFICATE-----\n`. `close` prints `{finished: 1}\n` (L24). status records produce nothing. Note: this is the `--output-format certs` path (main-conf.c:1701); the base64 itself was produced by §1.5.

---

## 2. X.509 DER parser (proto-x509.c 1392 L, proto-x509.h)

### 2.1 Design
Incremental state-machine DER parser, **no allocation, no reassembly**; ~60 bytes of state in `struct CertDecode` (proto-x509.c:1-17, proto-x509.h:10-82). A manual ASN.1 length stack: `stack.remainings[9]` (u16), `stack.states[9]` (u8), `depth` (proto-x509.h:20-24). `ASN1_push` (L304-374): rejects `remaining>>16 != 0` (>64 K → `state=0xFFFFFFFF`, stderr "ASN.1 length field too big"), rejects `depth>=9` ("recursion too deep"), and **[ASN1-CHILD-OVERFLOW]** rejects child length > parent (L345-351); pushes by `memmove`-ing the arrays (index 0 = top). `ASN1_pop` (L382-395). `ASN1_skip` (L404-427) fast-forwards remainder of a field. `x509_decode_init` (L1378-1383): memset + push outer length (the cert_len from §1.5).

### 2.2 State enum & kludge (proto-x509.c:439-526)
~130 states enumerated in field order (TAG0 … ENC_CONTENTS, PADDING=254, ERROR=0xFFFFFFFF). Walks the RFC-5280 `Certificate`→`TBSCertificate` tree (comment L45-86). `kludge_next()` (L485-526) is a hand-maintained "what state comes after this length field" table — **a Rust port should replace this with a real recursive-descent or table-driven ASN.1 model; it is the most error-prone part.** Length parsing (L825-942): short form `<0x80`, else `0x81 XX` / `0x82 XX XX`; checks `[ASN1-DER-LENGTH]` strictness (leading-zero and minimal-length → `is_der_failure=1`, but **never acted on**, L1024-1041).

### 2.3 What is extracted (OID table `mib[]` L124-170)
Only a handful of OIDs matter; matched via an **Aho-Corasick DFA** (`smack.h`) built in `x509_init()` (L250-280, must be called at startup — main.c:1663). OIDs are typed in human form and converted to DER by `convert_oid` (L205-241). The only *captured* fields:
- `85.4.3` = `2.5.4.3` commonName → `Subject_Common` (L159).
- `85.29.17` = `2.5.29.17` subjectAltName → also `Subject_Common` (L168) — SAN dNSNames are emitted the same way as CN.
Other named OIDs (country/org/unit/serial/locality/state/email, sysDescr… SNMP MIB, sig algs md5/sha/sha256WithRSA) are in the table for *recognition* but **not output**. There is **no issuer, no validity, no serial, no key** in the default live output. Issuer capture exists but only via `is_capture_issuer` (readscan path).
- Subject/SAN emission (L653-746, 795-809): CN bytes appended one-at-a-time to `PROTO_SSL3` preceded by `", "`. **Only the first cert in the chain** (`x->count <= 1`, L721) contributes names; chain certs' subjects are suppressed (L724-726). VERIFIED: yahoo_cert → 43 leaf SANs, google_cert → `", www.google.com, www.google.com"`; multi-cert case3 reports only leaf names.
- Validity (`VNBEFORE/VNAFTER_CONTENTS` L944-1022): parses UTCTime digits into a `tm`, `mktime`, stores `x->prev` — but the day-count `printf` is commented out (L1015). **Validity is parsed but never output.** `tm` is only partially initialized before `mktime` (no tm_wday/yday set to safe — actually set to 0 L1004-1005) — a latent bug surface.
- `is_capture_subject`/`is_capture_issuer` branches wrap CN bytes in `" subject["…"]"` / `" issuer["…"]"` (L589-608, 653-665) — used only on readscan re-decode.

### 2.4 Error handling on malformed input
- Tag mismatches → mostly `state=ERROR` (`ASN1_skip` drains) or `state++` skip-this-field; some are hard-fail (e.g. ENC_TAG expects 0x03, VERSION0 expects 0xa0). `PADDING` (L1024-1041) swallows unparsed trailing bytes silently (intentional — parser is incomplete, can't distinguish DER error from unsupported field). The outer loop pops the stack whenever `remainings[0]==0`, returning when depth hits 0 (L567-571).
- **Observed robustness**: 20 K-iteration bit-flip fuzz of the case3 cert stream under ASan+UBSan (chunked at every segment size incl. 1 byte) in progress at write time; no SSL/X.509 crash observed in the crafted + selftest corpus (§7). The DER parser's u16 length stack + child-overflow check make it comparatively hardened — but see §7 UB.

### 2.5 `spnego_decode` lives here too (proto-x509.c:1061-1368)
A **second** ASN.1 state machine (reuses `struct CertDecode` as a generic ASN.1 cursor, see proto-spnego.h:10-16 "KLUDGE") for SPNEGO NegTokenInit/Resp. Walks `a0/a1/a2/a3` context tags; the `responseToken`/`mechToken` OCTET STRING contents are handed to `ntlmssp_decode` (L1287-1306). `spnego_decode_init` (L1384-1390). This is the SMB→NTLM bridge (§3).

---

## 3. SMB / NTLMSSP / SPNEGO (proto-smb.c 2097 L, proto-ntlmssp.c, proto-spnego.h)

### 3.1 Registration & probes
- `banner_smb0` = {"smb", **139**, `smb0_hello_template`, …, parse=`smb_parse_record`, cleanup=`smb_cleanup`} (proto-smb.c:2083-2089); `banner_smb1` = {"smb", **445**, `smb1_hello_template`, …} (L2090-2096). Wired at proto-banner1.c:524-525. SMACK patterns (proto-banner1.c:35-44) detect SMB by `\x00\x00**\xffSMB`, `\x00\x00**\xfeSMB`, and NBT session responses `\x82..`, `\x83....`.
- **Probe sequence (multi-round, driven by the parser, not the hello alone):**
  1. Port 139: `smb0_hello_template` = NetBIOS **session request** (`81 00 00 44` + encoded called/calling names, L1862-1872). Server replies `82` positive → parser sends `smb1_hello_template` (L1739-1742).
  2. Port 445 (or after NBT 82): `smb1_hello_template` = SMB1 **NEGOTIATE** `72` offering dialects `NT LM 0.12`,`SMB 2.002`,`SMB 2.???` (L96-109). `--hello smbv1` swaps in `smb1_hello_template_v1` (identical bytes here; `smb_set_hello_v1` L126-130) to force SMBv1.
  3. On SMB1 negotiate response (cmd 0x72): parser auto-sends a **null session setup** — `smb1_null_session_setup_ex` (SPNEGO/NTLMSSP Type-1, L152-177) if extended-security flag `flags2 & 0x0800`, else `smb1_null_session_setup` (L132-150, patches 4-byte SessionKey at offset 0x2f) (L1453-1472).
  4. If server chose SMB2 (`fe SMB`): parser emits `smb2_negotiate_request` (L179-194) then `smb2_null_session_setup` (SPNEGO/NTLMSSP Type-1, L195-217) based on `seqno` (L1591-1596).
- Closes the connection after Session Setup response (L1514-1515, L1641-1642).

### 3.2 Parse state machine
- `smb_parse_record` (L1670-1812): NBT framing `TYPE|FLAGS|LEN16` (len is 17-bit: high bit from flags byte, L1706-1707). Dispatches NBT types: 00→SMB body, 82→send SMB1 hello, 83→error string, 85 keepalive, others → `PROTO_SMB " PARSERR(...) "`.
- `smb_parse_smb` (L1241-1655): giant enum covering SMB1 header (command/status/flags/pid/tid/uid/mid/word_count) and SMB2 header. `SMB_VER` prints `"SMBv1 "`/`"SMBv2 "`/`"SMBv? "` once (L1309-1328). SMB1 word-count params parsed by `smb_params_parse` (L230-302, the "UGLY HACK" struct-driven field extractor, see §7 bug). SMB1 byte/data by `smb1_parse_negotiate1/2`, `smb1_parse_setup1/2`. SMB2 by `smb2_parse_header`/`_negotiate`/`_setup`/`_response`.

### 3.3 Reported fields & text format — VERIFIED (selftest vectors)
All into `PROTO_SMB`("smb"), space-separated:
- SMBv1 negotiate (cmd 0x72): `" time=%Y-%m-%d %H:%M:%S"` (FILETIME via `convert_windows_time`, L1437-1450) + `" TZ=%+d "` (ServerTimeZone) + domain/name from the challenge area (`" domain="`,`" name="`, ASCII or UTF-16, L1437-1450, smb1_parse_negotiate1 L364-430).
- SMBv1 session setup (cmd 0x73): `" os="`,`" ver="`,`" domain="` (smb1_parse_setup1/2 L487-532,690-735), plus NTLMSSP fields if the blob carries a Type-2 (§3.4).
- SMBv2 negotiate: `" guid=%08x-%04x-%04x-%02x-…"` (16-byte server GUID as hex, N_GUID states L956-993), `" time=…"`/`" boottime=…"` from the two FILETIMEs (L1000-1031). `PARSERROR[flags|hdrlen|structlen]` on bad lengths.
- Observed: `SMBv1  time=2014-01-12 22:08:34 TZ=+0  domain=WORKGROUP version=87.0.79 ntlm-ver=0 domain=WORKGROUP name=EPSON8831FE domain-dns= name-dns=EPSON8831FE os=EPSON Storage Server ver=NQ 6.2 domain=WORKGROUP` and `…TZ=+0  domain=S659C27D` (the two selftest vectors).

### 3.4 NTLMSSP CHALLENGE parsing (proto-ntlmssp.c:105-241)
Reached via SPNEGO responseToken. `ntlmssp_decode_init` caps length at 65536 (L253-269). `ntlmssp_decode` (L106-241): reassembles fragments into a malloc'd `buf` across calls (L118-137) — **the only heap buffer in the banner path besides banout expansion**; freed at `end:` (L236-239) and `ntlmssp_cleanup`. Requires ≥56 bytes, `memcmp("NTLMSSP",8)`, `message_type==2` (L139-152). Extracts: TargetName (`" domain="`), **version** `" version=%u.%u.%u ntlm-ver=%u"` (ProductMajor/Minor/Build, NTLMRevision, L170-179), and the AV_PAIR TargetInfo list (L182-226): type1 `" name="`, 2 `" domain="`, 3 `" name-dns="`, 4 `" domain-dns="`, 5 `" forest="`, 9 `" target="` (unicode via `append_unicode_string` L92-103). All appended as `PROTO_SMB`.

---

## 4. Trigger wiring from proto-banner1.c & STARTTLS (brief)
- `banner1_parse` (proto-banner1.c:113-325): switch on `app_proto`; `PROTO_SSL3`→`banner_ssl.parse`, `PROTO_SMB`→`banner_smb1.parse` (L258-275). Unknown ports go through the SMACK heuristic first (L126-186), buffering bytes in `PROTO_HEUR` and re-dispatching when a pattern hits.
- `banner_ssl.hello`/`hello_length` are read live by the **STARTTLS hand-offs**: SMTP (proto-smtp.c:99 `EHLO masscan`, 119 `STARTTLS`, 149 send ssl hello on 220), POP3 (proto-pop3.c:52 `CAPA`, 111 `STLS`, 131 send on +OK), IMAP4 (proto-imap4.c:92 `a001 CAPABILITY`, 159 `a002 STARTTLS`, 181 send), FTP (proto-ftp.c:73 `AUTH TLS`, 103 send on 234). Each resets `StreamState`, sets `app_proto=PROTO_SSL3` + `is_sent_sslhello=1`, then transmits the shared `banner_ssl.hello` — so **STARTTLS reuses whatever hello variant `--heartbleed` etc. installed**. There is no STARTTLS path that is SMB-related. `App_SendFirst` (stack-tcp-app.c:154-195) sends `stream->hello` and, for `banner_ssl`, calls `banner_set_sslhello(true)`; heartbleed also sets a small TCP window (`banner_set_small_window`, L165-171, stack-tcp-core.c:1163 → window 600, to coax fragmented replies).

---

## 5. Port surface for the Rust port

### 5.1 Self-contained vs coupled
- **Self-contained, pure byte→banner (easy, port first):** `proto-banout.*` (growable byte sink + base64), `BANNER_VERSION`/`BANNER_CIPHER`, `parse_server_hello`/`parse_alert`/`parse_heartbeat`, `ssl_parse_record`/`parse_handshake` (minus the `tcpapi_send` calls), the whole X.509 decoder (`x509_decode*`, `ASN1_*`, OID matcher), `ntlmssp_decode`. These take `(bytes, &mut sink)` and return nothing — ideal `fn(&[u8], &mut BanOut)` with an explicit resumable state struct. In Rust, model each as a struct holding the state enum + stack and a `feed(&[u8])` method; the C "persist state across fragments" maps directly to a struct field, no `unsafe` needed.
- **Coupled to TCP stack (port via a trait):** anything calling `tcpapi_send`/`tcpapi_close`/`tcpapi_reconnect` — the heartbleed inject (proto-ssl.c:583-588), all SMB auto-responses (proto-smb.c:1453-1472,1593-1596,1740), STARTTLS hand-offs. Define a `TcpActions` trait with `send(&[u8], flags)` / `close()`; the parsers get `&mut dyn TcpActions`. `TCP__flags` enum (stack-tcp-api.h:8-12: static/copy/adopt/close_fin) — in Rust just take owned `Vec<u8>` or `&'static [u8]`.
- **Template generation:** `ssl_hello`, `ssl_add_cipherspec*` (realloc + in-place length patching) — rewrite as `Vec<u8>` builders; the siphash fingerprint needs a SipHash-2-4 crate (or keep CC0 reference). `convert_oid` (OID text→DER) can be a `const fn`/build-time table.
- **Config:** replicate the `is_capture_*` / `is_heartbleed` / `is_ticketbleed` / `is_poodle_sslv3` bitset (proto-banner1.h:31-38) and the CLI wiring (main-conf.c SET_capture L1132-, `--vuln` L2929-, `--heartbleed`/`--ticketbleed` L2810-). Keep proto id **numbers** stable for binary-file compat (§0.2).
- **SMACK Aho-Corasick** (`smack1.c`): used both for protocol heuristics (proto-banner1.c) and the X.509 OID matcher. A Rust port can use `aho-corasick` crate; watch the `SMACK_SNMP_HACK` flag (smack1.c:716,826-827,931,980) which adds a `0x80` self-loop so multibyte OID arcs match — i.e. OID sub-identifier high-bit continuation. The `smack_search_next` resumable API (smack1.c:1410) maps to the crate's streaming/overlapping iterator.

### 5.2 Memory-safety hot spots (the reason to port) — the fuzz-sensitive paths
Prioritize differential-fuzzing these against the C:
1. **SMB `smb_params_parse` global-buffer-overflow (CONFIRMED CRASH).** VERIFIED: an SMB response with command byte `0xFF` makes the `for (c=0; params[c].command != cmd && != 0xFF; c++)` scan run **past the end of the `params[]` table** (proto-smb.c:241-242) because 0xFF is also the sentinel — ASan: `global-buffer-overflow READ of size 2 at … after global variable 'params'` (proto-smb.c:250). A hostile/garbage SMB server triggers it. The Rust port must bound this table walk.
2. **NTLMSSP TargetInfo offset (UB / near-OOB).** `info_offset` is a full 32-bit value from the wire; the loop `for (i=info_offset; i+4<info_offset+info_length && i+4<length; …)` (proto-ntlmssp.c:182) relies on unsigned wraparound to stay safe when `info_offset` is huge. VERIFIED: `info_offset=0xFFFFFFFC` makes the `i`-indexed reads wrap; under ASan on a heap buffer this faults (BUS/overflow). The domain-field check `name_offset <= length && name_length <= length-name_offset` (L158) is correct, but the AV-pair loop's arithmetic is fragile. Rust: use checked slicing.
3. **SMB1 `byte_count`/`param_offset` arithmetic** (`smb1_parse_*`, `smb_params_parse` L236-237, `max = offset + (byte_count - byte_offset)`): unsigned subtraction underflow if `byte_offset > byte_count`. Produces garbage-but-bounded output in tests (chunk-size-dependent, §7); worth a Rust checked rewrite.
4. **SMB `smb_params_parse` shift UB (CONFIRMED UBSan).** `px[offset] << ((param_offset-external_offset)*8)` with a u8 promoted to int shifted by 24 → `left shift of 128 by 24 cannot be represented in int` (proto-smb.c:286, UBSan). Harmless on most targets but UB. Rust: shift as u32/u64.
5. **X.509 validity `mktime`** with partially filled `struct tm` (proto-x509.c:994-1017) — latent, output is discarded, but a Rust port should drop this dead code rather than port it.
6. **ASN.1 length stack**: `remainings` are u16, `states` u8, depth capped at 9 (proto-x509.c:316-330) — correct, but the `memmove`-per-push is O(depth); fine. The child-overflow check (L345-351) is the key safety invariant to preserve.
7. **Chunk/fragmentation sensitivity** (§7): several SMB sub-parsers produce **different banners depending on TCP segment boundaries** — a correctness bug, not memory-safety, but a Rust port should decide whether to match C bug-for-bug or fix (I recommend documenting and fixing, since it's a real info-fidelity defect).

### 5.3 Offline unit-test corpus (reusable fixtures)
- **`proto-ssl-test.c` (2432 L)** holds ready-to-use byte vectors — all directly reusable as Rust test fixtures:
  - `ssl_test_case_1[]` (L2-1566, ~24992 B): full TLS1.2 ServerHello+Certificate, Google cert chain. Expected leaf banner: `TLS/1.2 cipher:0xc007, *.google.com, …` (many SANs).
  - `ssl_test_case_2[]` (L1568-1761, 1471 B): Fortinet (`FGT80C3911602112`), expected `TLS/1.0 cipher:0x39, FGT80C3911602112 ALERT(0xf0f1) `. Contains embedded `peer1_x` continuation chunks (commented) — reconstruct as one stream.
  - `ssl_test_case_3[]` (L1764-2228, 3672 B): Puppet/ubuntu self-signed **two-cert chain**; expected `TLS/1.0 cipher:0x88, ubuntu.localdomain, puppet, puppet.localdomain, ubuntu.localdomain`; with `is_capture_cert` → `X509`(leaf,1916 B b64) + `X509CA`(CA,1808 B b64).
  - `google_cert[]` (L2231-2304) & `yahoo_cert[]` (L2306-2431): bare DER (not TLS-wrapped), feed straight to `x509_decode`. Expected (from `ssl_selftest` L1296,1325): google → `, www.google.com, www.google.com`; yahoo → contains `, fr.yahoo.com, ` (43 SANs). `*_size` for the `const char[]` certs is `sizeof-1` (drop the implicit NUL); `ssl_test_case_2/3` are `unsigned char[]` with plain `sizeof`.
- **SMB**: two inline vectors in `smb_selftest` (proto-smb.c:1929-1991, 2998-2011) → assertions `os=EPSON` and `domain=S659C27D`. Reusable. There's a commented-out bit-flip fuzzer (L2023-2066) showing the intended fuzz approach.
- `banout_selftest` (proto-banout.c:463-540): base64 boundary vectors.
- **These vectors are the recommended Rust golden-test set**: parse whole-buffer AND byte-at-a-time AND record-refragmented, assert identical banner (the C selftest already does whole + byte-at-a-time, L1343-1390).

---

## 6. Config / CLI quick map
- `--banners` (SET_banners, main-conf.c:2377). `--capture cert|servername|html|heartbleed|ticketbleed`, `--nocapture …` (L2402-2403, SET_capture L1132). `cert` default on (main.c:1610).
- `--heartbleed` (L2810-2814): sets is_heartbleed, nocapture cert+heartbleed, banners on. `--ticketbleed` (L2815-2819). `--vuln heartbleed|ticketbleed|poodle|sslv3` (L2929-2941). `--sslv3`≡`--vuln poodle`.
- `--hello ssl|smbv1|http` (SET_hello L1181-1205). `--hello-string[port]` / `--hello-file[port]` install custom probes (base64) (stack-tcp-core.c:590-612). `x509_init()` + `snmp_init()` must run at startup (main.c:1662-1663).

---

## 7. Verification log (offline, read-only — no network, no scanning)
Compiled the actual masscan modules (`proto-ssl.c`+`proto-x509.c`+`proto-banout.c`+`proto-ntlmssp.c`+`proto-smb.c`+`smack1.c`+siphash+util) with clang `-fsanitize=address,undefined` on arm64, linked against ~30-line stubs for `tcpapi_send/close` and `ipaddress_fmt`, driving the parsers with the in-tree test vectors, the decoded ClientHello templates, and crafted/mutated inputs. Confirmed:
- All five ClientHello templates decode to well-formed TLS records (byte tables in §1.2 are machine-decoded, not hand-read).
- TLS banner text, heartbleed/ticketbleed/POODLE/alert findings, cert base64 + proto-id split, X.509 leaf-only CN/SAN capture — all as described (§0.3,1.4,1.5,2.3), identical whole-buffer vs 1-byte-at-a-time.
- **Segment-boundary dependence**: for `ssl_*` the banner was **identical across all 1..400-byte chunk sizes and across record-refragmentation** (good — the SSL/X.509 machines are fragmentation-robust). For **SMB** the banner **varied with chunk size** (e.g. chunk=1 truncates to `time=… TZ=+0 `, chunk=200 gives full `domain=…name=…os=…`, chunk=256/300 corrupts the unicode) — SMB sub-parsers are **not** segmentation-safe; port with care / tests at multiple chunk sizes.
- **Crashes/UB found** (all memory-safety, all in SMB/NTLM — see §5.2): (1) `smb_params_parse` global-buffer-overflow on command 0xFF; (2) NTLMSSP huge `info_offset` OOB/BUS; (4) `<<24` of u8→int UB in `smb_params_parse`. The SSL/X.509 fuzz (20k bit-flip iters, chunked) had not surfaced a crash at write time (job still running); the X.509 u16-length-stack + child-overflow guard make it the hardened part.
- Scratch harness lives outside the repo; nothing in `masscan-studio-banners` was modified except this note.
