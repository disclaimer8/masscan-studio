# masscan `--banners` recon, part 1: framework + text/simple TCP parsers (upstream masscan clone at commit 8e6b3b0)

Citations are `src/<file>:<line>` of upstream masscan. C string escapes are quoted unexpanded. "Inferred" marks anything derived by reasoning rather than read directly. No code was run except a scratch `cc` build that measured `sizeof` of hello literals (§6.2).
Out of scope here (other notes): TLS/X.509/SMB/NTLMSSP internals (only the hand-off points, §8), UDP banners, the TCP stack internals (only its contract with the app layer, §1), per-format banner serialization (pointers only, §9; binary records are in `2026-11-06-rmasscan-output-formats-c-reference.md` §1.9).

## 0. Data flow in one paragraph

SYN-ACK with `--banners` -> `tcpcon_create_tcb(..., stream=NULL, ...)` (`src/main.c:978-983`) -> stream := `banner1->payloads.tcp[port_them]` (may be NULL) and `banner1_state.port = port_them` (`src/stack-tcp-core.c:1043-1048`), `banout_init` (`:1049`) -> `APP_CONNECTED` -> wait 2 s for the server to talk -> if it talks, bytes go to `banner1_parse`; if not, the stream's hello (if any) is sent -> response bytes go to `banner1_parse` -> the parser selected **by pattern match on the first bytes** appends text to per-app-type buffers (`banout`) and may itself send/close -> on peer FIN, RST or the 30 s connection timeout, every non-empty buffer is reported as one banner record (`banner_flush`, `src/stack-tcp-core.c:800-830`). The port only chooses the hello; it never chooses the parser (sole exception: `"220 "` -> SMTP on ports 25/587, §2.3).

## 1. App-layer state machine (`src/stack-tcp-app.c`) and socket API (`src/stack-tcp-api.h`)

- App states (`src/stack-tcp-app.c:11-18`): `App_Connect, App_ReceiveHello, App_ReceiveNext, App_SendFirst, App_SendNext, App_Close` (App_Close unused). Events (`src/stack-tcp-app.h:10-17`): `APP_CONNECTED, APP_RECV_TIMEOUT, APP_RECV_PAYLOAD, APP_SENDING, APP_SEND_SENT, APP_CLOSE`.
- Connect (`:54-87`): if `stream->next` -> `tcpapi_reconnect(socket, stream->next, App_Connect)` (opens a 2nd TCB from another source port/IP; `src/stack-tcp-core.c:1645-1694`, `ERRMSG("There must be multiple source ports/addresses for reconnection\n")` at `:1669` when none). Only user: `banner_ssl.next = &banner_ssl_12` (`src/proto-ssl.c:1442-1450`) => **every SSL-hello port gets two connections** (TLS1.0-record hello and TLS1.2 hello). `SF__nowait_hello` -> send at once (`:71-74`; no stream sets it). Else `tcpapi_set_timeout(socket, 2 /*tcpcon->timeout_hello*/, 0)` (`:76`), recv, -> ReceiveHello.
- **`--hello-timeout` is dead**: `tcpcon->timeout_hello` is set (`src/stack-tcp-core.c:490-496`, default 2 at `:668`) but never read; the 2 s is hard-coded at `src/stack-tcp-app.c:76`.
- ReceiveHello (`:88-115`): TIMEOUT -> if `stream` non-NULL go to SendFirst (`:90-99`); if NULL nothing happens (connection idles until the connection timeout). PAYLOAD -> ReceiveNext and re-dispatch the same payload (`:100-105`), i.e. **if the server talks first the hello is never sent**. CLOSE -> `banner_flush` + `tcpapi_close` (`:106-109`).
- ReceiveNext (`:117-152`): PAYLOAD -> `banner_parse` -> `banner1_parse` (`src/stack-tcp-core.c:1576-1595`); CLOSE -> flush + close; TIMEOUT ignored (`:137-138`); SENDING (emitted synchronously by `_tcb_seg_send`, `src/stack-tcp-core.c:1398`, i.e. from inside a parser's `tcpapi_send`) -> SendNext (`:139-143`).
- SendFirst (`:154-195`): if `stream == &banner_ssl || stream == &banner_ssl_12` (pointer equality) -> `banner_set_sslhello(socket, true)` (`:157-163`; sets `StreamState.is_sent_sslhello`, `src/stack-tcp-core.c:1554-1557`). Heartbleed small-window kludge `:165-171`. If `stream->transmit_hello` call it (only `banner_scripting`), else if `hello_length` -> `tcpapi_send(socket, hello, hello_length, TCP__static)` and, if `SF__close`, `tcpapi_close` right after (FIN; only `banner_ssl`, `src/proto-ssl.c:1444`). -> SendNext.
- SendNext (`:196-211`): SEND_SENT -> `tcpapi_recv` + ReceiveNext. APP_CLOSE/PAYLOAD here hit the `ERRMSG("TCP.app: unhandled event...")` default.
- TCP stack contract worth preserving (Inferred where noted): while the TCB is in a SEND state incoming data is **dropped, not buffered**, relying on peer retransmission (`src/stack-tcp-core.c:2071-2076`); sends are split at MSS (`:1350-1352`); `TCP__copy` makes the stack copy the buffer (`:1386-1388`), `TCP__static` keeps the pointer. Timeout events tick every 2 s (`:322-327`). Connection lifetime: on any TIMEOUT event, `when_created + timeout_connection < secs` -> RST + destroy (`:1971-1981`); default 30 (`:665-667`; `masscan->tcb.timeout` passed at `src/main.c:618` is never assigned anywhere -> 0 -> 30). Destroy always flushes banners first (`:874-877`) and runs `banner_smb1.cleanup` only if `app_proto == PROTO_SMB` (`:900-904`).
- API (`src/stack-tcp-api.h`): `tcpapi_set_timeout`, `tcpapi_recv`, `tcpapi_send(socket, buf, len, TCP__static|TCP__copy|TCP__adopt|TCP__close_fin)`, `tcpapi_reconnect`, `tcpapi_change_app_state`, `tcpapi_close` (half-close: FIN, keep receiving). `recv`/`send`/`close`/`reconnect`/`change_app_state` return `SOCKERR_EBADF` on a NULL socket or tcb (`:1738-1739, :1763-1764, :1784-1785, :1799-1800, :1813-1814`; `set_timeout` dereferences before its check, `:1717-1721`), which is how the C selftests run parsers without a stack. Parsers pass flags `0` (= `TCP__static`) everywhere except telnet (`TCP__copy`).

## 2. Dispatcher (`src/proto-banner1.c`, `src/proto-banner1.h`)

### 2.1 Structures
- `struct Banner1` (`src/proto-banner1.h:22-45`): `L` (Lua), smack tables `smack` (detection), `http_fields`, `html_fields`, `memcached_responses`, `memcached_stats`; capture bits `is_capture_html/cert/servername/heartbleed/ticketbleed`, `is_heartbleed/is_ticketbleed/is_poodle_sslv3`; `payloads.tcp[65536]` (port -> `ProtocolParserStream*`, the hello table); `parser[PROTO_end_of_list]` (unused: grep finds no `->parser[` reader). One `Banner1` per receive thread (`banner1_create` from `tcpcon_create_table`, `src/stack-tcp-core.c:714`).
- `struct StreamState` (per TCB, `:244-264`): `state` (u32, parser-private encoding), `remaining`, `port` (u16, remote port), `app_proto` (u16), `is_sent_sslhello:1`, `base64` (2-bit state + 24-bit temp), union `sub` {ssl, vnc, ftp, smtp, pop3, memcached, smb, rdp, mc, ssh}. Zeroed with the TCB (`src/stack-tcp-core.c:1010`).
- `struct ProtocolParserStream` (`:277-303`): `name, port, hello, hello_length, flags, selftest, init, parse, cleanup, transmit_hello, next`. **`parse` of the stream is never called**: `banner1_parse` dispatches on `app_proto` through a hard-coded switch (`src/proto-banner1.c:126-322`). `port` is informational only (several are copy-paste wrong: imap4 21, notes_rpc/ms_sql_s 6379, versioning/scripting 11211).
- `struct Patterns` (`:310-333`): `pattern, pattern_length, id, is_anchored` (actually smack flags), `extra`.

### 2.2 Detection pattern table (`src/proto-banner1.c:34-106`), compiled CASE-INSENSITIVE (`:509`)
Pattern index = smack id; `patterns[x].id` = app proto. A = `SMACK_ANCHOR_BEGIN` (stream offset 0 only), U = unanchored (anywhere in the not-yet-classified stream), W = `SMACK_WILDCARDS`.

| src line | bytes (len) | proto | flags | extra |
|---|---|---|---|---|
| 35-36 | `"\x00\x00" "**" "\xff" "SMB"`, `... "\xfe" "SMB"` (8) | SMB | A+W | 0 |
| 38 | `"\x82\x00\x00\x00"` (4) NBT positive session response | SMB | A | 0 |
| 40-44 | `"\x83\x00\x00\x01"` + one of `\x80 \x81 \x82 \x83 \x8f` (5) NBT negative | SMB | A | 0 |
| 47 | `"{\x22"` = `{"` (2) | MC | **U** | 0 |
| 48 / 49 | `"SSH-1."` / `"SSH-2."` (6) | SSH1 / SSH2 | A | 0 |
| 50 | `"HTTP/1."` (7) | HTTP | A | 0 |
| 51 | `"220-"` (4) | FTP | A | 0 |
| 52 | `"220 "` (4) | FTP | A | **1** |
| 53 | `"+OK "` (4) | POP3 | A | 0 |
| 54 | `"* OK "` (5) | IMAP4 | A | 0 |
| 55 | `"521 "` (4) | SMTP | A | 0 |
| 56-63 | `"\x16\x03\x00".."\x16\x03\x03"`, `"\x15\x03\x00".."\x15\x03\x03"` (3) | SSL3 | A | 0 |
| 64 | `"RFB 000.000\n"` (12) UltraVNC repeater | VNC_RFB | A | 1 |
| 65-67 | `"RFB 003.003\n"`, `"RFB 003.005\n"`, `"RFB 003.006\n"` | VNC_RFB | A | 3 |
| 68 | `"RFB 003.007\n"` | VNC_RFB | A | 7 |
| 69-74 | `"RFB 003.008\n"`, `"RFB 003.889\n"` (Apple), `"RFB 003.009\n"`, `"RFB 004.000\n"`, `"RFB 004.001\n"`, `"RFB 004.002\n"` | VNC_RFB | A | 8 |
| 75 | `"STAT pid "` (9) | MEMCACHED | A | 0 |
| 78-92 | 5-byte IAC sequences: `\xff\xfb\x01` + `\xff\xf0`/`\xff\xfb`/`\xff\xfc`/`\xff\xfd`/`\xff\xfe`/`\x0a\x0d`/`\x0d\x0a`/`\x0d\x0d`/`\x0a\x0a`; `"\xff\xfb%\x25xff\xfb"`; `\xff\xfb\x26\xff\xfd`; `\xff\xfd` + `\x18`/`\x20`/`\x23`/`\x27` + `\xff\xfd` | TELNET | **U** | 0 |
| 93-96 | `"\xff\xfb\x01\x1b["` (5), `"\xff\xfb\x01Input"` (8), `"\xff\xfb\x01   "` (6), `"\xff\xfb\x01login"` (8) | TELNET | A | 0 |
| 97-98 | `"login:"` (6), `"password:"` (9) | TELNET | A | 0 |
| 100-103 | `"\x03\x00\x00\x13\x0e\xd0\xbe\xef\x12\x34\x00\x02..."`, `"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02..."`, length **12** (literal is 19 bytes) | RDP | A | 0 |

Notes: `"\xff\xfb%\x25xff\xfb"` (`:87`) is a C escape bug: `\x25` ends at the non-hex `x`, bytes are `ff fb 25 25 78 66 66 fb`, of which the first 5 (`ff fb 25 25 78`) are the pattern (measured with `cc`); intended `"\xff\xfb\x25\xff\xfb"` (Inferred). RDP patterns only match a **successful** RDP_NEG response (byte 12 = type 2) with dst-ref 0x0000/0xBEEF and src-ref 0x1234; negotiation failures (type 3) never classify as RDP (go to "unknown"), so the `" NLA-unsupported"`/`" failure"` branches of the RDP parser are reachable only in its selftest (Inferred). Case-insensitivity applies to every pattern (e.g. `"http/1."`, `"rfb 003.008\n"`, `"\xffsmb"`, `"Login:"` all match).

### 2.3 `banner1_parse(banner1, tcb_state, px, length, banout, socket)` (`src/proto-banner1.c:113-325`)
1. `app_proto` NONE(0) or HEUR(1) (`:127-186`): `x = smack_search_next(banner1->smack, &tcb_state->state, px, &offset=0, length)` - one call, first match only; state persists across segments in `tcb_state->state`.
2. Accept match unless `proto == PROTO_SSL3 && !is_sent_sslhello` (`:137-138`): TLS-looking bytes before we sent a ClientHello are treated as unrecognized.
3. Kludges (`:147-157`): FTP with `extra == 1` (`"220 "`) and `port == 25 || port == 587` -> SMTP. `"220-"` has extra 0 so **multi-line SMTP greetings on 25/587 are parsed as FTP** (FTP parser then sends `AUTH TLS`). `"220 "` SMTP on any other port (2525, ...) -> FTP. VNC: `sub.vnc.version = extra`.
4. `app_proto = proto; state = 0;` then **replay**: if the HEUR buffer is non-empty, `banner1_parse(HEUR bytes)` then `banner1_parse(px)` from offset 0 (`:165-182`). The new parser sees the stream from byte 0 even if the match ended mid-segment.
5. No match: `banout_append(banout, PROTO_HEUR, px, length)` (`:184`). Unrecognized data accumulates without limit and is reported as app `"unknown"`. **The HEUR buffer is never cleared after a later match**, so a stream classified on its 2nd+ segment yields both an `unknown` record (pre-match bytes) and the protocol record(s) (Inferred from code; nothing removes it).
6. Other `app_proto` values dispatch (`:187-316`): FTP, SMTP, TELNET, RDP, POP3, IMAP4, SSH1/SSH2 (same parser), HTTP, SSL3 (`banner_ssl.parse`), SMB (`banner_smb1.parse`, also for port 139), VNC_RFB, MEMCACHED, SCRIPTING, VERSIONING, MC. Each gets `banner1->http_fields` as `banner1_private` (unused by all). Default: `fprintf(stderr, "banner1: internal error\n")` (`:318-320`).
- Dead code: the "re-read the stuff that we missed" loop computes `i` and discards it (`:141-143`). Return value (`app_proto`) is ignored by the caller.
- Re-entrancy hazard (Inferred): the HEUR replay passes a pointer into the banout buffer; a parser that appends to `PROTO_HEUR` during replay (RDP `UNKNOWN_PROTOCOL`, `src/proto-tcp-rdp.c:95,189,281`) can trigger `banout_expand` and free that buffer mid-iteration.
- `banner1_destroy` (`:641-651`) frees only `smack` and `http_fields` (leaks `html_fields`, memcached tables). `banner1_create` (`:495-636`): compiles patterns, fills the hello table (§6.1), calls `init` of ftp, http, imap4, memcached, pop3, smtp, ssh, ssl, ssl_12, smb0, smb1, telnet, rdp, vnc, mc (`:614-628`); scripting/versioning init commented out (`:631-632`).

## 3. smack Aho-Corasick (`src/smack1.c`, `src/smack.h`, `src/smackqueue.c`)

API used by banners: `smack_create(name, SMACK_CASE_INSENSITIVE)`, `smack_add_pattern(smack, bytes, len, id, flags)`, `smack_compile`, `smack_search_next(smack, &state, px, &offset, length)`, `smack_next_match(smack, &state)`, `smack_destroy`. `SMACK_NOT_FOUND = (size_t)~0` (`src/smack.h:5`); flags `SMACK_ANCHOR_BEGIN=1, SMACK_ANCHOR_END=2, SMACK_SNMP_HACK=4, SMACK_WILDCARDS=8` (`:13-18`). `smackqueue.c` is only a malloc'd FIFO for BFS during compile (`src/smackqueue.c:21-90`).

Semantics needed for an equivalent reimplementation:
- Alphabet = 256 bytes + 2 virtual symbols `CHAR_ANCHOR_START=256`, `CHAR_ANCHOR_END=257` (`src/smack1.c:187-196`). Textbook AC: goto trie (`smack_add_prefixes`, `:794-850`), BFS fail links with output-set merge (`:898-952`), full DFA by filling FAIL transitions from the fail state (`:958-987`).
- Case-insensitive: patterns stored `tolower` (`:643-646, :673-677`); at compile `char_to_symbol['A'..'Z'] = char_to_symbol[tolower]` (`:1163-1167`). Only ASCII A-Z fold (C locale `tolower`).
- Anchored-begin: the trie edge `GOTO(0, CHAR_ANCHOR_START)` leads to a dedicated anchor state; at compile rows 0 and 1 are swapped so **the search starts in the anchor state** (`:1199-1203`). The anchor state's fail is the root, so unanchored patterns also match from offset 0; after the first byte the anchor state is unreachable. With the state persisted across calls, "anchored" means **offset 0 of the whole stream**, and partial anchored matches continue across segment boundaries. Any leading byte (e.g. a stray `\r\n` before `"220 "`) defeats every anchored pattern.
- `smack_search_next` (`:1409-1487`): runs the DFA from `*offset` until the first state that has matches; returns one id, sets `*offset` to the byte **after** the match end (`:1471-1474`), or returns NOT_FOUND with `*offset = length`. The state word packs row in bits 0-23 and "remaining matches at this state" in bits 24-31 (`:1430-1433, :1485`); if several patterns end at the same position the **last-merged id is returned first** (`m_ids[count-1]`, `:1480-1483`) and `smack_next_match` returns the rest in reverse order (`:1492-1513`). Match lists at a state are [own pattern, then fail-inherited ids] (`smack_copy_matches`, `:561-599`, used at `:849` then `:942-947`). For the banner1 table no two patterns can end at the same position (no pattern is a suffix of another; Inferred by inspection), so order only matters for HTTP's `"Server:"`/`":"` pair (§7.1).
- Matches are found at the earliest end position (not longest; "TODO: Make it so that the longest match triggers first", `:101`).
- Wildcards (`:1106-1148`, "KLUDGE ... only works ... for the SMB parser"): after compile, for each `*` in a W pattern, every table entry of the preceding row that points to the base state is redirected to the `*`-successor. So `*` matches any byte **except** bytes that start another unanchored pattern from the root, i.e. `0x7B '{'` and `0xFF` for the banner1 table (Inferred): an NBT header whose length bytes contain 0x7B/0xFF is not classified as SMB.
- Table compression: bytes not used by any pattern share symbol 0; rows are power-of-two wide; transitions are `unsigned short` (`:178`) -> at most 65535 states.
- `SMACK_ANCHOR_END`/`smack_search_end`/`smack_search_next_end` and `SMACK_SNMP_HACK` are unused by TCP banners (`:1518-1597`).
- Equivalence recipe (Inferred): the banner1 table is 60 patterns of length <= 12, all anchored except `{"` and 15 telnet IAC sequences. A hand-rolled matcher (anchored prefix check over the first <= 12 stream bytes, buffered across segments, plus a streaming search for the 16 unanchored patterns, first match by earliest end offset, case-folding A-Z, `*` = any byte except 0x7B/0xFF) reproduces it; the general AC engine is only needed if bug-for-bug parity on pathological inputs is wanted. HTTP, HTML and memcached uses are small too (§7.1, §7.10).

## 4. Banner buffers (`src/proto-banout.c`, `src/proto-banout.h`)

- `struct BannerOutput { next, protocol (u32), length, max_length, banner[200] }` (`src/proto-banout.h:15-21`); singly linked list whose head is embedded in the TCB. One record per app type; bit 31 of `protocol` = "ended" (`banout_end`, `src/proto-banout.c:162-171`, used only by SSL certs `src/proto-ssl.c:472`).
- `banout_append(banout, proto, px, len)` (`:328-363`): `len == AUTO_LEN` -> `strlen` (`:334-335`); find record by **exact** `protocol` (incl. bit 31, `:48-54`), else create; grow by doubling (`:351-353`, `banout_expand :258-286`). **No size cap anywhere**; raw bytes, no escaping (escaping happens at output, §9).
- Record creation (`banout_new_proto`, `:237-253`): reuse the head if it is empty (`protocol == 0 && length == 0`), otherwise **insert right after the head**. Expanding the head copies it into a new node after the head and empties the head (`:271-275`), which the next new app type then reuses. => Report order = head, then non-head records newest-first, and it depends on which app type was appended first and on whether the head outgrew 200 bytes (Inferred). Example (single segment `HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<title>t</title>`): `http.server` (appended during header parsing) is the head, then `title`, then `http` (Inferred trace of §7.1).
- `banout_string(banout, proto)` matches `protocol & 0xFFFF` (`:58-68`) but `banout_string_length` matches the full value (`:135-145`): after `banout_end`, string and length can refer to different records (C bug; matters only for SSL).
- Helpers: `banout_append_char` (`:175-180`), `banout_newline` (append `'\n'` only if the record is non-empty, `:149-158`), `banout_append_hexint` (`:184-197`), `banout_append_unicode` (UTF-8 encode, `:202-231`), `banout_printf` (`:295-324`), streaming base64 `banout_init_base64/append_base64/finalize_base64` (`:365-442`, standard alphabet with `=` padding), `banout_is_equal`/`banout_is_contains` (selftests, `:72-131`), `banout_release` (`:34-43`).
- Flush (`src/stack-tcp-core.c:800-830`): for each record with `length && protocol`, `report_banner(out, global_now, ip_them, 6, port_them, protocol & 0x0FFFFFFF, tcb->ttl, banner, length)`; then release. TTL = the SYN-ACK TTL. Flush happens once per TCB (APP_CLOSE or destroy); there is no incremental reporting.

## 5. App types (`src/masscan-app.h:8-49`, `src/masscan-app.c`)

Values are persisted in `-oB` files ("don't change the values", `src/masscan-app.h:4-7`). Name = `masscan_app_to_string` (`src/masscan-app.c:8-57`); key = `masscan_string_to_app` (`:61-112`, exact case-sensitive `strcmp`, returns 0 when unknown). TCP emitter column covers this note's parsers.

| v | enum | output name | key(s) | TCP emitter (this note) |
|---|---|---|---|---|
| 0 | NONE | unknown | - | - |
| 1 | HEUR | unknown | - | dispatcher HEUR (§2.3), RDP unknown |
| 2 | SSH1 | ssh | ssh1 | never appended (ssh parser always uses SSH2) |
| 3 | SSH2 | ssh | ssh2, ssh | §7.2 |
| 4 | HTTP | http | http | §7.1 |
| 5 | FTP | ftp | ftp | §7.3 |
| 6/7/8 | DNS_VERSIONBIND/SNMP/NBTSTAT | dns-ver/snmp/nbtstat | same | UDP |
| 9 | SSL3 | ssl | ssl | TLS (§8) |
| 10 | SMB | smb | smb | SMB (§8) |
| 11/12/13 | SMTP/POP3/IMAP4 | smtp/**pop**/**imap** | smtp/pop/imap | §7.4-7.6 |
| 14 | UDP_ZEROACCESS | zeroaccess | zeroaccess | UDP |
| 15/16 | X509_CERT/X509_CACERT | **X509/X509CA** | x509/x509ca | TLS |
| 17/18 | HTML_TITLE/HTML_FULL | title/html | title/html | §7.1 |
| 19 | NTP | ntp | ntp | UDP |
| 20/21/22/24 | VULN/HEARTBLEED/TICKETBLEED/SAFE | vuln/heartbleed/ticketbleed/safe | same | TLS |
| 23 | VNC_OLD | vnc | vnc-old | none |
| 25 | MEMCACHED | memcached | memcached | §7.10 |
| 26/27 | SCRIPTING/VERSIONING | scripting/versioning | same | stubs, never set |
| 28 | COAP | coap | coap | UDP |
| 29 | TELNET | telnet | telnet | §7.8 |
| 30 | RDP | rdp | rdp | §7.9 |
| 31 | HTTP_SERVER | http.server | http.server | §7.1 |
| 32 | MC | minecraft | minecraft | §7.11 |
| 33 | VNC_RFB | vnc | vnc | §7.7 |
| 34 | VNC_INFO | vnc-info | vnc-info | §7.7 |
| 35 | ISAKMP | isakmp | isakmp | UDP |
| 36 | ERROR | error | - | UDP (isakmp) |
| other | - | `"(%u)"` from a static buffer (`:53-55`, not thread-safe) | - | - |

`masscan_app_selftest` prints a hard-coded `30` in its error message (`:139`).

## 6. Hello selection and options

### 6.1 Port -> stream (hello) table (`src/proto-banner1.c:522-608`, plus `mc_init`)
Streams with a parser (masscan-original hellos, quoted in §7): HTTP 80, 8080, 8530 (`:522-526`); SSL (+reconnect TLS1.2) 443, 465, 990, 991, 992, 993, 994, 995, 2083, 2087, 2096, 8443, 9050, 8140, 8531, 49955, 636, 637, 3269, 11712, 5061, 322, 2376; SMB0 139, SMB1 445; memcached 11211; telnet 23; RDP 3389; Minecraft 25565 (`src/proto-mc.c:102`).
Hello-only streams (no parser; responses go to HEUR/"unknown" unless a pattern happens to match): JavaRMI 1098, 1099; X11 6000-6019; Kerberos 88; mongodb 9001, 27017, 49153; dicom 104, 2345, 2761, 2762, 4242, 11112; LDAP 256, 257, 389, 390, 1702, 3268, 3892, 11711; SIP 406, 5060, **8081**, 31337; RTSP 554, 8554; RPC 111, 2049; DNS-version 53, **135**, 50000-50002; docker 2375, 2379, 2380; redis 6379; NotesRPC 130, 427, 1352, 1972, 7171, 8728, 22001; ms-sql-s 1433; AFP 548. `banner_genericlines` (`:334-339`) is defined but registered nowhere.
No hello (server speaks first; parser found by pattern): SSH, FTP, SMTP, POP3, IMAP4, VNC. Every port without an entry sends nothing; a silent service there yields no banner.

### 6.2 nmap-derived hellos (licensing, see §10.2)
`src/proto-banner1.c:327-489`, comment `:328` "Simple banners with hello probes from nmap-service-probes"; names match nmap probe names. Lengths (`sizeof-1`, measured): GenericLines 4, X11Probe 12, JavaRMI 7, mongodb 65, Kerberos 117, dicom 211, LDAPSearchReq 51, SIPOptions 223, RTSPRequest 22, RPCCheck 44, DNSVersionBindReqTCP 32, docker 25, redis-server 14, NotesRPC 60, ms-sql-s 52, afp 18. Bytes deliberately not reproduced here. All have flags 0 and `parse == NULL`.

### 6.3 Options (`src/main-conf.c` unless noted; names compared by `EQUALS`, which ignores `-` `.` `_` and case and treats `name[...]` as an array suffix, `:832-849`)

| option (aliases) | setter | effect / quirks |
|---|---|---|
| `--banners` (`banner`), bool | `:1106-1116`, table `:2377` | `is_banners`. `--nobanners` (`nobanner`) `:1546-1554` negates. `--rawudp` sets it too (`:1118-1130`). `--heartbleed`/`--ticketbleed`/`--vuln poodle\|sslv3` force it (`:2810-2819, :2929-2941`). |
| `--hello <ssl\|smbv1\|http>` | `:1181-1205` | applied in `src/main.c:643-654` via `tcpcon_set_parameter`: `ssl` / `http` point `payloads.tcp[i]` at `banner_ssl` / `banner_http` for `i < 65535` (**port 65535 excluded**, `src/stack-tcp-core.c:501-524`); `smbv1` -> `smb_set_hello_v1(&banner_smb1)` (`src/proto-smb.c:126-130`). Unknown value -> `"FAIL: %s: unknown hello type\n"`, CONF_ERR (ignored by caller per output-formats note §4). Multiple `--hello` flags all apply in order smbv1, http, ssl (ssl wins). |
| `--hello-string[PORT] <base64>` | `:1256-1286` | stores base64 in a linked list; index via `ARRAY` (`:881-890`): **no `[PORT]` -> port 0** silently; `>= 65536` -> `"%s: bad index\n"`, `exit(1)`. Applied last (`src/main.c:727-734`) as `"hello-string[%u]"` -> `src/stack-tcp-core.c:595-616`: CALLOC a new stream, `memcpy` the existing stream for that port (keeps `next`, flags), `name="(allocated)"`, `hello = base64_decode(...)`. Because SendFirst tests `stream == &banner_ssl` by pointer, **a custom hello on an SSL port disables `is_sent_sslhello`, so TLS replies are never parsed** (Inferred). |
| `--hello-file[PORT] <file>` (`hello-filename`) | `:1207-1254` | reads at most 16384 bytes (`:1211, :1237`), base64-encodes into a 16384-byte buffer with dst size 16383 (`:1246`) -> **silently truncated to 12285 bytes** (`src/crypto-base64.c:25-30` stops at whole quads; Inferred arithmetic), then re-enters as `hello-string[PORT]`. Empty file -> `"[FAILED] could not read hello file\n"` + `perror`. Same port-0 default. |
| `--hello-timeout <n>` | `:1288-1298` | stored, passed to the stack (`src/main.c:696-703`), **never used** (§1). |
| `--connection-timeout <n>` (`tcp-timeout`), old-style | `:2765-2767` | `tcp_connection_timeout` -> `tcpcon_set_parameter("timeout")` (`src/main.c:688-695`, `src/stack-tcp-core.c:484-489`). Default 30 s. |
| `--capture <cert\|servername\|html\|heartbleed\|ticketbleed>`, `--nocapture` (`no-capture`) | `:1132-1179` | sets/clears bits; unknown -> `"FAIL: %s: unknown capture type\n"` / `"... unknown nocapture type\n"`, CONF_ERR. Default: only `cert` on (`src/main.c:1610`). `html` -> `PROTO_HTML_FULL` (§7.1). `servername` has **no consumer** (only forced to 1 in the HTTP selftest, `src/proto-http.c:727`). cert/heartbleed/ticketbleed: TLS. One value per option, not a list. |
| `--banner-types <app>` (`banner-type`, `banner-apps`, `banner-app`), old-style | `:2683-2697` | one key per option (exact `strcmp`, §5); unknown -> `LOG(0, "FAIL: bad banner app: %s\n")`, `"err\n"` on stderr, `exit(1)`. **Only consulted by `--readscan`** (`src/in-filter.c:18-21`, which also drops status records when set); live scans are not filtered. |
| `--http-method/-url (http-uri)/-version/-host/-user-agent (http-useragent)/-payload <s>` | `:1410-1505` | each keeps one malloc'd string (last wins); applied in this order: payload, user-agent, host, method, url, version (`src/main.c:656-685`). |
| `--http-header Name:value`, `--http-header[Name] value` (`http-field`) | `:1335-1408` | `name += 11` assumes the literal 11-char `http-header` (`:1361`): the `http-field` alias (10 chars) or a dash-less spelling read past the name (UB; `--http-field[Name] v` mis-parses, `--http-field Name:v` reads past the NUL). Name trimmed of trailing spaces, value of leading spaces; no `:` and no `[` -> message + `exit(1)`. Max 16, extras silently dropped (`:1400`). Applied with `http_field_replace` (`src/main.c:705-711`). |
| `--http-cookie <v>` | `:1300-1333` | max 16; each adds a separate `Cookie: v` line (`http_field_add`, `src/main.c:712-718`). |
| header removal | - | `http.remove[16]`/`remove_count` exist (`src/masscan.h:446-449`) but nothing sets them; the apply loop would use `headers[i].name` instead of `remove[i].name` (`src/main.c:719-725`). Man page `--http-field-remove` is not an option -> `"CONF: unknown config option: %s=%s\n"`, `exit(1)` (`:3035-3037`). |
| `--nmap-service-probes <f>` | `:1585-1597`, read at `:3197-3203` | parsed into `payloads.probes`, **no consumer in the banner path** (grep: only `main-conf.c`). |

All banner setup runs per receive thread and mutates **process-global** stream structs (`banner_http.hello`, `banner_ssl.hello`, `banner_smb1.hello`, `banner_mc.hello`, memcached smack globals); `http_init` re-copies the default HTTP request on every `banner1_create` (`src/proto-http.c:463-464`). With several NICs the per-thread application interleaves (e.g. cookies added twice, Inferred).

### 6.4 HTTP request builder (`src/proto-http.c`)
- Default (`:386-396`; `IVRE_BUILD` is not defined by the Makefile): `"GET / HTTP/1.0\r\n" "User-Agent: ivre-masscan/1.3 https://github.com/robertdavidgraham/\r\n" "Accept: */*\r\n" "\r\n"` (99 bytes). No `Host:` header unless `--http-host`. Flags 0 (sent only after the 2 s silence).
- `http_change_requestline(hdr, len, field, field_len, item)` (`:124-223`): item 0 method, 1 URL, 2 version, 3 payload (everything after the first empty line is replaced). Missing pieces are synthesized (`GET`, `" "`, `/`, `HTTP/1.0`, `\r\n`).
- `http_change_field(hdr, len, name, value, value_len, what)` (`:293-382`): trailing `:`/spaces trimmed from `name`; finds the first header line whose name matches case-insensitively followed by optional spaces and `:` (`_has_field_name :256-288`); replace -> `Name: value\r\n` in place; not found -> insert before the empty line; remove -> delete line. Output always `name + ": " + value + "\r\n"` (original spelling of an existing name is lost).
- `--http-payload` additionally sets `Content-Length: <len>` (replace/add) (`src/stack-tcp-core.c:405-424`); method stays GET unless changed.
- C bugs: `:343-347` reads `hdr[-1]` when `offset == 0` and assigns `header_length = _http_append(...)` (returns the appended length, not the total) on a `realloc`ed local copy; replace path `memmove` length uses `header_length - offset + 1` instead of `- next_offset` (`:362-364`, over-read); `_next_field` loops forever on a bare-`\n` line (`:241-254`, Inferred). Unreachable with the built-in `\r\n` template. Selftest checks use `&&` instead of `||` (`:815, :830, :845, :860`).

## 7. Parsers

Common shape: `parse(banner1, private, pstate, px, len, banout, socket)`, byte-at-a-time state machine over `pstate->state` (+ `pstate->sub.*`), no input buffering (except Minecraft), may call `tcpapi_send`/`tcpapi_close` mid-loop. "Stop" below = a state the parser never leaves; nothing more is appended and the TCB lives until FIN/RST/timeout.

### 7.1 HTTP (`src/proto-http.c:487-691`, stream `:946-951`, init `:432-467`)
Trigger: `"HTTP/1."` at stream offset 0. Sends nothing from the parser. State word: `state2<<16 | id<<8 | state` (`:517-519, :685-690`); `state2` is the smack state for header names / HTML.
- States 0-4: `toupper(c) == "HTTP/"[state]` else stop + `tcpapi_close` (`:523-529`); 5: digits until `.` (`:530-537`); 6: digits until whitespace (`:538-545`); 7: skip to `\n` (`:546-550`). Failure (e.g. `HTTP/1.1x`) -> state DONE (16) and **nothing from that segment is appended** (`:678-681` only logs when `state < CONTENT`).
- Header fields (`:551-629`): smack table `http_fields` (`:26-35`, case-insensitive): `"Server:"` A, `"Via:"` A, `"Location:"` A, `":"` U, `"\n"` U; anchored = at the start of each field because `state2` is reset at FIELD_START. On `":"` the code calls `smack_next_match` to prefer a known name (`:580-590`). Only **Server** is captured: each value byte except `\r`/`\n` is appended to `PROTO_HTTP_SERVER` (`:614-616`), leading whitespace skipped (FIELD_COLON `:594-605`), trailing spaces kept, **multiple `Server:` lines concatenated with no separator**. `Via`/`Location`/`Content-Length` recognized but ignored; `field_name()` (`:405-427`) is dead. `"Server :"` (space before colon) is not recognized.
- `PROTO_HTTP` = raw header bytes: per segment, `[0, i)` where `i` is the `\n` of the empty line (`:554-559`), or the whole segment while still in the header (`:678-681`). Result: status line through the `\r` of the final CRLF, i.e. it ends in `"\r\n\r"` (raw CR/LF kept; Inferred trace).
- Body (`:630-671`): if `--capture html`, every body byte goes to `PROTO_HTML_FULL` (unbounded). smack `html_fields` = `"<TiTle"` U case-insensitive (`:41-44`), so `<title`, `<TITLE id=x>`, `<titlex>`, SVG `<title>` all match. After the match, bytes up to and including `>` are skipped (CONTENT_TAG), then every byte until the next `<` goes to `PROTO_HTML_TITLE` (no trim, no entity decoding, raw newlines); each further `<title` match appends again (no separator); a title without a following `<` absorbs the rest of the body.
- Termination: none; HTTP/1.0 servers close, others wait for the 30 s timeout. No Content-Length/chunked handling.
- Example records for `HTTP/1.0 200 OK\r\nServer: gws\r\n\r\n<title>x</title>`: `http.server`="gws", `title`="x", `http`="HTTP/1.0 200 OK\r\nServer: gws\r\n\r" (Inferred; selftest asserts only `gws`, `:693-760`, and `banner1_selftest` asserts `http` starts with `"HTTP/1.0 302"` when fed one byte at a time, `src/proto-banner1.c:714-767`).

### 7.2 SSH (`src/proto-ssh.c:52-178`, stream `:200-205`, no hello)
Trigger: `"SSH-1."` or `"SSH-2."` at offset 0; both use this parser and **always append to `PROTO_SSH2`**.
- **Every received byte is appended** before the state switch (`:84`), so the banner is the ident line plus everything after it (server KEXINIT, KEXDH reply incl. host key), until the parser stops. Output escapes the binary (§9).
- BANNER (`:86-97`): on `\n` send `"SSH-2.0-OPENSSH_7.9\r\n"` (21 bytes, `:8-9`) and go to LENGTH_1; a byte that is NUL or neither `isspace` nor `isprint` (e.g. UTF-8 in the comment) -> ERROR + close. Lines before the ident are not special-cased (the first `\n` triggers).
- Binary packets: LENGTH_1..4 big-endian u32 (`:99-119`), PADDING_LENGTH (`:121-124`), MESSAGE_CODE (`:126-143`). **Fallthrough bug**: the inner `switch` has no `break` after it, so for any message code control falls into `MSG_KEY_EXCHANGE_INIT` (`:145-149`): `packet_length--` again, send the canned 1248-byte KEXINIT+KEXDH_INIT blob (`:10-41`, `SIZE_KEY_EXCHANGE_INIT (1100+4+140+4)`), state CHECK_LENGTH. Consequences: our KEX blob is re-sent on **every** server packet; the message-code byte is counted twice, so the next length field is read one byte early and every packet after the first is misframed; `MSG_NEW_KEYS`/`BEFORE_END`/`END` (and the only `tcpapi_close` on success) are unreachable (Inferred). CHECK_LENGTH with `packet_length` already 0 underflows (`size_t`) and never resyncs.
- ERROR/0xffffffff states still append the first byte of each later segment (append precedes the `default:` exit, `:84, :172-173`).
- Termination: server disconnect (likely after our canned DH) or 30 s timeout.

### 7.3 FTP (`src/proto-ftp.c:13-123`, stream `:146-151`, no hello)
Trigger: `"220-"` on any port, or `"220 "` on ports other than 25/587.
- Greeting lines (states 0-5, `:32-87`): 3 digits (appended, code accumulated), separator `' '` (last line) or `'-'` (appended), text: `\r` skipped, other bytes appended until `\n` (appended). Non-digit start, bad separator, or NUL/non-`isprint` byte (incl. TAB) -> stop + close. Multi-line replies must have a code on every line (RFC 959 free-form continuation lines kill it).
- After the last greeting line: send `"AUTH TLS\r\n"`, state 100 (`:72-75`).
- Reply (100-105, `:88-116`): code, separator and text appended, `\r` skipped, **the final `\n` is not appended**. On the first `\n`: code 234 -> hand off to TLS (§8); else stop + close.
- Banner example: `"220 ProFTPD Server\n234 AUTH TLS successful"` then `ssl`/`X509` records from the TLS parser. After the hand-off, remaining bytes of the same segment are still run through the FTP switch with state 0 (`:101`, loop continues; Inferred, normally none).

### 7.4 SMTP (`src/proto-smtp.c:34-169`, stream `:191-196`, no hello)
Trigger: `"220 "` on port 25 or 587, or `"521 "` anywhere. Same line grammar and `PROTO_SMTP` appends as FTP, three phases:
- Greeting (0-5, `:53-113`): last line -> send `"EHLO masscan\r\n"` (`:99`), state 100.
- EHLO reply (100-105, `:114-133`): every line appended incl. `\n`; last line -> send `"STARTTLS\r\n"` (`:119`) **regardless of the EHLO code or advertised extensions**, state 200.
- STARTTLS reply (200-205, `:134-162`): first `\n` (not appended): code 220 -> TLS hand-off; else stop + close.
- Example: `"220 mx ESMTP\n250-mx\n250-PIPELINING\n250 STARTTLS\n220 2.0.0 Ready to start TLS"`.

### 7.5 POP3 (`src/proto-pop3.c:20-152`, stream `:174-179`, no hello)
Trigger: `"+OK "` at offset 0. All `\r` bytes are skipped before the switch (`:36-37`); everything else is appended to `PROTO_POP3`.
- 0-2 must be `+OK` (each byte appended even when it mismatches, then stop + close) (`:41-48`); 3: until `\n` -> send `"CAPA\r\n"` (`:49-55`).
- CAPA reply: 4 `'+'` -> 5 `'O'` -> 6 `'K'` -> 8 (`state += 2`, `:82`); 4 `'-'` -> state 100: append until `\n`, then stop + close (`:137-145`), so no STLS without CAPA. 8/9/10 read lines until a line `"."` (`:88-116`), then send `"STLS\r\n"`, state 204.
- STLS reply: 204 `'+'`/`'-'` (as above), 205 `'O'`, 206 `'K'`, 208: append until `\n` (appended) -> TLS hand-off (no further code check) (`:118-135`).
- Example: `"+OK Dovecot ready.\n+OK\nCAPA\nTOP\n...\n.\n+OK Begin TLS negotiation now.\n"`.

### 7.6 IMAP4 (`src/proto-imap4.c:20-193`, stream `:215-220`, no hello) - broken in this commit
Trigger: `"* OK "` at offset 0. `\r` skipped globally (`:36-37`).
- **Bug** (`:49-66`, since 2018 per `git blame`): state 1 consumes spaces; on the first non-space it sets `state = 0xffffffff` and calls `tcpapi_close`, then falls through to case 2, which appends the byte and, because it is `'O'`, does `state++` -> wraps to 0. The next byte `'K'` fails state 0 (`'*'` expected) -> stop + second close. **Every IMAP banner is exactly `"* OK"`** and the connection is closed (Inferred trace; no selftest exists).
- Intended (unreachable) flow: greeting line (4/5, `:76-95`) -> `"a001 CAPABILITY\r\n"` (`:92`); untagged `*` lines (200 -> back to 100) until `"a001 "` line (101-105) -> `"a002 STARTTLS\r\n"` (`:159`); untagged lines (400 -> 300) until `"a002 "` (301-304) -> at `\n` TLS hand-off without checking OK/NO (`:171-184`, nothing appended in 305).

### 7.7 VNC / RFB (`src/proto-vnc.c:93-337`, stream `:359-364`, no hello)
Trigger: one of the `"RFB xxx.yyy\n"` patterns; `sub.vnc.version` = pattern extra (1/3/7/8). Types: `PROTO_VNC_RFB` ("vnc") and `PROTO_VNC_INFO` ("vnc-info").
- 0-11 (`:119-165`): append the 12 version bytes to VNC_RFB; byte 12 must be `\n` (else stop + close); send `response[version % 10]` (12 bytes; `"RFB 003.003\n"` for 1/3, `"RFB 003.007\n"` for 7, `"RFB 003.008\n"` for 8, `:134-148`).
- v3.3 (version < 7): u32 BE security type (`:166-201`): VNC_INFO `"Security types:\n"` + `"  <name>"` (no newline). 0 -> error path; 1 (None) -> send `"\x01"` (ClientInit shared) -> ServerInit; anything else -> stop + close.
- v3.7/3.8: u8 count (0 -> error path), VNC_INFO `"Security types:\n"`, then `"  <name>\n"` per type (`:229-258`). Then **always selects type 1 (None)** even if not offered: v3.7 sends `"\x01\x01"` (choice + ClientInit) -> ServerInit; v3.8 sends `"\x01"` -> SecurityResult u32 (`:202-213`): 0 -> send `"\x01"` -> ServerInit; else error path.
- Error path (`:214-228`): 4-byte reason length but **only the low byte is kept** (`sectype = px[i]` instead of `|=`, `:216`); VNC_INFO `"ERROR: "` + reason bytes; then stop + close on the next byte.
- ServerInit (`:262-324`): VNC_RFB `" width=%u"`, `" height=%u"` (u16 BE each); skip 16-byte pixel format; u32 BE name length (0 -> stop + close); VNC_INFO `"Name: "` + name bytes + `"\n"`, stop + close.
- Names (`:35-88`): 0 `invalid`, 1 `none`, 2 `VNC-chap`, 5 `RA2`, 6 `RA2ne`, 7 `SSPI`, 8 `SSPIne`, 16 `Tight`, 17 `Ultra`, 18 `TLS`, 19 `VeNCrypt`, 20 `GTK-VNC-SASL`, 21 `MD5`, 22 `Colin-Dean-xvp`, 30 `Apple30`, 35 `Apple35`, else decimal; each prefixed by two spaces.
- Example v3.8 + None: `vnc` = `"RFB 003.008\n width=1024 height=768"`, `vnc-info` = `"Security types:\n  none\nName: host\n"`. v3.3 run-on: `"Security types:\n  noneName: ..."`.

### 7.8 Telnet (`src/proto-tcp-telnet.c:93-252`, stream `:351-356`)
Trigger: any telnet pattern (§2.2). Hello on port 23 after 2 s silence: `"\xff\xf6"` (IAC AYT).
- **Every byte, including IAC sequences, is appended raw** to `PROTO_TELNET` (`:123`).
- IAC handling (`:125-210`): `0xFF` -> IAC; then SE/NOP/DM/BRK/IP/AO/AYT/EC/EL/GA -> data; SB -> skip option byte -> data until `0xFF`; WILL/WONT/DO/DONT + option -> record refusal; **IAC IAC (escaped 0xFF data) or any other byte -> TELNET_INVALID = stop** (each later segment still appends its first byte, `:211-213`).
- Replies are per call (local `nego[256]`, `:115`): DO/DONT x -> `IAC WONT x`; WILL/WONT x -> `IAC DONT x`; emitted once per option in ascending option order, last command per option wins; sent with `TCP__copy` from a `MALLOC`ed buffer that is never freed (`:245-249`, leak). The `options[]` name table (`:20-69`) is unused (`#if 0`, `:71-82`).
- Termination: none (server close / timeout). Selftest vectors `:309-347` (substring checks, e.g. `"F670\r\n\rLogin:"`).

### 7.9 RDP (`src/proto-tcp-rdp.c:201-289`, stream `:375-380`)
Trigger: the 12-byte success-response prefix (§2.2). Hello on 3389 after 2 s silence (`:366-370`, 45 bytes): TPKT `"\x03\x00\x00\x2d"`, X.224 CR `"\x28\xe0\x00\x00\x00\x00\x00"`, `"Cookie: mstshash=masscan\r\n"`, RDP_NEG_REQ `"\x01\x00\x08\x00\x03\x00\x00\x00"` (requestedProtocols = TLS|CredSSP).
- TPKT (`:223-286`): version 3, reserved, length u16 (**high byte discarded**: `tpkt_length = tpkt_length` at `:239-242`), content -> COTP. Non-3 first byte -> UNKNOWN: append the **whole segment from offset 0** to `PROTO_HEUR` (`:226-230, :280-283`; `offset--` at 0 wraps and relies on unsigned wrap).
- COTP (`:111-197`): LI (< 6 -> unknown), PDU type, dst ref, src ref (stored into `dstref`, harmless), class; type `0xD0` (CC) -> RDP_NEG parser; other types -> `" COTPPDU=unknown"`.
- RDP_NEG (`cc_parse`, `:19-103`): type, flags, length low byte (`< 4` -> unknown), length high byte (treated as "reserved"), then u32 LE result. Type 2: `result & 2` -> `" NLA-supported"` else `" NLA-unused"`; type 3: result 5 -> `" NLA-unsupported"` (code 5 is HYBRID_REQUIRED_BY_SERVER, so the label is inverted, Inferred) else `" failure"`; other types never print.
- **The `rdp` banner is only these flag strings with a leading space**, e.g. `" NLA-supported"`; nothing else is ever appended to `PROTO_RDP`. Never sends, never closes. Selftests `:346-361`.

### 7.10 memcached, TCP side (`src/proto-memcached.c:106-223`, init `:227-293`, stream `:429-434`)
Trigger: `"STAT pid "` at offset 0. Hello on 11211: `"stats\r\n"` (7 bytes).
- Two smack tables (case-insensitive, anchored); each keyword is added 4 times with a trailing `' '`, `'\t'`, `'\r'`, `'\n'` (`:246-255`). Responses (`:47-69`): ERROR, CLIENT_ERROR, SERVER_ERROR, STORED, NOT_STORED, EXISTS, NOT_FOUND, END, VALUE, DELETED, TOUCHED, OK, BUSY, BADCLASS, NOSPARE, NOTFULL, UNSAFE, SAME, STAT, `""` (=lone whitespace). Stats (`:87-102`): pid, uptime, time, version, pointer_size, rusage_user, rusage_system, curr_items, total_items, bytes, max_connections, curr_connections, total_connections.
- Lines: `STAT` -> skip spaces -> stat name; only **uptime, time, version** are kept: append `"<name>="` then the value bytes (`\r` skipped) and `' '` at `\n` (`:182-219`); other stats/lines skipped to `\n`; `END` -> stop (`:148-150`). Output e.g. `"uptime=123 time=1700000000 version=1.6.21 "` (trailing space).
- Never closes (memcached keeps the connection) -> banner appears at the 30 s timeout.
- Bugs: state 0 is never advanced to 1 on NOT_FOUND, so a keyword split across segments is lost (`:129-137`); case 2 reads `px[length]` (`:162-167`, 1-byte over-read); `STAT\n` skips the following line (`:143-146`). Smack tables are also stored in process globals `sm_memcached_*` (`:22-23, :260, :290`) shared with the UDP parser.

### 7.11 Minecraft (`src/proto-mc.c:47-90`, init `:94-104`)
Trigger: **unanchored `{"`** anywhere in the unclassified stream on **any port** (any JSON-first or JSON-containing unknown response is hijacked as `minecraft`). Hello on 25565 (19 bytes, built by `hand_shake(25565, "localhost", 9)`, `:13-29`): `10 00 f7 05 09 "localhost" 63 dd 01 01 00` (handshake: length 16, id 0, protocol varint `f7 05` = 759, host, port 25565 BE, next-state 1; then status request `01 00`).
- Parsing: counts `{` and `}` bytes in each segment (also inside strings); `brackcount <= 0` -> `tcpapi_close` (`:59-66`). If the whole JSON arrives in one segment it is appended raw incl. the varint length prefix and the base64 favicon (`:68-69`).
- Multi-segment path (`:70-89`) accumulates into `mc->banmem` to strip `"data:image/png;base64..."` up to the next `"`; bugs: `banmem[totalLen] = 0` zeroes the **first byte of every accumulated segment** (`:73`); the end quote is searched only in later segments; overlapping `memcpy` (`:83`); `banmem` freed but not NULLed (`:86`); if the final segment closes the braces before the favicon end is found, only that final segment is appended and the accumulated data is lost; no cleanup hook (leak). `memstr` misses a match at the very end (`:38`).

### 7.12 Stubs and hello-only streams
- `banner_versioning` (`src/proto-versioning.c:25-98`) and `banner_scripting` (`src/scripting-banner.c:26-173`, ports registered from Lua `setTcpPorts`) are empty parsers; no pattern maps to them, so `app_proto` never takes those values (Inferred). Scripting's `transmit_hello` only logs (`:27-31`), so Lua-registered ports send nothing.
- Hello-only streams (§6.1): responses are classified by §2.2 patterns or end up in `unknown` as raw bytes (e.g. the redis `INFO` reply, LDAP/Kerberos binary replies; a JSON body would become `minecraft`). These never close; banner appears at the server's close or the 30 s timeout.

## 8. Hand-offs to TLS and SMB (triggers only)
- TLS parser `banner_ssl.parse = ssl_parse_record` (`src/proto-ssl.c:1442-1450`) runs when `app_proto == PROTO_SSL3`, set by: (a) pattern `\x16\x03\x0[0-3]` / `\x15\x03\x0[0-3]` at offset 0 **and** `is_sent_sslhello`, which only SendFirst sets for `banner_ssl`/`banner_ssl_12` (§1); (b) STARTTLS success in FTP (234), SMTP (220), POP3 (`+OK`), IMAP4 (unreachable): `memset(pstate, 0)`, `app_proto = PROTO_SSL3`, `is_sent_sslhello = 1`, port restored, then `tcpapi_send(banner_ssl.hello, banner_ssl.hello_length, 0)` (`src/proto-ftp.c:93-104`, `src/proto-smtp.c:139-150`, `src/proto-pop3.c:122-133`, `src/proto-imap4.c:172-182`). The STARTTLS ClientHello is `banner_ssl.hello` (TLS1.0-record template `src/proto-ssl.c:1077`, or the heartbleed/ticketbleed/sslv3 variant if those options replaced it, `src/stack-tcp-core.c:537-588`).
- SMB parser (`banner_smb1.parse`, `src/proto-smb.c:2090-2096`) runs for `app_proto == PROTO_SMB` from the SMB/NBT patterns (§2.2) on any port; hellos only on 139 (`smb0`) and 445 (`smb1`, `--hello smbv1` -> v1-only). Cleanup on TCB destroy (`src/stack-tcp-core.c:900-904`).

## 9. Output-side pointers (serialization belongs to the output-formats work)
- `output_report_banner` (`src/output.c:886-956`): dropped unless `out->is_banner` (`:898-899`); interactive/default format prints `"Banner on port %u/%s on %s: [%s] %s"` padded to 79 cols (`:903-923`); then lazy header, `funcs->banner(...)`.
- Escaping: `normalize_string` (`src/output.c:143-170`, text/xml/grepable/interactive): bytes that are `isprint` and not `< > & \ " '` copied, others `\xNN` (lowercase hex); buffer `MAX_BANNER_LENGTH` 8192 (`src/output.h:12`); when full, escapes are dropped but later printable bytes can still be added (gappy truncation). JSON/NDJSON use `\u00NN` with 65536-byte buffers (`src/out-json.c:69-97, :108`; `src/out-ndjson.c:65-93, :104`). Binary drops banners with `length >= 128*128-14` (`src/out-binary.c:313-314`).
- Per-format banner functions: `src/out-text.c:52-73`, `src/out-json.c:102-134`, `src/out-ndjson.c:98-153`, `src/out-xml.c:96`, `src/out-grepable.c:179`, `src/out-binary.c:294`, `src/out-hostonly.c:46`, `src/out-unicornscan.c:62`, `src/out-redis.c:321`, `src/out-certs.c:50`, `src/out-null.c:55`.

## 10. Port surface

### 10.1 Suggested grouping
- G0 framework (needed by everything): app-type enum/names (§5, values are a file format), banner buffers with a size cap (§4), first-bytes classifier + HEUR replay (§2-3), app state machine with the 2 s hello wait, hello table and config options (§1, §6), injectable "socket" for send/close, flush at close/timeout. Requires the TCP stack (separate work).
- G1 easy (line-oriented, server-first): FTP, SMTP, POP3 (STARTTLS reply recorded; TLS hand-off can be a no-op until TLS lands), memcached TCP, telnet.
- G2 moderate: HTTP (request builder + header/title state machine, `--http-*`, `--capture html`), VNC (binary, multi-step), RDP (TPKT/COTP/RDP_NEG), SSH (decide: bug-for-bug raw dump vs. ident-line only).
- G3 decide-before-porting: IMAP4 (broken in C), Minecraft (unanchored trigger, data-losing multi-segment path), nmap-derived hello-only streams (§10.2), scripting/versioning stubs (skip).
- Depends on other notes: TLS (`ssl`, X509, vuln/heartbleed), SMB.

### 10.2 Licensing
- No banner-related file carries a per-file license or copyright header (grep of every file cited here); the repo `LICENSE` is AGPL-3.0, so all reference code here is AGPL.
- NPSL risk: the 16 hello payloads at `src/proto-banner1.c:327-489` are taken from nmap-service-probes (`:328`). Exclude them, or re-derive any wanted probe independently from the protocol specs. They only change what is sent; their responses are not parsed (they land in `unknown`). `read-service-probes.c` / `--nmap-service-probes` are unused by the TCP banner path (§6.3) and stay out.
- Identity strings to decide on, not licensing: default HTTP User-Agent `ivre-masscan/1.3 https://github.com/robertdavidgraham/`, SSH client ident `SSH-2.0-OPENSSH_7.9`, RDP cookie `mstshash=masscan`, SMTP `EHLO masscan`.

### 10.3 C bugs and oddities (decide per item: replicate, fix, or document)
1. `--hello-timeout` ignored; wait is a constant 2 s (`src/stack-tcp-app.c:76`).
2. Classification ignores the port except `"220 "`+25/587: `"220-"` SMTP -> FTP (+`AUTH TLS`); `"220 "` SMTP elsewhere -> FTP (`src/proto-banner1.c:51-52, :147-153`).
3. HEUR bytes are reported as `unknown` in addition to the real banner when detection happens after segment 1 (`:165-184`).
4. Telnet pattern escape bug `"\xff\xfb%\x25xff\xfb"` (`:87`).
5. RDP detection only for successful negotiation with src-ref 0x1234 (`:100-103`); TPKT high length byte dropped (`src/proto-tcp-rdp.c:239-242`); "NLA-unsupported" label for HYBRID_REQUIRED (`:77-81`).
6. IMAP4 always `"* OK"`, never CAPABILITY/STARTTLS (`src/proto-imap4.c:49-66`).
7. SSH: raw dump of all bytes; fallthrough resends 1248-byte KEX per packet; off-by-one framing; success close unreachable (`src/proto-ssh.c:84, :126-149`).
8. VNC error reason length uses only the low byte (`src/proto-vnc.c:216`); client picks security type None even when not offered (`:239-254`).
9. Telnet stops at IAC IAC; leaked reply buffer (`src/proto-tcp-telnet.c:177-181, :246-248`).
10. memcached: no close (30 s per host), split-keyword loss, 1-byte over-read (`src/proto-memcached.c:129-167`).
11. Minecraft: unanchored `{"` hijack on any port; first byte of each accumulated segment zeroed; data loss and leaks (`src/proto-mc.c:68-89`, `src/proto-banner1.c:47`).
12. `banout` unbounded; record order depends on creation order and head expansion (`src/proto-banout.c:237-286, :351-353`); `banout_string` vs `banout_string_length` mask mismatch (`:61, :138`).
13. Options: `--hello-string`/`--hello-file` without `[PORT]` -> port 0; `--hello-file` truncated at 12285 bytes; `--hello ssl|http` skip port 65535; custom hello on an SSL port disables TLS parsing; `--http-field` alias UB (`src/main-conf.c:1361`); header-remove dead and wrong (`src/main.c:719-725`); `--http-field-remove` documented but rejected; `--capture servername` no-op; `--banner-types` only filters `--readscan`.
14. `base64_decode` loops forever when a non-alphabet byte (space, newline) sits at the 3rd or 4th position of a quad: the skip loops at `src/crypto-base64.c:134` and `:146` never increment `i`; it also reads `src[sizeof_src]` (`:118, :124`). Reachable from `--hello-string`.
15. HTTP: `Server` values concatenated without separator; title capture unbounded and prefix-matched (`<titlex>`); failed status-line segment drops its bytes; request-builder memory bugs on malformed templates (`src/proto-http.c:343-364`).
16. Global mutable stream structs reconfigured per receive thread (`src/proto-http.c:463-464`, `src/stack-tcp-core.c:375-616`).
17. Each SSL-hello port opens a 2nd connection (`src/stack-tcp-app.c:61-63`); with a single source port this logs an error per target (`src/stack-tcp-core.c:1669`).

### 10.4 Offline-testable surface (no network)
- Every parser is a pure function of (state, input bytes) -> (state, appended bytes per app type, actions: send(bytes), close). With a trait-object or recorded-actions "socket", all of §7 plus the classifier/replay (§2.3), banout ordering (§4), smack semantics (§3), the HTTP request builder (§6.4), base64, and option parsing (§6.3) can be unit-tested by feeding byte streams: whole buffer, one byte at a time (as `banner1_selftest` does, `src/proto-banner1.c:741-767`), and random splits; equality across splits is the core streaming invariant (it fails in C for memcached split keywords and Minecraft).
- Existing C vectors usable as fixtures: `banout_selftest` base64 cases (`src/proto-banout.c:463-540`), HTTP parser/config selftests (`src/proto-http.c:693-920`), telnet (`src/proto-tcp-telnet.c:309-347`), RDP (`src/proto-tcp-rdp.c:346-361`), smack (`src/smack1.c:1690+`), banner1 HTTP header (`src/proto-banner1.c:714-725`).
- C golden outputs can be produced offline by compiling the `proto-*.c` parsers with stubbed `tcpapi_*` (they already tolerate a NULL socket) and dumping the banout list; that gives byte-exact parity fixtures without a live stack (Inferred feasibility; not built).
- Needs the live stack / a scripted peer (not pure-offline): the 2 s hello wait, data dropped while in SEND state, FIN/RST/timeout flush timing, the SSL reconnect.

### 10.5 Design constraints that fall out of the C
- Parsers must be resumable per-byte state machines (TCP segments arrive one at a time; the C stack does no reassembly buffering and drops data while sending).
- Parsers send mid-parse and can switch the connection's protocol (STARTTLS -> TLS with fresh state); the classifier replays buffered pre-classification bytes into the chosen parser.
- One connection produces several typed banner records, emitted only when the connection ends; the record set (not the order) is the stable thing to compare against C.
- Per-connection memory: C keeps everything; a Rust port needs an explicit per-record cap (output already truncates at 8192/65536 escaped chars, and `-oB` drops records of 16370+ bytes).
- Config should be one immutable per-scan structure (port -> hello, HTTP request bytes, capture flags) instead of the C globals.
