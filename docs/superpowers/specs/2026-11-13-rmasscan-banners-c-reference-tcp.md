# masscan TCP banners for sub-stage 4b (user-mode stack, framework, text parsers): C reference (upstream masscan at commit 8e6b3b0)

Companion to the stage design (`2026-11-13-rmasscan-banners-design.md`, Р1-Р17, §10 И1-И7) and to the two recon notes it
was built from, [TCP stack](2026-11-13-rmasscan-banners-c-reference-tcpstack.md) and [framework and text
parsers](2026-11-13-rmasscan-banners-c-reference-parsers.md). This note is the byte-level authority for the 4b plan: it
restates only what 4b implements, re-checked against the source in this pass (cites marked ✓ were re-read for this
note; the others are carried from the two recon notes), corrects them where they were wrong (§F), and adds what they
lacked: the receive-thread integration as one ordered table, rate accounting, `EQUALS`, the option setters, the banner
buffer order, the segmentation dependencies of every 4b parser (Р13), the 4b scope boundary, IPv6 deltas and a numbered
catalogue of defects of classes а-г. C is cited `src/file.c:LINE`, Rust `rmasscan/crates/...`. Format strings are
verbatim (C escapes unexpanded). "Inferred" = read, not run. Nothing was executed for this note.

## A. Stack

### A0. Data flow (one connection, `--banners`)

SYN-ACK passes the cookie -> TCB created (`tcpcon_create_tcb`, `src/stack-tcp-core.c:970` ✓) -> `SYNACK` event: ACK sent,
state ESTABLISHED_RECV, `APP_CONNECTED` (`:2013-2026` ✓) -> the app arms a 2 s timer and waits (`src/stack-tcp-app.c:76` ✓)
-> server bytes go to `banner1_parse` (classifier, then the chosen parser, which may send or close) or, after 2 s of
silence, the port's hello is sent -> the open status record was already written at the SYN-ACK (`src/main.c:1048-1092` ✓)
-> banner records appear only when the TCB is flushed: app `APP_CLOSE` (peer FIN, or ACK of our FIN), TCB destroy
(lifetime RST, peer RST, CLOSING/TIME_WAIT end) or table teardown at the end of the scan (`banner_flush`,
`src/stack-tcp-core.c:800` ✓, called first by `tcpcon_destroy_tcb` `:838` ✓).

### A1. Receive-thread order per frame (`src/main.c:753-1123` ✓)

| # | Step | Code |
| --- | --- | --- |
| 1 | `rawsock_recv_packet`; on no packet (1 s pcap timeout) `tcpcon_timeouts(tcpcon, time(0), 0)` and `continue` | `:777-787` |
| 2 | `tcpcon_timeouts(tcpcon, secs, usecs)` with the capture timestamp, before any filter | `:794-797` |
| 3 | drop `length > 1514`; `preprocess_frame`; `seqno_them = TCP_SEQNO`, `seqno_me = TCP_ACKNO` | `:799-815` |
| 4 | `cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy) & 0xFFFFFFFF` (SCTP: `port_them \| Proto_SCTP<<16`) | `:817-826` |
| 5 | `is_my_ip` (else NDP NS to multicast), non-TCP protocols handled and `continue`, `is_my_port`, `--packet-trace`, `--pcap` | `:829-951` |
| 6 | stack block, only when `tcpcon` exists (`--banners`): see A2 | `:962-1043` |
| 7 | status block for `TCP_IS_SYNACK \|\| TCP_IS_RST`: status Open, RST wins Closed; cookie re-check (`cookie != seqno_me - 1` -> `continue`); `dedup_is_duplicate` -> `continue`; `output_report_status(out, global_now, ...)` | `:1048-1092` |
| 8 | `if (tcpcon == NULL && !masscan->is_noreset) tcp_send_RST(templ, stack, ip_them, ip_me, port_them, port_me, 0, seqno_me)` | `:1094-1100` |
| 9 | after the loop: `tcpcon_destroy_table` (flush every live TCB, no packet) | `:1111-1113` |

`TCP_IS_*` are bit tests (`src/stack-tcp-core.h:15-21`): SYN-ACK = `(flags & 0x12) == 0x12`.

### A2. Stack block (`src/main.c:962-1043` ✓)

- Lookup by 4-tuple first (`tcpcon_lookup_tcb`, `src/stack-tcp-core.c:1067`).
- SYN-ACK: bad cookie -> `LOG(2, "%s - bad cookie: ackno=0x%08x expected=0x%08x\n", ...)` and `continue` (no status
  record either); no TCB -> `tcpcon_create_tcb(ip_me, ip_them, port_me, port_them, seqno_me, seqno_them+1,
  parsed.ip_ttl, NULL, secs, usecs)` and `(*status_tcb_count)++` (`:984`); then `SYNACK` event with
  `(seqno_them+1, seqno_me)`. A SYN-ACK for an existing TCB re-enters the state machine (EST_RECV ignores it, A4).
- Not a SYN-ACK, TCB exists: in this fixed order, each its own event: `ACK` if the ACK bit is set; `DATA` if
  `app_length > 0`; `FIN` if FIN and not RST, with `seqno = seqno_them + app_length`; `RST` if RST. No cookie check, and
  the `TCB__destroyed` result of one event is ignored by the next (`Q +=`, E1.5).
- Not a SYN-ACK, no TCB, FIN set, RST clear: `rstfilter_is_filter` (A7) then `tcpcon_send_RST(tcpcon, ip_me, ip_them,
  port_me, port_them, seqno_them, seqno_me)` (`:1033-1041`). Independent of `--noreset`.
- Status records of A1 step 7 run after this block, for banners on and off: `open` is written at the first SYN-ACK,
  long before any banner.

### A3. TCB, timers, lifetime

- TCB fields used by 4b (`src/stack-tcp-core.c:109-166`): 4-tuple, `seqno_me` (next to send), `seqno_them` (next
  expected), `ackno_me`, `ackno_them`, `tcpstate`, `is_their_fin`, `is_small_window` (TLS only), `ttl` (SYN-ACK TTL),
  `mss` = 1400 constant (`:1031`), `segments` (send queue), `when_created`, `banout`, `banner1_state`, `stream`.
- Create (`:970-1060`): existing key -> that TCB unchanged; else zeroed (state SYN_SENT = 0, app App_Connect = 0);
  `seqno_them = ackno_me = their seq + 1`; `seqno_me = ackno_them = their ack`; `when_created = global_now`; timer
  armed at `secs + 1` (`:1035-1040`); `stream = banner1->payloads.tcp[port_them]` (NULL for unmapped ports),
  `banner1_state.port = port_them`, `banout_init` (`:1043-1049`).
- Timer arm sites (whole-second grid: `TICKS_FROM_USECS` divides, `src/event-timeout.h:129`):

| Arm | Value | Code |
| --- | --- | --- |
| TCB create | +1 s | `src/stack-tcp-core.c:1035-1040` |
| `APP_CONNECTED` -> `tcpapi_set_timeout(socket, 2, 0)` (replaces the +1 s) | +2 s | `src/stack-tcp-app.c:76` ✓ |
| every TIMEOUT that does not destroy and left the timer unlinked | +2 s | `src/stack-tcp-core.c:322-327` ✓ |
| FIN in FIN_WAIT2/TIME_WAIT | +5 s | `:2249-2253` |

- Lifetime: on every TIMEOUT event, `when_created + timeout_connection < secs` -> RST (`tcpcon_send_packet(..., 0x04)`,
  seq `seqno_me`, ack `seqno_them`) + destroy (`:1970-1980` ✓). Default `timeout_connection` 30 (`:665-667`); `--wait`
  default 10 (`src/main.c:1598`) is shorter, so connections alive at the end are cut by the teardown, not timed out.
- Hello: the first TIMEOUT (2 s after the SYN-ACK) in EST_RECV gives `APP_RECV_TIMEOUT`; App_ReceiveHello with a
  non-NULL stream goes to App_SendFirst and sends the hello (A5). With a NULL stream it never sends.
- `--hello-timeout` is stored (`src/stack-tcp-core.c:490-496`) and never read: the 2 is a literal (Р1, Р17).
- `when_created = global_now` is refreshed only by the status printer and `output_report_status`; under `--nostatus`
  a TCB created after a quiet period is born old and reset at its first tick (E1.8).

### A4. State machine `stack_incoming_tcp` (`src/stack-tcp-core.c:1910-2313` ✓)

Prologue for every event (`:1920-1987` ✓): payload filter (`payload_offset = seqno_them - tcb->seqno_them`; fully old
-> return without ACK; partly old -> trimmed; future -> dropped without ACK, no reassembly); FIN filter (`seqno_them ==
tcb->seqno_them - 1` -> duplicate FIN, ACK, return; `!= tcb->seqno_them` -> drop); TIMEOUT past lifetime -> RST +
destroy; RST -> destroy, nothing sent, no sequence check. Unlisted pairs log `"%s:%s **** UNHANDLED EVENT ****\n"`.

| State | Event | Action, frames | Next |
| --- | --- | --- | --- |
| SYN_SENT | TIMEOUT | SYN `0x02` (reconnect only, 4c) | same |
| SYN_SENT | SYNACK | `seqno_them = seq+1`, `seqno_me = ack`; ACK `0x10`; `APP_CONNECTED` | EST_RECV |
| EST_SEND | CLOSE | queue FIN (sent now only if the queue is empty) | FIN_WAIT1_SEND |
| EST_SEND | FIN ok | `_tcb_seg_recv(FIN)` (ACK) + a second ACK; no `APP_CLOSE` | FIN_WAIT1_SEND |
| EST_SEND | ACK | acknowledge; queue empty or head length 0 -> `APP_SEND_SENT` | EST_RECV |
| EST_SEND | TIMEOUT | resend head | same |
| EST_SEND | DATA, SYNACK | ignored, no ACK | same |
| EST_RECV | CLOSE | queue FIN, head -> `0x19` now | FIN_WAIT1_RECV |
| EST_RECV | FIN ok | `_tcb_seg_recv(FIN)` (one ACK), `APP_CLOSE` | CLOSE_WAIT |
| EST_RECV | ACK | acknowledge | same |
| EST_RECV | TIMEOUT | `APP_RECV_TIMEOUT` | same |
| EST_RECV | DATA | `_tcb_seg_recv`: `APP_RECV_PAYLOAD` first, then ACK (`:1884-1896` ✓) | same |
| EST_RECV | SYNACK | ignored | same |
| FIN_WAIT1_SEND | ACK good | queue empty or head len 0 -> `APP_SEND_SENT` | FIN_WAIT1_RECV |
| FIN_WAIT1_SEND | TIMEOUT | resend head | same |
| FIN_WAIT1_SEND | FIN, DATA | ignored | same |
| FIN_WAIT1_RECV | FIN | `_tcb_seg_recv(FIN)` (ACK) + second ACK, `APP_CLOSE` | CLOSING |
| FIN_WAIT1_RECV | ACK good, my FIN acked | `APP_CLOSE` | FIN_WAIT2 |
| FIN_WAIT1_RECV | TIMEOUT | resend head (pure FIN `0x11`) | same |
| FIN_WAIT1_RECV | DATA | `_tcb_seg_recv` | same |
| CLOSING | TIMEOUT | destroy, no frame | - |
| CLOSING | ACK, my FIN acked | destroy | - |
| CLOSING | FIN | ACK | same |
| CLOSING | CLOSE | silent | same |
| FIN_WAIT2 | TIMEOUT | nothing (ends by lifetime RST) | same |
| FIN_WAIT2, TIME_WAIT | FIN | `_tcb_seg_recv(FIN)` (ACK), timer +5 s | TIME_WAIT |
| FIN_WAIT2, TIME_WAIT | other | ignored (DATA not ACKed) | same |
| TIME_WAIT | TIMEOUT | destroy | - |
| CLOSE_WAIT | CLOSE | queue FIN, head -> `0x19` | LAST_ACK |
| CLOSE_WAIT | TIMEOUT | `APP_CLOSE` again | same |
| LAST_ACK | TIMEOUT | resend head (`0x11`) | same |
| LAST_ACK | ACK good | destroy | - |

### A5. Send, acknowledge, receive

- `_tcb_seg_send` (`src/stack-tcp-core.c:1337-1427` ✓): chunks of `mss` = 1400; zero-length non-FIN is a no-op; append
  after a queued FIN logs `"can't send past a FIN\n"` and drops; only the queue head is transmitted on enqueue
  (`0x18 | fin`), then state EST_SEND (non-FIN); later segments leave on later ticks via `_tcb_seg_resend` (`:1290`),
  which sends nothing and logs `"SEQNO FAILURE diff=%d %s\n"` when `seqno_me != head.seqno`. One segment in flight,
  peer window and MSS ignored, retransmit = tick, no backoff.
- `_tcp_seg_acknowledge` (`:1432-1550`): `ack == seqno_me` -> 0; `ack - seqno_me > 100000` -> "from past", 0; FIN at the
  head: `seqno+1 == ack` -> `seqno_me++`, `ackno_them++`, return 1 (FIN stays queued for `_tcb_they_have_acked_my_fin`);
  whole segments retired; partial ACK advances `seqno_me` but not `seg->seqno`, so the next resend is refused and the
  connection stalls until the lifetime RST (Р1: reproduce).
- `_tcb_seg_recv` (`:1843-1899` ✓): FIN-only at `seqno_them` -> `is_their_fin`, `seqno_them++`, ACK; old data -> ACK;
  after `is_their_fin` payload is ignored; else `seqno_them += len`, `APP_RECV_PAYLOAD`, then ACK. Every data segment
  gets its own ACK, after whatever the parser sent in reaction (wire order: our data, then the pure ACK).
- `tcpapi_send` (`:1757-1778` ✓) switches EST_RECV to EST_SEND before `_tcb_seg_send`, so `APP_SENDING` (`:1397-1398`
  ✓, only when the state is not EST_SEND) never reaches the app from a send; other states log `"TCP app attempted SEND
  in wrong state\n"` and send nothing. `tcpapi_recv` (`:1734-1755` ✓): EST_SEND and unlisted states -> EST_RECV,
  FIN_WAIT1_SEND -> FIN_WAIT1_RECV. `tcpapi_close` (`:1812`) is a `CLOSE` event.

### A6. Frames (`tcp_create_packet`, `src/templ-pkt.c:419-613` ✓)

- Copy of the TCP template of the scan (link header and the TCP options the SYN carries: MSS 1460 by default, plus
  `--tcp-mss/--tcp-wscale/--tcp-tsecho/--tcp-sackok`, data offset from the template), payload after the options.
- IPv4: total length; IP ID `(ip_them ^ port_them ^ seqno) & 0xFFFF` (`:432`); addresses; TTL/TOS/DF from the template
  (`--ttl`); header checksum by incremental update folded twice (`:466-473`, E1.10); TCP ports, seq, ack, flags byte
  overwritten whole (`:495` ✓), window forced to 1200 (`0x04B0`, `:497-498` ✓), checksum recomputed in full; zero
  padding to 60 bytes on every link (`:510-513`).
- IPv6 (`:515-611`): payload length, addresses, same TCP writes, hop limit 255 from the template, no padding.
- `tcpcon_send_packet` (`src/stack-tcp-core.c:1107-1171` ✓): seq `seqno_me - is_syn`, ack `seqno_them`; small window
  600 only for heartbleed (4c). Frames the stack emits: ACK `0x10`, data `0x18`, data+FIN `0x19`, resent pure FIN
  `0x11`, RST `0x04` (no ACK bit, ack field still `seqno_them`), SYN `0x02` (reconnect, 4c).

### A7. RST paths and `--noreset`

| RST | When | Fields | `--noreset` | Code |
| --- | --- | --- | --- | --- |
| stateless | no `--banners`; every SYN-ACK **and** every RST reply that passed cookie and dedup | seq = their ack (`cookie+1`), ack = 0, flags `0x04` | suppresses | `src/main.c:1094-1100` ✓, `src/stack-tcp-core.c:1176-1219` ✓ |
| lifetime | TIMEOUT past `when_created + timeout` | seq `seqno_me`, ack `seqno_them`, `0x04` | ignored | `src/stack-tcp-core.c:1970-1980` ✓ |
| FIN without TCB | non-SYN-ACK with FIN, no RST bit, no TCB, rstfilter passes | temporary TCB: seq = their ack, ack = their seq + 1, `0x04` | ignored | `src/main.c:1019-1041` ✓, `src/stack-tcp-core.c:1261-1282` ✓ |

- Without `--banners` the stateless RST also answers RST replies (closed ports): C resets a reset (lab 7b r1 saw it).
- rstfilter (`src/misc-rstfilter.c:61-133`): 16384 buckets of 4-bit counters keyed by SipHash `{seed, seed}`; a bucket
  at 15 filters; each call decrements one pseudo-random bucket. IPv4 hashes an uninitialised `input[4]` (E1.11).

### A8. Queue and rate (`src/stack-queue.c` ✓, `src/main.c:270-305, 465-500` ✓)

- RX formats every stack frame and RST into a pool buffer and enqueues it on a 16384-slot ring per NIC; `BUFFER_COUNT
  - 1` = 16383 buffers (`src/stack-queue.c:105-124`). Getting a buffer spins with 1 ms sleeps until one is free
  (`:8-22`): a lagging TX stalls RX (E1.12).
- TX: each throttle batch first drains stack frames (`stack_flush_packets`, `:46-96`), each counted in `packets_sent`
  (the throttle's counter) and decrementing the batch; SYNs use what is left (`src/main.c:289-299`: "This takes
  priority over sending SYN packets"). After the last SYN TX loops until `is_rx_done`, flushing stack frames under the
  same throttle every 100 us (`:470-494`). ARP and NDP replies share this queue in C.
- `--rate 100` therefore carries SYNs, ACKs, hellos, FINs and RSTs together.

### A9. End of scan

`is_rx_done` after `--wait` seconds past the last SYN (`src/main.c:1459-1497`); RX leaves its loop and
`tcpcon_destroy_table` (`src/stack-tcp-core.c:933-961`) flushes every live TCB (partial banners included) and sends
nothing. Table creation size hint `max_rate/5/nic_count`, clamped to `[1<<10, 1<<24]` buckets, is not a capacity: C
has no TCB limit (`:673-697`).

### A10. IPv6 deltas

- The stack, hash, `tcp_create_packet` and rstfilter all have IPv6 branches; `--banners` over IPv6 is wired but
  upstream never tested it (Р16).
- `is_my_ip` for IPv6 matches only `src->ipv6.first` (`src/stack-src.c:13-14` ✓); IPv6 SYNs use `src.port` = first port
  only (`src/main.c:345-346` ✓).
- `parsed.ip_ttl` is set only for IPv4 (`src/proto-preprocess.c:127` ✓): the TTL of IPv6 status records and of TCBs is
  stale or uninitialised (E1.9).
- No padding, hop limit 255, no VLAN on stack frames; reconnect over IPv6 is "untested, yolo" (4c).

## B. Banner framework

### B1. `banner1_parse` (`src/proto-banner1.c:113-325` ✓)

1. `app_proto` NONE or HEUR: one `smack_search_next` call over the segment, the smack state kept in `tcb_state->state`
   across segments (`:127-134`).
2. A match is accepted unless it is SSL3 and `!is_sent_sslhello` (`:137-138`).
3. Kludges (`:147-157`): FTP pattern with `extra == 1` (`"220 "`) on remote port 25 or 587 -> SMTP; VNC version =
   pattern `extra`.
4. `app_proto = proto; state = 0;` then, if the HEUR record is non-empty, `banner1_parse(HEUR bytes)` followed by
   `banner1_parse(px)` from offset 0 (`:159-182`): the parser sees the stream from its first byte. The HEUR record is
   not cleared (B3, E2.1).
5. No match (or a rejected SSL3 match): `banout_append(banout, PROTO_HEUR, px, length)` (`:184`).
6. Other `app_proto`: dispatch by a fixed switch (`:187-316`); `parse` of the stream struct is never called.

### B2. Classifier patterns (`src/proto-banner1.c:34-106`, compiled case-insensitive `:509`)

A = anchored at stream offset 0 (`SMACK_ANCHOR_BEGIN`), U = anywhere in the unclassified stream, W = wildcards.

| Bytes | App | Flags | 4b |
| --- | --- | --- | --- |
| `"\x00\x00**\xffSMB"`, `"\x00\x00**\xfeSMB"`; `"\x82\x00\x00\x00"`; `"\x83\x00\x00\x01"` + `\x80`/`\x81`/`\x82`/`\x83`/`\x8f` | SMB (10) | A(+W) | unported (B6) |
| `"{\x22"` | MC (32) | **U** | Minecraft |
| `"SSH-1."`, `"SSH-2."` | SSH1 (2), SSH2 (3) | A | SSH |
| `"HTTP/1."` | HTTP (4) | A | HTTP |
| `"220-"` / `"220 "` (extra 1) | FTP (5) | A | FTP, or SMTP on 25/587 for `"220 "` |
| `"+OK "` | POP3 (12) | A | POP3 |
| `"* OK "` | IMAP4 (13) | A | IMAP4 |
| `"521 "` | SMTP (11) | A | SMTP |
| `"\x16\x03\x00"`..`"\x16\x03\x03"`, `"\x15\x03\x00"`..`"\x15\x03\x03"` | SSL3 (9) | A | rejected without hello -> HEUR |
| `"RFB 000.000\n"` (1), `"RFB 003.00{3,5,6}\n"` (3), `"RFB 003.007\n"` (7), `"RFB 003.008\n"`, `"003.889"`, `"003.009"`, `"004.00{0,1,2}"` (8) | VNC_RFB (33) | A | VNC |
| `"STAT pid "` | MEMCACHED (25) | A | memcached |
| 15 IAC sequences (`:78-92`, including the escape-bug pattern `ff fb 25 25 78`) | TELNET (29) | **U** | Telnet |
| `"\xff\xfb\x01\x1b["`, `"\xff\xfb\x01Input"`, `"\xff\xfb\x01   "`, `"\xff\xfb\x01login"`, `"login:"`, `"password:"` | TELNET | A | Telnet |
| two 12-byte RDP negotiation-success prefixes (`:100-103`, literal 19 bytes, length 12) | RDP (30) | A | RDP |

smack semantics a reimplementation must keep (parsers ref §3): ASCII A-Z fold only; anchored means offset 0 of the
whole stream, partial anchored matches continue across segments, any leading byte defeats all anchored patterns;
first match by earliest end offset, one id per call; `*` matches any byte except the first byte of another unanchored
pattern (`{` 0x7B and 0xFF here; Inferred, pin with the oracle). No two patterns end at the same offset in this table.

### B3. Banner buffers and record order (`src/proto-banout.c` ✓)

- One record per app type, found by exact `protocol` (`:48-54`); bytes appended raw; no cap (Р5 caps at 65 536).
- New record (`banout_new_proto`, `:237-253` ✓): reuse the head if `protocol == 0 && length == 0`, else insert right
  after the head. Growth (`:326-363` ✓): while `length + n >= max_length` (200 initially) expand; expanding the head
  moves its content to a new node right after the head and empties the head (`banout_expand`, `:258-286` ✓), which the
  next new app then takes. Non-head records keep their place.
- Flush order (`banner_flush`, `src/stack-tcp-core.c:800-830`): list order, records with `length && protocol`; app =
  `protocol & 0x0FFFFFFF`; TTL = `tcb->ttl`; time = `global_now`. Example: `http.server` is appended first, so HTTP
  gives `http.server`, then `title`, then `http` when everything fits in 200 bytes (parsers ref §4).

### B4. Hello table (`banner1_create`, `src/proto-banner1.c:518-610` ✓, plus `mc_init`)

| Ports | Stream | 4b |
| --- | --- | --- |
| 80, 8080, 8530 | HTTP request (C3) | sent |
| 23 | Telnet `"\xff\xf6"` (IAC AYT) | sent |
| 3389 | RDP 45-byte connection request with `Cookie: mstshash=masscan\r\n` (`src/proto-tcp-rdp.c:366-370`) | sent |
| 11211 | `"stats\r\n"` | sent |
| 25565 | Minecraft handshake + status request, 19 bytes (`src/proto-mc.c:13-29, :102`) | sent |
| 443, 465, 990-995, 2083, 2087, 2096, 8443, 9050, 8140, 8531, 49955, 636, 637, 3269, 11712, 5061, 322, 2376 | TLS ClientHello, `SF__close`, `next` = TLS 1.2 reconnect | **not sent (4c)** |
| 139, 445 | SMB negotiate | **not sent (4d)** |
| ~50 NPSL ports (1098, 1099, 6000-6019, 88, 9001, 27017, 49153, 104, ..., 548) | nmap-service-probes hellos | **never sent (Р3)** |
| every other port | none (NULL stream) | none |

`--hello http` / `--hello ssl` point `payloads.tcp[i]` for `i < 65535` (port 65535 excluded, E3.6) at the HTTP / TLS
stream (`src/stack-tcp-core.c:501-524` ✓); `--hello smbv1` downgrades the SMB hello. Applied in the order smbv1, http,
ssl (`src/main.c:643-648` ✓), then `--hello-string` per port (C2).

### B5. App layer (`application_event`, `src/stack-tcp-app.c:43-218` ✓)

| App state | Event | Action |
| --- | --- | --- |
| Connect | CONNECTED | `stream->next` -> reconnect (4c); else `tcpapi_set_timeout(2)`, `tcpapi_recv`, -> ReceiveHello |
| ReceiveHello | RECV_TIMEOUT | stream non-NULL -> SendFirst; NULL -> nothing, forever |
| ReceiveHello | RECV_PAYLOAD | -> ReceiveNext, re-dispatch (server spoke first: the hello is never sent) |
| ReceiveHello, ReceiveNext | CLOSE | `banner_flush`, `tcpapi_close` |
| ReceiveNext | RECV_PAYLOAD | `banner_parse` -> `banner1_parse` |
| ReceiveNext | RECV_TIMEOUT, SEND_SENT | nothing |
| SendFirst | (internal) | TLS kludges (4c); `tcpapi_send(hello, hello_length, TCP__static)` if `hello_length`, `tcpapi_close` if `SF__close`; -> SendNext |
| SendNext | SEND_SENT | `tcpapi_recv`, -> ReceiveNext |
| SendNext | anything else | `"TCP.app: unhandled event: state=%s event=%s\n"`; a payload here is **not parsed** (the stack still ACKs it) |

A stream with `hello_length == 0` (an empty `--hello-string`) sends nothing in SendFirst and stays in SendNext for
ever: later server bytes are ACKed and never parsed (Р1, reproduce).

### B6. 4b scope boundary

- TLS (app 9 parser, X.509, heartbleed, ticketbleed, poodle, the TLS 1.2 reconnect) is 4c, SMB/NTLMSSP is 4d. Until
  then (spec §3): no hello on their ports; a stream classified as SMB, and every byte after a STARTTLS hand-off, is
  recorded as `unknown` (app 1); an SSL3 match is rejected as in C (no hello sent, B1.2) and lands in `unknown` too.
- STARTTLS hand-offs (FTP 234, SMTP 220, POP3 `+OK`, IMAP4 unreachable): C `memset`s the stream state, sets
  `app_proto = PROTO_SSL3`, `is_sent_sslhello = 1`, restores the port and sends `banner_ssl.hello`
  (`src/proto-ftp.c:93-104`, `src/proto-smtp.c:139-150`, `src/proto-pop3.c:122-133`). 4b performs the switch to app 9
  but sends nothing (no TLS hello). C then sets `state = 0` and the parser loop goes on (`src/proto-ftp.c:101`,
  `src/proto-smtp.c:147`, `src/proto-pop3.c:129`): the rest of that segment is parsed as a new greeting. 4b does not
  follow C there: every byte after the go-ahead line, in the rest of that segment and in every later one, is one
  `unknown` record, app_proto 9, in any split (E2.8).

## C. Options

### C1. Matching (`src/main-conf.c:833-849` ✓, `:3211-3300` ✓)

- `EQUALS(table, user)`: skips `-`, `.`, `_` on both sides, compares `tolower`, and returns true when the table name
  ends where the user name has `[` (array suffix, `:840-841` ✓): `--banner-types[0] dns-ver` or `--rate[7] 100` are
  accepted and only options that read an index (`nic[i]` keys, `hello-string`, `hello-file`, `http-header`) use it;
  anything after `[` need not be closed. The table is `config_parameters[]` (`:2369-...` ✓) with up to five
  aliases each; the first matching row wins. Old-style options (`connection-timeout`, `banner-types`, ...) are matched
  by the same `EQUALS` chain in `masscan_set_parameter`.
- One alias pair collides after normalisation: `nocapture` and its alias `no-capture` (`:2403` ✓), same setter.
- Command line: `--name=value`, `--name:value`, else the next argv (singletons take `""`); `F_NUMABLE` names take the
  next word only if it is an integer or boolean (`:3236-3260` ✓).
- Errors: an unknown name prints `"CONF: unknown config option: %s=%s\n"` and `exit(1)` (`:3036` ✓); a value missing at
  the end of argv prints `"%.*s: empty parameter\n"` and stops parsing without failing (`:3300-3302` ✓); `--help`
  prints the help and `exit(1)` (`:3225-3227` ✓). rmasscan's clap errors exit 2 today (`rmasscan-cli/src/main.rs:21`).
- Unclosed `[`: `EQUALS` stops comparing at `[` and `ARRAY` reads the index with `parseInt` (`:881-890`), so C takes
  `--hello-string[80 x` as port 80 and `--rate[ 100` as `--rate 100`. Р17 ("непарный индекс") makes it exit 1 in
  rmasscan for every option; a closed `[…]` on an option that reads no index is dropped as in C.

### C2. `--hello*` (`src/main-conf.c:1181-1298` ✓)

- `--hello <ssl|smbv1|http>`: value matched with `EQUALS`; else `"FAIL: %s: unknown hello type\n"`, `CONF_ERR`
  (ignored by the caller). Echo prints one line, `ssl` > `smbv1` > `http`, even when several are set.
- `--hello-string[PORT] <base64>`: index by `ARRAY` (`:881-890`: no `[` -> 0); `>= 65536` -> `"%s: bad index\n"`,
  `exit(1)`. Entries are **prepended** (`:1281-1284` ✓) and applied newest first (`src/main.c:727-734` ✓), so for one
  port the **first given wins**. Applied as a copy of the port's current stream (flags and `next` kept) with `hello =
  base64_decode(value)` (`src/stack-tcp-core.c:595-616` ✓). Echo: `hello-string[%u] = %s`, newest first.
- `base64_decode` (`src/crypto-base64.c:104-160` ✓): positions 1-2 of a quad skip non-alphabet bytes; at positions 3-4
  the skip loops do not advance `i` (`:134`, `:146`): a non-alphabet byte other than `=` there loops for ever (E1.6);
  `=` ends decoding; `src[len]` (the string's NUL) is read and harmless.
- **Valid base64** (the rmasscan rule for Р17 "неверный base64 — код 1"; anything else is exit 1): only the bytes
  `A-Z a-z 0-9 + /`, then at most two `=` and nothing after them; with `n` alphabet bytes, `n mod 4 != 1`; when `=`
  is present, `n mod 4` is 2 with exactly `==` or 3 with exactly `=`; the empty string is valid (an empty hello, B5).
  On valid input C's decoder equals standard base64 decoding with the unused low bits of the last quad ignored, so
  rmasscan decodes byte-identically to C. Whitespace, `=` in the middle, `QUJD=` and a lone trailing alphabet byte are
  invalid (C would skip, hang, or drop them).
- `--hello-file[PORT] <file>` (`hello-filename`): reads at most 16384 bytes, base64-encodes into 16383 bytes, which
  silently truncates the hello to 12285 bytes, then re-enters as `hello-string[PORT]`; empty file -> `"[FAILED] could
  not read hello file\n"`; open failure -> `"[-] [FAILED] --hello-file\n"` and `"[-] %s: %s\n"`. Not echoed.
- `--hello-timeout <n>`: `parseInt`, echoed `hello-timeout = %u` when non-zero, no effect.

### C3. `--http-*` and the request (`src/main-conf.c:1300-1505` ✓, `src/main.c:656-725` ✓, `src/proto-http.c:124-396`)

- Default request (`src/proto-http.c:386-396`): `"GET / HTTP/1.0\r\n" "User-Agent: ivre-masscan/1.3
  https://github.com/robertdavidgraham/\r\n" "Accept: */*\r\n" "\r\n"` (99 bytes), no `Host:`.
- Apply order (`src/main.c:656-685` ✓): payload (also sets `Content-Length: <n>` by replace, `src/stack-tcp-core.c:405-424`
  ✓), user-agent (`User-Agent:`), host (`Host:`), method, url, version; then every `--http-header` by replace
  (`:705-711`), every `--http-cookie` as an added `Cookie:` line (`:712-718`); the remove loop is dead (`:719-725`).
- `http_change_requestline(item)`: 0 method, 1 URL, 2 version, 3 payload (everything after the first empty line);
  missing parts synthesised. `http_change_field`: name trimmed of trailing `:`/spaces, first case-insensitive match
  replaced by `Name: value\r\n`, else inserted before the empty line; original spelling of the name is lost.
- `--http-header Name:value` (name = value up to the first `:`, trimmed of trailing spaces; value after it, trimmed of
  leading spaces) or `--http-header[Name] value` (leading and trailing `ispunct` bytes stripped from the bracket text).
  The setter picks the form by `name += 11` on the option name **as typed** (`:1361` ✓): from index 11 on, a `[` means
  the bracket form, anything else the colon form. So `http-header[X]` and `HTTP_HEADER[X]` use the bracket,
  `httpheader[X]` (10 letters, the rest is `X]`) needs a `:` in the value, and a typed name shorter than 11 characters
  (`http-field`, `httpheader`, `http.field`) makes `name` point past its NUL: undefined (E1.7). Neither form -> two
  lines `"[-] --http-header needs both a name and value\n"`, `"    hint: \"--http-header Name:value\"\n"` and `exit(1)`
  (`:1388-1390` ✓). At most 16 headers and 16 cookies, extras dropped silently. Each `--http-method/-url/-version/-host/
  -user-agent/-payload` keeps the last value.
- Echo: `http-cookie = %.*s` per cookie, `http-header = %s:%.*s` per header, `http-method = `, `http-version = `,
  `http-url = `, `http-user-agent = `, `http-host = `, `http-payload = ` in table order (`:2391-2398` ✓).
- Builder with user values (`src/proto-http.c:52-118, :125-382` ✓): the output is deterministic for every value an
  option can carry (well-formed CRLF, bare LF, spaces, empty values). Oddities to reproduce: a value with a bare `\n`
  stops the field search at that line, so later headers are inserted there (`_next_field` returns the `\n` position
  and `_field_length` there is 0, `:226-254`); an empty or spaced method or URL shifts the request-line tokens and a
  missing URL loses its space (`_skip`, `:65-95`). One internal over-read never reaches the output: the replace path
  moves `header_length - offset + 1` bytes from `next_offset` (`:362-364`), reading `next_offset - offset` bytes past
  the header end, beyond the allocation (`header_length + new line + 3`, `:337`) whenever the old line is more than 2
  bytes longer than the new one (`--http-user-agent x` over the 68-byte default line); those bytes land after the new
  terminator. Unreachable from options, because the
  template always keeps its empty line: `hdr[-1]` (`:343`, needs an empty header) and `header_length =
  _http_append(...)` (`:345-347`, needs a header without an empty line). The recon note's "bare-LF loop" does not
  exist (§F4).

- Task 10 oracle correction (E1.17): `_http_insert` shrinks the allocation **before** moving the tail
  (`src/proto-http.c:110-114`). Empty method, empty version and the short version `a\r\nb` read beyond the new
  allocation; the normal allocator retained the logical CRLF tail, while ASan produced NUL/redzone bytes in the
  returned request. The deterministic rule is a safe logical splice preserving the entire old tail, never allocator
  bytes. Short and empty values remain accepted; ordinary C output agreement does not establish defined C behavior.

### C4. Others

- `--connection-timeout <n>` / `--tcp-timeout` (old-style, `src/main-conf.c:2765-2767` ✓): `parseInt`; 0 means the
  default 30 (`src/main.c:688-695` ✓); not echoed.
- `--capture html` makes the HTTP body go to `html` (app 18); `servername` has no consumer; `cert`, `heartbleed`,
  `ticketbleed` are TLS (4c). Default: only `cert` on (`src/main.c:1610`).
- `--noreset` (`F_BOOL`, `:1556-1565`): gates only the stateless RST (A7).
- Echo order of the table rows that 4b adds or touches: `banners`, `rawudp`, `nobanners`, `noreset`, ..., `hello`,
  `hello-string`, `hello-timeout`, `http-cookie`, `http-header`, `http-method`, `http-version`, `http-url`,
  `http-user-agent`, `http-host`, `http-payload`, ..., `capture`/`nocapture` (`src/main-conf.c:2377-2403` ✓).

## D. Parsers (byte detail in the parsers ref §7; here: outputs, sends, closes, segmentation)

Common shape: byte-at-a-time state machine over `pstate->state` (+ `sub`), may `tcpapi_send`/`tcpapi_close` mid-loop.
"Split" names how C's result depends on where segments end (E2). Records are listed in banout order (B3).

| § | Parser, trigger | Sends | Records (app) | Split |
| --- | --- | --- | --- | --- |
| D1 | HTTP (`src/proto-http.c:487-691`), `"HTTP/1."` | none | `http.server` (31): each `Server:` value byte except CR/LF, values concatenated; `title` (17): bytes after `<title...>` up to `<`, again per match; `html` (18) with `--capture html`: every body byte; `http` (4): header bytes through the CR of the final CRLF | E2.3 |
| D2 | FTP (`src/proto-ftp.c:13-123`), `"220-"` any port, `"220 "` not 25/587 | `"AUTH TLS\r\n"` after the greeting | `ftp` (5): greeting lines (code, separator, text, `\n`; CR skipped only inside the text, states 5 and 105, `src/proto-ftp.c:69`, `:89`; a CR where a code digit or the separator is due closes, `:43-45`), then the AUTH reply without its final `\n`; 234 -> STARTTLS (B6) | E2.8 |
| D3 | SMTP (`src/proto-smtp.c:34-169`), `"220 "` on 25/587, `"521 "` | `"EHLO masscan\r\n"`, then `"STARTTLS\r\n"` whatever EHLO said | `smtp` (11): greeting, EHLO reply lines; 220 to STARTTLS -> hand-off | E2.8 |
| D4 | POP3 (`src/proto-pop3.c:20-152`), `"+OK "` | `"CAPA\r\n"`, then `"STLS\r\n"` | `pop` (12): every non-CR byte through the STLS reply; `-` to CAPA -> line, stop; `+OK` STLS reply line -> hand-off | E2.8 |
| D5 | IMAP4 (`src/proto-imap4.c:20-193`), `"* OK "` | none (CAPABILITY unreachable) | `imap` (13) = `"* OK"` (spaces after `*` kept), then `tcpapi_close` twice (`:54-55`, then after the fall-through `:63-64`); on `"* ok "` the classifier (case-insensitive) matches but the parser's `'O'` test (`:60`) is not, so the record is `"* o"`, again two closes (`:49-66` ✓) | none |
| D6 | SSH (`src/proto-ssh.c:52-178`), `"SSH-1."`/`"SSH-2."` | `"SSH-2.0-OPENSSH_7.9\r\n"` at the first `\n`; the 1248-byte KEX blob on every server packet (fallthrough) | `ssh` (always 3): **every byte received**, until stop | E2.4 |
| D7 | VNC (`src/proto-vnc.c:93-337`), `"RFB ..."` | 12-byte version reply; `"\x01"` / `"\x01\x01"` choosing None even if not offered | `vnc` (33): version bytes, ` width=%u`, ` height=%u`; `vnc-info` (34): `Security types:\n`, `  <name>`(+`\n` in 3.7+), `ERROR: `+reason, `Name: `+name+`\n` | none |
| D8 | Telnet (`src/proto-tcp-telnet.c:93-252`), IAC/login patterns | per call: one reply per option, ascending option order, `IAC WONT x` for DO/DONT, `IAC DONT x` for WILL/WONT (`TCP__copy`) | `telnet` (29): every byte received, raw | E2.4 |
| D9 | RDP (`src/proto-tcp-rdp.c:201-289`), 12-byte success prefix | none | `rdp` (30): ` NLA-supported`/` NLA-unused`/` NLA-unsupported`/` failure`/` COTPPDU=unknown`; non-3 TPKT -> whole current segment to `unknown` (`:281` ✓) | E2.5 |
| D10 | memcached (`src/proto-memcached.c:106-223` ✓), `"STAT pid "` | none (hello `stats\r\n` on 11211) | `memcached` (25): `uptime=`, `time=`, `version=` + value + `' '` | E2.6, E1.4 |
| D11 | Minecraft (`src/proto-mc.c:47-90` ✓), `{"` anywhere, any port | `tcpapi_close` when the running brace count <= 0 | `minecraft` (32): whole segment raw when count <= 0 after it; multi-segment path strips the favicon with data-losing bugs | E2.7 |

Details the tests must pin:
- HTTP status line: states 0-4 `toupper(c) == "HTTP/"[state]`, 5 digits to `.`, 6 digits to whitespace, else
  `DONE_PARSING` + close (`:523-545` ✓) and nothing of that segment is appended (`:678` ✓).
- SSH: append precedes the switch (`:84` ✓); a byte that is NUL or neither `isspace` nor `isprint` in the ident line ->
  ERROR + close + `continue`, so the **next byte is still appended** before `default` ends the loop (`:92-96`, `:172-173`).
- Telnet: append precedes the switch (`:123`); IAC IAC or an unknown command -> INVALID (`:180` ✓), the next byte is
  appended, then `default` ends the loop (`:212` ✓).
- memcached: smack tables built by `memcached_init` (`:227-293`), each word + one of ` \t\r\n`; state 0 resets the
  matcher on every entry, including the start of the next segment (`:129-137`); state 2 reads `px[length]` (`:165` ✓).
- FTP/SMTP greeting grammar, POP3 CAPA/STLS states, VNC security names (`  none`, `  VNC-chap`, ..., decimal), RDP
  COTP/NEG offsets: parsers ref §7.3-7.9.

## E. Port surface

### E1. Defects of classes а-г (fixed by rmasscan, each a README line with this cite)

| # | Class | C | rmasscan | Verifier kind |
| --- | --- | --- | --- | --- |
| E1.1 | а | partial ACK of a `TCP__static` hello advances `seg->buf` without shrinking `length` (`src/stack-tcp-core.c:1525-1545`) | the stall is kept (Р1), no buffer arithmetic exists | - |
| E1.2 | а | `assert(payload_length < 2000)` on a trimmed retransmission (`:1941`) | no assert; frames > 1514 never reach it | - |
| E1.3 | а | HEUR replay reads the HEUR buffer while RDP may append to it (`src/proto-banner1.c:165-182` + `src/proto-tcp-rdp.c:281`) | replay works on a moved copy | - |
| E1.4 | а/в | memcached state 2 reads `px[length]` past the segment (`src/proto-memcached.c:165`); a `\n` there ends the line early and changes the next segment's parse | the byte past the segment is never read: treated as "not `\n`" | `memcached-tcp-past-segment` |
| E1.5 | г | events after a destroying event of the same frame use the scrubbed TCB (`src/main.c:991-1018`), e.g. an ACK to 255.255.255.255:65535 | processing of a frame stops at `Destroyed` | `no-frame-from-destroyed-tcb` |
| E1.6 | б | `base64_decode` loops for ever on a non-alphabet byte at quad positions 3-4 (`src/crypto-base64.c:134, :146`) | every input outside the C2 definition of valid base64 (this one included) is refused, exit 1 (Р17); valid input decodes as C | - |
| E1.7 | а | `--http-header` spelled with fewer than 11 characters (`http-field`, `httpheader`, `http.field`): `name += 11` points past the name's NUL (`src/main-conf.c:1361`); replace path of the request builder reads past the header end (`src/proto-http.c:362-364`) without effect on the output | the short spelling is refused, exit 1 (the only `--http-*` input refused for this class); every other spelling and value is reproduced (C3), the builder has no buffer arithmetic | - |
| E1.8 | в | stale `when_created` under `--nostatus` (`src/stack-tcp-core.c:1029`, `src/main.c:94`) | creation time from the engine clock | - |
| E1.9 | в | IPv6 TTL indeterminate (`src/proto-preprocess.c:127`) | real hop limit | `ipv6-ttl` |
| E1.10 | г | IPv4 header checksum folded twice (`src/templ-pkt.c:466-473`), ~1e-5 of stack frames wrong (vector: `ip_me=0xd5a30aac ip_them=0x4ba3e552 port_them=55289 seqno=0x3e8f982c`, C `0xffff`, right `0xfffe`) | full checksum | `ipv4-stack-checksum` |
| E1.11 | в | rstfilter hashes uninitialised `input[4]` (`src/misc-rstfilter.c:67-82`) | `input[4] = 0` | - |
| E1.12 | б | blocking packet pool stalls RX (`src/stack-queue.c:8-22`) | bounded queue, overflow counted (Р7) | - |
| E1.13 | а | Minecraft multi-segment path: overlapping `memcpy`, freed `banmem` not cleared, first byte of every accumulated segment zeroed (`src/proto-mc.c:68-89`) | unsplit rule E2.7 | `minecraft-unsplit` |
| E1.14 | б | `--hello-file` silently truncated to 12285 bytes (`src/main-conf.c:1237-1246`) | longer file refused, exit 1 (Р17) | - |
| E1.15 | - (receive rule of every rmasscan receiver, not а-г; ruling of task 3 review) | no checksum verified on receive (`src/proto-preprocess.c:10`, `:96` `TODO: verify checksum`; `src/main.c:808-1043` goes from `preprocess_frame` to `is_my_ip`/`is_my_port` and `stack_incoming_tcp`): a segment with a wrong IPv4 header or TCP sum reaches the stack (ACK advances, payload reaches the banner parser, FIN/RST change state) | `tcp_segment` drops it before the stack, as `parse_reply` (`ChecksumPolicy::Verify`, the default) drops a bad-sum SYN-ACK; `tcp_segment` has no `ChecksumPolicy` parameter, so the stack path always verifies | - |
| E1.16 | б | a FIN at the next sequence number in FIN_WAIT2 or TIME_WAIT re-arms the timer at `secs + 5` (`src/stack-tcp-core.c:2243-2253`) and the lifetime is checked only on TIMEOUT (`:1970-1980`): a peer sending such FINs less than 5 s apart keeps a TCB for ever (slot leak) | every deadline is capped at `created + lifetime + 2 s` (the 2 s grid tick on which the automaton RSTs by lifetime); the table capacity itself is D7, not an E1 fix | - |
| E1.17 | а | `_http_insert` calls `REALLOC(new_header_length + 1)` before moving the old tail (`src/proto-http.c:110-114`); shrinking method/URL/version can read bytes beyond the new allocation into the visible request (ASan differs from ordinary C for empty method, empty version, version `a\r\nb`) | safe logical splice preserves the full tail; no rejection of short/empty values and no allocator-dependent bytes | request fixtures `method-2`, `version-8`, `version-9` |

### E2. Segmentation dependencies (Р13: the reference is C on the unsplit stream)

"Unsplit" = the whole server stream handed to `banner1_parse` in one call. Every rule below is what C does on that one
call, expressed so a streaming parser can do it.

| # | Where | C on split segments | Unsplit rule rmasscan implements |
| --- | --- | --- | --- |
| E2.1 | classifier (`src/proto-banner1.c:165-184`) | a match in segment k >= 2 leaves segments 1..k-1 in HEUR: an extra `unknown` record | no `unknown` record from pre-match bytes; they are replayed and dropped |
| E2.2 | classifier | after a rejected SSL3 match, a later segment can still match `{"` or IAC | the first match decides; a rejected first match makes the rest of the stream `unknown` |
| E2.3 | HTTP (`src/proto-http.c:520-545, :678`) | a status line failing after a segment end keeps the earlier segment's bytes in `http` | bytes of the status line are held back until state 7 or failure; failure drops them |
| E2.4 | SSH (`src/proto-ssh.c:84, :92-96, :172-173`), Telnet (`src/proto-tcp-telnet.c:123, :180, :212`) | after the stop byte: one more byte of that segment, then the first byte of every later segment | exactly one byte after the stop byte, then nothing |
| E2.5 | RDP (`src/proto-tcp-rdp.c:223-283`) | UNKNOWN appends the whole current segment (from its offset 0) | on entering UNKNOWN with at least one more byte, append every byte the RDP parser has seen since its start, and all later bytes |
| E2.6 | memcached (`src/proto-memcached.c:129-137`) | a keyword split across segments is lost (matcher reset in state 0) | the matcher continues across segments (C state 1) |
| E2.7 | Minecraft (`src/proto-mc.c:59-89`) | favicon stripping with zeroed bytes and lost segments | record = every byte the parser saw, raw, if the brace count over them is <= 0 at flush, else none; close when the running count drops <= 0 after a segment |
| E2.8 | FTP (`src/proto-ftp.c:93-104`), SMTP (`:139-150`), POP3 (`:122-133`), STARTTLS go-ahead | after the go-ahead C sets `state = 0` and keeps parsing the rest of that segment (`src/proto-ftp.c:101`, `src/proto-smtp.c:147`, `src/proto-pop3.c:129`): on a single segment the tail is a new greeting, a second `AUTH TLS` / `EHLO` / `CAPA` is sent and the tail can be appended to the text record; split at the go-ahead (or byte by byte) the next segment goes to the TLS parser (app 9), which records nothing here | every byte after the go-ahead line is one `unknown` record (app 1), in any split, app_proto 9, no TLS hello and no second command. This is the B6 boundary, not "C on the unsplit stream", until 4c ports TLS. Record order as B3: the `unknown` record after the text record while that is under 200 bytes, before it from 200 bytes on |

Parsers without an entry (IMAP4, VNC; FTP, SMTP and POP3 except for the STARTTLS go-ahead, E2.8) are split-invariant
in C: their stop states append nothing.
Sends are compared only on the unsplit run: Telnet replies per segment by design.

### E3. Deterministic C behaviour kept (Р1)

1. Hello wait 2 s, `--hello-timeout` ignored; server-first streams never get the hello.
2. One segment in flight, head-only transmit, FIN behind a hello leaves a tick later, partial ACK stall, no ACK in SEND
   states, out-of-order data dropped, double ACKs (A4, A5).
3. Port only picks the hello: `"220-"` SMTP on 25 is parsed as FTP (sends `AUTH TLS`), `"220 "` SMTP on 2525 is FTP.
4. IMAP always `"* OK"` (two closes; `"* ok "` gives `"* o"`); SSH dumps every byte and re-sends the KEX blob per packet; HTTP `Server` values concatenated;
   VNC selects None; RDP labels code 5 `NLA-unsupported`; memcached never closes; telnet stops at IAC IAC.
5. `--hello-string` first-given wins per port; `--hello` echo prints one value; `--hello-string` on a TLS port keeps
   `SF__close` and `next` (4c).
6. `--hello http|ssl` skip port 65535; window 1200 and template options on every stack frame; stateless RST answers
   RST replies too.

### E4. Oracles (Р14)

- Offline parser oracle (off-repo, like `udp-oracle`): link `proto-banner1.c`, `proto-banout.c`, `smack1.c`,
  `smackqueue.c`, `proto-{http,ftp,smtp,pop3,imap4,ssh,vnc,tcp-telnet,tcp-rdp,memcached,mc}.c`, `crypto-base64.c` and
  the TLS/SMB units `banner1_create` initialises; replace `tcpapi_*` with recorders (`send <hex>`, `close`, `recv`,
  `set_timeout`, `reconnect`, `change_app_state`). Per case: `banner1_create`, a `StreamState` with `port`, then
  `banner1_parse` once with the whole stream (unsplit, the golden) and once byte by byte (documents E2); print the
  banout list in order, the action log and the final `app_proto` (the classification). Also dump
  `payloads.tcp[p]->hello` for each B4 port and the HTTP request
  after each `--http-*` combination (direct `http_change_*` calls in the C2/C3 order).
- Offline frame oracle: `tcp_create_packet` over the default template and over templates with each `--tcp-*` option
  and `--ttl`, IPv4 and IPv6, flags `0x10 0x18 0x19 0x11 0x04`, payload 0/1/1400 bytes; the E1.10 vector is pinned as a
  named difference.
- Selftest vectors usable as fixtures: `src/proto-http.c:693-920`, `src/proto-tcp-telnet.c:309-347`,
  `src/proto-tcp-rdp.c:346-361`, `src/proto-banner1.c:714-767`, `src/smack1.c:1690+`.
- Live: the Linux stand, C and rmasscan with one `--seed`, a scan address the scanner kernel does not own (Р9).

## F. Corrections to the recon notes

1. Parsers ref §1 says a parser's send emits `APP_SENDING` and moves the app to SendNext. It does not: `tcpapi_send`
   enters EST_SEND first (`src/stack-tcp-core.c:1769` ✓) and `_tcb_seg_send` notifies only outside EST_SEND (`:1397-1398`
   ✓). The app stays in ReceiveNext; the stack's `APP_SEND_SENT` on the ACK is ignored there.
2. Parsers ref §7.2 says SSH in ERROR appends the first byte of each later segment; it also appends the byte right after
   the error byte in the same segment (`continue` then `default`, `src/proto-ssh.c:95, :172-173`). Telnet INVALID alike.
3. TCP stack ref §8.2 counts the stateless RST "per distinct SYN-ACK AND per distinct RST reply": confirmed, and it is
   the only RST `--noreset` suppresses.
4. Parsers ref §6.4 says `_next_field` loops for ever on a bare-`\n` line. It does not: when it stops on a `\n` it
   returns that position, and `_field_length` there is 0, so `http_change_field` takes it as the end of the header
   and inserts there (`src/proto-http.c:226-254`, `:319-332` ✓). The other two defects it lists (`hdr[-1]`, the
   `_http_append` assignment) need a header without an empty line, which no option can produce (C3).
5. Parsers ref §7.3 and E2 here (before this fix) list FTP, SMTP and POP3 as split-invariant. They are not after a
   STARTTLS go-ahead: C continues the same segment from state 0 (`src/proto-ftp.c:101`, `src/proto-smtp.c:147`,
   `src/proto-pop3.c:129`), so on one segment the tail is a new greeting with a second `AUTH TLS` / `EHLO` / `CAPA`,
   and split at the go-ahead it goes to TLS (E2.8; oracle `*-tail` cases).
6. D2 "CR skipped" holds only inside the text (states 5 and 105, `src/proto-ftp.c:69`, `:89`); a CR where a code digit
   is due closes the connection (`:43-45`, oracle `ftp-cr-before-code`).
7. D5 / E3.4 "IMAP `* OK`, then close": C closes twice (`src/proto-imap4.c:54-55`, `:63-64`), and `"* ok "` yields
   `"* o"`: the classifier is case-insensitive, the parser's `'O'` (`:60`) is not (oracle `imap4-lowercase`).
8. B6 said "4b performs the switch but sends nothing" and omitted that C keeps parsing the rest of the segment after
   the switch; B6 now states it and the 4b rule for it (E2.8).
