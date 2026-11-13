# masscan user-mode TCP stack recon for `--banners` (upstream masscan at commit 8e6b3b0)

C is cited as `src/file.c:L` (upstream tree), Rust as `rmasscan/crates/...`. Format strings and constants are verbatim
(C escapes left as written). "Inferred" marks a conclusion drawn from code that was not executed or observed. Scope:
the TCP connection machinery under `--banners` (TCB table, timers, state machine, app glue, packet build, queueing,
`main.c` integration, options). Protocol parsers (`proto-*.c`) and banner output formats are out of scope except where
they drive the stack.

## 0. Units and enums

| Unit | Lines | Role |
|---|---|---|
| `src/stack-tcp-core.c` | 2314 | TCB table, hash, segments, `stack_incoming_tcp` state machine, `tcpapi_*` |
| `src/stack-tcp-app.c` | 219 | `application_event`: app-level state machine (hello timing, send/recv/close) |
| `src/stack-tcp-api.h` / `-core.h` / `-app.h` | 80/167/51 | API, enums, macros |
| `src/event-timeout.c/.h` | 176/132 | timer wheel, one entry embedded per TCB |
| `src/stack-queue.c/.h` | 130/48 | packet-buffer pool + RX->TX transmit ring |
| `src/stack-src.c/.h` | 23/35 | `is_my_ip` / `is_my_port` / source ranges |
| `src/misc-rstfilter.c/.h` | 194/60 | rate limiter for RSTs sent to unknown FINs |
| `src/templ-pkt.c` | 1561 | `tcp_create_packet`, `tcp_set_window`, templates |

- `TCP_What` (`src/stack-tcp-core.h:99-107`): TIMEOUT=0, SYNACK=1, RST=2, FIN=3, ACK=4, DATA=5, CLOSE=6. `TCB_result`: `TCB__okay`=0, `TCB__destroyed`=1 (:109-112).
- TCP states (`src/stack-tcp-core.c:199-211`, 4-bit field `tcpstate` :131): SYN_SENT=0 ("must be zero", it is the memset state), ESTABLISHED_SEND=1, ESTABLISHED_RECV=2, CLOSE_WAIT=3, LAST_ACK=4, FIN_WAIT1_SEND=5, FIN_WAIT1_RECV=6, FIN_WAIT2=7, CLOSING=8, TIME_WAIT=9. No LISTEN/SYN_RCVD (`//STATE_SYN_RECEIVED` commented :201). ESTABLISHED and FIN-WAIT-1 are split into SEND/RECV "half-duplex" sub-states: the stack either sends or receives, never both.
- App states (`src/stack-tcp-app.c:11-18`): App_Connect=0, App_ReceiveHello=1, App_ReceiveNext=2, App_SendFirst=3, App_SendNext=4, App_Close=5 (never used).
- App events (`src/stack-tcp-app.h:10-17`): APP_CONNECTED=0, APP_RECV_TIMEOUT=1, APP_RECV_PAYLOAD=2, APP_SENDING=3, APP_SEND_SENT=4, APP_CLOSE=5 ("FIN received").
- Send-buffer ownership `TCP__flags` (`src/stack-tcp-api.h:8-13`): `TCP__static`=0 (pointer kept), `TCP__copy` (malloc+memcpy), `TCP__adopt` (stack frees), `TCP__close_fin` (FIN marker). Parsers pass literal `0` (= static), e.g. `src/proto-smtp.c:99`.
- `DestroyReason` (`src/stack-tcp-core.c:784-792`) is passed but unused (`UNUSEDPARM(reason)` :846).
- Header macros (`src/stack-tcp-core.h:15-21`): `TCP_IS_SYNACK` = `(flags & 0x12) == 0x12`, `TCP_IS_ACK` 0x10, `TCP_IS_RST` 0x04, `TCP_IS_FIN` 0x01 (bit tests, not equality).

## 1. TCB table (`src/stack-tcp-core.c`)

### 1.1 Structures
- `struct TCP_Control_Block` (:109-166): `ip_me, ip_them` (`ipaddress`, v4 or v6), `port_me, port_them` (u16), `seqno_me` ("next seqno I will use for transmit"), `seqno_them` ("the next seqno I expect to receive"), `ackno_me`, `ackno_them`, `seqno_me_first`, `seqno_them_first` (debug baselines), `next` (hash chain), `timeout[1]` (embedded timer), `ttl` (u8), `syns_sent` (u8, never read), `mss` (u16; comment says 1460, set to 1400), bitfields `tcpstate:4, is_ipv6:1 (never set), is_small_window:1, is_their_fin:1, is_active:1, is_payload_dynamic:1 (never set)`, `app_state`, `segments` (send queue), `when_created` (`time_t`), `scripting_thread`, `stream` (protocol handler), `banout` (banner accumulator), `banner1_state`, `packet_number` (unused).
- `struct TCP_Segment` (:92-99): `seqno, buf, length, flags, is_fin, next`.
- `struct TCP_ConnectionTable` (:168-197): `entries` (bucket heads), `freed_list` (TCB pool), `count, mask`, `timeout_connection`, `timeout_hello`, `active_count`, `entropy`, `timeouts`, `pkt_template`, `stack`, `banner1`, `report_banner`, `out`, `scripting_vm`, `next_ip_port` (unused).
- One table per receive thread (= per NIC), created only when `masscan->is_banners` (`src/main.c:605-620`).

### 1.2 Creation `tcpcon_create_table` (:651-719)
- Called as `tcpcon_create_table((size_t)((masscan->max_rate/5) / masscan->nic_count), parms->stack, &parms->tmplset->pkts[Proto_TCP], output_report_banner, out, masscan->tcb.timeout, masscan->seed)` (`src/main.c:612-620`).
- `timeout_connection = connection_timeout; if 0 -> 30` ("half a minute before destroying tcb", :665-667). `masscan->tcb.timeout` is never written anywhere (only read at `src/main.c:618`), so this is always 30 at creation; `--connection-timeout` is applied afterwards (section 8.1).
- `timeout_hello = 2` (:668). `entropy = masscan->seed` (same key as SYN cookies).
- Bucket count: next power of two >= hint, clamped to `[1<<10, 1<<24]` (:673-688). Default `--rate 100` gives hint 20 -> 1024 buckets. If `malloc` fails the count is halved until it succeeds (:692-697). Buckets are chain heads, NOT a capacity: there is no limit on live TCBs (`active_count` is never checked against anything; Inferred: memory is the only bound).
- `timeouts_create(TICKS_FROM_SECS(time(0)))` (:706); `banner1_create()` (:714): per-thread `payloads.tcp[65536]` stream table + pattern matchers (`src/proto-banner1.h:40-42`).

### 1.3 Key, hash, lookup
- Key = (`ip_me`, `ip_them`, `port_me`, `port_them`) with IP version (`TCB_EQUALS` :721-740; v6 compares both 128-bit addresses).
- `tcb_hash` (:753-782) is symmetric: IPv4 `syn_cookie_ipv4(ip_me^ip_them, port_me^port_them, ip_me^ip_them, port_me^port_them, entropy)`; IPv6 XORs `hi`/`lo` and calls `syn_cookie_ipv6(x, pme^pthem, x, pme^pthem, entropy)`. Both are SipHash-2-4 keyed `{entropy, entropy}` over `unsigned data[4]` (16 bytes) resp. `uint64_t data[5]` with `data[4] = port_them<<16 | port_me` (`src/syn-cookie.c:134-171`). Bucket = `hash & mask`, separate chaining via `tcb->next`, new TCB pushed at chain head (:1013-1014).
- `tcpcon_lookup_tcb` (:1066-1101) logs `LOG(1, "tcb_hash(0x%08x) = %s %u %s %u\n", ...)` on EVERY call (:1087), i.e. every received TCP packet with `-v`.

### 1.4 Create `tcpcon_create_tcb` (:969-1060)
- If the key exists, returns the existing TCB unchanged (:998-1001).
- Pool: pop `freed_list` else `MALLOC`; `memset 0` (:1004-1010) => state SYN_SENT, app_state App_Connect.
- Init (:1019-1031): `seqno_them_first = seqno_them = ackno_me = <their seq+1>`; `seqno_me_first = seqno_me = ackno_them = <my seq>`; `when_created = global_now`; `ttl`; `mss = 1400`.
- Timer armed at `TICKS_FROM_TV(secs+1, usecs)` (:1035-1040): "A TCB must always have a timeout active."
- `stream = banner1->payloads.tcp[port_them]` unless the caller passes one (:1043-1048); NULL for unmapped ports.
- `active_count++`; a redundant `tcpcon_lookup_tcb` whose result is discarded (:1057).

### 1.5 Destroy `tcpcon_destroy_tcb` (:837-925) and table teardown
- Re-hashes to find the chain slot; if absent `LOG(1, "tcb: double free\n")` and return (:852-867).
- Always `banner_flush` first (:874-877): for each `banout` with `length && protocol`: `report_banner(out, global_now, ip_them, 6, port_them, protocol & 0x0FFFFFFF, tcb->ttl, banner, length)` (:799-830). This is the ONLY place a banner record is produced besides the app's explicit `banner_flush` on FIN (section 4).
- Frees queued segments (`copy`/`adopt` buffers) (:884-893); SMB cleanup kludge (:900-904); `timeout_unlink` (:909); scrubs `ip_them.ipv4 = ip_me.ipv4 = ~0`, ports `0xFFFF`, `is_active = 0` (:911-916); moves to `freed_list` (:921-924). No packet is sent by destroy itself.
- `tcpcon_destroy_table` (:932-961): destroys every live TCB (flushing banners, "At the end of a scan, you'll see a bunch of banners all at once", `src/stack-tcp-core.h:84-86`), then frees. No FIN/RST is sent to peers at shutdown.

### 1.6 Memory per receive thread (no limits)
- Timer wheel `slots[1024*1024]` pointers = 8 MiB (`src/event-timeout.c:67`), plus bucket array (8 B x count, max 128 MiB at `1<<24`).
- Packet-buffer pool: `BUFFER_COUNT 16384` rings, 16383 buffers of `struct PacketBuffer { size_t length; unsigned char px[2040]; }` ~32 MiB per NIC, allocated unconditionally (`src/stack-queue.c:111-124`, `src/stack-queue.h:11-14`, `src/main.c:1322`).
- Per TCB: struct incl. inline `BannerOutput` with `banner[200]` (`src/proto-banout.h:15-21`) that grows by doubling (`src/proto-banout.c:265-269`) and `StreamState` (size not measured). No cap on TCB count or banner size was found in the stack.

## 2. Timers (`src/event-timeout.c/.h`)

- Units: `TICKS_PER_SECOND 16384`; `TICKS_FROM_SECS(s) = s*16384`; `TICKS_FROM_USECS(us) = us/16384` (BUG: divides instead of scaling, so the sub-second part contributes 0..61 ticks = at most 3.7 ms); `TICKS_FROM_TV(s,us)` = sum (`src/event-timeout.h:127-130`). Net effect: every timer is effectively "at whole second S", S = packet second + delta.
- Wheel: `slots[2^20]` (64 s span), `current_index` starts at `TICKS(time(0))` (`src/event-timeout.c:72-101`). `timeouts_add` unlinks then pushes at head of `slots[ts & mask]` (:107-136). `timeouts_remove(now)` walks `current_index` tick by tick up to `now`, skipping entries whose `timestamp > now` (far-future wrap) and returns the first due entry, unlinked (:141-174). An entry added behind `current_index` is found only after a full wrap (64 s) (Inferred).
- `timeouts--;` at :169 decrements the local pointer, not `outstanding_count` (counter is never read; harmless bug).
- `timeout_is_unlinked` tests `prev == 0 || next == 0` (`src/event-timeout.h:40-46`) while `timeout_unlink` early-returns on `prev == 0 && next == 0` (:50-61): a linked TAIL entry (next == NULL, the common case in a sparse wheel) reads as "unlinked".
- Driver `tcpcon_timeouts(tcpcon, secs, usecs)` (`src/stack-tcp-core.c:283-329`): pops every due TCB, calls `stack_incoming_tcp(TIMEOUT, ..., tcb->seqno_them, tcb->ackno_them)`, and if not destroyed and `timeout_is_unlinked` re-arms at `TICKS_FROM_TV(secs+2, usecs)` ("KLUDGE ... catch-all", :314-327). Result: every live TCB ticks every ~2 s for its whole life; per-state "timers" are just the next tick. Latent (Inferred): a timer re-armed inside a TIMEOUT handler whose entry is a chain tail would be overwritten by the +2 s catch-all; no current handler re-arms there.
- Who calls it (`src/main.c`): on every received frame BEFORE any filtering, with the pcap timestamp `secs, usecs` (:795-797); on receive timeout (pcap read timeout 1000 ms, `src/rawsock.c:760`, NULL packet -> return 1 at :380-386) with `((unsigned)time(0), 0)` (:783-786). Because idle polls pass `usecs=0` and timers carry +delta ticks, on an idle link a timer due at second S fires on the poll at second S+1 (Inferred).
- Timer table (all relative to the event's packet second):

| Arm site | Value | Code |
|---|---|---|
| TCB created | +1 s | `src/stack-tcp-core.c:1036-1040` |
| App_Connect (hello wait) | +2 s, hard-coded `2 /*tcpcon->timeout_hello*/` | `src/stack-tcp-app.c:76` via `tcpapi_set_timeout` (`src/stack-tcp-core.c:1712-1729`) |
| any expiry not destroying | +2 s catch-all | `src/stack-tcp-core.c:322-327` |
| FIN_WAIT2/TIME_WAIT + FIN | +5 s | `src/stack-tcp-core.c:2249-2253` |
| connection lifetime | `when_created + timeout_connection < secs` checked only on TIMEOUT -> RST + destroy | `src/stack-tcp-core.c:1971-1981` |

- Effective hello delay after the SYN-ACK: (1, 2] s on a busy link, up to ~3 s on an idle link (Inferred from the two tick bugs above). Effective lifetime: first TIMEOUT tick after `when_created + 30` s.
- `when_created = global_now` (`src/stack-tcp-core.c:1029`). `global_now` (`src/main.c:94`) is refreshed only by `status_print` (`src/main-status.c:136`, ~every 750 ms during TX, 250 ms during wait) and by `output_report_status` (`src/output.c:755`), which runs AFTER the TCB is created (`src/main.c:978` vs `:1077`). Inferred bug: with `--nostatus` (`src/main-conf.c:2844-2845`) a TCB created after a quiet period inherits a stale `when_created` and is RST+destroyed at its first tick, before the hello.

## 3. Send, ACK and receive mechanics

### 3.1 `tcpcon_send_packet(tcpcon, tcb, flags, payload, len)` (`src/stack-tcp-core.c:1106-1171`)
- `is_syn = (flags == 0x02)`; seq field = `seqno_me - is_syn`, ack field = `seqno_them` (:1150-1158). Always via `tcp_create_packet` with the TCP template of the receive thread (section 6).
- `stack_get_packetbuffer` blocks (1 ms sleeps) until a buffer is free (`src/stack-queue.c:8-22`), so the NULL branch "packet buffers empty (should be impossible)\n" (:1127-1141) is dead; the receive thread stalls instead.
- `is_small_window` -> `tcp_set_window(px, len, 600)` (:1163-1164). Then `stack_transmit_packetbuffer` (ring enqueue, spins on full with "[-] transmit queue full (should be impossible)\n", `src/stack-queue.c:24-35`).
- The four packet kinds the stack emits: ACK `0x10`; data `0x18` (PSH|ACK), data+FIN `0x19`; first FIN `0x19` (via `_tcb_seg_send`), retransmitted pure FIN `0x11` (`_tcb_seg_resend`); RST `0x04` (no ACK flag); SYN `0x02` (reconnect only).

### 3.2 Segmentation and send queue `_tcb_seg_send` (:1337-1427)
- Chunk size = `tcb->mss` = 1400, constant; the peer's MSS option is never parsed. Remainder handled by recursion; `adopt` becomes `copy` for tails (:1350-1353, :1416-1423).
- Zero-length non-FIN send is a no-op (:1356). Appending after a queued FIN logs `LOGip(0, ..., "can't send past a FIN\n")` and drops (frees `adopt`) (:1360-1371).
- `seg->seqno` = `seqno_me` if the queue is empty, else previous seg end (:1346, :1361). FIN flag only on the last chunk (:1394-1395).
- `APP_SENDING` is notified only if `tcpstate != ESTABLISHED_SEND` (:1397-1398); `tcpapi_send` switches to ESTABLISHED_SEND before calling, so APP_SENDING is effectively never delivered (Inferred).
- ONLY the head segment is transmitted on enqueue (`if (tcb->segments == seg)`, :1406-1412), then state -> ESTABLISHED_SEND (non-FIN). Nothing transmits the next queued segment when the head is ACKed; it goes out on the next timer tick via `_tcb_seg_resend`. Consequences (Inferred): a hello > 1400 bytes advances one segment per ~2 s; a FIN queued behind the hello (`SF__close`) leaves ~2 s after the hello, not "right after".
- `_tcb_seg_resend` (:1289-1312): head only; `ERRMSG("SEQNO FAILURE diff=%d %s\n", ...)` and no send if `seqno_me != seg->seqno`; pure FIN -> `0x11`, else `0x18 | fin`.
- Window: none. One segment in flight (stop-and-wait); peer window ignored; no congestion control; retransmit interval = tick (~2 s), no backoff, unlimited until connection timeout.

### 3.3 ACK processing `_tcp_seg_acknowledge(tcb, ackno)` (:1431-1550), returns 1 = "good ack"
- `ackno == seqno_me` -> 0 (:1443). `ackno - seqno_me > 100000` (unsigned) -> "ackno from past", 0 (:1449-1457; the log prints `tcb->ackno_me`, not `seqno_me`). The following "ackno from future" test `seqno_me - ackno < 100000` (:1461-1469) is unreachable. Any ack up to `seqno_me + 100000` is accepted; it retires at most the queued bytes.
- FIN at queue head (:1472-1487): `seg->seqno+1 == ackno` -> `seqno_me += 1; ackno_them += 1`, return 1 (FIN segment stays queued, which `_tcb_they_have_acked_my_fin` later reads, :1824-1832, non-wrapping `>=`); `== seqno` -> 0; else "@@@@@BAD ACK of FIN@@@@".
- Retire loop frees whole segments, advancing `seqno_me`/`ackno_them`; returns 1 early when `ackno == ackno_them` (:1490-1523).
- Partial ack (:1525-1545), BUG: advances `seqno_me` by `length + seg->is_fin` but never advances `seg->seqno`; for `TCP__static` it advances `seg->buf` without reducing `seg->length`. Next `_tcb_seg_resend` hits "SEQNO FAILURE" and sends nothing, so the connection stalls until the lifetime RST (Inferred); the static case would also over-read the hello by `length` bytes.

### 3.4 Receive path
- Pre-filter in `stack_incoming_tcp` for any event with payload (:1920-1949): `int payload_offset = seqno_them - tcb->seqno_them`; `< 0` and fully old -> return with NO ACK; partially old -> trimmed (`assert(payload_length < 2000)`); `> 0` (gap) -> silently dropped, no ACK ("force the other side to retransmit"). No reassembly, no buffering.
- FIN pre-filter (:1955-1966): `seqno_them == tcb->seqno_them - 1` -> "duplicate FIN", send ACK, return; `!= tcb->seqno_them` -> drop.
- `_tcb_seg_recv` (:1842-1899): FIN-only special case (`len 0 && is_fin && seq == seqno_them`) sets `is_their_fin`, `seqno_them++`, `ackno_me++`, sends ACK (:1851-1857). Old data -> ACK (:1860-1864, mostly unreachable due to the pre-filter). After `is_their_fin`, payload is ignored. Otherwise `seqno_them += len`, `APP_RECV_PAYLOAD` delivered BEFORE the ACK is queued, then ACK (:1884-1896). Every data segment gets its own ACK (no delayed ACK).
- Main loop splits one frame into events in fixed order: SYNACK branch, else ACK (if flag) -> DATA (if payload) -> FIN (if FIN and not RST, seq = `seq + app_length`) -> RST (`src/main.c:970-1018`). ACK first is what lets a piggybacked response be accepted: the ACK moves ESTABLISHED_SEND to RECV before DATA is examined.
- Payload length excludes Ethernet padding (IPv4 trimmed to total length `src/proto-preprocess.c:108`, IPv6 to payload length :228-229; `app_length = length - app_offset` :158-159).

## 4. State machine `stack_incoming_tcp` (`src/stack-tcp-core.c:1909-2313`)

Before dispatch, for every state: payload/FIN filters (3.4); TIMEOUT past lifetime -> RST `0x04` (seq `seqno_me`, ack `seqno_them`) + destroy (:1971-1981); RST -> destroy, nothing sent, no sequence validation (:1983-1987). Unlisted (state, event) pairs log `ERRMSGip(ip, port, "%s:%s **** UNHANDLED EVENT ****\n", state, what)` and do nothing.

| State | Event | Action / packets | Next |
|---|---|---|---|
| SYN_SENT | TIMEOUT | `syns_sent++` (no limit), send SYN `0x02` | same |
| SYN_SENT | SYNACK | `seqno_them = seq+1`, `seqno_me = their ack`, send ACK, `APP_CONNECTED` | EST_RECV |
| EST_SEND | CLOSE | queue FIN (sent now only if queue empty) | FIN_WAIT1_SEND |
| EST_SEND | FIN (seq ok) | `_tcb_seg_recv(FIN)` (ACK) + second ACK; no APP_CLOSE | FIN_WAIT1_SEND |
| EST_SEND | ACK | ack; if queue empty or head len 0: `APP_SEND_SENT` | EST_RECV |
| EST_SEND | TIMEOUT | resend head | same |
| EST_SEND | DATA / SYNACK | ignored, no ACK | same |
| EST_RECV | CLOSE | queue FIN (head -> sent `0x19` now) | FIN_WAIT1_RECV |
| EST_RECV | FIN (seq ok) | `_tcb_seg_recv(FIN)` (one ACK), `APP_CLOSE` | CLOSE_WAIT |
| EST_RECV | ACK | ack only | same |
| EST_RECV | TIMEOUT | `APP_RECV_TIMEOUT` | same |
| EST_RECV | DATA | `_tcb_seg_recv` (deliver, ACK) | same |
| EST_RECV | SYNACK | ignored (late SYN-ACK, :2115-2120) | same |
| FIN_WAIT1_SEND | FIN | ignored, no ACK | same |
| FIN_WAIT1_SEND | ACK | if good ack and queue empty/head len 0: `APP_SEND_SENT` | FIN_WAIT1_RECV |
| FIN_WAIT1_SEND | TIMEOUT | resend head (data or FIN) | same |
| FIN_WAIT1_SEND | DATA | ignored | same |
| FIN_WAIT1_RECV | FIN | `_tcb_seg_recv(FIN)` (ACK) + second ACK, `APP_CLOSE` | CLOSING |
| FIN_WAIT1_RECV | ACK | if good ack and my FIN acked: `APP_CLOSE` | FIN_WAIT2 |
| FIN_WAIT1_RECV | TIMEOUT | resend head (pure FIN `0x11`) | same |
| FIN_WAIT1_RECV | DATA | `_tcb_seg_recv` | same |
| CLOSING | TIMEOUT | destroy (no packet) | - |
| CLOSING | ACK | if my FIN acked: destroy | - |
| CLOSING | FIN | ACK | same |
| CLOSING | CLOSE | silent (app double close, :2216-2222) | same |
| FIN_WAIT2 | TIMEOUT | nothing (ends by lifetime RST) | same |
| FIN_WAIT2/TIME_WAIT | FIN | `_tcb_seg_recv(FIN)` (ACK), timer +5 s | TIME_WAIT |
| FIN_WAIT2/TIME_WAIT | ACK/SYNACK/RST/DATA/CLOSE | ignored (DATA not ACKed) | same |
| TIME_WAIT | TIMEOUT | destroy | - |
| CLOSE_WAIT | CLOSE | queue FIN (head -> `0x19`) | LAST_ACK |
| CLOSE_WAIT | TIMEOUT | `APP_CLOSE` again ("Remind the app") | same |
| LAST_ACK | TIMEOUT | resend head (FIN `0x11`) | same |
| LAST_ACK | ACK | if good ack: destroy | - |

Notes: duplicate ACKs on EST_SEND+FIN (:2045-2047) and FIN_WAIT1_RECV+FIN (:2172-2174 with :1855). EST_SEND+FIN never queues our FIN, so such connections end by the lifetime RST (Inferred). In CLOSE_WAIT any ACK/DATA logs UNHANDLED. `ERRMSG`/`ERRMSGip` print each distinct format string once per run (dedup by format pointer hash, `src/util-errormsg.c:40-62`, :64-85).

## 5. App layer (`src/stack-tcp-app.c`) and `tcpapi_*`

- `application_notify` builds `stack_handle_t {tcpcon, tcb, secs, usecs}` and calls `application_event(socket, tcb->app_state, event, tcb->stream, banner1, payload, len)` (`src/stack-tcp-core.c:1316-1332`). Re-entrant: the app calls `tcpapi_*` which re-enter `stack_incoming_tcp` synchronously (`tcpapi_close` -> `TCP_WHAT_CLOSE`, :1696-1708).
- `application_event` (:42-218):
  - App_Connect + APP_CONNECTED: if `stream && stream->next` -> `tcpapi_reconnect(socket, stream->next, App_Connect)`; if `stream->flags & SF__nowait_hello` -> App_SendFirst now (no stream in the tree sets it; only defined `src/proto-banner1.h:269`); else `tcpapi_set_timeout(socket, 2, 0)`, `tcpapi_recv`, -> App_ReceiveHello (:54-87).
  - App_ReceiveHello: RECV_TIMEOUT -> App_SendFirst if `stream` (NULL stream stays here forever); RECV_PAYLOAD -> App_ReceiveNext and re-dispatch (server spoke first); CLOSE -> `banner_flush` + `tcpapi_close` (:88-115).
  - App_ReceiveNext: RECV_PAYLOAD -> `banner_parse` (`banner1_parse` into `tcb->banout`, `src/stack-tcp-core.c:1576-1595`); CLOSE -> `banner_flush` + `tcpapi_close`; RECV_TIMEOUT, SEND_SENT -> nothing; SENDING -> App_SendNext (:117-152).
  - App_SendFirst (entered internally): `stream == &banner_ssl || &banner_ssl_12` -> `banner_set_sslhello`; heartbleed -> `banner_set_small_window` (window 600); `stream->transmit_hello` (only `banner_scripting`, `src/scripting-banner.c:166-173`) or `tcpapi_send(hello, hello_length, TCP__static)` and, if `SF__close`, `tcpapi_close`; -> App_SendNext (:154-195).
  - App_SendNext: SEND_SENT -> `tcpapi_recv`, App_ReceiveNext; SENDING -> nothing; anything else logs `ERRMSG("TCP.app: unhandled event: state=%s event=%s\n", ...)` and the payload is NOT parsed (the stack still ACKs it) (:196-211).
- `tcpapi_send` (:1757-1778): EST_RECV -> EST_SEND then `_tcb_seg_send`; EST_SEND -> `_tcb_seg_send`; other states `LOG(1, "TCP app attempted SEND in wrong state\n")`, return 1. `tcpapi_recv` (:1734-1755): EST_SEND and any unlisted state -> EST_RECV; FIN_WAIT1_SEND -> FIN_WAIT1_RECV. `tcpapi_close` -> `TCP_WHAT_CLOSE` event. `tcpapi_set_timeout` re-arms the single TCB timer at `socket->secs + secs` (dereferences `socket` before its NULL check, :1717-1721). `tcpapi_change_app_state` sets `app_state`.
- Stream flags (`src/proto-banner1.h:268-269`): `SF__close = 0x01` ("send FIN after the static Hello is sent"), `SF__nowait_hello = 0x02`. Only `banner_ssl` sets `SF__close` and only it has `next = &banner_ssl_12` (`src/proto-ssl.c:1435-1450`). Port -> stream map is fixed in `banner1_create` (`src/proto-banner1.c:522-570`; e.g. 80/8080 http, 443/465/990-995/8443 ssl, 139/445 smb); unmapped ports (22, 21, 25, ...) get `stream = NULL` and rely on server-first data plus pattern detection. Default HTTP hello starts `"GET / HTTP/1.0\r\n"` (`src/proto-http.c:387-395`, stream :946-951).
- Reconnect `_do_reconnect` (:1645-1694): new source via `_next_IP_port` (:1602-1641: `port_me+1`, wrap to `port.first` when `>= port.last`, so `port.last` is never used; on wrap also next source IP; IPv6 branch commented "TODO: this code is untested, yolo"); if unchanged `ERRMSG("There must be multiple source ports/addresses for reconnection\n")`; ISN `syn_cookie(ip_them, port_them, ip_me, port_me_new, entropy)`; `tcpcon_create_tcb(..., seqno+1, 0, 255, stream, ...)` then `new_tcb->app_state = established`. The SYN is not sent immediately: the new TCB's +1 s tick in SYN_SENT sends it, then every tick until the lifetime RST. If the new key collides with a live TCB (single source port, or wrap), `create` returns that TCB and its `app_state` is overwritten. TTL of the reconnect TCB stays 255 because the later SYN-ACK finds an existing TCB and skips `create` (`src/main.c:977-985`).
- Worked timelines (Inferred from the tables above): HTTP/80: SYN-ACK -> ACK queued, "open" status record -> ~2 s -> `GET` (`0x18`) -> peer ACK+data -> parse, ACK per segment -> peer FIN -> ACK, `banner_flush` (record), our FIN `0x19` -> peer ACK -> destroy. Server-first on an unmapped port (SSH): banner parsed on arrival, but the record appears only at peer FIN, the lifetime RST (~30 s) or end-of-scan teardown. SSL/443: as HTTP plus a parallel reconnect (TLS 1.2 hello) on another source port; our FIN leaves on the tick after the hello ACK; on ACK-of-FIN the TCB enters FIN_WAIT2 and the app flushes the banner; later DATA in FIN_WAIT2 is ignored.

## 6. Packet construction (`src/templ-pkt.c`)

- TCP template (`default_tcp_template`, :30-54): Ethernet `0800`, IPv4 `45 00`, total length `0x002c`, ID 0, frag 0, TTL `0xFF`, proto 6; TCP data offset `0x60` (24 bytes), flags `0x02`, window bytes `"\x04\x01"` (= 1025; comment says "window fixed to 1024"), urgent 0, option `"\x02\x04\x05\xb4"` (MSS 1460). `--tcp-mss/--tcp-wscale/--tcp-tsecho/--tcp-sackok` are applied to this buffer before `_template_init` (:1400-1411), so the same option bytes are copied into EVERY stack packet (pure ACKs, data, FIN, RST, reconnect SYN). Inferred interactions: with `--tcp-wscale` the fixed advertised window 1200 is scaled by the peer; with `--tcp-tsecho` a constant TSval rides on every packet.
- `tcp_create_packet(tmpl, ip_them, port_them, ip_me, port_me, seqno, ackno, flags, payload, len, px, px_len)` (:419-613; prototype `src/templ-pkt.h:174-182`). IPv4 (:431-514):
  - Copy the whole template (incl. link header and TCP options); payload at `offset_tcp + ((pkt[offset_tcp+12]&0xF0)>>2)`; `"tcp: err generating packet: too much payload\n"` and length 0 if it does not fit (:440-443).
  - IP total length = header + TCP header + payload; IP ID = `(ip_them ^ port_them ^ seqno) & 0xFFFF` (:432, :455-456); src/dst addresses; TTL, TOS, DF bits from template (TTL from `--ttl` via `template_set_ttl`, IPv4 only, `src/main.c:1328-1329`, :1474-1488).
  - IP checksum incremental from the template partial sum (computed with ID/csum/addresses zeroed, :1290-1295): `xsum = checksum_ip + (ip_id & 0xFFFF) + ip_me + ip_them + (ip_len - old_len)`, folded TWICE, inverted (:466-476). BUG: two folds of a sum that can exceed 2^33 do not always reach 16 bits. A scratch recomputation over 2,000,000 random (ip_me, ip_them, port_them, seqno) tuples on the default template found 19 wrong headers, e.g. `ip_me=0xd5a30aac ip_them=0x4ba3e552 port_them=55289 seqno=0x3e8f982c`: C writes `0xffff`, correct is `0xfffe` (Inferred: such packets are dropped by the peer; the SYN path recomputes the header sum fully, `src/templ-pkt.c:988`, and is unaffected).
  - TCP: ports, seq, ack, flags byte (`px[offset_tcp+13] = flags`, overwriting all bits), window forced to `1200` (`0x04B0`) (:497-498), checksum recomputed fully over pseudo-header + header + options + payload (`tcp_checksum2`, :210-236, odd length handled).
  - Zero padding to 60 bytes if shorter (:510-513), on every link type (Inferred: 16 trailing zeros on DLT_RAW, 12 on DLT_NULL). Default pure ACK on Ethernet = 58 -> 60 bytes.
- IPv6 (:515-611): copy template up to `offset_app`; payload length field; addresses; same TCP field writes, window 1200; checksum `checksum_ipv6` (folded and inverted, `src/util-checksum.c:118-153`); no padding; hop limit 0xFF always (template, :1199), traffic class/flow label 0; VLAN tag never added (`template_set_vlan` IPv4 only, :1491-1518).
- `tcp_set_window(px, len, window)` (:373-415): re-parses the frame with link type hard-coded `1 /*enet*/`, writes the window, recomputes the TCP checksum. Inferred: a no-op on raw/null links.
- RST helpers: `tcp_send_RST(templ, stack, ip_them, ip_me, port_them, port_me, seqno_them, seqno_me)` (`src/stack-tcp-core.c:1175-1219`) builds `seq = seqno_me, ack = seqno_them, flags 0x04`; the non-banners call passes `seqno_them = 0, seqno_me = <their ack>` (`src/main.c:1095-1100`). `tcpcon_send_RST` (:1260-1282) on a stack temporary TCB: `seq = <their ack>`, `ack = <their seq>+1`, flags `0x04`.

## 7. Queueing and transmit (`src/stack-queue.c`, `src/main.c` transmit_thread)

- `stack_t { packet_buffers, transmit_queue, source_mac, src }` (`src/stack-queue.h:16-21`), one per NIC, created for every scan (`src/main.c:1322`). Both rings SP/SC, 16384 slots, 16383 buffers (`src/stack-queue.c:98-127`). Producer = receive thread (TCP stack, RSTs, ARP and NDP replies), consumer = transmit thread.
- Priority: every throttle batch first drains stack packets, then sends SYNs with what is left (`src/main.c:289-299`, comment "This takes priority over sending SYN packets"). `stack_flush_packets` sends with `rawsock_send_packet(adapter, px, len, 1)` and counts each in `packets_sent`, so stack packets consume the `--rate` budget (`src/stack-queue.c:46-96`). Inferred: at the default `--rate 100` the stack (ACK + hello + per-segment ACKs + FIN per connection) and the SYNs share 100 pps, and a full pool stalls the receive thread (blocking `stack_get_packetbuffer`), which then misses frames.
- After the last SYN the transmit thread loops `while (!is_rx_done)` flushing stack packets under the throttle every 100 us (`src/main.c:470-494`); the stack keeps talking during `--wait`.
- Transmit thread sleeps 1 s at start "to make sure receive_thread is ready" (`src/main.c:231`).

## 8. Receive-thread integration (`src/main.c:532-1123`)

### 8.1 Setup when `is_banners` (`src/main.c:605-736`)
Create table; `scripting_init_tcp`; `tcpcon_set_banner_flags` (capture cert/servername/html/heartbleed/ticketbleed); `--hello` smbv1/http/ssl, heartbleed, ticketbleed, sslv3 via `tcpcon_set_parameter`; `--http-*` fields; `if (masscan->tcp_connection_timeout)` -> `tcpcon_set_parameter("timeout", "%u")` (`timeout_connection = n`, `LOG(1, "TCP connection-timeout = %u\n", ...)`, `src/stack-tcp-core.c:484-489`); `if (masscan->tcp_hello_timeout)` -> `"hello-timeout"` (stores `timeout_hello`, never read: `--hello-timeout` has NO effect in this commit, `src/stack-tcp-app.c:76`); per-port `"hello-string[%u]"` (base64-decoded copy of the port's stream incl. its `flags` and `next`, `src/stack-tcp-core.c:595-616`). `tcpcon_set_parameter`/`tcpcon_set_http_header` mutate the globals `banner_http`/`banner_ssl` (:383-389, :405-482, :537-588) once per receive thread (Inferred: with several NICs, edits are applied once per NIC and race). `--hello ssl|http` loops `i < 65535`, leaving port 65535 unmapped (:505, :519).

### 8.2 Per-frame order
1. `tcpcon_timeouts` (section 2); drop `length > 1514`; `preprocess_frame`; `seqno_them = TCP_SEQNO`, `seqno_me = TCP_ACKNO` (`src/main.c:795-815`).
2. `cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy) & 0xFFFFFFFF` (:820-826); `is_my_ip` (:829); non-TCP handled and `continue`; `is_my_port` (:935); `--pcap` write (:943-951).
3. Banners block, only if `tcpcon` (:962-1043): lookup; SYN-ACK: bad cookie (`cookie != seqno_me - 1`) -> `LOG(2, "%s - bad cookie: ackno=0x%08x expected=0x%08x\n", ...)` and `continue` (also skips status); no TCB -> `tcpcon_create_tcb(ip_me, ip_them, port_me, port_them, seqno_me, seqno_them+1, parsed.ip_ttl, NULL, secs, usecs)` and `(*status_tcb_count)++`; then `stack_incoming_tcp(SYNACK, ..., seqno_them+1, seqno_me)`. Non-SYN-ACK with TCB: ACK/DATA/FIN/RST events as in 3.4, with NO cookie check and the `TCB__destroyed` result ignored between events (`Q +=`, never read). Inferred bug: if ACK destroys the TCB (LAST_ACK/CLOSING) and the same frame carries a FIN, the duplicate-FIN path sends an ACK from the scrubbed TCB, i.e. to/from 255.255.255.255:65535 (IPv4). Non-SYN-ACK without TCB carrying FIN (not RST): `rstfilter_is_filter` then `tcpcon_send_RST` (:1019-1041); RST is sent regardless of `--noreset`.
4. Status block for SYN-ACK or RST, banners on or off (:1048-1102): status Open (SYN-ACK) / Closed (RST wins); cookie re-check; `dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me)`; `(*status_synack_count)++`; `output_report_status(out, global_now, status, ip_them, 6, port_them, flags, parsed.ip_ttl, mac_src)`. So `--banners` still emits the ordinary "open" record immediately at the first SYN-ACK, after the stack has queued its ACK. Banner records come later from `banner_flush`.
5. `if (tcpcon == NULL && !masscan->is_noreset) tcp_send_RST(...)` (:1094-1100): without `--banners` one RST per distinct SYN-ACK AND per distinct RST reply (the block is entered for both). With `--banners` this RST is never sent; the stack's own RSTs (lifetime, FIN-without-TCB) ignore `--noreset`.
- Dedup key includes `port_me` (`src/main-dedup.c:206-207`, IPv4 hash :243). Inferred: a reconnect SYN-ACK (different `port_me`) yields a second "open" record for the same ip:port.
- Mid-connection RSTs normally carry an ack != cookie+1 and produce no Closed record; a RST right after the handshake (ack == cookie+1) is a dedup duplicate of the SYN-ACK (Inferred).

### 8.3 End of scan and `--wait`
- Main thread: `is_tx_done = 1` when the minimum transmit index reaches `range` (`src/main.c:1425-1428`); `now = time(0)`; `is_rx_done = 1` once `time(0) - now >= masscan->wait` (default `wait = 10`, `src/main.c:1598`; `--wait forever` = `INT_MAX`, `src/main-conf.c:3028-3032`); forced `exit(0)` with "[-] Passed the wait window but still running, forcing exit...\n" after `wait + 10` s (:1459-1497).
- Receive thread leaves its loop, `tcpcon_destroy_table` flushes every live TCB's banner (partial banners included), no FIN/RST sent (:1111-1113). TCBs created in the last `wait` seconds get only that long; `--wait` (10) < lifetime (30) means connections alive at the end are cut, not timed out.
- Ctrl-C: first press sets `is_tx_done`; second sets `is_rx_done` (:1131-1154). `--offline`: receive thread never loops, table unused (:742-747).
- Status line shows TCB counts only in `--infinite` mode: `"rate:%6.2f-kpps, syn/s=%.0f ack/s=%.0f tcb-rate=%.0f, %" PRIu64 "-tcbs,         \r"` (`src/main-status.c:214`); `found=` counts deduped SYN-ACKs.

### 8.4 RST filter (`src/misc-rstfilter.c`)
- Used only for the FIN-without-TCB RST (`src/main.c:553`, :1033). `rstfilter_create(entropy=seed, 16384)`: power-of-two buckets, 4-bit counters, two per byte (`calloc(count/2)`, :37-49).
- `rstfilter_is_filter` (:61-133): SipHash-2-4 over `uint64_t input[5]` keyed `{seed, seed}`; IPv4 fills `input[0..3] = src_ip, src_port, dst_ip, dst_port` and leaves `input[4]` UNINITIALIZED (hashed anyway, so bucket choice is nondeterministic); IPv6 fills `hi, lo, hi, lo, src_port<<16 | dst_port`. Counter at 15 -> filter (return 1), else increment and pass. Then drains one pseudo-random bucket: `input[0] = (unsigned)hash; input[1] = counter++` re-hashed, decrement if non-zero. Selftest: first 15 calls pass, then passes must be > 0 and <= filtered/10 (:137-187).

### 8.5 Source address, kernel RSTs, IPv6
- No code checks or warns about the host kernel. The README states the problem ("When the local system receives a SYN-ACK from the probed target, it responds with a RST packet that kills the connection", `README.md:105-108`) and two remedies: a separate, unused source IP on the subnet (`README.md:110-118`, claims "Masscan will warn you"; no such warning was found in `src/main-initadapter.c`), or firewall the source port(s) (`iptables -A INPUT -p tcp --dport 61000 -j DROP`, `README.md:126-127`; pf range `40000:40015`, :155); "Windows doesn't respond with RST packets" (:166).
- Default source ports when not given: `port = 40000 + now % 20000; first = port; last = port + 16; range = 16` (`src/main.c:1315-1320`). Transmit uses `port_mask = last - first` = 16 (`src/main.c:186`, :383), so SYNs use only `p` and `p+16`; reconnects walk `p+1..p+15`. The user cannot predict these ports for a firewall rule, so `--source-port` is effectively required with `--banners` on Linux/macOS (Inferred).
- `--adapter-port`/`--source-port`/`--src-port`/`-g`: one range, size power of two, else `exit(1)` (`src/main-conf.c:2523-2556`, `sourceport` alias :2979-2980, `-g` :3360-3365); echoed as `adapter-port = %d[-%d]` (:3666-3674).
- IPv6: the stack code paths support v6 (hash, equality, `tcp_create_packet` v6 branch, rstfilter v6, `syn_cookie` dispatch), and the README shows an IPv6 `--banners` example (`README.md:114`), so `--banners` over IPv6 is wired in this commit (not run here). Caveats: IPv6 SYNs always use `src.port` = `port.first` (`src/main.c:345-346`); `is_my_ip` v6 matches only `ipv6.first` (`src/stack-src.c:13-14`); `parsed.ip_ttl` is never set for IPv6 (`src/proto-preprocess.c:127` is IPv4 only; `parsed` is not zeroed, `src/main.c:762`), so `tcb->ttl` and the status TTL of IPv6 replies are indeterminate (Inferred); reconnect v6 untested by upstream.

## 9. Options touching the stack (`src/main-conf.c`)

| Option (aliases) | Field, default | Parse | Echo |
|---|---|---|---|
| `banners` (`banner`), F_BOOL | `is_banners`, 0 | `parseBoolean`; bare flag = true (singleton via F_BOOL, :3065-3103, :3287-3291) (:1106-1116) | `banners = %s` if set or echo-all |
| `nobanners` (`nobanner`), F_BOOL | `is_banners = !value` | (:1546-1554) | none |
| `rawudp`, F_BOOL | `is_banners_rawudp`; true also sets `is_banners` | (:1118-1129) | `rawudp = %s` |
| `noreset`, F_BOOL | `is_noreset`, 0; only gates the non-banners RST | (:1556-1565) | `noreset = %s` |
| `connection-timeout` (`tcp-timeout`) | `tcp_connection_timeout`, 0 -> stack default 30 | old-style `parseInt` (digits until first non-digit, :576-585) (:2765-2767) | none (not echoed) |
| `hello-timeout` | `tcp_hello_timeout`, 0 | `parseInt` (:1288-1298) | `hello-timeout = %u` if non-zero; has no runtime effect |
| `hello` = `ssl`/`smbv1`/`http` | `is_hello_*` | else `"FAIL: %s: unknown hello type\n"` (:1181-1205) | `hello = ...` |
| `hello-string[PORT]` | list of base64 payloads | `ARRAY(name)`, index >= 65536 -> exit (:1256-1286) | `hello-string[%u] = %s` |
| `hello-file[PORT]` (`hello-filename`) | reads <= 16384 bytes, base64 -> `hello-string[PORT]` (:1207-1254) | | none |
| `capture`/`nocapture` (`no-capture`) cert, servername, html, heartbleed, ticketbleed | `is_capture_cert = 1` default (`src/main.c:1610`) | (:1131-1179) | `%scapture = ...` |
| `heartbleed`, `ticketbleed`, `vuln poodle`/`sslv3` | force `banners true` | (:2810-2819, :2936-2939) | |
| `debug-tcp` (`tcp-debug`), F_BOOL | global `is_tcp_debug` | (:2348-2358) | none |
| `wait` | `wait`, 10 | `forever` or int (:3028-3032) | |
| `tcp-mss`/`tcp-wscale`/`tcp-tsecho`/`tcp-sackok` | template options (MSS 1460 default) | (:2141-2345) | `tcp-mss = ...` etc. |
| `source-port`, `-g` | see section 8.5 | | `adapter-port = ` |

- Help text: "--banners: get the banners of the listening service if available. The\n    default timeout for waiting to receive data is 30 seconds.\n" and "--connection-timeout <number>: time in seconds a TCP connection will\n    timeout while waiting for banner data from a port.\n" (:199-200, :206-207). No `--max-connections`/TCB limit option exists. `--readscan` also sets `is_banners` (:3271) but builds no stack.
- `--debug-tcp` trace prefix: `"[%s:%u %4u,%4u] %s:%5u [%4u,%4u] {%s} "` (`src/stack-tcp-core.c:246-255`): them:port, their rel seq/ack, direction `-->`/`<--`, my port, my rel seq/ack, state name (strings :217-238). Useful for side-by-side traces with C.

## 10. Port surface

### 10.1 Minimal C units for a Rust stack
Timer wheel or any per-TCB single re-armable deadline (section 2); TCB table, `stack_incoming_tcp`, segments (sections 1, 3, 4); app glue (section 5); `tcp_create_packet` + `tcp_set_window` (section 6); RX->TX queue with priority and throttle accounting (section 7); receive integration and teardown (section 8); rstfilter (8.4). Already ported in rmasscan: SipHash SYN cookie, TCP/TCP6 SYN templates with options, checksum helpers, dedup, `preprocess` equivalents. Dependency outside this note: banner layer (`banout`, `banner1_parse`, at least one parser, `output_report_banner` formats); without it the stack produces nothing visible.

### 10.2 C bugs and ambiguities a spec must decide on (replicate or fix)
1. `--hello-timeout` is dead; hello wait is hard-coded 2 s (`src/stack-tcp-app.c:76`).
2. Timer resolution is whole seconds (`TICKS_FROM_USECS`, `src/event-timeout.h:129`); idle polls use `usecs=0` (`src/main.c:785`). Hello fires (1,2] s busy / up to ~3 s idle (Inferred).
3. Every TCB ticks every ~2 s (catch-all, `src/stack-tcp-core.c:322-327`); retransmit = tick, no backoff, no retry cap except lifetime.
4. Only the queue head is transmitted; queued segments and queued FINs wait for the next tick (`src/stack-tcp-core.c:1406`).
5. Partial-ACK handling corrupts the queue and stalls the connection (`src/stack-tcp-core.c:1525-1545` vs :1294-1297).
6. Dead "ackno from future" check (:1461); no snd_nxt bound.
7. No re-ACK of fully-old retransmitted data, no ACK of data in SEND states, out-of-order data dropped silently (:1931-1947, :2071-2076, :2160-2162).
8. EST_SEND+FIN -> FIN_WAIT1_SEND, no APP_CLOSE, our FIN never queued (:2042-2047); double ACKs (:2045-2047, :2172-2174).
9. `TCB__destroyed` ignored between ACK/DATA/FIN/RST of one frame (`src/main.c:991-1018`).
10. Stale `when_created` under `--nostatus` (section 2).
11. IPv4 header checksum two-fold bug (`src/templ-pkt.c:466-473`), ~1e-5 of stack packets.
12. Uninitialized `input[4]` in rstfilter (`src/misc-rstfilter.c:67-82`).
13. IPv6 TTL indeterminate; reconnect TCB TTL 255 (sections 8.5, 5).
14. Reconnect: second "open" record (dedup keyed by `port_me`), single-port ERRMSG and TCB clobbering, `port.last` unused (sections 5, 8.2).
15. Default source range `{p, p+16}` with mask 16 (section 8.5); rmasscan deliberately uses one port (`rmasscan/crates/rmasscan-cli/src/live.rs:421-425`), which disables C's reconnect path unless a range is given.
16. RST to RST replies in non-banners mode; stack RSTs ignore `--noreset` (section 8.2).
17. All template TCP options repeated on non-SYN packets; fixed window 1200 vs SYN window 1025 (section 6).
18. Global mutable hello buffers per receive thread; `--hello` loops miss port 65535; `hello-string` inherits `SF__close`/`next` (section 8.1).
19. Blocking packet-buffer pool (`src/stack-queue.c:14-20`): receive thread stalls when the throttled transmit side lags.
20. No sequence validation for RST/ACK (any matching 4-tuple RST kills a TCB) (:1983-1987).

### 10.3 Testable offline vs needs a live peer
- Pure / deterministic given an injected clock: `tcb_hash` and key equality; `tcp_create_packet` bytes for IPv4/IPv6/Raw/Null (golden vectors from a C harness, as done for the SYN template); the checksum fold quirk (vector in section 6); `tcp_set_window`; rstfilter with a fixed seed (C itself is nondeterministic, so only properties: 15 passes then mostly filtered); timer wheel; `_tcb_seg_send`/`_tcp_seg_acknowledge`/`_tcb_seg_recv` on a constructed TCB; every row of the section 4 table; the app state machine with a stub parser; default-port and `_next_IP_port` arithmetic; option parsing/echo.
- Engine-level offline: a scripted TCP peer behind the fake adapter with a manual clock (handshake, hello timing, ticks, FIN flows, lifetime RST, end-of-wait flush, queue priority/backpressure). Inferred C oracle offline: C accepts a pcap file as adapter with file timestamps driving the stack and EOF ending the scan (`src/rawsock.c:380-391`, `doc/howto-afl.md:95` uses `--adapter file:data/afl-http.pcap ... --banners`); not tried here.
- Needs a live peer: kernel RST interference and the firewall/source-IP recipes per OS; real stacks (delayed ACK, coalescing, retransmission, peer reactions to window 1200 with wscale/tsecho); pcap timestamp behaviour; IPv6 with NDP; throughput under `--rate`; C-vs-Rust parity on the wire.

## 11. Rust side today (brief)

- SYN-ACK/RST handling: `rmasscan/crates/rmasscan-core/src/receive.rs` `parse_reply` (:184) -> `parse_ipv4_tcp` (:311) / `parse_ipv6_tcp` (:473); status chosen from flags (:404-415, :553-563); any TCP frame that is neither SYN-ACK nor RST returns `Ok(None)` and is counted as discarded. `Reply` (:140-159) carries 4-tuple, status, flags, TTL, but no seq/ack/payload, so a stack needs a separate TCP segment view from the same parse. Unlike C, it also requires the remote to be in the effective target set (module doc :33-37).
- `rmasscan/crates/rmasscan-engine/src/engine.rs` `run_rx` (:840): `parse_reply` -> `DedupCache::insert` -> `queue.push_result` (:896-911). A C-like stack call site is right after parse and before/independent of dedup (C runs the stack before status/dedup, `src/main.c:962-1043` vs :1048-1102). RX loop iterations are bounded by `MAX_IO_TIMEOUT` 50 ms (:39), a natural place to drive timers from the engine `Clock` instead of pcap timestamps.
- RX->TX path: the NDP queue `ndp_out` (:366-371, cap `NDP_OUT_CAP = 64` :596) flushed by `flush_ndp` (:606-619) at the top of the TX loop (:660-667) and during linger until RX ends (:805-819) is the same pattern as `stack_transmit_packetbuffer`; it is unthrottled and drop-on-full, whereas C counts stack packets against `--rate`, sends them before SYNs, and blocks the producer.
- No RST is sent by rmasscan today (lab notes: `rmasscan/crates/rmasscan-lab/src/ipv6_verify.rs:825`, `protocols_verify.rs:915`); `noreset` is parsed only (`rmasscan/crates/rmasscan-core/src/config.rs:169`). A stage-4 TX path for stack packets could also carry C's non-banners RST.
- Packet building sits next to `TcpSynTemplate::build_syn` / `Tcp6SynTemplate` (`rmasscan/crates/rmasscan-core/src/packet.rs:124`, :216, :302), which already own the option bytes C repeats on stack packets.
- End of scan: RX `wait` deadline (`engine.rs:931-935`) is where C would destroy the table and flush banners; `Event` (`rmasscan/crates/rmasscan-engine/src/events.rs:79-95`) has no banner variant.
- Offline harness: `FakeAdapter::set_responder` (`rmasscan/crates/rmasscan-engine/src/fake.rs:245`) returns frames per sent frame (a scripted peer) and `ManualClock` (`fake.rs:23`) makes timers deterministic.
- CLI: `--banners` is rejected by clap (`rmasscan/crates/rmasscan-cli/src/args.rs:6`, test `lib.rs:522`) and `banners` is an unknown config key (`config.rs:2341`). `NicBinding.legacy_c_17_port_mask` already models the C `{p, p+16}` range (`rmasscan/crates/rmasscan-core/src/probe.rs:153-170`).
