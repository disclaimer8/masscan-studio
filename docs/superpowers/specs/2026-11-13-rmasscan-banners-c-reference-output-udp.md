# masscan banner records (output, `--readscan`) and UDP banner parsers: C reference (upstream masscan at commit 8e6b3b0)

Companion to `2026-11-06-rmasscan-output-formats-c-reference.md` (status records; its "Banner: ... later" lines are
expanded here). C is cited `src/file.c:LINE`, Rust `rmasscan/crates/...`. Format strings are verbatim (C escapes
unexpanded). "Inferred" = not read directly or not run. Nothing was executed for this note: source reading only.
MASSCAN_VERSION "1.3.9-integration". TCP banner *generation* (banner1, SSL, HTTP, ...) is out of scope; only its
hand-off to output is described (A0).

## A. Banner records in output

### A0. Who calls `output_report_banner`, and with what

Signature (`src/output.c:885-890`): `output_report_banner(out, time_t now, ipaddress ip, unsigned ip_proto, unsigned
port, unsigned proto /* enum ApplicationProtocol */, unsigned ttl, const unsigned char *px, unsigned length)`.

| caller | `now` | `ip_proto` | `ttl` | payload |
| --- | --- | --- | --- | --- |
| TCP `banner_flush` (`src/stack-tcp-core.c:798-829`), callback registered at `src/main.c:612-620` only when `is_banners` (`src/main.c:605`) | `global_now` (stale clock, status note §5) | 6 | `tcb->ttl` | every banout node with `length && protocol`; app = `protocol & 0x0FFFFFFF` (drops the `banout_end` flag 0x80000000, `src/proto-banout.c:163-171`). Empty TCP banners are never emitted. |
| UDP parsers (part B) | `secs`, the capture timestamp of the packet from `rawsock_recv_packet` (`src/main.c:777-782`, passed at `src/main.c:915`); NOT `global_now`. The UDP status record gets the same `secs`. | 17 | `parsed->ip_ttl` = IPv4 TTL (`src/proto-preprocess.c:127`, the only assignment: for IPv6 replies it is stale or uninitialised, Inferred from grep) | parser text; may be empty (`length` 0, `px` may be NULL) |
| `--readscan` (`src/in-binary.c:320,359,399,457`) | record timestamp | record byte (type 3: forced 6) | record byte (types 3/4/5: 0) | record payload |

No other callers (grep). SCTP, ICMP, ARP and other-IP-proto replies only emit status records (`src/proto-sctp.c:160,172`,
`src/proto-icmp.c:134-206`, `src/proto-arp.c:30`).

### A1. `output_report_banner` control flow (`src/output.c:886-956`)

1. `fp = out->fp; fmt = ipaddress_fmt(ip);`
2. `if (!out->is_banner) return;` (L898-899). `out->is_banner = masscan->is_banners` (L410), `is_banner_rawudp` (L411).
   Set by `--banners`/`--banner` (`SET_banners`, `src/main-conf.c:1106-1116`, table L2377), `--rawudp` (sets rawudp AND
   banners, L1118-1130, L2378), `--readscan` (forces `is_banners = is_banners_rawudp = true`, L3266-3272),
   `--heartbleed`, `--ticketbleed`, `--vuln poodle|sslv3` (L2810-2819, L2936-2939); cleared by `--nobanners`/`--nobanner`
   (L1546-1554, L2379). Comment L895-897: UDP parsers always run, this flag alone hides their banners.
3. No show filter (`is_show_open/closed` not consulted; contrast status L759-762): `--noshow open` still prints banners.
4. No counters: `out->counts` untouched (`counts.tcp.banner`, `src/output.h:97`, is never incremented anywhere: grep).
   So XML `<hosts up= down=>` ignores banners.
5. No dedup on the banner path (C dedups only TCP SYN-ACKs, `src/main.c:1067`; UDP not at all, see B0).
6. Interactive (L903-923), same condition as status: `out->is_interactive || out->format == 0 || out->format ==
   Output_Interactive`:
   `count = fprintf(stdout, "Banner on port %u/%s on %s: [%s] %s", port, name_from_ip_proto(ip_proto), fmt.string,
   masscan_app_to_string(proto), normalize_string(px, length, banner_buffer, sizeof(banner_buffer)));`
   `if (count < 80) fprintf(stdout, "%.*s", (int)(79-count), <42+42 spaces>);` `fprintf(stdout, "\n");`
   `banner_buffer[MAX_BANNER_LENGTH]`, 8192 (`src/output.h:12`). Unlike status (L797) there is no `fflush(stdout)`
   (same bytes, different buffering). Example: `Banner on port 53/udp on 192.0.2.1: [dns-ver] 9.18.24` + pad to 79 + `\n`.
7. `if (fp == NULL) return;` (L926-927): silent. Status prints the two `no output file` ERRMSG lines (L799-803); the
   banner path never does. Interactive and a file: both happen.
8. Rotation check uses `now` = the record's timestamp (L934-938); status uses `time(0)` (L752).
9. Lazy header (L943-946): a banner can be the record that writes the header; any banner makes the file non-virgin,
   so the footer follows at close even when the format's banner hook is a no-op (unicornscan banner-only file =
   `#masscan\n# end\n`; XML banner-only file = header, banner lines, footer with `up="0" down="0"`).
10. `out->funcs->banner(out, fp, now, ip, ip_proto, port, proto, ttl, px, length);` (L952), then
    `if (out->is_output_flush) fflush(fp);` (L954-955).

App-type selection: none at output for live scans. `--capture/--nocapture cert|servername|html|heartbleed|ticketbleed`
(`src/main-conf.c:1132-1180`, table L2402-2403) only configures the TCP banner engine (`src/main.c:637-642`).
`--banner-types|--banner-type|--banner-apps|--banner-app <name>` (`src/main-conf.c:2683-2697`) fills
`masscan->banner_types`, whose only consumer is `--readscan` (`src/in-binary.c:684`); bad name:
`LOG(0, "FAIL: bad banner app: %s\n", value); fprintf(stderr, "err\n"); exit(1);`.

### A2. String normalisation

- `normalize_string` (`src/output.c:143-170`; used by interactive, `-oL`, `-oX`, `-oG`). Per byte `c`: if
  `isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\' && c != '\"' && c != '\''` append it when
  `offset + 2 < buf_len`; else append `\x` + two LOWERCASE hex digits when `offset + 5 < buf_len`; then NUL.
  `isprint` in the C locale (masscan never calls `setlocale`, status note) = 0x20..0x7E, so escaped bytes are
  0x00-0x1F, 0x7F-0xFF and `" & ' < > \`; space is not escaped. Buffer 8192, so at most 8190 chars, and the cut is
  NOT clean: once an escape no longer fits (offset >= 8187) later printable bytes are still appended up to 8190
  ("holes" near the end). A port must apply the per-byte rule literally. Live UDP payloads are < 2000 bytes
  (`assert`, `src/proto-preprocess.c:174`), 4x < 8190, never truncated; TCP banners and `--readscan` payloads (up to
  16369 bytes, A5) can be.
- `normalize_json_string` (`src/out-json.c:68-97`) and `normalize_ndjson_string` (`src/out-ndjson.c:64-93`), identical:
  same predicate; escape = `\u00` + two lowercase hex (6 chars) when `offset + 7 < buf_len`; printable when
  `offset + 2 < buf_len`; buffer 65536 (`src/out-json.c:108`, `src/out-ndjson.c:104`). Valid JSON; bytes >= 0x80 become
  `\u0080`..`ÿ` (Latin-1 code points: UTF-8 text is not preserved). Truncation needs > ~10900 escaped bytes
  (Inferred arithmetic).
- No base64 at output. `-oB` stores raw bytes; certs prints raw text. (X.509 banners are already base64 text made by
  the TCP side, `banout_append_base64`, `src/proto-banout.c:386-417`; Inferred.)

### A3. Application names (`src/masscan-app.c:8-57`; enum `src/masscan-app.h:8-49`, ids are stored in `-oB` files)

`masscan_app_to_string`: 0 `unknown`, 1 `unknown`, 2 `ssh`, 3 `ssh`, 4 `http`, 5 `ftp`, 6 `dns-ver`, 7 `snmp`,
8 `nbtstat`, 9 `ssl`, 10 `smb`, 11 `smtp`, 12 `pop`, 13 `imap`, 14 `zeroaccess`, 15 `X509`, 16 `X509CA`, 17 `title`,
18 `html`, 19 `ntp`, 20 `vuln`, 21 `heartbleed`, 22 `ticketbleed`, 23 `vnc`, 24 `safe`, 25 `memcached`, 26 `scripting`,
27 `versioning`, 28 `coap`, 29 `telnet`, 30 `rdp`, 31 `http.server`, 32 `minecraft`, 33 `vnc`, 34 `vnc-info`,
35 `isakmp`, 36 `error`; anything else `snprintf(tmp, sizeof(tmp), "(%u)", proto)` into a static buffer (37 ->
`(37)`, 65535 -> `(65535)`).
`masscan_string_to_app` (L61-112, `--banner-types`), case-sensitive `strcmp`: `ssh1`->2, `ssh2`->3, `ssh`->3, `http`,
`ftp`, `dns-ver`, `snmp`, `nbtstat`, `ssl`, `smtp`, `smb`, `pop`, `imap`, `x509`->15, `x509ca`->16, `zeroaccess`,
`title`, `html`, `ntp`, `vuln`, `heartbleed`, `ticketbleed`, `vnc-old`->23, `safe`, `memcached`, `scripting`,
`versioning`, `coap`, `telnet`, `rdp`, `http.server`, `minecraft`, `vnc`->33, `vnc-info`, `isakmp`. Ids 0, 1 and 36
cannot be selected. `name_from_ip_proto` as for status (`src/output.c:71-82`); a `--readscan` banner record may carry
any byte, printed `err`.

### A4. Per-format banner bytes

1. `-oL` `text_out_banner` (`src/out-text.c:51-73`): `fprintf(fp, "%s %s %u %s %u %s %s\n", "banner",
   name_from_ip_proto(ip_proto), port, fmt.string, (unsigned)timestamp, masscan_app_to_string(proto),
   normalize_string(...));` ttl ignored. `banner udp 53 192.0.2.1 1700000000 dns-ver 9.18.24\n`; empty banner keeps
   the separator: `banner udp 123 192.0.2.1 1700000000 ntp \n`.
2. `-oJ` `json_out_banner` (`src/out-json.c:101-134`): shares `is_first_record_seen` with status (`,\n` before every
   record but the first, L116-119); `fprintf(fp, "{ ");` `fprintf(fp, "  \"ip\": \"%s\", ", fmt.string);`
   `fprintf(fp, "  \"timestamp\": \"%d\", \"ports\": [ {\"port\": %u, \"proto\": \"%s\", \"service\": {\"name\":
   \"%s\", \"banner\": \"%s\"} } ] ", (int) timestamp, port, name_from_ip_proto(ip_proto),
   masscan_app_to_string(proto), normalize_json_string(...));` `fprintf(fp, "}\n");` (the long literal is one line in
   source, L124). Bytes: `{   "ip": "192.0.2.1",   "timestamp": "1700000000", "ports": [ {"port": 53, "proto": "udp",
   "service": {"name": "dns-ver", "banner": "9.18.24"} } ] }\n` (one line). ttl ignored; no status/reason/ttl keys;
   note `} } ]` (status has `} ]`).
3. `-oD` `ndjson_out_banner` (`src/out-ndjson.c:97-153`): `{`, `"ip":"%s",`, `"timestamp":"%d","port":%u,"proto":"%s",
   "rec_type":"banner","data":{"service_name":"%s","banner":"%s"}`, `}\n` ->
   `{"ip":"192.0.2.1","timestamp":"1700000000","port":53,"proto":"udp","rec_type":"banner","data":{"service_name":
   "dns-ver","banner":"9.18.24"}}\n` (one line). L120-126 and L131-152 are commented out (the `normalize_string` hit
   at L151 is inside the comment).
4. `-oX` `xml_out_banner` (`src/out-xml.c:95-132`): `reason` is chosen by `switch (proto)` on the APP id: `case 6:
   reason = "syn-ack"; break; default: reason = "response";` (L106-109). Bug (meant `ip_proto`): `dns-ver` (app 6)
   banners say `syn-ack`, every TCP banner says `response`. Format: `"<host endtime=\"%u\">" "<address addr=\"%s\"
   addrtype=\"%s\"/>" "<ports>" "<port protocol=\"%s\" portid=\"%u\">" "<state state=\"open\" reason=\"%s\"
   reason_ttl=\"%u\" />" "<service name=\"%s\" banner=\"%s\"></service>" "</port>" "</ports>" "</host>" "\r\n"` with
   `(unsigned)timestamp, fmt.string, name_from_ip_version(ip.version), name_from_ip_proto(ip_proto), port, reason, ttl,
   masscan_app_to_string(proto), normalize_string(...)`. `<state ... />` has a space before `/>` (status record: none).
   `\xNN` escapes are literal attribute text; `< > & " '` never appear raw, so the XML stays well-formed.
5. `-oG` `grepable_out_banner` (`src/out-grepable.c:178-202`): `"Host: %s ()"`, `"\tPort: %u"`, `"\tService: %s"`
   (app name), `"\tBanner: %s\n"` -> `Host: 192.0.2.1 ()\tPort: 53\tService: dns-ver\tBanner: 9.18.24\n`. No
   `Timestamp:` field (status has one), no protocol, no services lookup; timestamp, ip_proto, ttl ignored.
6. `-oB` `binary_out_banner` (`src/out-binary.c:293-355`), IPv6 branch `binary_out_banner_ipv6` (L216-289) when
   `ip.version == 6` (L304-307). Type ids `src/out-record.h`: `Out_Banner9` 9, `Out_Banner6` 13. All big-endian.
   - Type 9 (IPv4), `HeaderLength = 14` (L302): `if (length >= 128 * 128 - HeaderLength) return;` (L313-314: payload
     >= 16370 is silently dropped, though the lazy header was already written). Length: payload <= 113 -> one byte
     `length + 14`; else two bytes `((length+14)>>7) | 0x80`, `(length+14) & 0x7F` (L315-322). Body: ts u32 (low 32
     bits of `time_t`), ipv4 u32, ip_proto u8, port u16, app u16, ttl u8, payload (L324-346).
   - Type 13 (IPv6), `HeaderLength = 14 + 13` = 27 (L225): drop when payload >= 16357 (L232-233); one-byte length when
     payload <= 100 (L234-241). Body: ts u32, ip_proto u8, port u16, app u16, ttl u8, `ip.version` u8 (6), hi u64,
     lo u64, payload (L243-280). Field order differs from type 9 (no address up front).
   - Short `fwrite` -> `perror("output"); exit(1);`. `rotate.bytes_written += n`. Payload raw, unescaped.
   - Example, IPv4 udp/53 ttl 57 app 6 ts 0x6553F100 payload `9.18.24`:
     `09 15 65 53 F1 00 C0 00 02 01 11 00 35 00 06 39 39 2E 31 38 2E 32 34`.
7. `-oU` `unicornscan_out_banner` (`src/out-unicornscan.c:61-79`): no-op (header/footer still happen, A1.9).
8. `-oH` `hostonly_out_banner` (`src/out-hostonly.c:45-65`): `fprintf(fp, "%s\n", fmt.string);` one more IP line per
   banner record.
9. certs, `--output-format certs` only (`src/main-conf.c:1701`, no `-o` letter), `src/out-certs.c`: open no-op
   (L10-15), status no-op (L29-44), close `fprintf(fp, "{finished: 1}\n");` (L21-25, so the file holds exactly that
   line once any record touched it). Banner (L49-80) ignores `fp` and every field and writes to STDOUT: strips a leading
   `cert:` if `length > 5`; `printf("-----BEGIN CERTIFICATE-----\n");`, then the raw payload in 72-byte lines
   `printf("%.*s\n", len, px+i)`, then `printf("-----END CERTIFICATE-----\n");`. Applies to EVERY app type (no X509
   check). Needs a filename (A1.7: with `fp == NULL` the hook is never reached). Never interactive.
10. `none` / default format 0 / `interactive`: `null_output` (`src/out-null.c:54-71`) no-op; no file is opened
    (`src/output.c:479`). Redis `-oR` (`src/out-redis.c:320-337`): no-op.
11. Console with no `-o`: only the A1.6 lines on stdout.

Status and banner records interleave in arrival order in every format.

### A5. `--readscan` banner records (`src/in-binary.c`)

Main loop L537-638 (type and length are 7-bit-group varints, L546-570; `length > BUF_MAX` (1 MiB, L25) -> `[-] file
corrupt`). Banner cases L592-627:

| type | parser | body after type+length | short body | filters | re-emitted with |
| --- | --- | --- | --- | --- | --- |
| 3 | `parse_banner3` L339-369 | ts4 ip4 port2 app2, payload @12 | NO check: body < 12 makes `(unsigned)buf_length-12` wrap, a ~4 GiB read (crash, Inferred) | none | ip_proto 6 (forced), ttl 0 |
| 4 | first reads ONE EXTRA BYTE from the file into the body (L595-602; failure: `LOG(0, "[-] read() error\n"); exit(1);`), then `parse_banner4` L375-409 | ts4 ip4 proto1 port2 app2, payload @13 | < 13 skipped silently | none | ttl 0 |
| 5 | `parse_banner4` | same, no extra byte | < 13 skipped | none | ttl 0 |
| 9 | `parse_banner9` L414-467 | ts4 ip4 proto1 port2 app2 ttl1, payload @14 | < 14 skipped silently | `readscan_filter_pass` L450-452 | as stored |
| 13 | `parse_banner6` L280-330 via `_get_*` (L156-223: past the end reads 0xFF..) | ts4 proto1 port2 app2 ttl1 ver1 hi8 lo8, payload @27 | ver != 6 (incl. body < 11): `fprintf(stderr, "[-] corrupt record\n")`, skip, keep reading (L297-300); ver 6 but body < 27: skipped silently after the filter (`if (offset > length) return;` L318-319) | `readscan_filter_pass` L311-313 | as stored |

- `when_scan_started` is set from the first record that reaches any parse function, before filters (L304-305,
  L353-354, L393-394, L437-438). With `--banner-types`, status records never reach theirs (next item).
- `--banner-types` non-empty: every status record (types 1, 2, 6, 7, 10, 11) is dropped unparsed (`if (!btypes->count)`,
  L584-623). Types 3/4/5 ignore both the address/port filter and `--banner-types`.
- `readscan_filter_pass` (`src/in-filter.c:5-24`): address check only if `filter->count_ipv4s` (an IPv6-only range list
  filters nothing, as for status; Rust R14); `massip_has_port(filter, port)` with the UNSHIFTED port (UDP/SCTP banner
  records cannot match `-pU:`; Rust R5 for status); `btypes->count` -> `rangelist_is_contains(btypes, app)`.
- Every record, `'m'` included, counts towards the progress line (L635-637).
- Re-emission goes through A1 with `is_banner` forced on (a later `--nobanners` would turn it off again, Inferred from
  in-order option processing). So the default format prints `Banner on port ...` lines; `-oB` rewrites types 3/4/5
  as type 9 (they are IPv4-only); a payload >= 16370 is dropped (reachable only through 3-byte length varints, which
  no writer emits).
- `parse_banner9` computes `buf_length-14` before its `< 14` check (L420-424), harmless.

### A6. Rust side today (mapping)

- `rmasscan/crates/rmasscan-cli/src/output/record.rs`: `Record` (L76-89) is a status record (no app id, no payload);
  `Proto` (L26-32) has no "other" value, so `err` cannot be printed (status uses an `UnsupportedProtocol` error instead,
  R13). Banner needs its own record type (ts, ip v4/v6, ip_proto byte, port, app u16, ttl, payload bytes) and an
  app-name table (A3) plus the two normalisers (A2).
- `.../output/formats.rs`: `Formatter` trait = `header/record/footer` (L51-55); `formatter()` (L58-70); `Format`
  (L14-27) has no `Certs`/`Redis` (`.../src/args.rs:42-43` refuses certs "it needs --banners"). Banner hooks to add:
  `List` (L83), `Json` (L106-107, its first-record flag must be shared), `Ndjson` (L139), `Hostonly` (L165), `Xml`
  (L180), `Binary` (L232: types 9/13, varint length, silent drop); `.../output/grepable.rs`: `Grepable` (L57),
  `Unicornscan` (L107, no-op).
- `.../output/pipeline.rs` `report_record` (L126): show filter -> interactive line -> TCP counts -> lazy header ->
  record -> flush. A banner path is: no show filter, no counts, the `Banner on port` line, silent drop without a file,
  shared `virgin` flag. `.../output/mod.rs`: `Sink` (L29-34) has only `report(&Reply)`.
- `.../src/readscan.rs`: `read_records_counted` (L161) dispatch L205-283: types 6-8, 10-11, `0x6D`; `1..=5 | 9 | 12 |
  13` -> `ReadError::Unsupported` (L281, stops the read). Banner types plug in there (a second callback or an item
  enum); `ReadFilter` (L312-341) needs the app-type set and the "status records dropped when `--banner-types`" rule;
  `port_index` (L293-301) already uses shifted ports (R5).
- Receive: `rmasscan/crates/rmasscan-core/src/receive.rs` `Reply` (L140-158) carries no payload; `parse_udp_reply`
  (L652-711) returns the status record only (and, unlike C, requires the target set and verifies checksums).
  `rmasscan/crates/rmasscan-engine/src/engine.rs` `DedupCache` (L131-200) dedups UDP `Open` replies; C does not (B0),
  so C prints one status line and the banners PER DATAGRAM.
- `rmasscan/crates/rmasscan-core/src/payloads.rs`: `CookieMutator` (L34-60: Dns, Ntp, Snmp, Isakmp, Coap, Memcached)
  already writes the probe cookies that the B parsers check.
- `--banners` is a clap error today (`rmasscan/crates/rmasscan-cli/src/lib.rs:522` test).

Goldens: `rmasscan/tests/golden/formats/` (README, `manifest.json`, `inputs/*.scan.bin`, `outputs/*.out`), replayed by
`rmasscan/crates/rmasscan-cli/tests/formats_golden.rs` (masks `xml_start`, `xml_finished`, `grepable_done`; `SKIPS`
empty). "74" was the first capture (4 inputs x 18 cases + 2 filter cases); the manifest now has 119 cases (inputs
basic, edge, empty, many, protocols, ipv6: 6 x 18, plus 11 filter cases), 101 stored outputs (`many` is hash-only).
NO input contains a banner record: walking the five stored inputs gives only types 6, 7, 10, 11 and the `'m'` footer.
Inputs come from `rmasscan/crates/rmasscan-cli/examples/format_inputs.rs` (writer = rmasscan's own status writer);
`rmasscan/scripts/build-format-goldens.sh` `walk_records` (L108-128) accepts only types 6/7 with length 13 and 10/11
with length 26 and rejects anything else, so it must learn types 9/13 (two-byte lengths) first.

## B. UDP (and other non-TCP) application parsing that emits banners

### B0. `handle_udp` (`src/proto-udp.c:54-132`)

Called for `FOUND_UDP` and `FOUND_DNS` (either port 53, `src/proto-preprocess.c:176-178,209-213`) after `is_my_ip`
and `is_nic_port(port_me)` (`src/main.c:829-838, 909-916`); IPv4 and IPv6 (IPv6 next-header 17 also goes to
`parse_udp`, `src/proto-preprocess.c:286-290`). No dedup, no cookie check, no target-range check at this level.

1. Always first: `output_report_status(out, timestamp, PortStatus_Open, ip_them, 17, port_them, 0, parsed->ip_ttl,
   parsed->mac_src)` (L63-73): one `open udp` record per datagram, duplicates and wrong-cookie replies included;
   reason 0 -> `none`. Subject to `--show` like any status record. Happens with or without `--banners`.
2. Dispatch on the reply's SOURCE port only, never on payload (L76-113): 53 `handle_dns`; 123 `ntp_handle_response`;
   137 `handle_nbtstat`; 161 `handle_snmp` (these four get the whole frame and use `parsed->app_offset`); 500
   `isakmp_parse(px + app_offset, app_length)`; 5683 `coap_handle_response(px + app_offset, app_length)`; 11211:
   `px += parsed->app_offset; length = parsed->app_length;` then `memcached_udp_parse` (L97-101); 16464, 16465,
   16470, 16471 `handle_zeroaccess` (whole frame); default: `px += parsed->app_offset; length = parsed->app_length;`
   then `default_udp_parse` (L108-112).
3. Fallback (L116-131): `if (status == 0 || out->is_banner_rawudp)` -> `output_report_banner(out, timestamp, ip_them,
   17, port_them, PROTO_NONE, parsed->ip_ttl, px + parsed->app_offset, parsed->app_length)` ("raw": app 0, printed
   `unknown`, the whole UDP payload). BUG: in the 11211 and default branches `px` was already advanced, so this reads
   `app_length` bytes from frame + 2*app_offset, i.e. `app_offset` (42 for Ethernet/IPv4) bytes past the end of the
   datagram, from the capture buffer: non-deterministic garbage ("raw*" below).
4. `default_udp_parse` (L27-50): `if (length > 64) length = 64;` then a PROTO_NONE banner of those bytes; returns 0
   ("def64").
5. Return value: 1 = handled (no fallback), 0 = fallback. Most parsers return 0 even after reporting.

Banners emitted per reply (with `--banners`, without `--rawudp`; all need `is_banner`):

| port | condition | banners, in order |
| --- | --- | --- |
| 53 | DNS id != cookie (also payload < 12: id uninitialised, B1) | none |
| 53 | `qr != 1` | raw |
| 53 | rcode 1-9 | `dns-ver` `N:NAME`, raw |
| 53 | rcode 0 (or >= 10) and first answer is CHAOS TXT | `dns-ver` text only |
| 53 | rcode 0, anything else | raw |
| 123 | app < 4 bytes or version != 2 | raw |
| 123 | version 2 | `ntp` text (may be empty), raw |
| 137 | DNS id != cookie | none |
| 137 | any later check fails | raw |
| 137 | parsed | `nbtstat` text, raw |
| 161 | request-id != cookie (also every non-SNMPv1 reply: request-id stays 0) | none |
| 161 | cookie ok | `snmp` text (may be empty), raw |
| 500 | app < 16 bytes or 8-byte cookie mismatch | raw |
| 500 | cookie ok | `isakmp` text only |
| 5683 | `coap_parse` false | def64, raw |
| 5683 | valid | `coap` text (+ ` IP-MISMATCH`), raw |
| 11211 | app < 8 bytes | raw* |
| 11211 | seq > 100, datagrams > 100 or reserved != 0 | def64, raw* |
| 11211 | header ok | `memcached` text (+ ` IP-MISMATCH`), raw* |
| 16464/5/70/71 | any check fails | raw |
| 16464/5/70/71 | ok | `zeroaccess` text, raw |
| other | always | def64, raw* |

With `--rawudp` the raw (or raw*) banner is added to the "none" and "text only" rows too (DNS/NBNS/SNMP cookie
failures and successes, ISAKMP success).

### B1. DNS, port 53 (`src/proto-dns.c`)

- `handle_dns` (L353-449): `seqno = (unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy);`
  (L369); `proto_dns_parse(dns, px, parsed->app_offset, parsed->app_offset + parsed->app_length)` (L371, offsets stay
  absolute in the frame); `if ((seqno & 0xFFFF) != dns->id) return 1;` (L373-374).
- `proto_dns_parse` (L175-322) returns before setting `id`/`qr`/`rr_count` when the payload is < 12 bytes (L205-206):
  the stack `DNS_Incoming` is not zeroed, so the id compare reads garbage (treat as mismatch). Questions: name skip +4,
  class must be 1, 255 or 3 else stop (L238-253). Answers+authority: name + 10 + rdlength (L277-290). Additional:
  EDNS0 OPT detection, `payload_size < 512` stops, `rcode |= px[offset+5]<<4` (extended rcode, can exceed 15) (L291-315).
  Up to `rr_offset[]` capacity RRs.
- `if (dns->qr != 1) return 0;` (L381-382).
- rcode strings (L388-399): `"1:FORMERR"`, `"2:SERVFAIL"`, `"3:NXDOMAIN"`, `"4:NOTIMP"`, `"5:REFUSED"`,
  `"6:YXDOMAIN"`, `"7:XRRSET"`, `"8:NOTAUTH"`, `"9:NOTZONE"`; reported as `PROTO_DNS_VERSIONBIND` then `return 0`
  (L400-409; so a raw banner follows). rcode 0 and >= 10 fall through.
- TXT (L419-447): `offset = dns->rr_offset[1]` (the first answer when qdcount = 1; uninitialised if fewer than 2 RRs
  were recorded); `dns_name_skip(px, offset, length)` (`length` = whole frame incl. any Ethernet padding);
  `if (offset + 10 >= length) return 0;`; type, class, rdlength; `txtlen = px[offset+10]` (first character-string
  length); `offset += 11`; clamp `txtlen` to the frame; `if (rrlen == 0 || txtlen > rrlen-1) return 0;`
  `if (type != 0x10 || xclass != 3) return 0;` then report `px + offset, txtlen` as `dns-ver` and `return 1`. Only the
  first character-string of a CHAOS TXT answer; the answer name is not compared with `version.bind`.
- Probe (`src/templ-payloads.c:76-86`): `version.bind` TXT CHAOS, `dns_set_cookie` (`src/proto-dns.c:333-342`) writes
  the low 16 bits of the cookie big-endian into the id.

### B2. NTP, port 123 (`src/proto-ntp.c`)

- `ntp_handle_response` (L228-282): `if (parsed->app_length < 4) return 0;`; version `(px[app_offset]>>3)&7` must be 2,
  else `return 0` (L251-262). Otherwise `ntp_v2_parse` then ALWAYS reports `PROTO_NTP` with
  `banout_string/banout_string_length` (possibly NULL/0 -> an empty `ntp` banner) and `return 0` (L270-281). No cookie:
  `ntp_set_cookie` is a no-op (L21-28) and the check is commented out (L264-267).
- `ntp_v2_parse` (L191-222): needs >= 4 bytes, response bit (`px[0]>>7`), version 2; mode 7 -> `ntp_priv`; mode 6 and
  others add nothing.
- `ntp_priv` (L157-187): implementation `px[2]`: 0 -> `UNIV` (stop), 2 -> `XNTPD-OLD` (stop), 3 -> `XNTPD`, else nothing.
  For 3: if `px[3]` is in `request_codes` (L34-73) append `" "` + name; if code 42 -> `ntp_modlist_parse`.
- `ntp_modlist_parse` (L100-153), offset 4: needs `offset + 4 < length`; `errcode = (px[4]>>4)&0xF`; error ->
  `"Response was NTP Error Code "` + `%u` + `" - \""` + text (`error_codes` L75-83: 0 No Error, 1 Incompatible
  Implementation Number, 2 Unimplemented Request Code, 3 Format Error, 4 No Data Available, 7 Authentication Failure;
  else `Bogus Error Code`) + `"\""`; NO separator before `Response`. Else if `4 + count*size > length` or
  `count*size > 500` -> `response-too-big` (no separator either); else `" response-size=%u-bytes more=%s"` with
  `count*size` and bit 6 of `px[0]`.
- Probe `src/templ-payloads.c:104-108` (`17 00 03 2a`, v2 mode 7 XNTPD MON_GETLIST_1). Typical texts:
  `XNTPD MON_GETLIST_1 response-size=432-bytes more=false`, `XNTPD MON_GETLIST_1Response was NTP Error Code 4 - "No
  Data Available"` (the `"` print as `\x22` / `"`).

### B3. NetBIOS name service, port 137 (`src/proto-netbios.c`)

- `handle_nbtstat` (L110-169): same cookie scheme as DNS (L125-130, `return 1` on mismatch); then `return 0` (raw)
  unless `qr == 1`, `rcode == 0`, `qdcount <= 1`, `ancount >= 1`, `rr_count >= 1` (L132-141);
  `offset = rr_offset[qdcount]`, name skip against the whole frame, `offset + 10 >= length` -> 0; type must be 0x21
  (NBSTAT), class 1, `rrlen != 0`, `txtlen = px[offset+10] <= rrlen-1` (L144-158); then `handle_nbtstat_rr(px+offset+10,
  length-offset-10)` whose result (always 0) is returned, so a raw banner follows.
- `handle_nbtstat_rr` (L60-104): `name_count = px[0]`; per 18-byte entry while it fits: `append_name` (L28-55): 15 bytes,
  each `0x20` or NUL -> space, `isalnum || ispunct` -> itself, else `<` + two UPPERCASE hex + `>`; then the 16th byte as
  `<XX>` and `\n`. Then the MAC: BUG `unsigned char c = px[offset];` (L87) repeats the FIRST MAC byte six times,
  uppercase hex joined by `-` (only for `offset + i < length`). 64 KiB buffer.
  Example: `HOST1          <00>\nWORKGROUP      <00>\n52-52-52-52-52-52` (in `-oL`: `<` -> `\x3c`, `\n` -> `\x0a`).
- Probe `src/templ-payloads.c:109-118` (wildcard NBSTAT query, `dns_set_cookie`).

### B4. SNMP, port 161 (`src/proto-snmp.c`, BER helpers in the same file)

- `handle_snmp` (L536-584): `snmp_parse(px + app_offset, app_length, banout, &request_id)`, then
  `if ((seqno&0x7FFFffff) != request_id) return 1;` (L567-569; `request_id` stays 0 when parsing stops early), report
  `PROTO_SNMP` (possibly empty) and `return 0` (raw follows).
- `snmp_parse` (L301-398): `30` + length (clamps `length`); `asn1_integer` version must be 0 (SNMPv1 only: a v2c reply
  gives no banner at all); `04` community; PDU tag 0xA0..0xA5; request-id, error-status, error-index integers; `30`
  varbind list; per varbind `30` + length (`varbind_end > length` -> stop); OID tag 6 else stop; value tag/length;
  tag 5 (NULL) skipped; else `snmp_banner`.
- BER helpers: `asn1_length` (L105-139: long form up to the remaining bytes, value > 0x10000 or length-of-length 0 ->
  error 0xFFFFffff); `asn1_integer` (L145-175: reads the tag byte without a bounds check; length <= 20; unsigned
  big-endian); `asn1_tag` (L179-185); `next_id` (L189-202, base-128).
- `snmp_banner` (L255-292): `\n` before every varbind but the first (`banout_newline` appends only if non-empty,
  `src/proto-banout.c:149-158`); OID text; `:`; value: tag 2 -> `%llu` of the bytes as unsigned big-endian (no sign,
  wraps past 8 bytes); tag 6 -> OID text; anything else (4 OCTET STRING, 0x40 IpAddress, 0x41 Counter32, 0x43
  TimeTicks, ...) -> raw bytes ("TODO: this needs to be normalized").
- OID text `snmp_banner_oid` (L206-251): longest MIB match from `mib[]` (L73-95) by the Aho-Corasick matcher
  (`snmp_init` L593-623: patterns from `convert_oid` L499-531, flags `SMACK_ANCHOR_BEGIN | SMACK_SNMP_HACK`; the hack
  makes a 0x80 byte loop on pattern states, `src/smack1.c:826-827`, so the probe's IDS-evasion padding `2b 06 01 80
  02 ...` still matches); then each remaining sub-id as `.%llu`, except that a final sub-id 0 is dropped
  (`if (x == 0 && i >= oid_length) break;`). So `1.3.6.1.2.1.1.1.0` -> `sysDescr`. Names: `43`->iso.org, `.6` dod,
  `.6.1` inet, `.6.1.2` mgmt, `.6.1.2.1` mib2, `"43.6.1.2.1."` sys (same bytes as mib2 after `convert_oid`; which id
  wins is a matcher detail, Inferred `mib2`), sysDescr .1.1.1, sysObjectID .1.1.2, sysUpTime .1.1.3, sysContact
  .1.1.4, sysName .1.1.5, sysLocation .1.1.6, sysServices .1.1.7, priv .6.1.4, enterprise .6.1.4.1, okidata
  .6.1.4.1.2001, selftest `43.1006.51.341332`. Anchoring semantics of `src/smack1.c` were not traced; the self-test
  vector (`snmp_selftest_banner`, L627-670) pins `sysObjectID:okidata.1.1.1.297.93.1.27.2.2.1`.
- Probe `src/templ-payloads.c:146-159`: v1 `public` GetRequest, 4-byte request-id (the `snmp_set_cookie` case-4 path,
  L457-462: top bit cleared), varbinds sysDescr.0 then sysName.0 (the source comments swap the names). Expected banner:
  `sysDescr:<descr>\nsysName:<name>`.

### B5. memcached, UDP port 11211 (`src/proto-memcached.c`)

- `memcached_udp_parse` (L298-392): `length < 8` -> `return 0`; header request-id, sequence, total datagrams, reserved;
  seq > 100, total > 100 or reserved != 0 -> `default_udp_parse` (L390-391, def64, returns 0). Else run the TCP parser
  `memcached_tcp_parse(0, 0, stuff, px+8, length-8, banout, 0)` (L361-371), append `" IP-MISMATCH"` when
  `(cookie&0xffff) != request_id` (L373-374, cookie from `syn_cookie(... port_them | Templ_UDP ...)` L353; the hard
  check is commented out L354-355), report `PROTO_MEMCACHED` (possibly empty) and `return 0` (L377-388).
- `memcached_tcp_parse` (L106-223) needs the matchers built by `memcached_init` (L227-293), which only runs from
  `banner1_create` (`src/proto-banner1.c:617`) when the TCP table exists, i.e. with `--banners`; without it the parser
  returns at once (no output anyway). Case-insensitive, line-anchored response keywords (each with one of
  space/tab/CR/LF appended). For `STAT <name> <value>` lines only `uptime`, `time`, `version` are kept: append the name,
  `=`, the value bytes up to `\n` (CR dropped), then one space. `END` stops. Text: `uptime=12345 time=1700000000
  version=1.6.21 ` (order as the server sends; trailing space), then maybe ` IP-MISMATCH`.
- Probe `src/templ-payloads.c:294-296`: `00 00 00 00 00 01 00 00 stats\r\n`; `memcached_udp_set_cookie` (L396-417)
  writes the low 16 bits into bytes 0-1.

### B6. CoAP, port 5683 (`src/proto-coap.c`)

- `coap_handle_response` (L536-589): `coap_parse(px, length, banout, &message_id)`; append `" IP-MISMATCH"` if
  `(cookie&0xffff) != message_id` (L564-571, soft check); valid -> report `PROTO_COAP`, `return 0` (raw follows);
  invalid -> `return default_udp_parse(...)` (def64; raw follows).
- `coap_parse` (L288-531) valid iff length >= 4, version 1, type 2 (ACK), TKL <= 8 and fits. Text:
  `"rsp=%u.%u(%s)"` (`code>>5`, `code&0x1F`, `response_code` L59-95, fallback by class `Okay`/`Error`/`PARSE_ERR`);
  if token != 0: `" token=0x%llu"` (BUG: the token is built from `px[0..TKL-1]`, the header, not `px[4..]`, L345-349,
  and printed in decimal after `0x`, L364); per option ` /If-Match/`, ` /Uri-Host/`, ` /Etag` (no trailing slash),
  ` /If-None-Match/`, ` /Uri-Port/`, ` /Location-Path/`, ` /Uri-Path/`, ` /Content-Format/` (value read), ` /Max-Age/`,
  ` /Uri-Query/`, ` /Accept/`, ` /Location-Query/`, ` /Proxy-Uri/`, ` /Proxy-Scheme/`, ` /Size1/`, else
  ` /(Unknown)/`; malformed extended delta/length or overrun -> ` PARSE_ERR` and stop (L397-502); `0xFF` ends options.
  Then by content format (default 0 even with no Content-Format option): 0 ` text-plain`, 40 ` application/link-format`
  followed by `" " + link` for each `<link>` found by `parse_links` (L120-284; BUG L239 compares `offset == ';'`),
  41 ` application/xml`, 42 ` application/octet-stream`, 47 ` application/exi`, 50 ` application/json`, else
  ` (unknown-content-type)`.
- Probe `src/templ-payloads.c:281-290`: CON GET `/.well-known/core`; `coap_udp_set_cookie` (L593-615) writes the low
  16 bits into the message id. Self-test (L646-733) checks only `rsp=2.5(Content)` loosely (L724).

### B7. ISAKMP, port 500 (`src/proto-isakmp.c`)

- `isakmp_parse` (L378-443): app < 16 -> `return 0`; `cookie = (unsigned)syn_cookie(...)`; the 8-byte initiator cookie
  read big-endian as 64 bits must equal it (the probe stores the 32-bit cookie zero-extended: `isakmp_set_cookie`
  L445-462 writes 8 bytes of a `seqno` that is 32-bit, `src/templ-pkt.c:618-655`), else `return 0` (raw; the
  `PROTO_ERROR "IP-MISSMATCH"` report is commented out, L417-419); match -> `_parse_response` text as `PROTO_ISAKMP`,
  `return 1` (no raw).
- `_parse_response` (L255-376) via `e_next_*` (`src/util-extract.c`: past the end returns all-ones, offset unchanged):
  `"v%u.%u "`, `"xchg=id-prot "` (2) or `"xchg=%u "`; flags bit 0 -> `"ENCRYPTED "` and stop; per payload the name
  `"%s "` from `payload_names[]` (`[SEC-ASSOC]` 1, `[KEY-XCHG]` 4, `[NONCE]` 10, `""` for 13 vendor-id, `[NAT-D]` 20,
  `[n]` otherwise; `[%u] ` for >= 32); SA: `DOI=generic ` / `DOI=ipsec ` + `IDENTITY `/`SECRECY `/`INTEGRITY ` +
  proposals (`"%u "` number, `id=ISAKMP ` or `id=%u `) + transforms (`trans=IKE ` + attributes `3DES-CBC `, `AES-CBC `,
  `encrypt=0x%x `, `SHA `, `hash=0x%x `, `PSK ` for auth 1 AND 5, `auth=0x%x `, `key=%ubits `, `val=0x%04x%04x `,
  group/life types silent, a non-TV attribute ends the transform; or `trans=%u `) or `DOI=%u `; vendor-id by exact
  length+bytes: `{RFC-39947-NAT} `, `{CISCO-UNITY} `, `{RFC3706-DPD} `, `{XAUTH} `.
- BUG: a payload header with length 0 and a non-zero next-payload loops forever (`ebuf->offset += payload.length`,
  L372-373; same in `_parse_transforms` L146 and `_parse_proposals` L191) - a replying target can hang the receive
  thread (Inferred, not run).
- Self-test strings (L556-568), e.g. `v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE 3DES-CBC
  SHA PSK` (a prefix), but `_test_sample` returns 0 on failure too (L538-541), so they are unenforced.
- Probe `src/templ-payloads.c:315` (352 bytes; its `source_port` 500 is never used, `src/templ-pkt.c:618-659`).

### B8. ZeroAccess, ports 16464/16465/16470/16471 (`src/proto-zeroaccess.c`)

`handle_zeroaccess` (L170-259): XOR-decrypt with key `"ftp2"` rotated left 1 bit per word (`zadecrypt`); CRC32 of the
packet with the CRC field zeroed must equal the stored little-endian CRC; bytes 4-7 `"Lter"`; count = LE u32 at 12,
<= 256 and fits; banner `"ZeroAccess:"` + `"%u.%u.%u.%u "` per address, `return 0` (raw follows). BUG: `banout` is
initialised by hand without `max_length` (L183-185) and never released: undefined behaviour on append (Inferred). No
cookie. Probe: fixed `getL` packet (`src/templ-payloads.c:299-306`).

### B9. Others

- SCTP (`src/proto-sctp.c`), ICMP/ICMPv6 (`src/proto-icmp.c`), oproto: status only, no banners. ICMP 3/3 for a UDP
  probe -> `closed udp` status (`src/proto-icmp.c:194-204`), never a banner.
- Ports with a probe but no parser (7, 17, 19, 69, 111, 138, 443, 520, 1645, 1646, 1701, 1812, 1813, 1900, 2049, 5060,
  27960; `src/templ-payloads.c:66-315`): default path (def64 + raw*). 111 and 2049 even get `dns_set_cookie` but nothing
  checks it.

### B10. Probe payloads and parser cookies (`payloads.rs` is the port of `src/templ-payloads.c`)

TX cookie: `syn_cookie_ipv4(ip_them, Templ_UDP + port, ip_me, port_me, entropy)` (`src/main.c:389`), passed as
32-bit `seqno` to `set_cookie` (`src/templ-pkt.c:618-655`); RX recomputes `syn_cookie(ip_them, port_them | Templ_UDP,
ip_me, port_me, entropy)` (same value). So every check depends on the scan's entropy (`--seed`) and on the reply
echoing the field.

| port | probe writes | RX check | on mismatch |
| --- | --- | --- | --- |
| 53, 137 | id = cookie & 0xFFFF | hard | no banner (`return 1`) |
| 161 | request-id = cookie & 0x7FFFFFFF | hard | no banner |
| 500 | init cookie = 00 00 00 00 + cookie BE | hard | raw only |
| 5683 | message id = cookie & 0xFFFF | soft | ` IP-MISMATCH` appended |
| 11211 | request id = cookie & 0xFFFF | soft | ` IP-MISMATCH` appended |
| 123 | nothing | none | - |

User payloads (`--nmap-payloads`, `--pcap-payloads`) are added with `set_cookie = 0` and replace the built-in entry for
the same port (`src/templ-payloads.c:619-680`): then DNS/NBNS/SNMP banners are always suppressed, CoAP/memcached
always say ` IP-MISMATCH`, ISAKMP always falls back to raw.

## C. Port surface

### C1. C bugs and oddities (decide: reproduce or name a difference)

1. Fallback raw banner over-reads past the datagram for port 11211 and every unparsed port (`src/proto-udp.c:97-101,
   108-112` with L129): non-deterministic bytes; not reproducible, must be a named difference.
2. Most UDP parsers return 0 after reporting, so a raw `unknown` banner duplicates nearly every parsed banner (B0
   table); `--rawudp` forces it everywhere.
3. No dedup of UDP datagrams: one status + banners per duplicate packet (`src/main.c:909-916`); rmasscan dedups.
4. UDP banner/status timestamps are capture times (`secs`), TCP ones are the stale `global_now` (A0).
5. IPv6 UDP banners carry a stale TTL (`ip_ttl` never set for IPv6).
6. XML banner `reason` keyed on the app id (`src/out-xml.c:106-109`); ` />` spacing differs from status.
7. normalize_* truncation leaves holes (A2); JSON turns bytes >= 0x80 into Latin-1 `\u00XX`.
8. `-oB` silently drops payloads >= 16370 (v4) / >= 16357 (v6) (`src/out-binary.c:313-314, 232-233`).
9. certs prints every banner type as a PEM block on stdout and only `{finished: 1}` in the file (`src/out-certs.c`).
10. `--readscan`: type 3 has no length check; type 4 reads an extra byte; types 3/4/5 bypass all filters; `--banner-types`
    drops all status records; address filter gated on IPv4 count; unshifted port filter (A5).
11. NBTSTAT MAC prints the first byte six times (`src/proto-netbios.c:87`).
12. NTP error/too-big text lacks a separator after the request name (`src/proto-ntp.c:126,135-139`).
13. SNMP: v1 only; final `.0` dropped; non-string values (TimeTicks, Counter, IpAddress) dumped raw; integers unsigned.
14. CoAP token from the wrong bytes and printed `0x<decimal>`; `offset == ';'`; ` text-plain` without Content-Format.
15. ISAKMP infinite loop on zero-length payloads; auth 5 printed `PSK`; unenforced self-tests.
16. DNS/NBNS read an uninitialised id (payload < 12) and possibly uninitialised `rr_offset[]` on malformed replies
    (`src/proto-dns.c:205-206,419`, `src/proto-netbios.c:144`).
17. ZeroAccess `banout` without `max_length` (UB).
18. Banner interactive line not flushed; banner with a real format but no file is dropped silently (no ERRMSG).
19. `--adapter file:<pcap>` (`src/rawsock.c:712-731`) opens the file and then falls through into the live libpcap
    open, overwriting the handle: C cannot replay a capture through the parsers (Inferred, not run).

### C2. Testable offline with C `--readscan` goldens (no network)

Everything in part A: per-format bytes of types 9 and 13 (and the reader of 3/4/5), all 256 byte values through both
normalisers, empty payloads, app ids 0..36, 37 and 65535 (`(N)`), ip_proto 0/1/6/17/132 and another byte (`err`),
app 6 vs others in XML, IPv6 banners, the one/two-byte length boundary (v4 payload 113/114, v6 100/101), a 16369-byte
payload (text truncation at 8190, JSON past the 65536 buffer when mostly non-printable), mixed status+banner files
(JSON commas, lazy header, XML `up=` unaffected, grepable/XML header time from the first record whatever its type),
`-oH` extra lines, `-oU` header+footer only, certs (stdout PEM + `{finished: 1}`), default format (`Banner on port`
lines on stdout, A1.6), `--banner-types` (status dropped, app filter, types 3/4/5 unfiltered), `--range`/`-p` filters on
banner records, `-oB` round trip (3/4/5 rewritten as 9). Short-body and corrupt cases are better unit tests than goldens.
None of the UDP parsers (part B) is reachable through `--readscan`: it replays stored banner text only.

### C3. C runs needed for new goldens

1. Offline (oracle host, same procedure as `tests/golden/formats/README.md`): a banner `-oB` input written by an
   extended `format_inputs.rs`, `walk_records` extended for types 9/13 (and 3/4/5 if pinned), then `--readscan` for
   `-oL -oJ -oD -oG -oX -oB -oH -oU`, `--webxml`, `--output-format certs --output-filename`, the default format (stdout),
   `--banner-types <app>` and filter cases. No new clock masks: banner times come from the records.
2. Live (lab, C and rmasscan with the same `--seed`, `--banners`, one probe per port): responders that echo the probe's
   id fields with known answers - DNS CHAOS TXT `version.bind` (plus an rcode != 0 and a `qr = 0` variant), NBSTAT
   node status, SNMPv1 GetResponse for sysDescr/sysName (plus a v2c reply: no banner), NTP mode-7 monlist reply and
   error reply, CoAP ACK 2.05 with link-format, memcached UDP `stats`, ISAKMP main-mode SA reply; plus wrong-cookie
   variants. Capture C's `-oB` (raw payloads) and one text format; mask record times (capture clock); exclude or mask the
   raw* banners of port 11211 and unparsed ports (C1.1). The C `-oB` files can then serve as extra `--readscan` inputs.
3. Without a lab, the C self-test vectors give unit-test fixtures for the parsers: SNMP (`src/proto-snmp.c:627-670`),
   ISAKMP samples (`src/proto-isakmp.c:464-568`, expectations unenforced), CoAP (`src/proto-coap.c:646-733`),
   ZeroAccess (`src/proto-zeroaccess.c:263-304`).
