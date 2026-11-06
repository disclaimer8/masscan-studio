# masscan output formats recon (upstream masscan clone at commit 8e6b3b0)

All paths are under `src/`. `L` = line. Format strings are quoted verbatim from source (C escapes unexpanded).
"Inferred" marks anything not read directly. MASSCAN_VERSION = "1.3.9-integration" (masscan-version.h:3).

## 0. Dispatch skeleton (output.c)

- `struct OutputType { ext, create, open, close, status, banner }` (output.h:27-41). Per format: text_output "txt", json_output "json", ndjson_output "ndjson", grepable_output "grepable", xml_output "xml", binary_output "scan", hostonly_output "hostonly", unicornscan_output "uni", null_output "null". The ext string is never used for filenames.
- Format enum (masscan.h:50-65): Default=0x0, Interactive=0x1, List=0x2, Binary=0x4, XML=0x8, JSON=0x10, NDJSON=0x11, Nmap=0x20, ScriptKiddie=0x40, Grepable=0x80, Redis=0x100, Unicornscan=0x200, None=0x400, Certs=0x800, Hostonly=0x1000, All=0xFFBF.
- output_create (output.c:389-515) picks `funcs` by format (L435-472): List->text, Unicornscan, XML, JSON, NDJSON, Certs, Binary, Grepable, Redis, Hostonly, None->null, **default (incl. Default=0 and Interactive=1)->null_output**.
- Header ("open") is written LAZILY: only when the first record that survives all filters is written (output.c:867-870, `is_virgin_file`). **A scan with zero reported results produces a 0-byte file for every format** (no header). Footer ("close") is skipped if the file is still virgin (output.c:258-259). Inference consequence for Rust: header+footer only if >=1 record written.
- `out->when_scan_started = time(0)` at output_create (L398). Used by binary header, grepable header.
- Flush: `if (out->is_output_flush) fflush(fp);` after each status record (L878-879). Otherwise stdio buffering only (no explicit per-record flush); close does fflush+fclose (L267-268). Option `--output-flush` (bool, main-conf.c:2411, `SET_output_flush` L1630-1641).

## 1. Per-format bytes

Common helpers (output.c):
- `name_from_ip_proto` L71-82: 0->"arp", 1->"icmp", 6->"tcp", 17->"udp", 132->"sctp", else "err".
- `name_from_ip_version` L88-96: 4->"ipv4", 6->"ipv6", else "err".
- `status_string` L103-112: PortStatus_Open->"open", Closed->"closed", Arp->"up", else "unknown". Enum masscan-status.h:18-24: Unknown=0, Open=1, Closed=2, Arp=3.
- `reason_string(x, buf, n)` L118-136: `snprintf(buffer, n, "%s%s%s%s%s%s%s%s", (x&0x01)?"fin-":"", (x&0x02)?"syn-":"", (x&0x04)?"rst-":"", (x&0x08)?"psh-":"", (x&0x10)?"ack-":"", (x&0x20)?"urg-":"", (x&0x40)?"ece-":"", (x&0x80)?"cwr-":"")`; if empty -> returns "none"; else strips the last char (trailing '-'). Order is fixed fin,syn,rst,psh,ack,urg,ece,cwr. SYN-ACK flags byte 0x12 -> "syn-ack"; RST 0x04 -> "rst"; RST+ACK 0x14 -> "rst-ack".
- `ipaddress_fmt` (massip-addr.c:191-216): IPv4 = dotted decimal with no zero padding ("1.255.0.163"). IPv6 branch exists (ipv6address_fmt); not needed.
- `reason`/`ttl` passed to formats: reason = raw TCP flags byte `px[transport_offset+13]`, ttl = parsed.ip_ttl (main.c:1077-1085).

### 1.1 list (-oL) — out-text.c
- Header (L15): `fprintf(fp, "#masscan\n");`  (no time/version/argv)
- Status (L39-45): `fprintf(fp, "%s %s %u %s %u\n", status_string(status), name_from_ip_proto(ip_proto), port, fmt.string, (unsigned)timestamp);`  e.g. `open tcp 80 1.2.3.4 1700000000\n`. reason/ttl ignored. Closed identical with "closed".
- Footer (L24): `fprintf(fp, "# end\n");`
- Banner (not needed): L64 `"%s %s %u %s %u %s %s\n"` with "banner".

### 1.2 json (-oJ) — out-json.c
- Header (L14): `fprintf(fp, "[\n");`
- Status (L42-59), comma-prepend scheme:
  - if `out->is_first_record_seen`: `fprintf(fp, ",\n");` else set it =1 (first record: no leading comma).
  - `fprintf(fp, "{ ");`
  - `fprintf(fp, "  \"ip\": \"%s\", ", fmt.string);`
  - `fprintf(fp, "  \"timestamp\": \"%d\", \"ports\": [ {\"port\": %u, \"proto\": \"%s\", \"status\": \"%s\"," " \"reason\": \"%s\", \"ttl\": %u} ] ", (int) timestamp, port, name_from_ip_proto(ip_proto), status_string(status), reason_string(...), ttl);`  (adjacent string literals concatenate: `... \"status\": \"%s\", \"reason\": \"%s\", \"ttl\": %u} ] `)
  - `fprintf(fp, "}\n");`
  - Full record bytes: `{   "ip": "1.2.3.4",   "timestamp": "1700000000", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 57} ] }\n`  (note: `{ ` then two spaces before "ip" => three spaces after `{`; `"ip": "..." , ` then two spaces before "timestamp"). Timestamp is a quoted string; `%d` of (int)timestamp.
  - Record i>0 is preceded by `,\n` written right before `{ ` , so the file looks like `[\n{...}\n,\n{...}\n]\n`.
- Footer (L24): `fprintf(fp, "]\n");`
- Banner record: L124 format (not needed). Banner records share is_first_record_seen.

### 1.3 ndjson (-oD) — out-ndjson.c
- Header: none (L11-15 empty). Footer: none.
- Status (L38-50): `fprintf(fp, "{");` then `fprintf(fp, "\"ip\":\"%s\",", fmt.string);` then `fprintf(fp, "\"timestamp\":\"%d\",\"port\":%u,\"proto\":\"%s\",\"rec_type\":\"status\",\"data\":{\"status\":\"%s\"," "\"reason\":\"%s\",\"ttl\":%u}", (int)timestamp, port, name_from_ip_proto(ip_proto), status_string(status), reason_string(...), ttl);` then `fprintf(fp, "}\n");`
  - Bytes: `{"ip":"1.2.3.4","timestamp":"1700000000","port":80,"proto":"tcp","rec_type":"status","data":{"status":"open","reason":"syn-ack","ttl":57}}\n`  (no spaces, no commas between lines).
- Banner: L113 (rec_type "banner", data.service_name/banner) — later stage.

### 1.4 grepable (-oG) — out-grepable.c
- Header (L78-108):
  - `safe_gmtime(&tm, &out->when_scan_started); strftime(timestamp, 64, "%c", &tm);`  (always GMT, regardless of is_gmt; %c is locale-dependent; masscan never calls setlocale (grep found none) so it is the C locale: `%a %b %e %H:%M:%S %Y`, e.g. `Tue Jan 21 20:23:22 2014`; the %e space-padding is inferred from libc, not read in tree.)
  - L84: `fprintf(fp, "# Masscan " MASSCAN_VERSION " scan initiated %s\n", timestamp);`  -> `# Masscan 1.3.9-integration scan initiated Tue Jan 21 20:23:22 2014\n`
  - L87-90: `count = count_type(&ports, Templ_TCP, Templ_TCP_last);` (Templ_TCP=0, last=65535; massip-port.h:12-13) `fprintf(fp, "# Ports scanned: TCP(%u;", count); if (count) print_port_list(ports, Templ_TCP, fp);`
  - print_port_list (L42-62): iterates ALL ranges in the list, clamps to [type, type+65535], skips non-overlapping, prints `fprintf(fp, "%u-%u%s", r.begin, r.end, (i+1<ports->count)?",":"")` — note separator test uses index in the WHOLE list (incl. UDP/SCTP ranges), so a trailing comma can appear when later non-TCP ranges exist. A single port is printed as `80-80`. Begin/end are NOT rebased for UDP type (bug, irrelevant).
  - L93 `fprintf(fp, ") UDP(%u;", count); if (count) print_port_list(..., Templ_UDP, fp);` (Templ_UDP=65536, last=65536+65535)
  - L99 `fprintf(fp, ") SCTP(%u;", count); ...` (Templ_SCTP=65536*2)
  - L104 `fprintf(fp, ") PROTOCOLS(%u;", count); ...` (Templ_Oproto_first=65536*3+256..Templ_Oproto_last)
  - L108 `fprintf(fp, ")\n");`
  - TCP-only scan of -p80,443: `# Ports scanned: TCP(2;80-80,443-443) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n` (assuming no later ranges; ranges list is sorted/merged by masscan's RangeList: adjacent ports merge, e.g. -p80-81 -> `80-81`).
- Status (L157-169): `fprintf(fp, "Timestamp: %llu", (unsigned long long)timestamp);` `fprintf(fp, "\tHost: %s ()", fmt.string);` `fprintf(fp, "\tPorts: %u/%s/%s/%s/%s/%s/%s\n", port, status_string(status), name_from_ip_proto(ip_proto), "", service, "", "");`
  - Bytes: `Timestamp: 1700000000\tHost: 1.2.3.4 ()\tPorts: 80/open/tcp//http//\n` (tab = 0x09). Service for TCP = `tcp_service_name(port)` (out-tcp-services.c): caches `getservbyport_r(htons(port),"tcp")` result (Linux) / `getservbyport` (others), returns "unknown" if not found. **Depends on the host's /etc/services (or macOS netdb)** — a Rust port must decide: libc getservbyport via FFI, or embedded table. For UDP `udp_service_name`, else `oproto_service_name`.
- Footer (L119-132): `time_t now = time(0); safe_gmtime; strftime("%c")` -> `fprintf(fp, "# Masscan done at %s\n", timestamp);` (time of close, GMT).
- Banner: L193-200 (`"Host: %s ()"`, `"\tPort: %u"`, `"\tService: %s"`, `"\tBanner: %s\n"`) — later.

### 1.5 xml (-oX) — out-xml.c (all line endings are CRLF "\r\n")
- Header (L15-28):
  - `fprintf(fp, "<?xml version=\"1.0\"?>\r\n");`
  - `fprintf(fp, "<!-- masscan v1.0 scan -->\r\n");`
  - if `out->xml.stylesheet && out->xml.stylesheet[0]`: `fprintf(fp, "<?xml-stylesheet href=\"%s\" type=\"text/xsl\"?>\r\n", out->xml.stylesheet);`  (source: `--stylesheet <url>` or `--webxml` => "http://nmap.org/svn/docs/nmap.xsl", main-conf.c:3033-3034; no "--no-stylesheet" handling found beyond being listed as singleton at main-conf.c:3075)
  - `fprintf(fp, "<nmaprun scanner=\"%s\" start=\"%u\" version=\"%s\"  xmloutputversion=\"%s\">\r\n", "masscan", (unsigned)time(0), "1.0-BETA", "1.03");`  -> NOTE two spaces before `xmloutputversion`; `start` is **time(0) at header-write time** (i.e. at first record), NOT when_scan_started.
  - `fprintf(fp, "<scaninfo type=\"%s\" protocol=\"%s\" />\r\n", "syn", "tcp");`
- Status (L73-90): `"<host endtime=\"%u\">" "<address addr=\"%s\" addrtype=\"%s\"/>" "<ports>" "<port protocol=\"%s\" portid=\"%u\">" "<state state=\"%s\" reason=\"%s\" reason_ttl=\"%u\"/>" "</port>" "</ports>" "</host>" "\r\n"` args: (unsigned)timestamp, fmt.string, name_from_ip_version(ip.version) ("ipv4"), name_from_ip_proto, port, status_string, reason_string, ttl.
  - One line per record, no whitespace: `<host endtime="1700000000"><address addr="1.2.3.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="57"/></port></ports></host>\r\n`
- Footer (L37-59): `now = time(0)`; `if (out->is_gmt) safe_gmtime else safe_localtime`; `strftime(buffer, 256, "%Y-%m-%d %H:%M:%S", &tm)` (**local time by default**; is_gmt is never set by any option, see section 5); then `"<runstats>\r\n" "<finished time=\"%u\" timestr=\"%s\" elapsed=\"%u\" />\r\n" "<hosts up=\"%" PRIu64 "\" down=\"%" PRIu64 "\" total=\"%" PRIu64 "\" />\r\n" "</runstats>\r\n" "</nmaprun>\r\n"` args: (unsigned)now, buffer, (unsigned)(now - out->rotate.last), counts.tcp.open, counts.tcp.closed, open+closed.
  - `elapsed` = now - rotate.last, where rotate.last = time(0) at output_create after file open (output.c:489) => seconds since file open (NOT since first record). `up` = number of TCP open records counted (counts incremented BEFORE the show filter at output.c:819-855 only after top-level filter; so with default settings: closed never counted, `down="0"`). Counts for non-TCP go to other buckets and don't appear.
  - counts are reset at close_rotate (memset L261) AFTER footer, so they are per-file.
- Banner: L113-122 — later.

### 1.6 hostonly (-oH) — out-hostonly.c
- Header/footer: none.
- Status (L39): `fprintf(fp, "%s\n", fmt.string);` — IP only, one per record; open AND closed (status ignored; duplicates per port are NOT deduped: one line per (ip,port) record).
- Banner (L62): also prints `"%s\n"` of ip (a banner record emits an extra IP line).

### 1.7 unicornscan (-oU) — out-unicornscan.c
- Header (L16): `fprintf(fp, "#masscan\n");`  Footer (L24): `fprintf(fp, "# end\n");`
- Status TCP (L36-42): `fprintf(fp,"TCP %s\t%16s[%5d]\t\tfrom %s  ttl %-3d\n", status_string(status), tcp_service_name(port), port, fmt.string, ttl);`
  - e.g. `TCP open\t            http[   80]\t\tfrom 1.2.3.4  ttl 57 \n` (service right-aligned width 16; port right-aligned width 5 as %d; "ttl " then ttl left-aligned width 3 => trailing spaces; two spaces before "ttl"). Same getservbyport dependency as grepable.
- Non-TCP branch L45-54: grepable-style (not needed).
- Banner: no-op (L66-78).

### 1.8 null / none — out-null.c
- All hooks empty. `--output-format none` (Output_None) maps to null_output. Also: `output_create` skips opening any file when `out->funcs == &null_output` (output.c:479) even if a filename was given. Default (format 0) and `interactive` also select null_output.
- Redis (-oR) and certs: out of scope.

### 1.9 binary (-oB) — out-binary.c; record ids out-record.h; reader in-binary.c
Everything big-endian ("network order") via explicit shifts.
- Header, binary_out_open (L11-29): buffer of `2+'a'` = **99 bytes** zero-filled; `snprintf(firstrecord, 2+'a', "masscan/1.1\ns:%u\n", (unsigned)out->when_scan_started)`; fwrite all 99 bytes. Layout: `masscan/1.1\n` (12 bytes) + `s:<decimal start time>\n` + zero padding to 99. Start time = output_create time(0) (host-rendered decimal ASCII). On fwrite short: `perror("output"); exit(1);`.
- Footer, binary_out_close (L34-50): 99 bytes: `snprintf(buf, 99, "masscan/1.1")` then zeros (i.e. "masscan/1.1" + 88 NULs). The reader consumes this as a record of type 'm'(0x6D), length 'a'(0x61=97), 97 body bytes = 99 total, case 'm' ignored (in-binary.c `case 'm': /* FILEHEADER */`). (Elegant coincidence; byte-exact reproduction just needs 99 bytes.)
- Record enum (out-record.h): Out_Open=1, Out_Closed=2, Out_Banner1=5, Out_Open2=6, Out_Closed2=7, Out_Arp2=8, Out_Banner9=9, Out_Open6=10, Out_Closed6=11, Out_Arp6=12, Out_Banner6=13.
- IPv4 status record (binary_out_status L154-211), **15 bytes** total:

| off | size | field |
|---|---|---|
| 0 | 1 | type: Out_Open2 (6) for open, Out_Closed2 (7) closed, Out_Arp2 (8) arp; other status -> nothing written |
| 1 | 1 | length = 13 (body bytes after this 2-byte prefix) |
| 2 | 4 | timestamp, u32 BE (low 32 bits of time_t) |
| 6 | 4 | ipv4, BE |
| 10 | 1 | ip_proto (6 for TCP) |
| 11 | 2 | port BE |
| 13 | 1 | reason = raw TCP flags byte (0x12 for SYN-ACK, 0x04 RST, 0x14 RST+ACK) |
| 14 | 1 | ttl |

  - `out->rotate.bytes_written += 15`. No MAC for TCP (ARP records have extra? binary_out_status writes only 15 bytes even for ARP, so MAC not stored — inferred from code, not needed).
  - No flush besides is_output_flush.
- IPv6 status (L103-149): type 10/11/12, length 26: ts u32, proto u8, port u16, reason u8, ttl u8, ip.version u8, hi u64, lo u64 (not needed).
- Banner records (later stage): Out_Banner9 (9) v4: type, varint length (1 byte if `length+14 < 128` else 2 bytes `(len>>7)|0x80, len&0x7F`; records with `length >= 128*128-14` dropped), then ts4, ip4, proto1, port2, app_proto2, ttl1 (=14 header bytes) + payload. Banner6 (13): header 27. These plug in at `binary_out_banner` (L294-355) via output_report_banner (output.c:886-956; gated by `out->is_banner`). Status records (type 6/7) and banner records are interleaved in arrival order.
- Reader (--readscan), in-binary.c:
  - CLI: `--readscan f1 f2 ...` sets `masscan->op = Operation_ReadScan`, `is_banners = true`, `is_banners_rawudp = true`, then swallows following args not starting with '-' (main-conf.c:3266-3278). main.c:1764 `case Operation_ReadScan` finds files after `--readscan` and calls `readscan_binary_scanfile` (in-binary.c:~650-691) which does `out = output_create(masscan, 0)` (so all -oX/-oJ/... options apply to the converted output), sets `out->when_scan_started = 0`, runs `_binaryfile_parse` per file, then `output_destroy(out)`.
  - `_binaryfile_parse` (in-binary.c ~L470-640): fopen "rb"; error: `fprintf(stderr, "[-] FAIL: --readscan\n"); fprintf(stderr, "[-] %s: %s\n", filename, strerror(errno));`. Reads 'a'+2 = 99 bytes; requires `memcmp(buf,"masscan/1.1",11)==0` else LOG(0, "[-] %s: unknown file format (expected \"masscan/1.1\")\n"). The "start time" block is guarded by `buf[11]=='.'` which is false for our own files (buf[11]=='\n') so it is dead for files this version writes (inferred); `when_scan_started` is instead set from the first status record's timestamp (parse_status*: `if (out->when_scan_started == 0) out->when_scan_started = record.timestamp;`).
  - Loop: type = 1-byte varint (bit7 continuation, 7-bit groups); length = 1-byte varint likewise; `length > BUF_MAX(1 MiB)` -> "[-] file corrupt"; reads `length` bytes; short read = stop. Dispatch: 1 open(v1), 2 closed(v1), 3 banner3, 4 banner4 (reads 1 extra byte), 5 banner4, 6 parse_status2 open, 7 parse_status2 closed, 9 banner9, 10/11 status6, 13 banner6, 'm' ignored, default -> "[-] file corrupt: unknown type %u" and stop. (Type 8 Arp2/12 Arp6 hit default = "file corrupt".) status records are skipped when `btypes->count` (a banner-type filter) is set.
  - parse_status2 (in-binary.c ~L100-150): needs buf_length>=13; reads ts,ip,proto,port,reason,ttl; if ip==0 and len>=19 copies MAC; applies target filters (`filter->count_ipv4s` -> massip_has_ip; `count_ports` -> massip_has_port); calls `output_report_status(out, record.timestamp, status, ip, proto, port, reason, ttl, mac)` — so the ORIGINAL record timestamp is passed through and the output goes through the same formatter path. Legacy v1 records (types 1/2) infer proto from port numbers (53,123,137,161 -> UDP; 36422,36412,2905 -> SCTP; else TCP).
  - Progress: `LOG(0, "[+] %s: %8" PRIu64 "\r", ...)` every 65536 records; `LOG(0, "[+] --readscan %s\n", filename)` per file.
  - Cost judgement: writer is trivial (99+15n+99 bytes). Reader for status-only records (types 6/7 + skip 'm', error on others) is ~60 lines; banner types 3/4/5/9/13, IPv6 (10/11), and the filter/btypes hooks are the extra surface. Reasonable to port -oB writer now and a status-only --readscan next.

## 2. output_report_status control flow (output.c:746-880)

Signature: `output_report_status(out, timestamp, status, ip, ip_proto, port, reason, ttl, mac[6])`.
1. `fp = out->fp; now = time(0); global_now = now;` (L752-755; global_now updated AFTER the `timestamp` argument was already captured by the caller).
2. Filters (L759-762): `if (!out->is_show_closed && status == PortStatus_Closed) return; if (!out->is_show_open && status == PortStatus_Open) return;`  (nothing is counted if filtered here).
3. Interactive branch (L766-803): condition `out->is_interactive || out->format == 0 || out->format == Output_Interactive`.
   - TCP/default proto (L781-786): `fprintf(stdout, "Discovered %s port %u/%s on %s", status_string(status), port, name_from_ip_proto(ip_proto), fmt.string)` -> `Discovered open port 80/tcp on 1.2.3.4`. (ARP variant L771: `"Discovered %s port %u/%s on %s (%02x:%02x:%02x:%02x:%02x:%02x) %s"` — not needed.)
   - Padding (L791-794): `count = fprintf(...)` = chars printed; `if (count < 80) fprintf(stdout, "%.*s", (int)(79-count), <84 spaces>);` then `fprintf(stdout, "\n"); fflush(stdout);`  So the line is padded with spaces to 79 columns then "\n" (no "\r"); lines >= 80 chars get no padding. Purpose: overwrite the stderr "%done" status line. Flushed every line.
   - `else if (fp == NULL)` (L799-803): `ERRMSG("no output file, use `--output-filename <filename>` to set one\n"); ERRMSG("for `stdout`, use `--output-filename -`\n"); return;` — ERRMSG (util-errormsg.c) prefixes `"[-] ERR: "` on stderr and dedups repeats by format-string pointer (prints each once, effectively). The record is dropped (not counted). Reached when a non-default format is set without a filename and not interactive (e.g. `--output-format json` alone).
   - If interactive AND a file is open: both happen (stdout line, then file record). If interactive and fp==NULL with a real format (e.g. `--output-format json --interactive`): falls through to `out->funcs->open(out, NULL)` -> fprintf(NULL) crash (inferred, not run). With default format 0 / Interactive, funcs==null_output so the file hooks are no-ops.
4. Rotation (L810-814): `if (is_rotate_time(out, now, fp)) { fp = output_do_rotate(out, 0); if (fp == NULL) return; }`. is_rotate_time (L668-679): false if virgin; true if `now >= rotate.next` or (`rotate.filesize != 0 && ftell(fp) >= filesize`). Default rotate.next = LONG_MAX.
5. Counters (L819-862): Open: ip_proto 1->icmp.echo, 6->tcp.open, 17->udp.open, 132->sctp.open, else oproto.open; then `if (!out->is_show_open) return;` Closed: 6->tcp.closed etc.; `if (!out->is_show_closed) return;`. Arp -> arp.open. Other status -> `LOG(0, "unknown status type: %u\n", status); return;`
6. Lazy header (L867-870): `if (out->is_virgin_file) { out->funcs->open(out, fp); out->is_virgin_file = 0; }`
7. `out->funcs->status(out, fp, timestamp, status, ip, ip_proto, port, reason, ttl);` (L876)
8. `if (out->is_output_flush) fflush(fp);` (L878)

### Option semantics
- Defaults (main.c:1596-1597): `is_show_open = 1`, `is_show_closed = 0`, `is_show_host = 0`, `is_status_updates = 1`, `is_interactive = 0`, `is_append = 0`, `is_output_flush = 0`. (RST -> Closed records are dropped by default.)
- `--open` / `--open-only` (bool, main-conf.c:2409, SET_output_show_open L1795-1806): show_open=1, show_closed=0, show_host=0 (just restores the default; also singleton at L3074).
- `--show <list>` aliases `--output-status`, `--output-show` (L2407; SET_output_show L1745-1790): comma list of `open`, `closed`|`close`, `host`, `all` setting each to 1; unknown item -> `LOG(0, "FAIL: unknown 'show' spec: %.*s\n", len, val); exit(1);`.
- `--noshow <list>` / `--output-noshow` (SET_output_noshow L1712-1743): same tokens, sets to 0; unknown -> `LOG(0, "FAIL: unknown 'noshow' spec: %.*s\n", ...); exit(1);`.
- is_show_host: only copied into Output; not consulted by any TCP-port format path (inferred: grep shows only the struct field).

## 3. output_create / destroy / open_rotate / close_rotate

- output_create (L389-515): CALLOC; copies masscan->output.* into `out` (rotate period/offset/filesize, redis, is_banner, is_gmt, is_interactive, is_show_*, is_append, is_output_flush, stylesheet, rotate dir; filename = copy, or `indexed_filename(name, thread_index)` ("foo.01.bar") if `nic_count > 1`; out->src[8] copied from nic[i].src). Opens the file immediately iff `masscan->output.filename[0] && out->funcs != &null_output` (L479): `fp = open_rotate(out, filename); if (fp==NULL) { perror(filename); exit(1); }`; `out->fp = fp; out->rotate.last = time(0);`. NB: open uses `masscan->output.filename` (un-indexed) for the first open even with multiple NICs.
- open_rotate (L180-239): "-" exactly -> `fp = stdout` (no fopen; stdout is NOT closed... actually close_rotate does fclose(fp) on it at exit). Else `pixie_fopen_shareable(&fp, filename, is_append)` -> `fopen(filename, is_append ? "a" : "w")` on non-Windows (pixie-file.c:60). On failure: `fprintf(stderr, "out: could not open file for %s\n", is_append?"appending":"writing"); perror(filename); is_tx_done = 1; return NULL;` then output_create does `perror(filename)` again and `exit(1)`. So stderr shows: `out: could not open file for writing\n<filename>: <strerror>\n<filename>: <strerror>\n`, exit status 1. Sets `out->is_virgin_file = 1`.
- Append mode (`--append-output` / `--output-append`, alias `append-output`, `overwrite` handled L1621-1625 by name "overwrite" or false value): just fopen "a"; a new header is written again at first record, so appended JSON/XML/binary files get concatenated documents (inferred consequence).
- close_rotate (L247-269): `if (!out->is_virgin_file) out->funcs->close(out, fp); memset(&out->counts,0,...); fflush; fclose` (Redis skipped).
- output_destroy (L962-988): if `rotate.period || rotate.filesize` -> `LOG(1,"doing finale rotate\n"); output_do_rotate(out, 1);` ; then `if (out->fp) close_rotate(out, out->fp);` free. Called when the receive thread ends (main.c; also readscan).
- --rotate summary: `--rotate <time>` (aliases output-rotate, rotate-output, rotate-time; parseTime e.g. "hourly"/seconds) period; `--rotate-offset`; `--rotate-dir <dir>` (aliases output-rotate-dir, rotate-directory; default "."; trailing / \\ stripped); `--rotate-size <size>` (aliases output-rotate-filesize, rotate-filesize). Rotation happens inline on the next record after the deadline (or size via ftell). The file is renamed while open to `<dir>/YYMMDD-HHMMSS-<basename>` (name based on `rotate.last`, localtime unless is_gmt; with filesize: `<dir>/<stem>-NNNNN<ext>` using filecount) then a fresh file is opened, old one closed (footer written), new header lazily on next record. Failure to rename: `LOG(0,"rename(\"%s\", \"%s\"): failed\n")` + perror, keeps old file. Safe to defer.

## 4. Option parsing (main-conf.c)

Single-dash `-o?` block (L3401-3459):
- `-oA` -> sets Output_All, stderr `nmap(-oA): unsupported output format`, exit(1). `-oN`, `-oS` -> same message pattern `nmap(%s): unsupported output format\n` (argv[i] printed, e.g. `-oN`), exit(1). Unknown letter (`-oZ`, bare `-o`): `nmap(%s): unknown output format\n`, exit(1). The message is printed BEFORE the filename check.
- `-oB` binary, `-oD` ndjson, `-oJ` json, `-oX` xml, `-oG` grepable set `output.format` directly; `-oL` -> `masscan_set_parameter(.., "output-format","list")`, `-oU` -> "unicornscan", `-oH` -> "hostonly"; `-oR` -> Output_Redis (+ optional `redis` target if next arg doesn't start with '-').
- After the letter: `++i; if (i >= argc || (argv[i][0] == '-' && argv[i][1] != '\0')) { fprintf(stderr, "missing output filename\n"); exit(1); }` then `masscan_set_parameter(masscan, "output-filename", argv[i]);`  => filename is ALWAYS the next argv element (`-oXfoo` is not supported: the 3rd char is ignored beyond the letter). A lone "-" is allowed (stdout). Anything else starting with '-' is rejected.
- Long forms: `--output-format <f>` (SET_output_format L1659-1711; values: unknown(0)->Interactive, interactive, list, unicornscan, xml, binary, greppable, grepable, json, ndjson, certs, none, redis, hostonly; unknown -> `LOG(0, "FAIL: unknown output-format: %s\n", value); LOG(0, "  hint: 'binary', 'xml', 'grepable', ...\n"); return CONF_ERR;` BUT masscan_set_parameter ignores the return value of config setters (main-conf.c:2480-2493), so execution continues with format unchanged and exit code NOT forced non-zero (inferred from the call site)). `--output-filename <f>` aliases `--output-file` (L2405). No `-oF`.
- SET_output_filename (L1643-1657): `if (output.format == 0) output.format = Output_XML;` ("TODO: Why is the default XML?") then copies the filename. So `--output-filename x` alone => XML. Likewise `--stylesheet` with format 0 -> XML (L2101-2102). Also `-oX`-style flags set the format first, so order does not matter except `--output-format` after `--output-filename` overrides.
- Other: `--output-flush` (bool), `--output-append`/`--append-output`/`--overwrite`(name check), `--show/--output-status/--output-show`, `--noshow/--output-noshow`, `--open/--open-only`, `--rotate*` (above), `--stylesheet <url>`, `--webxml`, `--interactive` / `--nointeractive` (main-conf.c:2838-2841, set `output.is_interactive` 1/0), `--status` / `--nostatus` (L2842-2845, `output.is_status_updates`), `--ndjson-status` (alias status-ndjson, bool; sets `is_status_ndjson`), `--json-status` (alias status-json) -> prints `[-] FAIL: %s not supported, use --status-ndjson` + hint, returns CONF_ERR (ignored), `--readscan`. No `--gmt` / `--quiet` option exists (is_gmt declared masscan.h:193 but never assigned anywhere; grep confirms).
- Interactive-line rule (answer to "is Discovered still printed with -o?"): **No, not by default.** `is_interactive` defaults to 0 and is only set by `--interactive`; the "Discovered ..." line is printed iff `is_interactive || format == 0 || format == Output_Interactive` (output.c:766). Any -oX/-oL/-oJ/... sets a non-zero format, so with a file format stdout is silent unless `--interactive` is given. With no -o option at all (format 0) the lines are printed to stdout and nothing is written to a file (null_output).

## 5. Timestamps

- Receive path caller: main.c:1077-1085:
  `output_report_status(out, global_now, status, ip_them, 6, port_them, px[parsed.transport_offset + 13], parsed.ip_ttl, parsed.mac_src);`
- `global_now` (main.c:94, `time_t`) is a coarse wall-clock (seconds) cache, written at: main() start (main.c:1576 `global_now = time(0)`), status_print every call (main-status.c:136, i.e. ~every 750 ms during TX, ~250 ms during the wait phase, only if status updates enabled), and inside output_report_status itself (output.c:755), but AFTER the caller already evaluated the argument. Consequence: the timestamp of record N is the time of the last status tick or of record N-1's report, whichever is later (can lag real receipt by up to ~1 s with status enabled; with `--nostatus` it lags by an arbitrary gap, first record gets the program start time). It is NOT time(0) at receipt. A Rust port can reproduce exactly: keep an atomic `global_now`, update it at start / on status ticks / at the top of each report call, pass the OLD value.
- Rendering: list `%u` of (unsigned)ts; json/ndjson `\"%d\"` (int cast, quoted); grepable `%llu` (unsigned long long); xml `endtime=\"%u\"`; binary low 32 bits BE. Epoch seconds, always UTC-independent.
- --gmt: no CLI/config option sets `is_gmt` (grep shows only masscan.h:193, output.c:412, output.c:568, out-xml.c:41), so effective value is always 0: XML footer `timestr` uses localtime; rotation filenames use localtime. Grepable header/footer always use gmtime regardless. Epoch timestamps are unaffected.

## 6. stderr status line (main-status.c:25-270) and run banner

Printing conditions (main.c:1399-1544): loop `while (!is_tx_done && output.is_status_updates)` calling `status_print` then `pixie_mssleep(750)`; in the wait phase `status_print(... exiting = wait - (time(0)-now), ...)` then `pixie_mssleep(250)`. **No isatty() check** (always stderr). Disabled by `--nostatus` (and default is on). `status_print` returns early without printing if elapsed_time <= 0. The wait phase length = `--wait` (default 10 s, main.c:1598).
Rate = smoothed over last 8 samples (status->last_rates ring of 8, averaged, L160-170); `percent_done = count*100.0/max_count`; `time_remaining = (1.0 - percent_done/100.0) * (max_count / rate)`. `pps` argument = sum of throttler current_rate.
All use `fprintf(stderr, fmt,...); fflush(stderr);` with trailing `\r` (no newline):
- Running (L247): `"rate:%6.2f-kpps, %5.2f%% done,%4u:%02u:%02u remaining, found=%" PRIu64 "       \r"` args: pps/1000.0, percent_done, (unsigned)(tr/3600), (unsigned)(tr/60)%60, (unsigned)tr%60, total_synacks.
- Waiting after TX done (L230): `"rate:%6.2f-kpps, %5.2f%% done, waiting %d-secs, found=%" PRIu64 "       \r"` args: pps/1000.0, percent_done, (int)exiting, total_synacks.
- Infinite (`--infinite`) (L214): `"rate:%6.2f-kpps, syn/s=%.0f ack/s=%.0f tcb-rate=%.0f, %" PRIu64 "-tcbs,         \r"`. 
- `--ndjson-status` variants (L56-125): json_fmt_infinite / json_fmt_waiting / json_fmt_running, each ending `}\n` (newline, no \r); quoted verbatim in source — e.g. running: `{"state":"running","rate":{"kpps":%.2f,"pps":%7$.2f},"progress":{"percent":%.2f,"eta":{"hours":%u,"mins":%u,"seconds":%u},"syn":{"sent":%8$,"total":%9$,"remaining":%10$},"found":%6$}}\n` (positional args).
- "found=" = total_synacks (SYN-ACK count), not including RSTs. "--banners" does not change the format string (only total_tcbs used in infinite mode).
- No --banners variant exists; no "kpps" difference besides above.
- At end: `status_finish` (L278-279) prints 77 spaces + `\r` to stderr to blank the line: `"                                                                             \r"`.
- If `!is_status_updates`: after threads join, `printf("%u milliseconds elapsed\n", ...)` to STDOUT (main.c:1548-1552).
- Start-up lines via LOG(0,...) -> stderr (util-logger.c): `"Starting masscan " MASSCAN_VERSION " (http://bit.ly/14GZzcT) at %s\n"` with `%Y-%m-%d %H:%M:%S GMT` (main.c:1351-1353); then `"Initiating SYN Stealth Scan\n"` and `"Scanning %u hosts [%u port%s/host]\n"` (count_ips, count_ports, "" if 1 else "s") (main.c:1366-1368); ICMP-only variant `"Initiating ICMP Echo Scan\n"` / `"Scanning %u hosts\n"`. (Also `"[+] waiting for threads to finish\n"` only at LOG level 1.) These are not part of port-record output but appear on stderr; stdout stays clean for `-oX -`/`-oL -`.

## 7. Source/adapter dependencies

- `out->src[8]` (copied from masscan->nic[i].src, output.c:426-428) is not referenced by any out-*.c status path read here (none of text/json/ndjson/grepable/xml/binary/hostonly/unicornscan touch `out->src`). Does not matter for TCP SYN records.
- `mac[6]`/`oui_from_mac` (output.c:686-739) used only in the ARP interactive branch (L770-779, ip_proto == 0). Irrelevant to TCP.
- `out->masscan` is used only in grepable header (target port list). `out->is_banner` gates banner output only.
- Dedup of duplicate SYN-ACKs happens before output (main.c:1067), cookie validation at 1060: so the output layer never dedups.

## 8. Rust port checklist (bytes that are easy to get wrong)
1. Lazy header; 0 results => 0-byte file; footer only if >=1 record written.
2. JSON: `,\n` before every record except first; record text has 3 spaces after `{` and 2 spaces before `"timestamp"`; trailing space before `}`; timestamp quoted.
3. NDJSON: no header/footer, compact.
4. XML: CRLF, double space before xmloutputversion, `start` = time at header write, footer elapsed = now - file-open time, local-time timestr, up/down counts (TCP only).
5. Grepable: `%c` time in GMT; TCP(n;a-b,...) quirks; service names from host services DB.
6. Binary: 99-byte header with `s:<ts>\n`, 15-byte v6/v7 records, 99-byte footer.
7. Timestamp = stale global_now (see section 5).
8. Interactive "Discovered" line only without -o (or --interactive); padded to 79 columns; stdout; flushed per line.
9. Reason string order fin,syn,rst,psh,ack,urg,ece,cwr joined by '-'; "none" if 0.
10. `-oX` etc. take filename from NEXT argv; errors: `missing output filename` / `nmap(%s): unsupported output format` (exit 1).
