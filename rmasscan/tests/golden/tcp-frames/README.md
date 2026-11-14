# TCP stack frame goldens from the pinned C masscan

Offline parity of `rmasscan_core::tcp_frame::TcpFrameBuilder::build` (`crates/rmasscan-core/src/tcp_frame.rs`) with
masscan's `tcp_create_packet` (`src/templ-pkt.c:419-613`, masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`): every
frame the user-mode stack sends (ACK `0x10`, data `0x18`, data+FIN `0x19`, resent FIN `0x11`, RST `0x04`) over the
default TCP template and over templates with each `--tcp-*` option and `--ttl`, IPv4 and IPv6. Banners sub-stage 4b,
task 3 (`docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tcp.md` A6, A7, E1.10, E4; design R14). The
test `crates/rmasscan-core/tests/tcp_frames.rs` rebuilds every frame and compares it with C's.

## The oracle

`tcp-frame-oracle` is a small C driver linked with the unmodified sources of the pinned commit: `templ-pkt.c`,
`templ-tcp-hdr.c`, `proto-preprocess.c`, `proto-sctp.c`, `util-checksum.c` and their helpers (`syn-cookie.c`,
`crypto-siphash24.c`, `util-malloc.c`, `util-safefunc.c`, `util-logger.c`, `pixie-timer.c`, `massip-addr.c`; the list
and every file's sha256 are in `manifest.json`). Two symbols of other units are stubs that abort if called, and no
TCP frame reaches either: `output_report_status` (called by `handle_sctp`) and `payloads_udp_lookup` (UDP probes).

For one case the driver does what masscan does for a stack frame: `template_packet_init` with the case's
`TemplateOptions` (`src/main.c:1301-1310`), `template_set_ttl` when the case sets `--ttl` (`:1328-1329`), then per
frame `tcp_create_packet(&tmplset.pkts[Proto_TCP], ...)` into a 2040-byte buffer (`sizeof(response->px)`,
`src/stack-queue.h:13`) and `tcp_set_window` when the frame sets a window (`src/stack-tcp-core.c:1163-1164`).

C is not allowed in this repository (`crates/rmasscan-lab/tests/rust_only.rs`), so the driver, its build script and
the runner live off the repository next to the oracle host's masscan clone (R14). `manifest.json` records their
sha256, the binary's sha256, the compiler and the masscan commit; the build script refuses a clone that is not at the
pin or is dirty and copies the sources before compiling (the clone is never modified).

## Regenerate

1. Inputs: `RMASSCAN_TCP_FRAMES_INPUTS=DIR cargo test -p rmasscan-core --test tcp_frames inputs_match_generator`
   writes `DIR/cases/<case>.in.txt` and `DIR/cases.tsv` (name, link, frame count, description) from the generator in
   the test. Without the variable the test fails if the generator and `cases/*.in.txt` drift apart.
2. On the oracle host: `build.sh` (binary and `BUILDINFO` from the pinned clone), then `run-goldens.sh DIR OUT` with a
   fresh `mktemp -d /tmp/rmasscan-tcpframes.XXXXXX` as `OUT`: every case through the oracle (10-second timeout each),
   then `OUT/golden/{manifest.json,cases/*}`. Under a second.
3. Copy `OUT/golden` here, check the sha256 in the manifest, run the privacy scan over this directory (host names,
   user names, local paths, LAN addresses), delete the host's temporary directory.

## Layout and format

- `cases/<case>.in.txt`: the oracle input, one directive per line (`#` lines are comments):

  ```
  tcp-frame-input v1
  link ethernet|null|raw
  macs src=XX:XX:XX:XX:XX:XX router4=XX:.. router6=XX:..
  template mss=default|off|N sackok=0|1 wscale=-|N tsecho=-|0xN ttl=-|N
  frame v4|v6 them=HEX port_them=N me=HEX port_me=N seq=0xN ack=0xN flags=0xN window=-|N payload=LEN:SEED
  ```

  `mss=default` keeps the template's MSS 1460 (no `--tcp-mss`), `off` is `--tcp-mss false`. Addresses are 8 (IPv4) or
  32 (IPv6) hex digits. Payload byte `k` is `(SEED + 131 * k) & 0xFF`. `them`/`port_them` are `tcp_create_packet`'s
  `ip_them`/`port_them` (the frame's destination), `me`/`port_me` its source.
- `cases/<case>.out`: C's frames, `tcp-frame-oracle v1 frames=N` and then one `frame I len=L HEX` line per frame.
- `manifest.json`: the oracle block above, `host` (OS and kernel only), `captured_at`, and per case `about`, `link`,
  `frames`, input and output sha256.

## What the goldens show (C at 8e6b3b0)

21 cases, 352 frames (the test asserts both). Eight templates on Ethernet, each for IPv4 and IPv6: the default (MSS
1460), `--tcp-mss 1400`, `--tcp-mss false` (no options, data offset 5), `--tcp-sackok`, `--tcp-wscale 7`,
`--tcp-tsecho` (C's default value 0x12345678), `--ttl 64`, and all of them at once (data offset 10). Each case has the
five stack flags with payloads of 0, 1 and 1400 bytes (the stack's segment size, reference A3), a frame of all-ones
addresses, ports and numbers, one of all zeros and, for IPv4, a frame with window 600. Raw IP (no link header): the
default and the option-less template, IPv4 and IPv6. One case holds the E1.10 vector.

C behaviour reproduced as it is (deterministic, R1): the frame is a copy of the scan's SYN template, so it carries
the SYN's TCP options and data offset, and TTL, TOS and DF of IPv4; the window is 1200 in every frame
(`src/templ-pkt.c:497-498`, the SYN's is 1024); the flags byte is overwritten whole (`:495`); IP ID is
`(ip_them ^ port_them ^ seqno) & 0xFFFF` (`:432`); an IPv4 frame shorter than 60 bytes is padded with zeros to 60 on
every link, raw IP included, while the IP total length stays (`:509-512`); IPv6 is never padded and its hop limit is
always 255, `--ttl` included (`template_set_ttl` touches only the IPv4 template, `:1473-1488`).

Named differences (the test derives C's frame from rmasscan's for each and compares that byte for byte):

- E1.10, IPv4 header checksum (R1 class г): C updates the template's partial sum with the IP ID, both addresses as
  whole 32-bit numbers and the length increase in a `uint64_t` and folds it only twice (`src/templ-pkt.c:466-473`);
  when the second fold carries, the stored sum is wrong. Vector: `ip_me=0xd5a30aac ip_them=0x4ba3e552 port_them=55289
  seqno=0x3e8f982c` on the default template without payload, C `0xffff`, right `0xfffe` (`eth-default-v4-e1-10`
  frames 0-2; frame 3 adds one payload byte and C is right). The test requires C's header sum to be wrong in exactly
  these three frames of the 352. rmasscan computes the full sum.
- `--tcp-tsecho` (carried over from the SYN template, scan-control design): C writes `field[2]` twice
  (`src/templ-tcp-hdr.c:1111-1112`), so its TSval is `ts>>24, ts>>16, ts, 0` (`12 34 78 00` for 0x12345678) and the
  TCP checksum follows; rmasscan's SYN and stack frames carry the whole value (`12 34 56 78`). 70 frames (`eth-tsecho-*`,
  `eth-all-options-*`).

Not in the goldens:

- Window 600 over IPv6 (heartbleed, sub-stage 4c): `tcp_set_window` recomputes the TCP sum with `tcp_checksum2`, whose
  pseudo-header is IPv4's (`src/templ-pkt.c:410-411`, `:210-236`), so over IPv6 it reads source-address bytes as IPv4
  addresses and writes a wrong sum (the oracle printed `0xe498` where the right sum is `0x8923`). It also parses the
  frame as Ethernet whatever the link (`:382`). Only Ethernet IPv4 frames with window 600 are in the goldens.
- DLT_NULL: C on Linux cannot build its templates. `_template_init_ipv6` writes the host's `AF_INET6` (10 on Linux,
  `src/templ-pkt.c:1160-1162`) and re-parses the frame with `preprocess_frame`, which knows only 24, 28 and 30, so
  `template_packet_init` exits with `[-] FAILED: bad packet template` (`:1202-1205`) before any frame. rmasscan builds
  Null frames as `TcpSynTemplate` does; the raw-IP cases cover the padding on a link without Ethernet.
- A payload that does not fit C's 2040-byte buffer: C prints `tcp: err generating packet: too much payload` and
  returns length 0 (`src/templ-pkt.c:440-443`, `:521-524`); rmasscan returns no frame (unit test
  `build_refuses_payload_past_c_buffer`).
