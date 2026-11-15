# ARP reply goldens from the pinned C masscan

Offline parity of `rmasscan_core::arp::answer_request` (`crates/rmasscan-core/src/arp.rs`), the responder that answers
ARP requests for the scanner's own IPv4 source addresses, with masscan's receive path for such a request
(`src/main.c:799-887`, `stack_arp_incoming_request` in `src/stack-arpv4.c:282-363`, masscan
`8e6b3b0c07a81e8ea61d557c06134a21a6881614`). Banners sub-stage 4b, task 14a (design R1, R9, R14). The test
`crates/rmasscan-core/tests/arp_replies.rs` runs every frame through rmasscan and compares the reply with C's byte for
byte, and "no reply" with "no reply".

## The oracle

`arp-reply-oracle` is a small C driver linked with the unmodified sources of the pinned commit: `proto-preprocess.c`,
`stack-arpv4.c`, `stack-src.c` and their helpers (`util-logger.c`, `util-safefunc.c`, `massip-addr.c`; the list and
every file's sha256 are in `manifest.json`). For each frame it does what masscan's receive thread does on an Ethernet
adapter, transcribed from `src/main.c:799-887` and calling the real C for every decision: a frame longer than 1514
bytes is skipped, `preprocess_frame(px, length, 1, &parsed)`, `ip_me = parsed.dst_ip`, `is_my_ip(stack->src, ip_me)`,
and `FOUND_ARP` with opcode 1 calls `stack_arp_incoming_request(stack, ip_me.ipv4, source_mac, px, length)`. The two
queue functions of `src/stack-queue.c` are replaced: `stack_get_packetbuffer` returns one static buffer pre-filled with
0xA5 (so the zeroed padding is C's doing), `stack_transmit_packetbuffer` records it. The rawsock symbols that
`stack_arp_resolve` (same file, never called) references abort if called.

Each frame sits in a heap buffer of exactly its length, and every case also runs through an AddressSanitizer and
UBSan build whose output must be identical (the signed-shift check is off: C shifts bytes of 0x80 and above into the
sign bit of `int`, `src/proto-preprocess.c:612-621`, `src/stack-arpv4.c:84`, `:89`).

C is not allowed in this repository (`crates/rmasscan-lab/tests/rust_only.rs`), so the driver, its build script and
the runner live off the repository (R14). `manifest.json` records their sha256, the binary's sha256, the compiler,
the host OS and the masscan commit; the build script refuses a clone that is not at the pin or whose `src/` is dirty
and copies the sources before compiling (the clone is never modified).

## Regenerate

1. Inputs: `RMASSCAN_ARP_REPLIES_INPUTS=DIR cargo test -p rmasscan-core --test arp_replies inputs_match_generator`
   writes `DIR/cases/<case>.in.txt` and `DIR/cases.tsv` (name, frame count, reply count, description) from the
   generator in the test. Without the variable the test fails if the generator and `cases/*.in.txt` drift apart.
2. On the oracle host (any machine with a C compiler and the pinned clone): `CLONE=<clone> build.sh` (both binaries and
   `BUILDINFO`), then `run-goldens.sh DIR OUT` with a fresh `mktemp -d /tmp/rmasscan-arpreply-out.XXXXXX` as `OUT`:
   every case through both builds (10-second timeout each), the frame and reply counts checked against `cases.tsv`,
   then `OUT/golden/{manifest.json,cases/*}`. Under a second.
3. Copy `OUT/golden` here, keep this README, check the sha256 in the manifest, run `rmasscan-lab privacy-scan` over
   this directory, delete the temporary directories.

## Layout and format

- `cases/<case>.in.txt`: the oracle input (`#` lines are comments; the generator writes one per frame):

  ```
  arp-reply-input v1
  me mac=XX:XX:XX:XX:XX:XX first=HEX8 last=HEX8
  frame HEX
  ```

  `first`/`last` are the adapter's IPv4 source range (`--adapter-ip A-B`, `stack->src->ipv4`); `frame -` is a
  zero-length frame.
- `cases/<case>.out`: `arp-reply-oracle v1 frames=N replies=M`, then per frame `frame I none` or
  `frame I reply len=60 HEX`.
- `manifest.json`: the oracle block, `host` (OS and kernel only), `captured_at`, and per case `about`, frame and reply
  counts, input and output sha256.

## What the goldens show (C at 8e6b3b0)

7 cases, 55 frames, 22 replies (the test asserts the counts). The reply is always 60 bytes: Ethernet to the request's
ARP sender hardware address (not the Ethernet source), from our MAC, 0x0806, then `0001 0800 0604 0002`, our MAC, the
requested address, the sender hardware address and the sender IP, zero padding.

- `plain`, `range`: a who-has for each of our addresses (one address, `--adapter-ip 192.0.2.250-192.0.2.253`) is
  answered with that address; broadcast or unicast, padded or 42 bytes, an Ethernet destination of another host (C
  does not look at it), an Ethernet source that differs from the ARP sender (the reply goes to the ARP sender), a
  non-zero target hardware field, an ARP probe with sender IP 0.0.0.0 (answered to 0.0.0.0), padding of 0xee (the
  reply's padding is zero). No reply for an address outside the range, opcode 2 (the ARP-scan path), 3 or 0x0101, a
  gratuitous request of another host, or a TCP frame to our address.
- `truncated`: the 6/4 request needs all 42 bytes.
- `encapsulated`: no reply to a request inside an 802.1Q tag (with or without priority), 802.1ad + 802.1Q, two
  802.1Q tags or LLC/SNAP. `preprocess_frame` finds the ARP header behind the tag and checks the address, but
  `stack_arp_incoming_request` parses from the fixed offset 14 (`src/stack-arpv4.c:309`), where the protocol type is
  the tag's inner EtherType or LLC bytes, never 0x0800.
- `header-quirks`, reproduced as they are (deterministic, R1): hardware type 6 is accepted; the length check rejects
  only when both lengths are wrong (`protocol_length != 4 && hardware_length != 6`, `src/stack-arpv4.c:70`), so 6/5,
  8/4, 0/4, 5/4, 6/0 and 6/255 requests are answered with the addresses read at their offsets, and the reply's
  "sender MAC" is always the 6 bytes at offset 22 (`:81`), whatever the hardware length. 7/3, hardware type 2 and
  protocol type 0x86dd are not answered; a 6/255 request one byte short of its 544 bytes is not either.
- `oversize`: a 1514-byte request is answered, a 1515-byte one is dropped before parsing (`src/main.c:799`).
- `unspecified-source`: with the source range 0.0.0.0-0.0.0.0, which C keeps in a scan without IPv4 targets
  (`src/main-initadapter.c:122-128`), a who-has 0.0.0.0 is answered with sender IP 0.0.0.0.

Not in the goldens (R1 class а, unit test `target_address_past_the_frame_end_gets_no_reply`): with lengths 6/0 to 6/3
C reads the target address past the verified bytes, and in a frame shorter than `38 + pl` bytes past the end of the
frame (`src/proto-preprocess.c:619-621` first; the oracle's AddressSanitizer build reports a heap-buffer-overflow
there). The value is whatever follows the frame in the capture buffer; rmasscan sends no reply to such a frame.
