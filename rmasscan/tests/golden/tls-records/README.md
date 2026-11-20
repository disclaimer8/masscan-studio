# TLS record-parser goldens from the pinned C masscan

Offline parity of `rmasscan_proto::banner1::tls` with masscan's `ssl_parse_record` and its sub-parsers
(`src/proto-ssl.c`, masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`): ServerHello, certificate framing with
X.509 capture, alerts, heartbeat and the heartbleed/ticketbleed/poodle findings (reference
[§B](../../../../docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tls.md); design R1, R13, R14).
Banners sub-stage 4c, task 4. The test is `crates/rmasscan-proto/tests/tls_golden.rs`.

## The oracle

The same off-repository `tcp-oracle` driver as `../tcp-banners/` and `../x509/`, mode `tls`: `x509_init()` and
`banner1_create()` once, the case's banner flags set on `Banner1`, then per run in a forked child with a
2-second alarm `banner_ssl.parse` over the stream (`whole`, `bytewise`, and `given` for multi-segment cases),
the `tcpapi_send` actions in call order and the records `banner_flush` reports. Both builds (default and
AddressSanitizer) must agree byte for byte; `manifest.json` records the provenance and per case the result.

The `case1`/`case2`/`case3` streams are the `ssl_test_case_*` arrays of `src/proto-ssl-test.c` at the pin,
dumped by oracle mode `x509-vectors`; the chain DERs come from their capture records. All other streams are
synthetic records built for these cases (names only under `.test`).

## Layout

- `cases/<case>.in.txt`: `tls-input v1`, one `flags` line (space-separated: `cert`/`nocert`, `cap-hb`,
  `cap-tb`, `heartbleed`, `ticketbleed`, `poodle`), then `segment HEX` lines; the stream is their
  concatenation.
- `cases/<case>.out`: `tls-oracle v1 segments=K bytes=N`, per run `run whole|bytewise|given calls=K`, the
  actions (`action send flags=F LEN BYTES`, `action close`), the records and `end`; or `hang` / `crash ...`.
  `BYTES` as in `../tcp-banners/` (`-`, `=stream`, else quoted with `\xNN`).
- `manifest.json`: the oracle block and per case `about`, `flags`, `bytes`, `segments`, input/output sha256
  and the AddressSanitizer result.
