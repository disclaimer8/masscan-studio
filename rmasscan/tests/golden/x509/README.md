# X.509 name-parser goldens from the pinned C masscan

Offline parity of `rmasscan_proto::banner1::x509` with masscan's `x509_decode` (`src/proto-x509.c`, masscan
`8e6b3b0c07a81e8ea61d557c06134a21a6881614`) for one certificate: which bytes reach the `ssl` banner record
(CN/SAN names of the leaf, reference
[§C](../../../../docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tls.md); design R1, R13, R14).
Banners sub-stage 4c, task 3. The test is `crates/rmasscan-proto/tests/x509_golden.rs`.

## The oracle

The same off-repository `tcp-oracle` driver as `../tcp-banners/`, extended with two modes (kept off the
repository, R14; sha256 of the driver, its build script and the masscan commit are in `manifest.json`):

- `x509-vectors`: dumps the bare DER vectors linked from `src/proto-ssl-test.c` (`google_cert`, `yahoo_cert`)
  and runs `banner_ssl.parse` with cert capture over `ssl_test_case_1`/`ssl_test_case_3`, whose `X509`/`X509CA`
  base64 records give the chain DERs used as case inputs.
- `x509`: one case from stdin (`x509-input v1`, `count N`, `der HEX` lines concatenated). `x509_init()` once,
  then per run in a forked child with a 2-second alarm: `x509_decode_init(len)`, `count` set as
  `parse_server_cert` sets it (1 = leaf, 2/3 = chain), `x509_decode` on the whole DER (`whole`, the reference)
  and byte by byte (`bytewise`), then the records `banner_flush` reports. Both builds (default and
  AddressSanitizer) must agree byte for byte; `manifest.json` records it per case.

Handcrafted DERs (`mini-*`) are synthetic certificates built field by field (names only under `.test`);
mutated cases are byte edits of the `google` vector. Inputs and the generator are not in the repository; the
generated `cases/*.in.txt` are the inputs and carry no host or account data.

## Layout

- `cases/<case>.in.txt`: `x509-input v1`, `count N`, then `der HEX` lines (64 bytes per line).
- `cases/<case>.out`: `x509-oracle v1 count=N bytes=L`, per run `run whole|bytewise calls=K`, the records
  (`record APP LEN BYTES`, same quoting as `../tcp-banners/`) and `end`; or `hang` / `crash ...`.
- `manifest.json`: the oracle block and per case `about`, `count`, `bytes`, input/output sha256 and the
  AddressSanitizer result.
