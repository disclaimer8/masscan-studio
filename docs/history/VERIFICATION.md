> Retired document: this is the verification record of the Swift macOS app (v0.1/v0.3), removed on 2026-10-24. Kept as history only.

# v0.1 verification — 2026-10-20

Environment: Apple Silicon, macOS 27.0.1, Swift 6.4, installed masscan 1.3.2.

Verified:
- Swift unit/integration suite: configuration validation, option injection
  rejection, result/progress parsing, chunk framing, resume index, numeric IP
  order, CSV, shell/AppleScript quoting, actual masscan --echo, transport lifecycle.
- Four runner integration cases (a script harness at the time; Swift tests since 2026-10-24): real output with fragmented handshake,
  disconnect before start, rejected invalid handshake, rejected target injection.
- Release .app build and strict recursive code-signature verification.
- Installed app opens, detects masscan, renders welcome and configuration sheet.
- Native Validate Setup returns actual scanner configuration without packets.
- Native result table loaded an explicitly labeled synthetic fixture: three
  results, two hosts, numeric IP order 192.0.2.2 before 192.0.2.10.
- Filter 443 leaves one result. CSV exported through NSSavePanel contained
  exactly 192.0.2.10:443. Synthetic session was removed afterward.

Not verified in this session:
- Administrator-authorized live network scanning and actual pause/resume on
  the user's network. No administrator password was requested or entered.
- Performance at hundreds of thousands or millions of results.
- Intel, older macOS releases, distribution signing and notarization.

The packaged app is a local first version, not a notarized public release.
The core and process integration tests send no scan packets.

## v0.2 verification — 2026-10-20

- 24 Swift tests and 6 runner integration tests passed (script harness at the time).
- Persistent runner handles two --echo jobs with the same PID, rejects injected
  targets, survives a rejected configuration, exits on idle disconnect, and
  rejects oversized commands and invalid/fragmented handshakes appropriately.
- Transport cancellation before authorization, old JSON schema compatibility,
  hostname inference evidence, malformed PTR decoding, resolver deadline, and
  enriched CSV escaping/formula neutralization are covered.
- Release built, installed and passed strict recursive signature verification.
- Native Validate Setup accepted 192.0.2.1:22,80,443 without sending scan packets.
- Existing user history retained all 971 endpoints and resume index 59171.
  Look Up Names returned actual PTR names; filtering by an observed hostname
  displayed exactly its three port rows. No synthetic history was added.
- Authorization reuse was tested in validation mode; the macOS administrator
  prompt and two live privileged scans were not exercised by the agent.
- Hostname resolution is best effort, limited to 512 hosts per action/scan.
  Port/name device hints do not verify a model, OS, or service implementation.

## v0.3 verification — 2026-10-20

- 30 Swift tests and 6 helper integration tests passed (script harness at the time).
- Link tests cover HTTPS and alternate ports, a sibling web port for non-web
  rows, absent names, fallback HTTPS, and unsafe hostname syntax.
- Nmap request tests restrict targets to one IPv4 address and discovered TCP
  ports; port 9100 is excluded. XML tests distinguish table guesses from probed
  responses, retain product/version/CPE/name evidence, reject wrong hosts,
  incomplete XML and entity declarations.
- Actual Nmap 7.992 identified an ephemeral loopback HTTP server as HTTP without
  administrator authorization. Owned-process deadline and cancellation tests passed.
- Native Inspect Device sheet ran against a temporary local fixture and displayed
  BaseHTTPServer 0.6 / Python with response matching evidence. The website link
  updated to the detected HTTP endpoint and correct ephemeral port. The main
  table displayed detected service details. Link destinations were inspected;
  browser navigation was not exercised.
- The local test fixture was removed after validation. The user's sessions,
  results and paused resume checkpoint were retained.

## 2026-10-24 note: the runner integration cases are Swift tests now

The six "Python" runner integration cases listed under v0.1 to v0.3 (fragmented handshake and two
jobs on one runner, disconnect before the start, invalid handshake, argument injection with
recovery, idle disconnect, oversized command) moved to `Tests/ScanCoreTests/RunnerTests.swift` and
drive the built `ScanHelper` over a loopback socket in `--echo` mode. The Nmap inspection test
serves its page from a Swift fixture. The repository contains no interpreted programs of the
banned kind (CI: `.github/workflows/language-guard.yml`). `swift test`: 36 tests, 0 failures
(Swift 6.4, macOS 27, Nmap 7.992, masscan 1.3.2). The v0.1 to v0.3 entries above are the
historical record of those sessions and were not edited.
