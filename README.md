# Masscan Studio

Native macOS GUI for a separately installed [masscan](https://github.com/robertdavidgraham/masscan).
Local first version: macOS 14+, Apple Silicon build, SwiftUI, no third-party app dependencies.

## Run

Open `~/Applications/Masscan Studio.app`. If masscan is missing, install it using
`brew install masscan`. The app detects `/opt/homebrew/bin/masscan` and
`/usr/local/bin/masscan`.

Choose **New Scan**, enter IPv4 targets and TCP ports, optionally use **Validate
Setup** (no packets sent), then **Start Scan**. macOS asks for administrator
authorization. Passwords are never collected or stored by the application.

Live results, numeric IP/port sorting, filtering, CSV/JSON export, local history,
saved profiles and pause/resume are included. The service column contains
port-based hints, not verified service identification. Export includes the
currently filtered results.

**Pause** sends SIGINT and waits for final replies and a checkpoint. **Resume**
reuses the original scope, seed and resume index. Quitting during a scan stops
the child; wait for Pause to finish before quitting if you need a resume point.

History and profiles are stored in
`~/Library/Application Support/Masscan Studio/`.

## Build and test

```sh
swift test
python3 scripts/test_helper.py
bash scripts/package.sh
```

Output: `dist/Masscan Studio.app`. Signing is ad-hoc for this local Mac;
this is not a notarized public release. masscan is not bundled.

## Architecture

- `ScanCore`: validated IPv4/TCP configuration, parsers, export, local transport.
- `ScanHelper`: dedicated runner; fixed masscan binary, argument arrays, private
  temporary working directory; returns data over an authenticated loopback
  stream. Only a stop control command is accepted. Lost connection stops its child.
- `MasscanStudio`: native UI and unprivileged history/export storage.

No firewall changes, persistent privileged daemon, arbitrary CLI field, or
automatic network scan. IPv6, UDP, banner collection, huge result-set database
storage, remote scanners and public distribution packaging are outside v0.1.
