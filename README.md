# Masscan Studio

Native macOS GUI for a separately installed [masscan](https://github.com/robertdavidgraham/masscan).
Local first version: macOS 14+, Apple Silicon build, SwiftUI, no third-party app dependencies.

## Run

Open `~/Applications/Masscan Studio.app`. If masscan is missing, install it using
`brew install masscan`. The app detects `/opt/homebrew/bin/masscan` and
`/usr/local/bin/masscan`.

Choose **New Scan**, enter IPv4 targets and TCP ports, optionally use **Validate
Setup** (no packets sent), then **Start Scan**. macOS asks for administrator
authorization once per app session. Later scans and resume reuse that runner.
Quit the app or use the sidebar lock button to end authorization. If the runner
fails, the next scan requests authorization again. Passwords are never collected
or stored by the application.

Live results, numeric IP/port sorting, filtering, CSV/JSON export, local history,
saved profiles and pause/resume are included. The service column contains
port-based hints, not verified service identification. Export includes the
currently filtered results.

Version 0.2 resolves hostnames in the background through the macOS DNS/mDNS
responder (up to 512 addresses per scan, four concurrent queries, three seconds
per query). Disable this in the scan sheet or refresh with **Look Up Names**.
Not all devices publish a reverse name. The **Device hint** column uses hostname
words and open ports; hover for evidence. These are guesses, not verified device
models or operating systems. Names and evidence are included in CSV/JSON.

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
  stream. Accepts typed, validated scan configurations, stop and quit commands.
  The authorized scanner executable is copied to a private session directory,
  so later jobs use the same executable. Lost connection stops its child and
  exits the runner.
- `MasscanStudio`: native UI and unprivileged history/export storage.

No firewall changes, persistent privileged daemon, arbitrary CLI field, or
automatic network scan. IPv6, UDP, banner collection, huge result-set database
storage, remote scanners and public distribution packaging are outside v0.2.
