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

Version 0.3 makes hostnames clickable. Web port rows open their HTTP/HTTPS URL;
other rows prefer a discovered web port on the same host, falling back to HTTPS
when a hostname exists. Web endpoints without a hostname have an IP link.

Click a **Device hint**, or select a host and choose **Inspect Device**. The detail
sheet runs the separately installed Nmap (`brew install nmap`) with TCP connect
and light service detection on that single host's discovered ports. No extra
administrator prompt is needed. It reports service product/version, reported
names, OS/device hints and CPE identifiers with their evidence. A service name
from the port table is distinguished from a matched response.

Checks are manual, one host at a time, at most 64 discovered ports, with a
55-second deadline and cancellation. Raw printing port 9100 is excluded.
No OS fingerprint scan or vulnerability scripts are requested. Reports are
saved in history and included in JSON export; CSV retains the device summary
and evidence. Service replies can be incomplete or misleading, so a hardware
model is not guaranteed.

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
automatic network scan. IPv6, UDP, huge result-set database
storage, remote scanners and public distribution packaging are outside v0.3.
