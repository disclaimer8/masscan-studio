# Masscan Studio v0.1

User approved the proposed first version on 2026-10-20. Intended outcome:
a usable native macOS interface to the already installed masscan, for local use.
Distribution to other users is outside this first build.

macOS 14+, SwiftUI, no third-party dependencies. Existing masscan at
/opt/homebrew/bin/masscan or /usr/local/bin/masscan remains separate.

Window: sidebar with profiles and history; toolbar for new scan and export;
central result table, search and summary; configuration sheet for targets,
ports, exclusions, interface, rate. Native light/dark appearance.

One active scan. IPv4 addresses, CIDRs and explicit ranges; TCP ports.
Default 100 packets/second. Explicit target entry, no automatic network scan.
Validate configuration without sending packets. Live progress from stderr,
discovered ports from stdout. Save history and results locally, CSV/JSON export.
Pause requests SIGINT, waits for masscan to drain, stores resume index.
Resume reuses original seed, targets and ports. Terminal outcomes distinguish
completed, paused, interrupted and failed.

Privilege boundary: UI never runs as root and never collects credentials.
AppleScript requests macOS administrator authorization for a dedicated runner.
Runner validates structured configuration again, starts only an allowlisted
masscan executable with an argument array, and streams output over an authenticated
loopback connection. Only stop is accepted from the client. Disconnection stops
the owned child. Root writes only to its private temporary working directory;
all history/export files are written by the unprivileged UI.

Tests cover invalid input, CLI option injection, partial output framing,
IPv4 sorting, export escaping, resume identity and real masscan --echo.
Build .app, verify signature, open and inspect the UI. No public-target scan
is part of automated verification.
