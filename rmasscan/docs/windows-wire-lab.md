# Windows wire lab package (stage 2B-Windows, task 4)

A reproducible x64 Windows package of the lab harness (`wire_scan`) and a PowerShell wrapper, so that someone with a
Windows 11 test machine and Npcap can run two explicit stages and send back one archive. It is a lab harness, not a
scanner: there is no default scan, no target discovery and no automatic upload or e-mail.

## Stages

1. **Inventory** (`-Mode Inventory`): lists Npcap (library and driver versions, DLL paths and SHA-256), every Npcap
   adapter with its OS MAC, and the build identity. No adapter is opened and no frame is sent.
2. **Explicit wire run** (`-Mode Run -ConfirmClosedLab ...`): sends SYN probes to the targets you name, through the
   adapter you name. Every parameter is required; there are no defaults for a scan.

Result of either stage: a folder and `<folder>.zip` with `inventory.json`, `reference.pcap` (run only), `run.json`
(run only), `run.log` and `verdict.txt` that starts with `PASS`, `FAIL` or `NOT RUN`. Nothing is uploaded or sent.

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-wire-lab.ps1 -Mode Inventory
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-wire-lab.ps1 -Mode Run -ConfirmClosedLab `
  -Interface '\Device\NPF_{GUID}' -SourceIp 198.18.0.1 -RouterMac 02:00:00:00:00:22 `
  -Targets 198.18.0.2 -Ports 22,80,443 -Seed 12345
```

## PowerShell versions

The wrapper targets **Windows PowerShell 5.1**, the only PowerShell on a stock Windows 11, and also runs on PowerShell 7.
It is ASCII-only and avoids 7-only syntax. Lab driving (the VM tooling) may use `pwsh` 7; the packaging script runs on both.

## Safety rules enforced by the wrapper

- Targets must be explicit IPv4 addresses, ranges or CIDR (no host names) inside 10/8, 172.16/12, 192.168/16 or
  198.18/15, at most 65536 addresses and 4096 ports. The source IP must be in the same ranges.
- `-ConfirmClosedLab` is required for the sending stage.
- The EXE is started with an **argument array** (`& $exe @args`); there is no `Invoke-Expression` and no command line
  built from strings.
- The EXE is checked against the `SHA256SUMS` shipped next to it; a mismatch is `NOT RUN`.
- The wrapper never changes UAC, the Npcap driver or service, the firewall, routes or adapter settings, and never
  installs or downloads Npcap.

## Source MAC

Promiscuous mode is not enabled, so replies reach the process only when they are addressed to the MAC of the NIC.
A source MAC that differs from the NIC's own MAC would give a scan that completes with zero results. Therefore:

- `-SourceMac` defaults to the MAC of the chosen adapter (from the inventory).
- An explicit `-SourceMac` that differs is refused (`wire_scan` exit 6, verdict `NOT RUN`) unless
  `-AllowForeignSourceMac` is given, which prints a warning and records `src_mac_check: "override-foreign"`.
- A run with zero replies is `FAIL`, not `PASS`.

`run.json` records how the MAC was chosen: `nic-default`, `explicit-equal`, `override-foreign` or `unverified`.

## Rights and Npcap Admin-only mode

If Npcap is missing, or is installed in "Administrators only" mode and the session lacks rights, the harness exits with
code 5 and the wrapper prints instructions (install Npcap yourself; start PowerShell as administrator) and exits 5 with
verdict `NOT RUN`. It changes nothing by itself. Measured on Npcap 1.90 (Administrators only): a restricted token
(`runas /trustlevel:0x20000`) still loads the DLL, but `pcap_findalldevs` then lists only the loopback adapter, and the
token still reports `TokenIsElevated` (and `IsTokenRestricted` is false for that token, so `restricted_token` in
`identity` is informational only). The harness therefore does not trust the flags: an inventory with no non-loopback
adapter is exit 5 with an `access_hint`.

## `wire_scan` modes (EXE)

| Mode | Opens adapter | Loads Npcap DLL | Sends |
| --- | --- | --- | --- |
| `--inventory` | no | yes (read only) | no |
| `--write-reference-pcap FILE` | no | no | no |
| `--forge-checkpoint-next-index N` | no | no | no |
| scan (all explicit parameters) | yes | yes | yes |

`--write-reference-pcap` writes the SYN frames the engine would send for the given explicit binding (same engine,
in-memory adapter, timestamps 0, byte-for-byte reproducible, at most 1,000,000 frames). It needs the same explicit
parameters as a scan, including `--src-mac`. A resume checkpoint is validated before the adapter is opened.

Exit codes: 0 ok; 2 argument/plan/open error; 3 failed run; 4 resume rejected before open; 5 Npcap missing or access
denied; 6 source MAC differs from the NIC MAC.

## Identity in every JSON

Each JSON line carries `identity`: `source_commit` (embedded at build time through `RMASSCAN_SOURCE_COMMIT`, no
`build.rs`), `binary_sha256` (computed at run time from the running EXE), `os` (family, arch, `RtlGetVersion` build
and revision), `npcap_abi`, and `elevated`. Scan and inventory outputs also carry `npcap` (library version, driver
version, loaded DLL paths, versions and SHA-256). The binding (interface, IPs, MACs, ports) is part of the job and its
digest.

## Metrics

`resources` in `run.json`: handle/fd counts, thread counts, working set, CPU times. Whatever the OS cannot measure is
`null`, never 0. On Linux the fd and thread counts come from `/proc/self`; on Windows the handle count, working set and
CPU times come from `GetProcessHandleCount`, `K32GetProcessMemoryInfo` and `GetProcessTimes`, and the thread count is
`null` (not measured). The Linux wire suites keep reading the same keys.

## Package

`scripts/package-windows-wire.ps1 -Commit <40-hex>` (run in `rmasscan\` on Windows x64) builds
`cargo build --locked --release -p rmasscan-net --example wire_scan` with `RMASSCAN_SOURCE_COMMIT` set and produces
`rmasscan-wire-windows-x64-<commit12>.zip` plus `.zip.sha256`:

| File | Purpose |
| --- | --- |
| `wire_scan.exe` | release x64 harness |
| `windows-wire-lab.ps1` | wrapper |
| `README.txt` | short user instructions |
| `SHA256SUMS` | hashes of the other files |
| `LICENSE`, `NOTICE` | AGPL-3.0-only and attribution |
| `SOURCE_COMMIT` | commit and the exact `git archive` command for the source |

No Npcap DLL or installer is included. The name carries the commit, never "latest". The ZIP container is deterministic
(fixed timestamps, sorted entries); the EXE itself is built from the pinned toolchain and `Cargo.lock` but bit-for-bit
EXE reproducibility across machines is not claimed.

Source of exactly a build:

```
git archive --format=tar --prefix=rmasscan-<commit12>/ <commit> rmasscan | tar -x
```

CI: the `package-windows-wire` job in `.github/workflows/rmasscan.yml` builds the package on `windows-2022`, checks the
hashes and the file list, and uploads `rmasscan-wire-windows-x64-<full-sha>`. It sends nothing and opens no adapter. It
could not be exercised without a push.

## Not covered

Windows ARM64, x86 and Wi-Fi monitor mode are not accepted from an x64 Ethernet result. The harness never targets
arbitrary home or office networks.
