# Studio: native profiles and release follow-up

Date: 2026-11-10. Branch: `integration/studio-current-engine`.
Review: [draft PR #54](https://github.com/disclaimer8/masscan-studio/pull/54).
Historical evidence: the package identities and SHAs below predate the
2026-11-10 history rewrite. They are preserved as recorded, not relabeled as
new-history builds. A later privacy review found personal build paths in the
old macOS binaries, so those packages are not current distribution candidates.
Fresh releases must follow the neutral-path and archive checks in
[packaging requirements](../../studio/PACKAGING.md).

The scanner scan-control work is integrated through main `755e7bd`; the separate
scanner worktree and existing VM lab were not changed.

## Code and scope

`8e4a6f2` adds native Linux/Windows physical profiles and package verification.
`49ab1583d62bcfaf7907735f548639740f5d5527` merges current main and is the clean,
exact source of the release packages below. `2ed9953` changes one Linux test
pattern from `1 | 2 | 3` to `1..=3` for Clippy; it changes no production code.
`db0d7c2` also corrects the xtask authorization-probe diagnostic to refer to
each profile's own network preparation instead of requiring a sealed stand for
every profile. This is a tooling message only; packaged `49ab1583` tools retain
the older message. No GUI, runner, scanner or admission behavior changed. The targeted xtask
suite passed 122 tests, with Clippy and formatting clean after this change.
Subsequent evidence commits do not change those package identities.

- IPC v5: `MacPhysical`, `LinuxPhysical`, `WindowsPhysical` each run only on their
  native OS. Existing macOS fixture profiles retain their admission checks.
  Foreign saved profiles round-trip but cannot start on the wrong platform.
- Linux uses bounded NETLINK_ROUTE observations with finite buffers/retries and
  cancellation/deadline checks. Non-unicast/non-local route kinds are rejected,
  including a custom broadcast route that cannot be inferred from an IP suffix.
- Windows IP Helper observations retain all valid IPv4 prefixes and validate
  buffer extents, lengths and linked-list traversal. Cancellation is checked
  before/after the synchronous OS call; it cannot forcibly interrupt that call.
- Persisted adapter identity uses the canonical device ID. On Windows this is
  the Npcap GUID device path, rather than a friendly name such as Ethernet 2.
- The existing privileged entry paths remain required. Route checks do not
  authorize packet access. The UI never runs as root to pass acceptance.
- Package manifest v2 inventories all regular files. Verification rejects
  missing/extra/changed files, symlinks and malformed paths. macOS also requires
  deep, strict codesign verification. Release Windows tools are release-built.

## Validation

| Environment | Result | Scope |
| --- | --- | --- |
| macOS Studio | 450 passed, 0 failed, 2 ignored; Clippy and fmt pass | Full `cargo xtask test` |
| macOS engine | 1903 passed, 0 failed, 23 ignored | Full workspace, all targets |
| Linux Studio, minipc | 302 passed, 0 failed, 4 ignored; Clippy and fmt pass | Exact clean `49ab1583` |
| Windows Studio, GitHub CI | 309 passed, 0 failed, 7 ignored; Clippy and fmt pass | PR head `2ed9953` and its GitHub merge checkout |
| Linux network crate | Earlier full set: 345 passed, 0 failed, 12 ignored; final focused set: 17 passed | Earlier implementation snapshot before three route-kind tests; final focused log is `route-kinds-green.log` |
| Windows network crate | 301 passed, 0 failed, 33 ignored; Clippy pass | Exact clean `49ab1583`; final observation set 12 passed |

The native Windows tests include actual read-only prefix/route queries, not
packet delivery. Linux strace recorded NETLINK_ROUTE observations without
AF_PACKET. Ignored tests are not counted as passes. An earlier incomplete Linux
temporary source snapshot failed lab tests because parent fixtures were absent;
it is not used as full-workspace acceptance evidence.
The earlier Linux 345/12 result is retained in the agent execution transcript
(session 5005, output chunk 0378fc, exit 0), not a standalone log. It is not
presented as a full network-crate rerun of final `49ab1583`; the complete final
engine CI is separate evidence below.

Initial Linux engine CI stopped at `manual_range_patterns` under `-D warnings`,
before tests. The exact warning was reproduced and fixed in `2ed9953`.
The replacement [Studio CI run](https://github.com/disclaimer8/masscan-studio/actions/runs/42817291878)
passed on macOS, Linux and Windows for PR head `2ed9953`. It also exercised actual
Linux pkexec/UID-PID authentication and owner-death cleanup without scan commands,
Windows restricted-token/elevated-entry and trusted-installation fixtures, and
Linux simulated GUI lifecycle. These are not manual desktop packet acceptance.
The complete [engine CI run](https://github.com/disclaimer8/masscan-studio/actions/runs/42817291866)
also passed for `2ed9953`: all three OS jobs plus the Windows wire-lab package.
The later `db0d7c2` tooling-message change was checked with the targeted 122-test
xtask suite, Clippy and fmt; its separate CI and the final documentation-head CI
can be inspected in PR #54. The earlier green runs are not relabeled as later
commit runs.

## macOS release: actual multi-peer GUI scan

Package: `studio/dist/build-1794314040454/Masscan Studio.app`.
Manifest: release, macOS/aarch64, `dirty=false`, IPC 5, ad-hoc signed,
`notarized=false`. All six inventoried files and deep/strict codesign pass.

The ordinary Slint window was launched with separate history at
`/tmp/studio-release-native-20261110/data`. Through its visible controls:

1. Entered two owned, SSH-verified peers, `192.168.1.148` and `192.168.1.191`;
   ports `22,65000`, rate 10, seed 51.
2. Read-only preflight showed en0, source `192.168.1.128`, two direct destinations
   and four probes. Authorized the matching packaged helper.
3. Validated settings, pressed Start, observed Completed, four saved rows,
   sent 4 / received 4: port 22 Open and port 65000 Closed on each peer.
4. Exported JSON through the native save dialog. The export contains four unique
   rows, original settings, both destination MACs and whole-scan coverage.

Independent tcpdump captures ran on eno1 of the first peer and enp2s0 of the
second. Each contains two SYNs, one matching SYN/ACK, one matching RST/ACK and
one local-kernel RST after the SYN/ACK. Parsed sequence/acknowledgement numbers
correlate all four replies with the four unique probes. No duplicate probe.
Both captures report zero dropped packets. Filters cover the Mac address and
TCP port 40000 on the peers, not all uplink traffic.

Authorization used the existing development work-session host, PID 49278.
Only the exact new GUI/helper hashes were staged, then the selected tool was
restored to xtask. The GUI remained ordinary-user. This is not fresh installation
or a new system authorization dialog. Earlier Pause/reopen/Resume and Stop tests
belong to `433f3d4`, as recorded in the [earlier report](2026-11-10-studio-integration.md);
those actions were not silently reclassified as this release's native results.

## Windows release

Package on Windows:
`C:\Users\lab\studio-release-20261110\studio\dist\build-1794314202174`.
Clean `49ab1583`, release/x86_64, IPC 5, WindowsPhysical, unsigned.
All five package files passed verification; the portable ZIP was extracted into
a fresh directory and verified again. SQLite came from the checked download
script. UI SHA-256:
`c9b96e958f64d65950958f30f5a36455d56141c3c12afac81bb40c31dd8d8709`.
Runner SHA-256:
`2ad4fb3283a552f5e7d6906d3234f31dc265be8bb0cd0a6d985b23c8a79e1c3c`.

The SSH token is administrator, so ordinary-user Studio tests were not forced
through it by spoofing CI or weakening the guard. Native manual GUI/UAC/packet
acceptance is pending: the existing VNC connection requires interactive login.
The VM network, Npcap policy and existing scanner lab were not changed.

## Linux release

Package on minipc:
`/home/a1/studio-release-20261110.34icX0/repo/studio/dist/build-1794315038407`.
Clean `49ab1583`, release/x86_64, IPC 5, LinuxPhysical, unsigned.
The three package files passed verification. A separate fresh checkout and copied
build cache were used; existing development checkouts were not repurposed.

The packaged UI passed built-in `--smoke-pause` and `--smoke-stop-race` under
separate Xvfb instances with the software renderer and separate histories.
Exits were 0, elapsed times 3.805 s and 0.490 s. SQLite integrity passed and both
jobs were recorded as Simulation/Stopped. No owned Xvfb or packaged child process
remained afterward. These are actual release-binary simulated lifecycle tests,
not a manual visual review, desktop polkit dialog or physical packet test.

Runtime inspection matters for this artifact: the build host is Ubuntu 26.04.1
with glibc 2.43; `studio-ui` imports GLIBC_2.43, while runner/inspector import at
most GLIBC_2.34. All `ldd` libraries resolve on the build host. The UI directly
requires SQLite/fontconfig as well as the system runtime; its display backend
has additional runtime requirements. This bundle is **not claimed compatible
with older Ubuntu releases**. A lower-baseline distribution build remains needed
for those systems.

## Artifacts and remaining acceptance

Permanent local evidence:
`/Users/owner/masscan-studio-evidence/2026-11-10-release/`.
Subdirectories contain manifests, build/test/verification logs, archives, native
macOS export, SQLite backup, captures and `native-summary.json`.

| Archive | SHA-256 |
| --- | --- |
| macOS `masscan-studio-macos-aarch64-49ab1583.zip` | `5036aa80a30f045a54105154690c1515d6589510c78de8e0ecbe29dbdfc5231b` |
| Windows `masscan-studio-windows-x86_64-49ab1583.zip` | `c66e9add9e2f7afb13074a3b556c6988b6f2d1973874ab9bba28d4a6eb4b2d76` |
| Linux `masscan-studio-linux-x86_64-49ab1583.tar.gz` | `0500b9b892b6a3a452194b07583318095df7b60accc7e12a37ea99a524d6dab4` |

Before claiming a public cross-platform release:

- Complete ordinary desktop Linux polkit and Windows UAC physical scan acceptance
  with independent captures. Native crate tests, CI fixtures and simulated UI
  lifecycle tests establish narrower facts.
- Add routed-target and network-change/sleep/wake physical acceptance. This
  pass establishes two direct peers on macOS.
- Configure public distribution signing. macOS has no Developer ID Application
  identity; the current package is ad-hoc signed and not notarized. Windows is
  unsigned; this Linux UI requires glibc 2.43 and system-library prerequisites.
  See [packaging requirements](../../studio/PACKAGING.md).
- Review the draft integration PR before merge; it includes preserved earlier
  Studio work as well as this follow-up. No merge or public release was performed.
