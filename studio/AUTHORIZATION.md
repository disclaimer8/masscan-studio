# Studio runner authorization

Status: macOS and Linux session bootstrap implemented; raw scanning disabled.
Windows simulation uses an authenticated named pipe; no Windows elevation claim
is made. Windows trusted installation is a separate prerequisite; session UAC
bootstrap remains subsequent acceptance work.

## Threat model and identity

Protect against other unprivileged local users, stale/foreign sessions, frame
replay, PID reuse, and endpoint substitution. Malicious code running as the UI's
own account and root/administrator compromise are outside this personal-build
model. Unsigned local software cannot prove that same-account code is benign.

The UI creates a random socket in a new 0700 directory, socket 0600. macOS also
rejects extended ACLs on that directory/socket. The path and process identity are
public argv values; there is no argv/env session secret. Both sides validate OS
peer credentials and process incarnation. Linux uses SO_PEERCRED and process
start time for the UI identity. The Linux UI authenticates root using SO_PEERCRED
and the exact unreaped pkexec Child PID, without reading root's `/proc/<pid>/exe`.
Direct exec must retain that PID; a forking launcher is refused.
On macOS the runner validates the unprivileged UI through
getpeereid/LOCAL_PEERPID and libproc start time (checked before/after path lookup).
The UI validates the root peer through LOCAL_PEERTOKEN and
proc_pidpath_audittoken, which binds the executable lookup to the kernel PID
generation. Reading root PROC_PIDTBSDINFO as a regular user fails with EPERM on
the development Mac; the audit-token API avoids that access requirement without
accepting an unbound numeric PID. The root peer additionally must run the
versioned, administrator-owned binary matching the UI's SHA-256.

API contract checked against the macOS SDK `libproc.h`, `mach/message.h`,
`bsm/libbsm.h` and [Apple's libproc implementation](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c).
The exit probe propagates unknown inspection errors rather than treating them as
proof of process death.

The endpoint is removed when the session closes; removal checks its saved
device/inode. The protocol has separate version, session/attempt IDs and strictly
ordered frames. Protocol v2 adds a read-only CheckNetwork command before any scan.

## macOS installation and launch

`cargo xtask prepare-runner` without a path builds the runner and reads the actual
executable path from Cargo JSON (including custom target directories). A supplied
path prepares that exact already-signed binary. Preparation checks code signing
and system-only linked libraries, writes a hash manifest and an installation
script, and changes no system directory.

`install-runner` regenerates and compares the reviewed script, checks the source
hash, then sends the script text to macOS's administrator dialog. Installation
checks root ownership, non-writable ancestors and absent ACLs, stages a fresh
copy, removes inherited ACLs, verifies SHA-256/signature and publishes a new
hash-named directory. It never overwrites an installed version. No launchd job,
daemon, firewall rule, driver or auto-start entry is installed.

Launch uses `/usr/bin/osascript` with administrator privileges, fixed system
commands and a cleared runner environment. Source/UI identity and socket path are
quoted arguments. Authorization is bounded to 180 seconds; protocol handshake to
10 seconds. The runner rejects root stdio mode and a root UI. The whole UI stays
unprivileged. A session can serve successive scans; Lock closes it.

## Linux installation and launch

The same prepare/install/probe commands apply to the exact Linux package's
`studio-runner`. Preparation uses readelf (binutils) to require the system x86-64
glibc interpreter and a small system runtime dependency set. Custom RPATH,
RUNPATH, loader audit/filter hooks and non-system dependency names are refused.
The administrator-managed loader, cache and system runtime remain trusted.
Other Linux architectures/libcs are not offered by this initial installer.

Installation stages the exact SHA-256 under
`/usr/local/libexec/masscan-studio/<sha256>/studio-runner`, checks root ownership
and non-writable canonical ancestors, and never replaces an installed version.
The reviewed installer text runs once with administrator authorization; each
session subsequently invokes only the hash-pinned installed runner.
`/usr/bin/pkexec --disable-internal-agent` receives an argv array and a cleared
environment. A desktop polkit authentication agent must be running. No password
passes through Studio and no textual stdin fallback is used. Generic polkit
administrator authentication applies; no product policy, daemon or service is
installed. Authorization/handshake deadlines remain 180/10 seconds.

After elevation, the runner sets PR_SET_PDEATHSIG(SIGKILL), checking its parent
PID before and after. The spawning controller thread stays alive for the session.
Socket closure ends the session; if credentials prevent the UI from killing a
root child, bounded cleanup delegates only reaping to a waiter. The runner's
disconnect/UI checks and parent-death signal govern exit. Linux preflight currently
reports unavailable and cannot enable raw scanning.

CI uses a temporary XML policy granting only its exact hash-addressed runner in
a disposable GitHub VM. It removes the policy after the probe and never bundles
it in artifacts. This verifies pkexec bootstrap and owner-death behavior; it does
not prove a desktop's password dialog or cancellation UX.
See the [pkexec contract](https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html).

## Closing and cancellation

The UI can cancel authorization without waiting for its worker command queue.
Failure to launch or verify a runner returns to a usable UI. Closing the session
shuts down the socket; the runner stops its engine on disconnect. It also checks
that the UI PID/birth/executable remains alive every 250 ms outside preflight.
The engine is in the runner process, so killing runner cannot orphan a separate
scanner process. The launcher is reaped; an installer/auth probe never starts an
engine or emits packets.

Preflight commands have five-second deadlines and two-MiB output limits.
Socket EOF cancels an outstanding command, kills/reaps it and aborts the check.
This is a pre-start observation, not a claim of continuous network monitoring.

## Fixed macOS feth preflight

The root-owned manifest and its dedicated directory reject symlinks, write access
for other accounts, and extended ACLs. The sole system-ancestor exception is
macOS `/private/var/run`, root:daemon (gid 1), which normally allows group write.
This explicitly trusts that system group; no arbitrary group-write exception is
allowed. The lab directory and manifest themselves have no such exception.

The preflight validates the sealed feth pair, actual MAC addresses, peer links,
scanner with no IPv4 address, peer 198.18.0.2/30, unchanged default uplink/gateway,
source/peer/public route choices, no overlapping VPN route, no other lab subnet
or bridge membership, permanent source ARP, and IPv4 forwarding off. Ambiguous,
missing or unparseable observations refuse the scan. The manifest is bounded and
re-read after observation. The checker does not create or modify the stand.

## Acceptance still required

- Real authorized UI/runner lifecycle and isolation evidence are recorded in
  VERIFICATION.md separately from offline tests and from engine Stage 2C.
- Raw Start/Pause/Resume/Stop with independent packet capture and mid-scan network
  drift handling must pass before RAW_SCANNING_ENABLED can change.
- Windows runas/session bootstrap (including other-account UAC);
  Linux desktop password prompt/cancellation remains a manual acceptance item.
- No physical NIC or three-OS raw support follows from this implementation.

## Windows simulation session transport

The UI creates a random `\\.\pipe\MasscanStudio-<nonce>` with one instance,
`FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, non-inherited
handles and a protected DACL granting access only to the current user SID.
It starts the ordinary child with `--connect-pipe`, then compares the pipe's
client PID with a retained handle to that launched process. The child verifies
the pipe's server PID against an independently opened, retained UI process handle.
Identity also includes creation time, executable path, SID and AuthenticationId.
Both sides require the same account and logon session; no cross-account elevation
support is implied. Endpoint and identity in argv are public, not secrets.
The client selects identification-only SQOS, preventing server impersonation.

Connect is bounded to ten seconds; the existing protocol handshake has its own
ten-second deadline. Close cancels pending I/O and disconnects the server end.
Operations observe peer death through retained process handles. The runner also
checks the UI handle during its normal lifecycle loop. A failed connection or
handshake closes the pipe and reaps the spawned child. No services, policies,
drivers or system files are installed by this transport.

Overlapped reads/writes query immediate completion before waiting on an event.
Cancellation always drains completion before releasing the operation buffer,
event or OVERLAPPED. `flush` adds no separate kernel wait: each Write already
waits for its own completion. Existing frame/queue bounds remain in effect.
See the [implementation plan and Win32 references](../docs/superpowers/plans/2026-10-26-studio-windows-pipe.md).

## Windows trusted installation prerequisite

`prepare-runner` copies the exact package runner and emits `manifest.json` plus a
reviewable `install.ps1`. Run that script once from an elevated 64-bit PowerShell.
This is a manual installation step, not application session authorization. No
service, driver, firewall change or UAC bypass is installed.

The destination is the system Known Folder Program Files followed by
`Masscan Studio\Runner\<sha256>\studio-runner.exe`; an environment variable cannot
redirect it. The installer checks ancestor types/owners/DACLs, stages a fresh
version with protected administrator-owned ACLs and ordinary-user read/execute,
verifies SHA-256, then publishes with a no-overwrite directory move.

`cargo xtask verify-installed-runner <sha256>` opens and retains handles to the
actual executable and every ancestor without write/delete sharing. It rejects
reparse points, wrong object types, untrusted owners, null DACLs and unprivileged
write/delete/ACL/ownership grants, then hashes the retained file handle. Trusted
owners are SYSTEM, builtin Administrators and Windows TrustedInstaller. Effective
ACE forms other than ordinary allow/deny fail closed; inherited-only entries do
not govern the current object. Only the volume root may grant directory creation
without granting deletion/modification of existing protected children.

The disposable CI VM can exercise actual installation because its job account
already has administrative rights. Tests check executable write/rename pinning,
no-overwrite, content tamper detection and reparse refusal. These checks do not
exercise UAC prompting, cancellation, alternate credentials or a raw adapter.
The Windows UI Authorize button remains unavailable until session bootstrap is
implemented and accepted separately.
