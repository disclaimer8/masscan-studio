# Studio runner authorization

Status: macOS session bootstrap implemented; raw scanning disabled. Linux peer
transport is separate from the still-unimplemented Linux elevated launcher.
Windows simulation remains available; no Windows elevation claim is made.

## Threat model and identity

Protect against other unprivileged local users, stale/foreign sessions, frame
replay, PID reuse, and endpoint substitution. Malicious code running as the UI's
own account and root/administrator compromise are outside this personal-build
model. Unsigned local software cannot prove that same-account code is benign.

The UI creates a random socket in a new 0700 directory, socket 0600. macOS also
rejects extended ACLs on that directory/socket. The path and process identity are
public argv values; there is no argv/env session secret. Both sides validate OS
peer credentials and process incarnation. Linux uses SO_PEERCRED and process
start time. On macOS the runner validates the unprivileged UI through
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

## Installation and launch

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
- Windows named pipe, retained process handles, DACL, runas and installation;
  Linux pkexec/install policy and elevated peer visibility remain separate work.
- No physical NIC or three-OS raw support follows from this implementation.
