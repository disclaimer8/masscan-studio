# Studio runner authorization

Status: macOS, Linux and Windows session bootstrap implemented; raw scanning disabled.
Windows same-account desktop UAC and elevated runner lifetime passed native
acceptance on 2026-10-26. Trusted installation remains a separate prerequisite.
See VERIFICATION.md for exact package provenance and acceptance limits.

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
- Windows alternate-account UAC refusal still needs a real second-account test;
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
reviewable `install.ps1`. Run that script once from elevated 64-bit PowerShell 7+.
This is a manual installation step, not application session authorization. No
service, driver, firewall change or UAC bypass is installed.

The destination is the system Known Folder Program Files followed by
`Masscan Studio\Runner\<sha256>\studio-runner.exe`; an environment variable cannot
redirect it. The installer checks ancestor types/owners/DACLs, stages a fresh
version with protected administrator-owned ACLs supplied atomically when each
directory is created, and ordinary-user read/execute,
verifies SHA-256, then publishes with a no-overwrite directory move.
Source paths are encoded as ASCII numeric UTF-16 expressions: PowerShell's
typographic quotation marks never become syntax. No path is evaluated as code.

`cargo xtask verify-installed-runner <sha256>` opens and retains handles to the
actual executable and every ancestor without write/delete sharing. Directory
handles request FILE_LIST_DIRECTORY so they participate in sharing checks. It rejects
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
Windows Authorize/Lock is enabled following the separately recorded desktop
session acceptance. Installation alone never establishes session readiness.

## Windows session bootstrap

The ordinary UI pins the exact installed runner and starts a fresh COM-initialized
worker thread for `ShellExecuteExW` with `runas` and `SEE_MASK_NOCLOSEPROCESS`.
Arguments use Windows argv quoting, not PowerShell or cmd. The returned process
handle is retained through the session: PID, account SID, elevation and executable
must match this launch and installation. The pipe kernel peer PID must match that
handle. The runner validates the original UI's retained process identity/birth and
requires an unelevated UI in the same account. Alternate-account UAC is refused.
AuthenticationId equality remains mandatory for ordinary simulation; it is not
assumed across UAC. Neither an arbitrary same-account PID nor just an elevated
token is sufficient to authenticate a launched runner.

Before launch, the UI creates an owner-only random named Job Object with
KILL_ON_JOB_CLOSE. The elevated runner joins it and closes its temporary job handle
before connecting to the pipe. The UI then verifies membership against the exact
retained process handle. Its handle is the sole persistent job handle: closing it,
including abrupt UI process death, terminates the runner. This does not require
the ordinary UI to obtain PROCESS_TERMINATE on an elevated child. Existing jobs
that prevent nested membership produce an error; there is no service fallback.

Authorization waiting is bounded to 180 seconds, Hello to 10 seconds. Cancellation
destroys the endpoint and job without joining a blocked Windows prompt thread;
late approval cannot activate that session. Only one launcher prompt can remain
pending in this Studio process. Dismiss a still-open system dialog before retrying.
Both peers retain installation pins until the session ends. Privileged `--stdio`
and ordinary `--connect-pipe` entry points are refused before message parsing.

After installing this exact build, an ordinary terminal can run
`cargo xtask probe-windows-authorization <sha256>` for Hello, two read-only network
checks and CloseSession. It opens no packet adapter and requires no Npcap. CI uses
a restricted token of its own account for ordinary application tests; the parent
remains administrative only for installation and lifecycle supervision. This
restricted token is not evidence of an interactive desktop split-token session.
Desktop allow/deny, retry, CloseSession, IPC loss, job closure, abrupt owner death
and approval of an already-cancelled launch passed on the lab VM. Alternate
credentials remain untested and unsupported, with same-SID rejection in code.

Before privileged IPC, the dedicated runner clears normal environment entries
and retains only SYSTEMROOT, WINDIR and PATH, derived from Windows system APIs.
It restricts subsequent default DLL lookup to System32. This policy is never
applied to the UI. Static imports necessarily load before Rust entry: the pinned
administrator-owned image and Windows runtime are the startup trust boundary.
Native tests poison PATH/an extra marker and place a benign DLL in the working
directory, then verify the allowlist and actual System32 module path.

Hosted GitHub Windows jobs cannot interact with the consent desktop: actual
runas returned ERROR_CANCELLED (1223). CI retains native identity, environment,
job lifetime, rejection, simulation, installer and package checks. It packages
the exact ignored integrated cancellation test for desktop execution. Passing
CI does not substitute for this desktop acceptance.
