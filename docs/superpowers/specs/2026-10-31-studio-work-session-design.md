# One authorization for a Studio working session

User explicitly requested implementation on2026-10-31 after repeated per-case macOS prompts. This authorizes building a usable session tool without another design-permission loop. Existing native evidence remains valid/failed as recorded; this change does not open the distributed network gate.

One `xtask work-session start RUNNER` authorization installs the exact reviewed tool if needed and launches a protected task host. It remains available until explicit `work-session stop`; individual Controller/process closure ends that helper only. No login item, launchd job, sudoers/password storage or generic command execution. Existing ordinary Studio authorization remains fallback when no work session exists; a present but invalid/unavailable host is an error, not an automatic new password request.

Host runs from root-owned versioned installed xtask. Fixed directory `/Library/PrivilegedHelperTools/MasscanStudio/work-UID` is root-owned, no symlinks/ACLs or writable ancestors. Root metadata publishes host/tool hash, allowed runner hash, allowed caller executable hash and pid. Socket is accessible but authenticates kernel audit uid/pid incarnation/executable; only the current user's exact approved xtask build is allowed initially. This version serves development/acceptance drivers, not arbitrary applications. GUI support can add a reviewed caller hash later. Client authenticates root audited peer and protected hash before sending requests. Requests are bounded typed JSON, unknown fields rejected.

Operations: status, stop, launch the single pinned helper using existing `--connect ENDPOINT OWNER` and audited caller identity; fixed fixture up/down/status/supervise commands; export one validated run nonce. Helper retains the existing direct authenticated Controller<->runner socket, protocol handshake, seal/report and cancellation checks. No arbitrary executable/argv/env/shell/path operation. Supervise accepts fixed case names, absolute isolated driver directory, optional pause nonce, current uid and pinned helper hash supplied by host. Existing supervisor validates descriptor ownership and all fixture data. Host operations use only system dependencies and cleared environments.

Multiple helper leases may coexist within a bounded request count (maximum8); fixture mutations serialize. Fixture output is retained in root-owned unique job directories and surfaced to the unprivileged client while running, so readiness tickets remain live. Individual helper lease EOF ends/reaps that child with existing bounded shutdown; host remains ready. Supervised fixture jobs retain their native time bounds and cleanup semantics. Stop refuses active jobs/leases; when idle it tears down any owned fixture and removes only its own runtime directory. Failed or stale host files are not silently reused/removed by an ordinary client.

Native checks: one actual start password prompt, two separate sequential Controller authorization probes without password prompts, root ownership/audit/hash checks, status and retained host after Controller closure. Then use the host for guard follow-up; do not trigger another direct osascript loop. Review/test before installation. Host lifetime stays under operator control; no idle timeout that silently revokes the requested working access.

## Reviewed build updates during the same working session

The fixed first host requires another OS authorization whenever the caller build changes.
Extend its explicit maintenance capability with `work-session stage TOOL RUNNER`:
only an already authorized caller for the same audited uid can select a pair of reviewed
binaries. This authorizes installing operator-selected code, not merely scanning; code
signature and system-library checks establish integrity, not a semantic security review.
The host remains immutable. Staging copies bounded regular caller-owned files from
no-follow descriptors into private root-owned directories, verifies the requested hashes
and signatures on those copied bytes, then publishes immutable hash directories. No shell
command, environment or arbitrary execution arguments are accepted over IPC.

Stage requires an idle session with no owned fixture. The host atomically publishes the
selected tool/helper pair only after both installs pass. Its own host hash stays fixed for
peer authentication; prior approved tool clients remain authorized, so a stable installed
client can stage subsequent builds. Fixture ownership uses the selected tool hash and
cannot change mid-fixture. Helper selection is checked again after reserving its lease.

The first transition from the older host needs one OS authorization: install the reviewed
new binaries, ask the old protected client to stop as its original uid, wait for its archive
and global lock release, then launch the replacement host. An active host refuses replacement.
Afterward staging does not prompt or end the host. No persistent login service or sudoers
change is introduced; explicit stop still releases the session.
