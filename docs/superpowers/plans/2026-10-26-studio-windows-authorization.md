# Studio Windows trusted installation and authorization

> Execute inline with superpowers:executing-plans; fresh review and exact-head CI before merge.

**Goal:** prepare and verify an immutable Windows runner, then establish a session
through UAC without changing the raw scanning gate or rmasscan.

**Architecture:** ordinary Slint UI → existing authenticated named pipe → exact
installed runner, launched with ShellExecuteExW(run as administrator) and retained
process handle. Installation/trust validation is a separately testable prerequisite.

**Tech stack:** Rust 1.99.1, existing windows-sys 0.61.2; PowerShell only for the
reviewable one-time operating-system installation. No service, drivers or policy
changes. Engine and home labs remain Claude's responsibility.

**Spec:** cross-platform design §5 and studio/AUTHORIZATION.md. Existing personal
threat model excludes malicious same-account code and compromised administrators.

## Global contracts

- Raw scanning remains false; no packet adapters opened by tests/installers.
- Installation uses the system Known Folder Program Files, not an environment
  variable, then Masscan Studio/Runner/<sha256>/studio-runner.exe.
- Installation creates a fresh version, verifies SHA-256, sets administrator-owned
  protected ACLs, and never overwrites an existing version. Source path is data.
- Verification rejects reparse points on the whole ancestry, untrusted owners,
  null DACLs and unprivileged write/delete/ACL/ownership grants. The volume root
  may grant directory creation only; that does not authorize deleting an existing
  protected Program Files directory. Other write permissions remain rejected.
- Pin read handles without write/delete sharing through validation and launch;
  hash the retained file handle. Do not validate one inode and launch another.
- No executable from the build tree is used as a session runner under elevation.
- Keep macOS/Linux behavior and Windows unprivileged simulation intact.

## Task 1 — trusted installation prerequisite

Files: platform win_setup.rs (portable script/argument validation),
windows/install.rs (Known Folder, handle-bound file/ACL trust), platform tests,
xtask Windows preparation/probe, AUTHORIZATION.md and verification report.

- [x] RED tests for quoting, hash/path rejection, immutable installer and trust
  policy; then implement with documented unsafe boundaries.
- [x] Windows native tests for owner/null-DACL/write grants, retained handles,
  wrong hash, directory/file confusion and reparse rejection.
- [x] Prepare an exact package runner and reviewable install script. Installation
  can be invoked manually from an elevated PowerShell for this prerequisite.
- [x] Disposable Windows CI install verifies actual Program Files ancestry and
  trusted copy. No UAC/password claim follows from an already-admin CI session.
- [x] Fresh review, all-OS CI, document evidence and merge this prerequisite (PR25).

## Task 2 — UAC bootstrap and session lifetime

- [x] Resolve same-account split-token behavior using a native prototype before
  deciding whether AuthenticationId matching must change. Do not silently allow
  foreign processes or relax the existing simulation pipe authentication.
- [x] ShellExecuteExW runas with SEE_MASK_NOCLOSEPROCESS; require a process handle,
  authenticate its pipe PID and executable against the pinned installation.
- [x] Runner authenticates original UI. Account-switch UAC is a separate explicit
  acceptance case; if unsupported, fail clearly before scanning.
- [x] Bound authorization/handshake to 180/10 seconds. UAC may block the calling
  thread: cancellation must invalidate the endpoint, and late authorization must
  fail closed. UI shutdown must not wait for the desktop dialog indefinitely.
- [x] Prove runner exit on UI death/IPC loss. Evaluate Job Object ownership across
  elevation; do not infer assignability of an elevated child from simulation.
- [x] Enable Windows Authorize/Lock only after the above contracts pass. Raw gate
  and unavailable Windows network preflight remain unchanged.

## Task 3 — acceptance

- [x] CI protocol/lifecycle failures, wrong peers, stale handles, timeout and late
  completion; no privileged stdio bypass.
- [x] Actual Windows desktop UAC allow/deny/cancel and same/other-account behavior
  are explicitly distinct from CI service-session tests. User authorized home VM
  UAC/lifetime checks on 2026-10-26, without packets or lab changes. Same-account
  acceptance passed; alternate-account remains unsupported and NOT RUN.
- [x] Package provenance and fresh whole-branch review; both review findings
  addressed. Exact-head three-OS CI remains a required external merge gate on
  PR26, whose check status records the final result.

## Review focus

- Default NTFS ACLs versus inherited-only and object/callback ACEs; fail closed
  on policy forms not understood, without claiming all Windows policies work.
- Path substitution, junctions, directory renames and mutable executable bytes
  between trust check and launch.
- Installer input quoting and publish races; no script/command injection.
- PID reuse, UAC alternate credentials, cancellation while the OS prompt lives.
- Limited UI rights to an elevated process; no unbounded waits or orphan runner.

References: [reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations),
[ShellExecuteEx process handles](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/shellapi/ns-shellapi-shellexecuteinfow.md).
