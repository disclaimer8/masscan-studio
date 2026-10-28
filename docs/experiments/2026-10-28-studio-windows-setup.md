# Native Windows helper setup acceptance — 2026-10-28

**PASS:** install the packaged helper through Studio on the existing Windows 11
test VM, deny UAC, retry, approve installation, and repeat the read-only check.
This is acceptance of one debug x86-64 package on one VM, not raw scan acceptance.

## Package and provenance

- CI: Studio run `40509803957`, successful for head
  `eab6f07bd7c7bf5cd750cb1a6d3ad565b4f464aa` on macOS, Windows and Ubuntu.
- Windows artifact: `12736119328`; package source PR merge commit
  `06bf606770b8d954fa064ff4cc76275e3f8836a4`, clean debug build.
- All five package file hashes were checked locally and again on the guest.
- UI SHA-256: `c4f2f4dc545a887ca05a665d7432610750348c20de20a672410a6dffa05730bc`.
- Runner SHA-256: `420c57583f3b2a6fc1c5f33a906670d4fd7b55c374e62e75926f6a1a369be8ce`.
- [Package manifest](2026-10-28-studio-windows-setup/package-manifest.json).

## Observed behavior

The prepared launcher refused elevated startup and started Studio in the ordinary
`lab` interactive desktop with a separate acceptance data directory. The
[launch record](2026-10-28-studio-windows-setup/ui-process.json) records
`elevated=false`. No source checkout or compiler was needed on the guest.

| Case | Result and evidence |
| --- | --- |
| Check missing helper | PASS: offers Install helper without elevation; [screen](2026-10-28-studio-windows-setup/setup-missing.png) |
| Install requests permission | PASS: native secure-desktop UAC for Microsoft PowerShell; [prompt](2026-10-28-studio-windows-setup/first-prompt.png) |
| Deny UAC | PASS: returns a failure/declined notice and usable Check again; [screen](2026-10-28-studio-windows-setup/uac-denied.png) |
| No installation after denial | PASS: expected destination absent, only studio-ui remains; [inspection](2026-10-28-studio-windows-setup/after-denial.json) |
| Retry after denial | PASS: Check again restores Install helper |
| User approves installation | PASS: protected destination contains the matching runner; [inspection](2026-10-28-studio-windows-setup/after-consent.json) |
| UI recognizes installation | PASS: Scanner helper is ready, Install removed; [screen](2026-10-28-studio-windows-setup/setup-ready.png) |
| Check again after installation | PASS: ready again without another prompt; [screen](2026-10-28-studio-windows-setup/setup-rechecked.png) |
| Close setup | PASS: Authorize remains available, no session opened; [screen](2026-10-28-studio-windows-setup/after-setup.png) |

The installed path is under `C:\Program Files\Masscan Studio\Runner\<SHA256>`.
The packaged `studio-tools.exe verify-installed-runner` returned exit 0 after
its normal path, ownership, ACL, reparse-point and hash validation. Recorded
file SDDL is `O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)`:
Administrators own the file; SYSTEM/Administrators have full access and Users
have read/execute access. No setup runner remained after completion.

A read-only copy of the idle acceptance database passed SQLite integrity_check
and contained zero scans and zero results; [record](2026-10-28-studio-windows-setup/history-check.json).
The active instance.lock was intentionally not part of the evidence copy.
No packet adapter, scan, authorized scanner session, driver installation or
laboratory network change was performed by this acceptance.

## Limits and remaining work

Native Cancel waiting, installer timeout, late approval after cancellation and
environment-poisoning checks of this setup entry were **NOT RUN**. Offline
coverage and earlier session-authorization tests do not establish those native
setup cases. The subsequent [Linux setup report](2026-10-28-studio-linux-setup.md)
records user-approved installation through a real graphical polkit agent and
its remaining coverage limits.

The refusal wording includes the executable path and generic exit code; recovery
works, but this run does not establish a distinct user-facing cancellation label.
No product code changed, and the existing offline suite was not rerun for this
documentation-only update. The package's prior CI is identified above.

Evidence checksums: [SHA256SUMS](2026-10-28-studio-windows-setup/SHA256SUMS).
