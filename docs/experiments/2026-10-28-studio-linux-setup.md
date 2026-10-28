# Native Linux helper setup acceptance — 2026-10-28

**PASS: user-approved installation through a real graphical polkit agent.**
The matching helper was installed and recognized by the ordinary Studio UI on
Ubuntu 26.04.1 LTS x86-64. This is one debug package on a virtual X desktop;
it does not establish GNOME/Wayland or raw scanning acceptance.

## Package and environment

- CI run `40509803957`, package source merge commit
  `06bf606770b8d954fa064ff4cc76275e3f8836a4`, clean debug build.
- [Package manifest](2026-10-28-studio-linux-setup/package-manifest.json).
- All three package hashes matched locally and on the Linux host.
- UI SHA-256: `aa409863b822bbe3f7834600a07e22565d9b202c67f803033879384ef8ed35c0`.
- Runner SHA-256: `783898ba1fb573ddc73fb016bfcd2f0d9206d7f59112fe3e0ee6242d3fe1b2a1`.
- Studio ran as uid/euid 1000 with a private acceptance data directory.
- Temporary Xvfb/Openbox desktop, private D-Bus session and the distribution's
  `polkit-gnome-authentication-agent-1`. Desktop tools were extracted into the
  user's test directory, not installed as system packages. Viewing used a
  localhost-only VNC listener through SSH. No system service or permissive
  polkit policy was added; the existing exec policy required `auth_admin`.

## Observed behavior

| Case | Result and evidence |
| --- | --- |
| Check missing helper | PASS: ordinary UI offers Install helper; [screen](2026-10-28-studio-linux-setup/setup-missing.png) |
| Native permission request | PASS: real graphical polkit password prompt for the installation shell command; [screen](2026-10-28-studio-linux-setup/polkit-prompt.png) |
| User approves installation | PASS: matching helper at its protected destination; [inspection](2026-10-28-studio-linux-setup/after-consent.txt) |
| UI recognizes installation | PASS: Scanner helper is ready; [screen](2026-10-28-studio-linux-setup/setup-ready.png) |
| Manual Check again and Close | User confirmed completion after being asked to perform both actions; no independent final UI capture |

The installed path is
`/usr/local/libexec/masscan-studio/<SHA256>/studio-runner`. The installed file
and every ancestor were root-owned, non-symlink paths with mode 0755. SHA-256
matched the packaged runner. Studio's ready state additionally requires its
normal path trust validation. The application remained uid/euid 1000, with no
`studio-runner` or `pkexec` process remaining after setup.

The acceptance database passed SQLite integrity_check and contained zero scans
and zero results; [record](2026-10-28-studio-linux-setup/history-after.json).
No scan, authorized scanner session, driver or laboratory network change was
performed during this acceptance.

After the user's final confirmation, a fresh SSH inspection again verified the
installed hash, root ownership, mode 0755, database integrity, zero scans/results
and no remaining runner or pkexec process; [final record](2026-10-28-studio-linux-setup/final-check.json).
The temporary Studio/VNC desktop had ended by this inspection, so Screen Sharing
showed Reconnecting rather than a live final application screen.

## Limits

Polkit refusal/retry is **INCONCLUSIVE**: a Cancel click was attempted through
Screen Sharing, but no declined state was captured before the user completed
installation. Subsequent remote clicks did not reliably activate controls.
An unchanged ready screenshot does not by itself prove that Check again ran.
Post-install Check again and Close are user-confirmed; their final UI behavior
was not independently captured before the temporary desktop ended.
Native Cancel waiting, timeout, late approval after cancellation and poisoned
environment cases were **NOT RUN**. The polkit prompt exposes a truncated shell
command rather than a friendly application-specific installer description.

No product code changed. The package's prior CI is identified above; the offline
suite was not rerun for this documentation-only update.

Evidence checksums: [MANIFEST.sha256](2026-10-28-studio-linux-setup/MANIFEST.sha256).
