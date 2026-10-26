# Windows desktop authorization acceptance

This checklist is separate from Windows Server CI. It uses no packet adapters,
Npcap, engine labs or network scans. Windows Authorize/Lock was enabled after
the desktop acceptance recorded in VERIFICATION.md. Repeat this checklist after
changes to bootstrap, IPC identity, cancellation or lifetime ownership.

Record the exact commit, Windows version, runner SHA-256, and whether the original
account belongs to Administrators. The supported model is an ordinary process of
the **same** account elevating itself; another administrator's credentials are not
supported. Never record passwords.

For a downloaded Windows package, no Rust toolchain is needed: open an ordinary
PowerShell in the package directory and replace `cargo xtask` below with
`.\studio-tools.exe`. Preparation must name the packaged runner explicitly:
`.\studio-tools.exe prepare-runner .\studio-runner.exe`. Use the SHA-256 printed
by that command. This utility accepts only preparation, installed-file verification
and the bounded authorization probe when distributed as `studio-tools.exe`.

1. In an ordinary PowerShell terminal at `studio/`, run
   `cargo xtask prepare-runner`. Review the emitted `install.ps1` and manifest.
   Run that script once in elevated PowerShell 7+. Close the elevated terminal.
   This installs a new immutable version; it does not authorize a Studio session.
2. From the ordinary terminal, run
   `cargo xtask probe-windows-authorization <manifest-sha256>` and allow Windows
   consent. Expected: elevated same-account runner, Hello, two unavailable network
   preflights, successful CloseSession, runner exit within two seconds. The UI
   account must remain unelevated. Repeat to verify a fresh session can start.
3. Repeat and deny the system dialog. Expected: an authorization error, no session
   or surviving runner. Retry must offer a fresh dialog and succeed after consent.
4. Start another probe and leave consent pending. Terminate only that probe process
   (close its terminal or use Task Manager), then respond to any remaining system
   dialog. Expected: late authorization cannot connect to the destroyed endpoint
   or join its destroyed Job Object; no runner survives. Record whether Windows
   dismisses the original dialog automatically. Do not mistake dialog dismissal
   for verification of a launched late process.
5. If a second local administrator account is available, repeat consent using its
   credentials. Expected: explicit alternate-account refusal, no session, no scan.
   Record NOT RUN when that account is unavailable; do not create one for this test.

6. For IPC loss and explicit Job Object closure, set
   `$env:STUDIO_UAC_LAB_ACCEPTANCE='1'`, then run the same probe with `disconnect`
   and `drop` as the last argument, consenting to each prompt. Each must report
   PASS and verify runner exit through a retained process handle within two seconds.
7. CI packages `uac-acceptance/studio-uac-tests.exe` and its hash/source manifest.
   Verify both against the package. From an ordinary terminal, set
   `$env:STUDIO_TEST_UAC_HASH` to the installed hash and the lab flag above, then run:

   ```powershell
   .\studio-uac-tests.exe --ignored --exact windows::uac::tests::cancellation_destroys_endpoints_before_late_runner_and_allows_retry --nocapture
   ```

   Consent to the deliberately late runner. The controlled launcher barrier
   proves cancellation while the owner stays alive, prompt exclusion until late
   completion, destroyed endpoints, late installed-runner exit and retry. This
   test cancels before releasing the ShellExecute call; case 4 separately covers
   actual owner death while the secure-desktop consent prompt is visible.
8. For abrupt death of an established owner, the lab-only `owner <ready-file>`
   probe writes retained runner/owner identities after Hello and repeated preflight.
   A supervisor must retain both process handles, compare creation times and
   executable paths, then terminate only that owner and wait at most two seconds
   for the retained runner. The fixture times out after 15 seconds if no supervisor
   intervenes. Never select processes by a broad name pattern.

Hosted Windows CI cannot answer UAC consent and returned ERROR_CANCELLED (1223).
It builds the fixture but does not mark these interactive checks passed.

Record PASS/FAIL/NOT RUN for each case with commit/hash and diagnostics. A green
offline test suite is not evidence that the desktop consent cases were performed.
