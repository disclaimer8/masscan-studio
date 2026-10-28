# Studio runner setup acceptance — 2026-10-27

Scope: explicit installation of the helper matching this application build. No
packet adapter, scan or authorized scanner session is started by setup.

## Source and package

- Code commit: `7322abd4c44da78a60dda201ed8b4237de6bb4b3`.
- macOS 27.0.1, Apple Silicon; debug package, clean source tree.
- Package: `studio/dist/build-1793106251940/Masscan Studio.app`.
- UI SHA-256: `eb172a46b748e1c7213e741e4f3c39144521bee6112d98491ef0851c41859164`.
- Runner SHA-256: `48d859da08c808cda139ec1ea49ea9e308698a47ba5982b022b13ee5bccac15a`.
- Full manifest, package/signature log and tests are in
  [the evidence directory](2026-10-27-studio-runner-setup/).

## Observed

- Workspace: **170 passed / 0 failed / 2 ignored** with the required external
  Homebrew SQLite. Ignored live checks were not converted to passes.
- New regression reproduced cleanup blocking for 0.51 seconds when termination
  fails; fixed cleanup detaches the remaining wait. The complete workspace passed
  after that fix. This is a failure-injection test, not native polkit acceptance.
- Package `codesign --verify --deep --strict` passed.
- Normal macOS app launch displayed the setup panel. **Scanner setup** checked
  the actual bundled helper, correctly reported this version absent, and offered
  **Install helper…** without launching a permission prompt.
- [Setup check screenshot](2026-10-27-studio-runner-setup/setup-check.png).

## Live installation status

**macOS installation: PASS.** The user clicked Install helper and confirmed the
system prompt. The panel changed to **Scanner helper is ready**, removing Install.
Check again also returned ready without a new permission prompt. Independent
inspection found the expected SHA-256 at the hash-addressed destination,
`root:wheel` ownership, mode `0755`, and a valid strict code signature. The
application's ready state additionally requires its normal ancestor/ACL/symlink
trust checks. [Ready screenshot](2026-10-27-studio-runner-setup/setup-ready.png)
and [installed file record](2026-10-27-studio-runner-setup/installed.txt).

This proves installation of this exact local debug build on one Mac. Native
permission-dialog cancellation/timeout was not exercised; the bounded cleanup
and failure paths were tested offline. No scan or authorized session was started.

**Windows installation and UAC refusal/retry: PASS on 2026-10-28.** See the
[native Windows setup report](2026-10-28-studio-windows-setup.md) for the exact
package, protected installed hash, UI recheck and retained evidence.
**Linux user-approved installation: PASS on 2026-10-28** in a temporary Xvfb
desktop with a real graphical polkit agent. See the [Linux setup report](2026-10-28-studio-linux-setup.md)
for evidence and the unverified refusal/retry and desktop-specific cases.
Earlier runner session-authorization acceptance is a different path.
Cross-platform CI covers compilation, offline behavior, existing installer tests
and packaging; it does not prove successful interaction with desktop prompts.

## Review

One fresh whole-branch review found one Important issue: Linux cancellation could
block in `Child::wait` after `pkexec` became root and kill failed. The fix was
verified RED → GREEN and with the whole workspace. No Critical or Minor findings.
Same-account malicious code and administrator compromise remain outside the
existing personal-build threat model. Engine/discovery work is unchanged.
