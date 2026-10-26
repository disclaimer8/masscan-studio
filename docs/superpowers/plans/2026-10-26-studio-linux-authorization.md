# Studio Linux session authorization

Continue after PR23. Implement the Linux launcher from spec §5 without enabling
raw scanning or modifying rmasscan. System polkit owns the password prompt.

1. Prepare an exact hash-addressed runner under
   `/usr/local/libexec/masscan-studio/<sha256>/studio-runner`; generate a reviewable
   one-time installer. No service, custom product policy or retained authorization.
   Verify root ownership, canonical non-writable ancestors and exact bundled hash.
2. Launch fixed `/usr/bin/pkexec --disable-internal-agent` with an argv array and
   cleared environment. UI remains unprivileged. Generic polkit administrator
   authentication is used; no internal textual password agent or password piping.
3. Authenticate root socket peer using SO_PEERCRED and the exact unreaped Child
   PID launched as pkexec. The child PID remains reserved while retained and the
   direct exec chain must keep that PID; unexpected forking fails closed. Avoid
   reading `/proc/<root-pid>/exe` as the ordinary UI user. Runner validates the
   UI's existing Unix identity and arms PR_SET_PDEATHSIG(SIGKILL) with parent checks.
4. Enable Authorize/Lock on Linux. Reuse the established session and existing
   handshake/cancellation behavior. Read-only preflight reports unsupported on
   Linux; raw gate stays closed. Simulation closes the elevated session first.
5. Tests: portable installer input/quoting/immutable-destination contracts;
   Linux child-PID/UID refusal, parent-death behavior; isolated GitHub Linux VM
   installs only its exact build and uses a temporary path-specific XML polkit
   policy to test actual pkexec without password interaction. Remove policy after
   probe. This proves machine bootstrap, not a user's desktop authentication UI.
6. Full three-OS tests, fresh review, exact-head CI, docs and merge. No home-lab
   activity. Real desktop prompt/cancel and raw acceptance remain explicit gates.

## Review focus

PID binding across pkexec exec and child exit/reaping; root /proc restrictions;
no untrusted root executable/env/shell arguments; immutable installation; delayed
authorization after cancellation; no UI wait forever for an unkillable root child;
parent-death signal set after exec with both race checks; no raw opening.

[pkexec contract](https://www.freedesktop.org/software/polkit/docs/latest/pkexec.1.html)
