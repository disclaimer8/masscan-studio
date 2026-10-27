# Studio restart and network guard acceptance

Scope: the sealed Mac feth pair only. This extends the accepted Studio scan,
pause/resume and stop window to two application processes and an actual change
observed by the production network guard. No engine/adapter changes, physical
NIC, Windows raw, Linux raw, sleep or VPN acceptance is implied.

## Procedure

Build a clean committed checkout with Homebrew SQLite:

```sh
cd studio
SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib cargo xtask build
cd ../rmasscan
cargo build --locked -p rmasscan-lab
```

Use the resulting absolute app bundle and laboratory binary paths as `APP` and
`LAB` below. `ROOT` is a new absolute private directory outside the repository.
Keep every attempted window, including NOT RUN and INVALID. Never reuse a
window directory. The orchestrator prints the exact installation/stand setup
commands if their gates are not satisfied; the user handles elevation.

From `studio/`, each command runs a separate UI process:

```sh
cargo xtask feth-acceptance --out "$ROOT/pause" --app "$APP" --lab "$LAB" --stage pause --history "$ROOT/restart-history"
cargo xtask feth-acceptance --out "$ROOT/resume" --app "$APP" --lab "$LAB" --stage resume --history "$ROOT/restart-history"
"$LAB" studio-verify --dir "$ROOT/resume" --pause-dir "$ROOT/pause" --out "$ROOT/resume/verdict.json" --expect-head "$HEAD"
cargo xtask feth-acceptance --out "$ROOT/guard" --app "$APP" --lab "$LAB" --stage guard --history "$ROOT/guard-history"
```

Pause and resume use target `198.18.0.2`, ports `8000-8031`, seed `2`, rate 4.
The first process pauses after 1.5 seconds of Scanning, waits for the durable
checkpoint ACK, locks its runner and quits. The second validates the closed
saved database, authorizes a new session, selects that scan and resumes. It
cannot substitute Start. Before opening the database it records its hash;
the verifier binds that to the first window's final hash and checks the exact
remaining SYN sequence/cookies, a fresh process and attempt, and saved results.
At least one wire-backed row must already be durable before restart; a scan
that received no replies before Pause cannot prove retention and does not PASS.

The guard case uses ports `8000-8255` at rate 4. Only after `guard-ready.json`
appears, remove **the lab source ARP entry on the peer interface**, using the
user-approved privileged operation:

```sh
/usr/sbin/arp -d 198.18.0.1 ifscope feth4202
# Wait for Interrupted; restore even on an error or interrupted operation:
"$LAB" macos-lab link --run-id m1 --up
/usr/sbin/arp -an -i feth4202
```

The existing lab `link --up` operation verifies the sealed peer and keeps it up,
deletes an incomplete source ARP entry if present, installs the fixed mapping,
and reads it back. A complete foreign entry is refused rather than overwritten.
Do not replace this with a plain `arp -S`: Darwin can return zero while retaining
an incomplete entry. Save the actual output of the final scoped ARP query to
`guard/restored-arp.txt` as the ordinary user. It must contain exactly one
permanent `198.18.0.1 -> 02:ac:00:00:00:01` entry on `feth4202`.

This operation must not modify another interface, route, firewall or VPN. Record
the actual UTC removal/restoration times (millisecond precision), exit codes,
and fixed scope in `guard/guard-change.json`. `restore_exit` is the status of
the checked lab restoration; `restored_utc` is taken after the scoped readback:

```json
{"schema":1,"interface":"feth4202","source_ip":"198.18.0.1","removed_utc":"<actual UTC>","restored_utc":"<actual UTC>","remove_exit":0,"restore_exit":0}
```

Do not write invented success values. Write the record as the ordinary user,
after restoration. The orchestrator holds both packet witnesses until the
restoration record and correct scoped ARP observation arrive (maximum 30 seconds after the UI exits), then keeps
them for another second. Missing restoration, witness loss or uplink traffic
invalidates the window. Independently verify the guard window with
`studio-verify --dir "$ROOT/guard" --out "$ROOT/guard/verdict.json" --expect-head "$HEAD"`.
It requires an ARP-related production guard interruption within five seconds,
no checkpoint, and captures covering the restoration. An ordinary Stop or
adapter error cannot pass.

Finally take the stand down and confirm BPF access has been revoked. Preserve
hash manifests, separate histories/chronicles and the independent verdicts;
the mutable private databases themselves stay outside the repository.

## Status

Live restart and guard windows: **NOT RUN**. Offline test success is not a live
acceptance result. Final build identity, runner hash and live evidence will be
recorded here when measured.

Offline verification on the Mac after the single review fix pass:

- Studio: 159 passed, 0 failed, 2 ignored; Clippy and formatting passed.
- rmasscan workspace: 1306 passed, 0 failed, 23 ignored; laboratory Clippy and
  formatting passed. This is offline coverage, including existing engine tests.
- Fresh branch review identified two Important issues: empty pre-restart history
  could pass retention acceptance, and `arp -S` could leave an incomplete entry.
  Both were reproduced as failing tests and fixed. Additional mutations remove
  a previously saved row and supply missing/incomplete/wrong restored ARP data.
  No Critical or deferred Minor findings.
- Initial clean debug bundle at `8107b89` passed codesign verification. Preflight
  refused before launching children: stand absent, BPF access denied, new bundle
  runner not installed, and the current default route is VPN `ppp0` without a
  gateway. System networking and the installed runner were not changed.
- PR #33 tracks delivery; exact-head CI and live windows are separate gates.

Decisions: use the existing sealed lab restoration helper rather than a bare
ARP command; if it cannot restore the mapping, keep the window invalid and
restore the lab before continuing. Reviewer exclusions (physical NIC, other
platforms, engine correctness and live timing) remain open/out of this branch's
scope; none is inferred from these offline results.
