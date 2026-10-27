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

The guard case uses ports `8000-8255` at rate 4. Only after `guard-ready.json`
appears, remove **the lab source ARP entry on the peer interface**, using the
user-approved privileged operation:

```sh
/usr/sbin/arp -d 198.18.0.1 ifscope feth4202
# Wait for Interrupted; restore even on an error or interrupted operation.
/usr/sbin/arp -S 198.18.0.1 02:ac:00:00:00:01 ifscope feth4202
```

This operation must not modify another interface, route, firewall or VPN. Record
the actual UTC removal/restoration times (millisecond precision), exit codes,
and fixed scope in `guard/guard-change.json`:

```json
{"schema":1,"interface":"feth4202","source_ip":"198.18.0.1","removed_utc":"<actual UTC>","restored_utc":"<actual UTC>","remove_exit":0,"restore_exit":0}
```

Do not write invented success values. Write the record as the ordinary user,
after restoration. The orchestrator holds both packet witnesses until the
restoration record arrives (maximum 30 seconds after the UI exits), then keeps
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
