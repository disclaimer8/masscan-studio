# Studio restart and network guard acceptance

Scope: the sealed Mac feth pair only. This extends the accepted Studio scan,
pause/resume and stop window to two application processes and an actual change
observed by the production network guard. No engine/adapter changes, physical
NIC, Windows raw, Linux raw, sleep or VPN acceptance is implied.

**Accepted on 2026-10-27:** restart Resume PASS 4/4; ARP-triggered interruption
PASS 2/2. Source/build `35b063cf943383765926fe1c417dcd8a6e36ca8d`, macOS 27.0.1,
Apple Silicon, debug bundle. Both archived windows were independently rechecked.
[Evidence and hashes](2026-10-27-studio-restart-guard-raw/README.md).

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

Live acceptance is limited to the exact Mac feth cases below. Offline test
success is recorded separately.

| Window | Observed result |
| --- | --- |
| `preflight-8107b89` | NOT RUN before children started: no stand, BPF grant or matching installed runner; VPN default route lacked a gateway. Preserved, not promoted. |
| `pause-35b063c-r1` | PASS 2/2. PID 15735, durable Paused checkpoint at index 7 (120 bytes), 7 saved rows, pause ACK in 3094 ms; runner locked and process exited. |
| `resume-35b063c-r1` paired with pause | PASS 4/4. New PID 16068 and engine attempt; identical saved scan/database before launch. Exact remaining 25 probes, final Completed with 32 rows (8 open), including the prior 7 rows. |
| `guard-35b063c-r1` | PASS 2/2. Source ARP entry removed at 11:02:43.119Z, production guard Interrupted at 11:02:44.261Z: **1142 ms**. 113 rows retained, no checkpoint/resume index. Permanent mapping read back at 11:02:48.172Z. |

The scoped ARP operation used the system authorization dialog, `arp -d`, a
five-second wait and the existing checked `macos-lab link --up` restoration.
An EXIT trap also requested restoration. Timestamps came from the system zsh
`EPOCHREALTIME` around the actual commands, converted to UTC milliseconds;
`guard-operator.log` preserves those raw values and return codes. No root process
wrote to the user-owned evidence directory; the ordinary operator saved the
returned record and scoped ARP output.

All three windows: zero lab packets on `en0`, complete independent witnesses,
zero reported kernel drops, clean closure and `raw_run_allowed: true` before
and after. The user disabled VPN before setup; its behavior was not tested.
After the final window, `down` removed the pair and revoked the grant:
`/dev/bpf0..15` are `0600 root:wheel`, status reports no stand, and no Studio or
tcpdump process remains. The ordinary default route stayed `en0` via its gateway.

Build identity:

- UI SHA-256: `305164bc2b8daa73546286c85e365dc29281b53ba6be61e5be6537f637746860`.
- Runner (bundle = installed): `f649ff03030e2bd08a54c83b5ea055e7829b4b4b75350acb7b0a4413f9dc6de4`.
- Laboratory verifier: `275c3e74570e1b107ad0681ad997036620519b874d5d6c6c157fffd3f32112d6`.
- Clean build manifest and code-head CI are in `verification/`. Studio and
  rmasscan passed macOS/Linux/Windows CI, including the Windows wire package.
  The delivery commit adds only this report/evidence and verification status;
  it does not change the tested code.

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
- [PR #33](https://github.com/disclaimer8/masscan-studio/pull/33) tracks delivery;
  its final documentation-head checks are separate from the archived code-head CI.

Decisions: use the existing sealed lab restoration helper rather than a bare
ARP command; if it cannot restore the mapping, keep the window invalid and
restore the lab before continuing. Reviewer exclusions (physical NIC, other
platforms and general engine correctness) remain open/out of this branch's
scope; none is inferred from these results. The measured guard timing covers
this ARP perturbation only, not sleep, VPN or physical link loss.
