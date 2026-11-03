# Saved native history and restarted GUI Resume — November 3

## Candidate and scope

Clean source `d732533350da45ce663df75950c9dea418c5223c`, optimized package
`studio/dist/build-1793705852120/Masscan Studio.app` (`dirty: false`):

| Executable | SHA256 |
| --- | --- |
| launcher | `a2d9cdf8fc101503af7dc69992948434c9acf0d1274672e3dfefb3ef3489937e` |
| GUI | `d53724806b7a5233b44a8daf713a02221fda3167c4445220d33dd9b0f11f3ca1` |
| helper | `5a36e5206db04e9a4314b9890f9ddecfedff87e107ee7798e9f43623eab70238` |
| inspect | `7e38220fee0bf6c080beba4fdc88915b52341d6591b47cea38378bc04437c5ca` |

The profile label and settings hint now accurately say that this development
build scans only the isolated local test network. README describes the actual
branch gates. This changes no scanner permission, helper admission, topology or
packet policy. Arbitrary physical Wi-Fi/Ethernet targets remain disabled.

## Saved native results: PASS

The packaged launcher ran `--smoke-history` against private SQLite backups of
all three independently witnessed native scans from the
[earlier GUI report](2026-11-02-studio-gui-work-session.md). Each run:

- Restored the correct Completed/Stopped status, every result and saved coverage.
- Opened History and used Repeat settings after deliberately changing the form;
  the exact backend, targets, ports, exclusions, rate and seed were restored.
- Filtered to one saved IP and sorted ports descending, then used an empty filter.
- Reselected History through its callback, resetting the filter and sort state.
- Exported the visible projection as both JSON and CSV for the full, filtered,
  empty and reselected views, through the same existing atomic writer used by
  the application's Export action.

| Original scan | Saved rows | Filtered rows | Exports | Outcome |
| --- | --- | --- | --- | --- |
| Complete first | 96 | 32 | 8 | PASS |
| Stop | 5 | 1 | 8 | PASS |
| Complete again | 96 | 32 | 8 | PASS |

A separate Python verifier parsed all 24 output files and compared result tuples,
state, timestamps and displayed order with the original SQLite records. JSON and
CSV agree. Whole-scan counts remain 9/288 requested, 7/224 candidates, 4/128
effective, 3/96 eligible, 1/32 unresolved and 3/96 automatically excluded, including
when the visible results are empty. CSV non-result records have no invented port,
protocol or open/closed state. Original job and scan identity remain exact.

Every copied database passed SQLite integrity and retained an identical logical
dump after the GUI actions. Original evidence file hashes were unchanged. No scan,
helper authorization, lookup or inspection callback was invoked by this driver.
Native save-file dialogs and the asynchronous Export callback are outside this
acceptance; this proves the shared projection/writer and GUI history controls,
not OS file-picker interaction or manual keyboard/mouse input.

Local evidence:
`.superpowers/sdd/2026-11-02-studio-gui-session/history-release/verified.json`,
per-case `output/history.json`, PNGs, JSON/CSV exports and `gui.log`.
`history-debug/` preserves the earlier successful development-binary trials.
The final driver clears itself after completion; its report contains each stage
once. Review caught and fixed a harness gap: sort properties are now set as the
header does before checking that History selection clears them.

## Pause and restarted Resume: PASS

The GUI driver now admits independently supervised `pause` and `resume` cases.
Pause uses the real button callback and requires a durable valid checkpoint.
Resume requires that marked paused history, waits for its restored Paused state
before authorization, and invokes the real Resume callback. It must preserve the
scan ID and frozen report, create a new attempt, finish with 96 cumulative rows,
and consume the checkpoint. Each Attempt record is published only after the GUI
and Controller have been dropped/joined.

The unchanged root verifier requires the previous protected pause nonce, the same
sealed generation, distinct driver PIDs, and exact remaining packet sequence. The
existing supervisor removes its trusted stop marker under lock before the next
case, preserving the fixture generation; no unprivileged marker removal or root
tool change was introduced.

Studio CI `41628983537` passed on macOS, Windows and Linux at the exact candidate.
Native admission reused successful engine CI `41624845306` at `4fbe472`; the
script asserts identical rmasscan tree and engine workflow blobs at both commits.
The fixture tool remains the reviewed immutable
`89cf345602bb9c7f9de6711e35bf031a5a87f35db5d0899506e7df8f43c55018` binary.

| Stage | GUI PID | Captured SYNs / replies | Durable result |
| --- | --- | --- | --- |
| Pause | 4857 | 5 / 5 | Paused, 5 rows, valid checkpoint at index 5 |
| Restarted Resume | 5441 | 91 / 91 | Completed, 96 cumulative rows, no checkpoint |

Root supervision verified the protected originals and exited 0 for both stages;
export and offline verification also exited 0. The packet verifier checked the
exact prefix and remaining sequence, correlated replies, timing/quiet periods,
and preservation of the same frozen report and fixture generation. All six
capture/responder children exited 0 without forced termination. Each uplink pcap
contains only its 24-byte header, with zero matching fixture frames; this makes
no assertion that the actual uplink had no unrelated traffic.

Independent verification checked every exported manifest hash, each archive
hash, SQLite integrity and exact saved rows/status/checkpoint/report against the
attempt records. It confirmed the same scan ID, distinct attempt IDs and driver
PIDs, and identical frozen coverage. A separate SQLite backup preserves the
Paused state before Resume changed the live test history. Both rendered terminal
snapshots are retained. Owned teardown succeeded; host PID 49278 remained ready,
active 0, with identical selection before/after and no additional password.

| Stage / nonce | Archive SHA256 |
| --- | --- |
| Pause / `13568aaf49f1efef6a5e0654f908b32d` | `e7f10fd662b6fdc5164e0764c059b68766671d2f60144d4784cb31267c2b3090` |
| Resume / `76fcf2cb8308f3ac7d7cc824e10f355a` | `99cd3029df462bcd79baf8e908b94a4acc6ef19e6e6f12936bff01c238c2cc9c` |

Local evidence: `.superpowers/sdd/2026-11-02-studio-gui-session/native-pause-resume1/`,
including `summary.json`, `verified.json`, root verifier transcripts, exported
archives, per-stage SQLite backups and `driver/pause-terminal.png` /
`driver/resume-terminal.png`. Raw captures remain local.

This proves Pause and Resume after restarting the GUI on the isolated fixture.
It does not prove same-window native Stop/Start or Pause/Resume, physical Wi-Fi
scanning, network-loss/sleep/VPN handling, or manual input acceptance.

## Validation

- Full local Studio workspace: 338 passed, zero failed, two ignored.
- Final affected GUI suite: 41 unit tests plus one launcher integration passed.
- Clippy with warnings denied, formatting and scoped code reviews passed.
- This exact package passed two helper authorizations/releases through the retained
  host, plus simulation Complete/Stop/Start with 8, 2 and 16 rows. Evidence:
  `pause-session/verified.json` under the same local session directory.
- The history gate was observed RED when it accepted missing rows/status/coverage,
  then GREEN. Pause/Resume admission was observed RED before implementation.
- Packet evidence and CI for the earlier Complete/Stop/Complete package retain
  their own `4fbe472` source provenance. Do not transfer them to this new GUI hash.
