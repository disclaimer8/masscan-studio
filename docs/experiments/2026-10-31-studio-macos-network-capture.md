# macOS capture replacement trial — 2026-10-31

**Partial acceptance.** The integrated replacement capture stopped cleanly with
no matching packets, and the complete fixed-fixture scan passed the root
supervisor's strict packet/lifecycle verifier. The remaining lifecycle cases
are not accepted: one authorization missed its ticket window, and a fresh
retry exposed a raw-peer parser failure on a valid macOS IGMPv3 report. This does not replace the retained
[October30 failed tcpdump trial](2026-10-30-studio-macos-network-native.md).

## Candidate and provenance

- Tested candidate: `11644d3f7b47181917a060bca0e733268cb62d48`; capture implementation
  is unchanged from `923334e44769e8026498a939c4ab6531e5f39363`.
- Exact-candidate Studio CI41103185475 and engine CI41103185467 passed on macOS15,
  Windows2025 and Ubuntu24.04, including language guards and Windows packaging.
  Logs and result JSON are retained in the local task evidence directory.
- The existing signed package is `studio/dist/build-1793382752065/Masscan Studio.app`.
  Its signature and both prepared executable hashes were rechecked before use.
- Helper SHA256:
  `e64c1b9181b6d579d13519b9136d601706b289fb2669e2627d34db86d3b1d574`.
- Tool SHA256:
  `21a15706878b968931695ddd6f33b66a9f8ff8b445402e729ab55dc7ce9ecd27`.

After the operator accepted macOS administrator authorization, the existing
reviewed immutable installer installed both binaries under their separate
root-owned hash directories in `/Library/PrivilegedHelperTools/MasscanStudio/`.
The xtask tool uses the installer's `studio-runner` filename. The root supervisor
ran that protected copy; the unprivileged Controller used the packaged helper
and normal session authorization. The stable application and history were not
replaced. No service was registered.

## Measured outcomes

The fixed feth4203/feth4204 topology was sealed with generation
`74e45d186814adbb1920f7a4e0da1a92`. Only the previously reviewed synthetic fixture
was used; no owned home/server or other physical-network target was scanned.

| Case | Observed result |
| --- | --- |
| Empty uplink capture | Waited for capture readiness, then one second before sending `S` through its owned pipe. Exit0; pcap24 bytes, zero records; reported `ps_recv=79`, `ps_drop=0`, `ps_ifdrop=0`. |
| Complete | Controller Completed; root strict verifier PASS:96 probes,96 correlated replies, cumulative cursor96. |
| Reopened complete history | Read-only SQLite query confirms96 rows:48 open,48 closed; persisted Completed status and184-byte network report. |
| Stop during preparation | No completed authorization event, Start event, scan row or result row. Controller reported its acceptance deadline expired and resources joined. This is not a Stop behavior pass. |
| Stop while running, Pause, restarted Resume, guard drift | Not run; suite stopped at the preceding failure. |
| Teardown | Supervisor EXIT cleanup succeeded; fixed interfaces and route removed, default uplink remains en0, no acceptance child processes remain. |

The complete case's root verifier requires successful owned-child shutdown,
packet/counter consistency and the quiet interval. Its successful result is
evidence of the integrated capture fix on this host. The originals were exported
with administrator authorization later on October31 and reviewed independently
of the live supervisor. Offline `verify-lifecycle` also passed. Manifest schema2
has `failure:null`; all three protected children exited0 without forced shutdown.
Peer capture contains250 records (`ps_recv=250`, `ps_drop=0`); uplink contains0
records (`ps_recv=23190`, `ps_drop=0`). Raw peer reports99 responses and its trusted
stop marker. These received counters have the qualification below.

- Archive SHA256: `6ac348e79a6a8c4110adce4bc5d2ca7eaaa54c3cbd465af4b6f1718bfcfd2c0a`.
- Complete manifest SHA256: `91d627bec5ddef0cef8bab18d77b0b14496402c4ff037f038df809e5f709bc34`.
- Complete peer pcap SHA256: `c76dc81ecceabaf71575470189703d11315670ab63804ab8a5eac1f02a7292d8`.
- Complete uplink pcap SHA256 matches the empty-capture hash below.

### Capture counter interpretation

The empty pcap's SHA256 is
`3655110dcbdeac48654f1892eaf351a8ab30a8528b40f4cebda08dcae2104745`.
Its79 received-counter events must not be described as79 matching packets or
fixture leakage. The published [Apple BPF implementation](https://github.com/apple-oss-distributions/libpcap/blob/main/libpcap/pcap-bpf.c)
counts packets handed to the filter in `ps_recv`, reads BPF buffer drops in
`ps_drop`, and sets `ps_ifdrop` to zero. The general
[libpcap statistics contract](https://www.tcpdump.org/manpages/pcap_stats.3pcap.html)
also warns that interface-drop availability varies. Therefore the reported zero
interface counter is not an independent measurement proving zero hardware or
driver loss. The reviewed published source is explanatory context, not a claim
that its revision was matched byte-for-byte to the installed Apple library.

## Retained evidence and continuation

Private root originals remain under `/private/var/run/studio-network-fixture-v1/`:

- Complete: `run-8057cca502d801ea38536c08d576d168`.
- Failed authorization attempt: `run-04677b5d1c2ba55b837b2344a5378f19`.

Root-owned public ticket/result files, empty-capture files and teardown output
remain under `/private/var/run/studio-network-tickets-v2-20261030/`. The directory
name reflects preparation on October30; these trials actually ran October31.
The suite exit code is1, preserving the failed second case.

Local Controller events and isolated histories are in
`.superpowers/sdd/2026-10-28-studio-macos-network/native-capture-v2/`.
The fresh retry and its exported evidence are in `native-capture-v2-retry1/`.
No failed evidence was overwritten.

## Fresh retry: IGMP parser failure

Retry seal `b544533fe9cae3dfd6c4f7fe55d53d77`, stop-preparing nonce
`7ea972a5615aa02f289c680935c0c1f6`, failed before Start. The raw peer exited1 after
0.456s with `malformed fixture IPv4 header`. Authorization finished at8.977s;
by then the root supervisor had removed the fixture. The Controller's route
mismatch was a consequence of teardown, not the initiating failure. Both capture
children exited0 without forced termination. No Stop behavior is accepted.
Automatic teardown and evidence export completed; suite exit remains1.

- Archive SHA256: `4a2fa79975d82e68e9d450752acd796d839999a0725b90951574081dba496377`.
- Peer pcap SHA256: `de284d117cd54c224abbf7eac82fb19ae0964b03ef368052afb5c5f6748d9b28`.
- Public output: `/private/var/run/studio-network-tickets-v2-retry1-20261031/`.

The peer capture contains a valid macOS IGMPv3 membership report with a24-byte
IPv4 header and Router Alert option. The existing fixture parser required a
20-byte IPv4 header before considering this kernel multicast. Protocol2, TTL1
and Router Alert are part of [IGMPv3](https://www.rfc-editor.org/rfc/rfc3376.html).
A proposed passive route diagnostic was cancelled before authorization/execution
once the original peer error and packet identified the cause.

## Reviewed correction and local checks

`wire.rs` now accepts only the observed fixed scanner identity and source-free
mDNS membership report: exact multicast destination, Router Alert, TTL, lengths,
fragment constraints, record types1–4, one group, and both valid checksums.
It classifies that report as kernel multicast and emits no response. TCP/UDP
rules, packet credit, zero-record uplink requirement and failed manifests remain
unchanged. Regression tests use only the54-byte synthetic frame, not captured
Bonjour metadata; repaired-checksum mutations, padding and truncations exercise
the rejection boundaries. Independent review found no issues.

The full run also exposed an unrelated existing UI test ambiguity: a filter
`80` matched timestamp milliseconds `.580` in both rows. The test now fixes that
collision timestamp and uses `80 tcp` for the intended row. Deterministic RED
and GREEN runs confirm the correction; application search behavior is unchanged.
Full Studio tests pass:314 passed,0 failed,2 ignored. Local logs and reviewer
notes are retained in the task evidence directory.

Next, after exact-source CI and installation of the corrected protected tool,
execute the remaining five cases on a newly sealed fixture. Pause and Resume must share that seal and paused history. Retain the
failed authorization attempt regardless of later results. The candidate remains
unmerged; complete lifecycle, owned-target and visible native UI acceptance are
still required before opening the distributed physical-network gate.


## October31 10:28 continuation: Stop and restarted Resume

Source46c0bc28e747dfa1a675470e7307d4fb8949ffe4 passed exact-source Studio
CI41191395865 and engine CI41191395844 on all three OSes, including Windows
packaging. Corrected tool SHA256
`51644dfac6e66c2c9000890d6c93dd46024ba95761a3341fb219a80de93d95ce`
was installed with operator authorization and independently hash/signature/owner
checked. Packaged helper remains `e64c1b9181b6d579d13519b9136d601706b289fb2669e2627d34db86d3b1d574`.

The operator authorized the native retry. Root-owned original evidence was
exported automatically on teardown and checked offline again.

| Case | Native result | Nonce |
| --- | --- | --- |
| Stop during preparation | PASS; Stopped,0 TCP probes/replies | `4831e82bb34a12a3e89bab283e22da75` |
| Stop while running | PASS; Stopped,5 probes/5 correlated replies | `9b293fa10821adea05622108d593b844` |
| Initial Pause | PASS; Paused at cursor5 | `7a2c6853145ea3000a2026e896f73c2e` |
| Fresh Pause | PASS; Paused at cursor5 | `2fda080fa7b413fb9cfb0ddc67c57115` |
| Restarted Resume | PASS;91 additional probes/replies, cumulative cursor96 | `458160bc4260207a156dacb57d02ef92` |
| Guard interruption | FAILED; guard mutation was never requested, scan Completed | `7b50ffce113489e5e01c6f4e7986296d` |

The initial retry stopped before Resume because its orchestration omitted
`prepare-drive resume` for the shared Pause directory. This was a preparation
error, not a Resume failure. A fresh seal and shared Pause/Resume history were
then prepared with both markers; the second pair passed. Both suite exit codes
remain1 because each suite contains an unaccepted case.

- Retry2 seal: `29c42397f009b6c48a178b83c4d2c985`.
- Retry2 archive SHA256: `cdd3433e1f187ae9ba8b2320257dbdd28d6f15af90bb359f0838a1aa8f73b711`.
- Retry3 seal: `d71ed420ce1d7de54da047cc3a79ddee`.
- Retry3 archive SHA256: `72259a6f5b21b7ee01eff0943224a8de399f1701a215783e87dc21374f5e857c`.
- Public originals/export records: `/private/var/run/studio-network-tickets-v2-retry2-20261031/`
  and `/private/var/run/studio-network-tickets-v2-retry3-20261031/`.
- Local copies: task evidence `native-capture-v2-retry2/evidence/` and
  `native-capture-v2-retry3/evidence/`; manifest/child summary in
  `native-20261031-lifecycle-summary.json`.

Guard diagnosis: the driver learns the active scan/attempt only from
`Update::History`. A successful new Start does not emit that update until its
terminal event, so the guard's `active` value remains absent while scanning and
`guard-phase.json` is never written. The scan therefore Completed rather than
Interrupted. The driver rejected that terminal status; the raw peer later reached
its90-second bound, and the supervisor retained a failed manifest. This is an
acceptance-driver defect; it supplies no evidence that the production network
guard would fail after an actual interface change. The failed manifest remains
rejected offline. A regression and reviewed correction are still required.

Both stands were automatically removed; feth4203/feth4204 are absent. There is
no pending authorization or native child. No owned physical target or final UI
acceptance is claimed. Guard acceptance is still outstanding.

The operator requested one authorization for the whole working period instead
of one per test process. The installed helper is retained. Ordinary Studio already
reuses its authorized helper for successive scans until Lock/application closure;
independent acceptance processes currently reopen authorization. No persistent
privileged service or generic command channel was added. A bounded shared
working-session authorization design remains a follow-up, before repeating a
multi-prompt test suite.
