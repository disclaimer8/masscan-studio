# macOS network acceptance: fixture tooling and pending native evidence

**2026-10-30 status:** the first native complete-case trial reached96 expected
results, but capture shutdown failed. Acceptance remains FAIL. See the
[native trial report](2026-10-30-studio-macos-network-native.md) for exact candidate,
packet observations, retained evidence, teardown and the remaining blocker.
The implementation-stage statements below describe the pre-trial preparation.

Task6a implements Rust tooling, portable tests and an actual Studio Controller
driver. **No native setup, BPF opening, packet transmission, helper installation,
stable history access or physical-network acceptance was performed for Task6a.**
PR41/integration remains closed-gate at f5b1877. This separate, unmerged
`acceptance/studio-macos-network-fixture` candidate implements Task6b1's mandatory
pre-ARP and persisted-report pre-ACK hooks and enables its MacNetwork gate/driver
interlock together. This is preparation for review, not native acceptance or an
execution grant. Task6b2 now prepares capture/peer supervision and partial lifecycle consistency
checks. They remain unrun on native interfaces. Do not run native commands until
the complete branch, exact binaries/dependencies/hashes, three-OS CI and the
concrete privilege action have been reviewed.

## Fixed topology

| Role | Interface / address | Ethernet identity |
| --- | --- | --- |
| Scanner | feth4203, 198.18.42.1/29 | 02:ac:42:00:00:01 |
| Raw peer adapter | feth4204, **no IPv4** | 02:ac:42:00:00:02 |
| Direct A | 198.18.42.2 | 02:ac:42:00:01:02 |
| Direct B | 198.18.42.3 | 02:ac:42:00:01:03 |
| Synthetic gateway | 198.18.42.4 | 02:ac:42:00:01:04 |
| Deliberately missing neighbour | 198.18.42.5 | no ARP reply |
| Routed destination | 198.19.42.2/32 via 198.18.42.4 | gateway MAC |

The fixed MacNetwork job requests `198.18.42.0/29,198.19.42.2`, excludes
`198.18.42.4,198.18.42.6`, uses ports8000–8031, seed42 and rate4. The planner must
exclude the scanner, network and broadcast endpoints; four effective targets
remain, three become TCP eligible, and the missing target stays explicitly
unscanned. Expected completed results:96 endpoints, even ports open and odd ports
closed. The peer implements independent ARP and IPv4/TCP codecs; it does not run
Engine or use Engine's packet builder. Tests may feed production-built SYNs into
that independent codec.

The existing feth4201/feth4202 /30 fixture and all product local-address exclusions
remain unchanged. No simulated target is assigned to a local interface. Setup
does not alter the default route, forwarding, firewall, BPF permissions or stable
application installation. A pre-existing overlapping route/prefix/address/MAC
or fixture interface name is a refusal.

## Implemented commands and ownership

Build with the existing Homebrew toolchain, without a second release target:

```sh
SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib SQLITE3_INCLUDE_DIR=/opt/homebrew/opt/sqlite/include /opt/homebrew/bin/cargo build --manifest-path studio/Cargo.toml --locked -p xtask
studio/target/debug/xtask network-acceptance plan
```

`plan` prints the exact fixed setup argv and job without OS network access.
The explicit privileged commands, after review of the exact binary/hash, are:

```sh
sudo /ABS/REVIEWED/xtask network-acceptance up
sudo /ABS/REVIEWED/xtask network-acceptance status
sudo /ABS/REVIEWED/xtask network-acceptance peer
sudo /ABS/REVIEWED/xtask network-acceptance stop-peer
sudo /ABS/REVIEWED/xtask network-acceptance down
```

These lines are the reviewable operator handoff, not a request to execute them
from this document. The parent records absolute paths, candidate commit and hashes
before requesting the concrete privilege action. `up` creates only the fixed
pair/source subnet and one host route. It writes an exclusive root-owned journal
under `/private/var/run/studio-network-fixture-v1` with a random generation,
tooling hash, creation/expiry times and observed interface indices/MACs/peers,
IPv4 addresses/prefixes, bridge memberships and administrative link state.
The seal lasts30minutes; expiration, backward time or partial setup cannot
authorize status/peer work. `up` never refreshes an existing seal. `down` permits
cleanup after expiration but requires live ownership matches.

Only an independently successful create establishes ownership of that resource;
setup never adopts the other interface merely because it became visible. Each
later command validates the prior identity and records only its expected
transition. Every confirmed setup operation updates the journal. A failed operation retains
the journal and resources for `down`; there is no blind rollback. If a crash
leaves an unrecorded interface, cleanup preserves it and reports the ambiguity.
Changed index/MAC/peer/address/prefix/bridge/route also stops cleanup; only the
documented scanner link-down transition is allowed. Exact host-route evidence
comes from bounded route-table rows with destination /32 and up/gateway/host/static
flags, never a reduced destination lookup. An absent host with ordinary uplink
fallback is distinct from a broader replacement using a fixture interface; the
latter preserves the stand for inspection. The journal/lock directory stays
for safe reuse; successful down removes the completed state and stop marker.
Native commands have5second subprocess deadlines and64KiB output limits. The
fixed root directory rejects symlinks, wrong owners, permissive modes, hardlinked
state files and extended ACLs.

The raw peer holds the fixture lock, so down cannot race it. It has a90second
deadline,2048reply cap,50ms I/O requests and measured zero-drop health checks. A
separate root-only stop marker cancels it. It never retries an uncertain or
unconfirmed send. Neither this deadline nor a5second subprocess deadline is a
hard preemption guarantee for a native kernel call; existing macOS BPF open/write
limitations still apply. The peer is non-promiscuous: **whether feth delivers the
distinct synthetic destination MACs to this BPF reader is untested**. Missing
delivery must fail acceptance, never justify weakening the product adapter.

## Task6b2: supervised evidence and unprivileged Controller

`supervise` is temporary acceptance tooling, not a daemon or product protocol.
Root owns three child handles from the exact protected xtask: independent capture
on `feth4204`, independent capture on the observed active Ethernet/Wi-Fi default
uplink, and the raw peer. The capture workers use system libpcap, separately from
the scanner's BPF adapters and packet builder. The fixed uplink IP/MAC filter is
unchanged. Each worker checks the sealed tooling hash, live fixture and expected
interface before opening a non-promiscuous Ethernet capture. The supervisor pins
child PID/OS start identity, exact argv, hash and explicit readiness before issuing
a ticket. Manifest schema2 requires these capture-worker commands and tooling
hashes; old tcpdump manifests cannot be accepted as schema2 evidence.

The privileged tool must link **only system libraries**, including system libpcap
and Apple SDK SQLite. Inspect all load commands and rerun affected tests for the
exact build before installing it. A user-writable Homebrew dependency remains a
refusal even when the executable itself is protected.

The supervisor writes only new root0700 `run-<nonce>` directories inside the
fixed seal directory. It never executes/signals a command/PID from driver files.
An approved read-only platform wrapper opens each path component with anchored
`openat`, rejects symlinks, pins directory identities and checks the intended
unprivileged owner. Only fixed preparation/phase/attempt basenames can be read;
nonregular, hardlinked, permissively writable, changed, oversized or late data
is refused. Replacing a parent directory is also a refusal. Driver files remain
untrusted evidence; matching a nonce does not turn them into privileged commands.

Each case has a120second supervisor deadline,16MiB capture caps,64KiB child-log
caps and5second shutdown waits. The raw peer retains its90second deadline and
2048reply cap. A timeout is a failure, including the peer reaching its deadline.
The driver must start from a fresh ticket and finish its main loop within70seconds
of readiness, including normal helper authorization. Slow authorization may fail
the case; no password storage, scripted SecurityAgent or root Controller is used.
These are cooperative deadlines; native kernel I/O is not forcibly preemptible.

Capture uses verified nonblocking reads, immediate mode, a131072-byte snapshot
and microsecond timestamps. An empty read returns promptly; idle polling sleeps
10ms. Readiness follows writing/flushing the pcap header. The supervisor sends a
single stop byte through its own inherited anonymous pipe, waits for exit0 and
retains measured libpcap statistics. EOF or an invalid command is a failure.
After Stop, the worker drains available packets under an absolute500ms budget;
the120second overall deadline and20000-record/16MiB limits remain in force. It
syncs the output before reporting final statistics and exiting. A timeout, write
error or drop cannot produce a successful shutdown. This replaces signal-driven
tcpdump shutdown after the documented native failure; it does not relax the
capture evidence criteria. The peer stops via the fixed
trusted stop marker and must exit0 with measured zero drops. Unexpected exit,
unknown/missing/duplicate capture counters, kernel/interface drops, malformed
pcap, uplink traffic, forced kill or deadline fails the case. Failure cleanup
kills/reaps only owned children; it never deletes interfaces, routes or evidence.
A fresh ownership check under the operation lock clears the previous case's
trusted peer-stop marker while preserving the seal for Pause→Resume.

### Concrete command sequence for final review (do not execute yet)

The parent substitutes reviewed absolute paths, UID, hashes and unique case
paths below. `ROOT-XTASK` must be a protected root-owned copy of the reviewed
system-library build; the unprivileged `XTASK` must have the same SHA256.
The packaged runner uses the normal helper installation/authorization flow.
First, as the ordinary user, prepare the new directory that root will pin:

```text
/ABS/XTASK network-acceptance prepare-drive complete /ABS/NEW-COMPLETE
```

In terminal1, the final approved root action starts supervision. The ordinary
shell opens the stdout redirect before `sudo`; the supervisor itself writes no
user-selected path. The first stdout line is the ticket, printed and flushed
only after all three children are ready:

```text
sudo /ABS/ROOT-XTASK network-acceptance supervise complete /ABS/NEW-COMPLETE USER_UID RUNNER_SHA256 > /ABS/complete-ticket-stream.ndjson
```

While that command is still running, in terminal2, after the JSON line appears:

```text
/usr/bin/head -n 1 /ABS/complete-ticket-stream.ndjson > /ABS/complete-ticket.json
/ABS/XTASK network-acceptance drive complete /ABS/CANDIDATE.app/Contents/MacOS/studio-runner /ABS/NEW-COMPLETE /ABS/complete-ticket.json
```

Use the same three-command sequence with distinct directories/ticket files for
`pause`, `stop-preparing`, `stop-running` and `guard`. Guard runs last. After a
successful pause, **do not down/up the fixture**. Start a new driver process and
a fresh supervised case against the same paused directory:

```text
/ABS/XTASK network-acceptance prepare-drive resume /ABS/NEW-PAUSE
sudo /ABS/ROOT-XTASK network-acceptance supervise resume /ABS/NEW-PAUSE USER_UID RUNNER_SHA256 PAUSE_RUN_NONCE > /ABS/resume-ticket-stream.ndjson
/usr/bin/head -n 1 /ABS/resume-ticket-stream.ndjson > /ABS/resume-ticket.json
/ABS/XTASK network-acceptance drive resume /ABS/CANDIDATE.app/Contents/MacOS/studio-runner /ABS/NEW-PAUSE /ABS/resume-ticket.json
```

The last two commands run in terminal2 while terminal1 supervises. The prior
nonce refers only to a fixed root-owned `run-<nonce>` directory, never a supplied
root read path. Resume requires the same seal/index, tooling/runner hashes, scan
and frozen report, a distinct run nonce, a different driver PID and attempt ID.

For `guard`, there is no separate operator `ifconfig` command. Only after the
real driver reports at least four sent probes and supplies matching scan/attempt
phase evidence does the supervisor consider a guard transition. **Before either
peer stop or link-down**, current root-owned captures must independently contain
at least the claimed number of distinct valid-cookie eligible SYNs strictly after
this ticket's Start and before its phase timestamp, with no uplink frame.
Readiness, driver Start, phase and current root time must be ordered and fresh;
malformed packets, duplicate probes or uncorrelated replies/resets refuse.
Only then does the supervisor stop/reap the healthy peer, freshly recheck ownership
and run exactly `/sbin/ifconfig feth4203 down`.

A concurrent tcpdump write may expose a partial header/record. The shared decoder
returns Pending and credits zero probes for that whole snapshot; it never discards
a truncated tail and treats the remaining prefix as proof. The supervisor rereads
under one deadline, the earlier of five seconds from first phase observation and
the remaining overall budget. A replaced/disappearing phase cannot renew that
budget. Missing/unflushed capture headers also fail at that deadline; native live
flush behavior is unrun. Exact accepted snapshots are synced in the private run
directory before mutation, hash-bound in the manifest and required to be byte-for-
byte prefixes of the same final captures. Final verification repeats the pre-action
gate and still requires an actual Controller `Interrupted` after the drift. Probes between peer shutdown and link-down still count; missing responses do
not become closed results. No supervisor action terminates the Controller.

The driver uses actual Controller/Store APIs, writes explicit Start/control/
terminal/joined anchors, leaves Controller alive for two seconds after terminal
to detect restart, then drops it and reopens the isolated Store. Both captures
continue at least another two seconds after joining. Successful supervision runs
the offline consistency checker before returning success. Original root-owned
artifacts include ticket, manifest, copied attempt/Store evidence, both captures,
child stdout/stderr, exact hashes, argv/PIDs, readiness/stop/reap windows and health.

Export the reviewed exact run directory through stdout; only the unprivileged
right-hand command writes to the user evidence directory:

```text
sudo /usr/bin/tar -C /private/var/run/studio-network-fixture-v1 -cf - run-RUN_NONCE | /usr/bin/tar -xf - -C /ABS/USER-EVIDENCE
/ABS/XTASK network-acceptance verify-lifecycle /ABS/USER-EVIDENCE/run-RUN_NONCE
/ABS/XTASK network-acceptance verify-lifecycle /ABS/USER-EVIDENCE/run-RESUME_NONCE /ABS/USER-EVIDENCE/run-PAUSE_NONCE
```

The fixed `down` command remains a separate, reviewed cleanup after all child
processes have ended. Capture evidence is retained. No stable application,
history, default route, forwarding, firewall or BPF permission is changed.

### What the evidence checks establish

The decoder remains independent and strict about Ethernet/TCP/checksums/MACs,
SYN cookies, matching replies and separately counted correlated kernel resets.
The new checker uses the existing production `NetworkCheckpoint`/engine decoder
and `ProbeCursor`, not a copied parser/permutation. Pause must match its durable
sent cursor exactly. Resume must continue the exact suffix without duplicate or
missing tuples, preserve the frozen unresolved target and reach96 cumulative
eligible endpoints with96 correct retained open/closed rows. Running Stop/guard
require a4–95 probe prefix and retained rows correlated to captured responses;
Stop during Preparing requires zero TCP and zero rows. Partial cases never
pretend all96 probes completed. Initial completed preparation still requires
three missing-neighbour ARPs with full one-second answer windows; Resume must
not ARP the formerly missing neighbour.

Wall timestamps are bracketed with monotonic reads. Independent50ms sampling
runs even while the driver or supervisor blocks. More than5ms cumulative
wall/monotonic divergence, reversed time, samples more than one second apart,
wrong windows or packet/event interval overlap fails as ambiguous. Scanner ARP
and SYN packets must be strictly before the **observed Controller terminal**;
peer replies after terminal are allowed and are not new scanner probes. Classic
pcap contributes up to1microsecond timestamp quantisation to the comparison.
This is sampled clock consistency: it cannot exclude a wall-clock step and
return entirely between samples, nor identify an earlier internal engine stop
instant. Native timestamp-source/clock assumptions require explicit review.

Output deliberately says **Offline consistency PASS**, not native acceptance.
Copied files cannot authenticate their original recorder, actual execution or
candidate binary. The native reviewer must compare the private root-owned
originals, package/dependency hashes, invocation/privilege record and timestamps.
The older `verify DIR` remains only the complete96-packet subset checker; it is
not a substitute for `verify-lifecycle` or provenance review. The Controller
fixture is not visible Slint UI acceptance.

## Task6b1: mandatory candidate hooks (implemented; native use unrun)

This separate **unmerged** candidate must not ship. There is no environment
bypass or new IPC field/user setting. The hooks are mandatory for all MacNetwork
actions, including manually launched UI scans. Pure predicates live in
`studio-protocol::sealed_fixture`; xtask re-exports the existing topology and
ownership modules. Root-only, read-only seal/live checks live in
`studio-platform::sealed_fixture`, with no peer-lock acquisition or seal refresh.
`studio-runner/src/network/native.rs` owns the session pin and hooks. The remaining
requirements below describe their enforced boundaries.

1. In `studio-runner/src/network/native.rs`, `Native::observe`: validate the exact fixed
   job and a fresh trusted sealed manifest before OS observation. Obtain the
   existing bounded production `plan_physical` result, then validate the exact
   feth source/index/MAC, original next-hop/exclusion map and live manifest
   ownership before returning. This applies to initial preparation, Resume,
   final launch and every running guard observation. Read-only preflight may
   allow masked source only if it never grants executable readiness.
2. In `Native::neighbours`, before `self.open`/`resolve_neighbours`, verify the
   same sealed source and full or frozen-eligible subset. Resume omits the
   previously unresolved target from neighbour resolution but must not add a
   new target. In `Native::open`, before `open_explicit`, reread/validate the
   trusted current seal and require `feth4203`, its recorded index/source/MAC,
   Ethernet and source port40000. This is necessary because a preflight result
   alone can race route changes and ARP precedes the report ACK.
3. Manifest validation is read-only: no creation, refresh or repair from the
   helper. Require root ownership/no ACL/symlink/hardlink/mode surprises,
   schema1, `sealed=true`, fresh30minute lease, fixed resource names/identities,
   exact host route and no peer IPv4/bridge. Pin generation and observed
   interface index for the helper's candidate session/attempt; do not accept a
   replacement seal after down/up or merely compare constants. The peer holds
   the fixture lock, so the helper must read the atomically replaced seal and
   check live identities rather than try to acquire that exclusive lock.
4. In `studio-app/src/lib.rs`, `commit_scan_events`, inside the
   `Event::NetworkPrepared` arm: after the existing `Store::apply_batch`
   commit and fetching `saved`, decode **saved.network_report**, validate its
   job and exact source/routes/direct MACs/gateway/missing/excluded coverage,
   then and only then allow `AckNetworkReport`. Validate the initial subset
   and Resume identically. Failure sends no ACK and follows existing error/
   connection teardown. Keep the existing halted/cancellation checks. The
   driver receiving `Update::NetworkCoverage` is too late to be this veto.
5. Add tests showing bad/missing/expired/replaced seals, wrong interface/source,
   route fallback to uplink, altered MAC/report and failed persisted report
   all refuse before open/ARP/ACK. Verify valid Resume's eligible subset. Only
   in that same reviewed commit enable the physical gate and change
   `SEALED_CANDIDATE_INTERLOCKS_REVIEWED` in the driver to true. Gate change
   alone deliberately cannot enable Task6a's driver.

The whole schema1 seal is pinned for the helper session, including generation,
scanner/peer indices and tooling hash; any replacement requires a new helper
session. The same sealed state is reread before and after live ownership checks.
No route fallback can pass the complete fixed plan predicate. Fresh initial ARP
and frozen eligible Resume ARP use the same production Native implementation.

Native checks and subprocesses consume the caller's absolute10second observation/
launch or3second guard deadline, with cancellation before/after steps. Adapter
open also receives the remaining deadline/cancellation callback; a late or
cancelled pair is dropped before a Launch can be published. BPF open/kernel calls
are still not forcibly preemptible. The Task6b1 subprocess wrapper remains for short ownership-observation
commands; Task6b2 separately owns long-lived capture/raw-peer child handles.

Candidate Check network cannot read a root0700 seal without an authorized helper
and refuses readiness. This temporary restriction does not change PR41's normal
closed-gate read-only route UX. A later general-purpose candidate should branch
from reviewed integration and deliberately carry the generic open deadline/
cancellation improvement; it must not accidentally drop that fix while omitting
the temporary fixture policy.

## Evidence status and remaining acceptance

Portable/synthetic tests cover fixture predicates, independent ARP/TCP codec,
capture parsing/outcomes/timing, partial/cumulative lifecycle evidence, decoded
checkpoints and reopened temporary Store rows, owned harmless-child cancellation,
read-only evidence-path substitution refusals, ownership-preserving cleanup,
stale leases, exact result rows and refusal before history access. Native setup rollback/crash
recovery, feth synthetic-MAC delivery, packet witnesses, preparation Stop,
running Stop, Pause/Resume, process restart, guard drift and visible UI are all
**unrun**. No all-unresolved or gateway-failure native scenario is implemented by
this fixed peer mode; existing fake tests do not replace those native checks.

After sealed-lab evidence is reviewed, a second separately reviewed unmerged
candidate may remove the fixture-only constraints for the operator's explicitly
owned home/server targets. Their addresses stay in the private
`acceptance-targets.md`, never in this report or PR evidence. Record actual link
type and expected ports, Wi-Fi/AP limitations, package/helper hashes and exact
three-OS CI before any release decision. Keep the distributed gate closed until
all required evidence passes.
