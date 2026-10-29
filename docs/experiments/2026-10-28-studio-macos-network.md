# macOS network acceptance: fixture tooling and pending native evidence

Task6a implements Rust tooling, portable tests and an actual Studio Controller
driver. **No native setup, BPF opening, packet transmission, helper installation,
stable history access or physical-network acceptance was performed for Task6a.**
The product physical gate remains closed. The driver additionally refuses before
creating its output/history directory until a separately reviewed candidate adds
the pre-ARP and pre-ACK constraints below. This refusal is not acceptance evidence.

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

## Independent witness and Controller driver

The parent/operator must supervise two independent tcpdump processes with a
bounded window, record exact argv/interface/PID/start/stop/exit status and require
the `listening on` readiness output before Start. Stop/reap only those processes
with SIGINT so capture statistics are preserved; a120second capture deadline is
the proposed window for each already-authorized short case. Capture supervision
and identity/hash evidence are not automated by Task6a and must be reviewed in
the native orchestration before execution.

Peer command argv:

```text
/usr/sbin/tcpdump -p -n -U -s 0 -i feth4204 -w /ABS/EVIDENCE/peer.pcap
```

Use the actual observed uplink, never an assumed `en0`, with this exact scope:

```text
/usr/sbin/tcpdump -p -n -U -s 0 -i VERIFIED_UPLINK -w /ABS/EVIDENCE/uplink.pcap 'net 198.18.42.0/29 or host 198.19.42.2 or ether host 02:ac:42:00:00:01 or ether host 02:ac:42:00:00:02 or ether host 02:ac:42:00:01:02 or ether host 02:ac:42:00:01:03 or ether host 02:ac:42:00:01:04'
```

Save stderr separately as `peer.stderr` and `uplink.stderr`. Any captured uplink
frame, unknown/dropped capture statistics, truncated capture or ambiguity aborts
the run. The offline verifier checks classic Ethernet pcap in either endian,
microsecond/nanosecond timestamps, bounded sizes/counts, ordered times, exact
SYN tuples/cookies/MACs/checksums, matching SYN-ACK/RST outcomes, three missing
neighbour ARPs with one-second spacing and final answer window, and zero uplink
frames. It rejects duplicate SYNs/replies and requires all96 completed probes.
All fixture-associated frames are classified or rejected. Valid kernel mDNS and
IPv6 neighbour-discovery multicast have explicit structural/checksum checks;
arbitrary UDP/IPv6 or malformed fixture frames are not silently skipped. Kernel
RSTs are counted separately and accepted only for an eligible even-port tuple
with the expected Ethernet identity, zero ACK/window, no options/data and sequence
matching an earlier captured SYN/SYN-ACK. Foreign/excluded/missing targets,
uncorrelated or duplicate resets fail. Actual native reset shape/count remains an
unmeasured Task6b question. Cookie validation uses the core cookie primitive;
Ethernet/TCP decoding and response construction are independent of Engine.

After Task6b interlocks, run the **unprivileged** driver with the exact packaged,
installed helper path and a new isolated output directory:

```text
/ABS/REVIEWED/xtask network-acceptance drive complete /ABS/CANDIDATE.app/Contents/MacOS/studio-runner /ABS/NEW-COMPLETE
/ABS/REVIEWED/xtask network-acceptance drive pause /ABS/CANDIDATE.app/Contents/MacOS/studio-runner /ABS/NEW-PAUSE
/ABS/REVIEWED/xtask network-acceptance drive resume /ABS/CANDIDATE.app/Contents/MacOS/studio-runner /ABS/NEW-PAUSE
/ABS/REVIEWED/xtask network-acceptance drive stop-preparing /ABS/CANDIDATE.app/Contents/MacOS/studio-runner /ABS/NEW-STOP-PREPARING
/ABS/REVIEWED/xtask network-acceptance drive stop-running /ABS/CANDIDATE.app/Contents/MacOS/studio-runner /ABS/NEW-STOP-RUNNING
/ABS/REVIEWED/xtask network-acceptance drive guard /ABS/CANDIDATE.app/Contents/MacOS/studio-runner /ABS/NEW-GUARD
```

The driver uses real `studio_app::Controller`, `AuthorizeFor`, Start/Resume,
durable coverage, Pause/Stop and Store reopening. It uses no standalone Engine
or mocked helper. It validates exact persisted results, checkpoint presence,
scan continuity/new attempt/frozen report after restart, and logs transitions.
The180second overall deadline includes the authorization dialog. Its local
read-only route check cannot enforce the pre-ARP race boundary; Task6b is required.

For guard drift only after the driver's `bound-for-drift` file exists, the
reviewed action is `sudo /sbin/ifconfig feth4203 down`; no route removal before
binding and no default-route manipulation. A fresh fixture must be established
before another case. The current peer will also stop on drift. The driver cannot
prove packet silence by itself; independent captures must cover the full Stop/
interruption and cleanup interval.

The driver writes `network-report.bin`, case event logs and case Store snapshots.
Copy the complete-case witness into that same evidence directory and run:

```text
/ABS/REVIEWED/xtask network-acceptance verify /ABS/NEW-COMPLETE
```

This command explicitly reports **packet subset PASS**, never full lifecycle
acceptance. It does not authenticate tcpdump provenance, candidate identity or
store artifacts; those require the supervising evidence manifest. Its completed
window contract is not a verifier for partial Stop/Pause/Resume windows. Those
windows need independent cumulative cursor/packet accounting in Task6b/native
review. The driver is controller-level acceptance, not visible Slint UI evidence.

## Task6b: exact candidate interlock design (not implemented here)

Create a separate reviewed **unmerged** commit; do not ship it. No environment
bypass or new IPC field/user setting is needed. Keep the checks mandatory for all
MacNetwork actions in this sealed candidate, including manually launched UI scans.

1. In `studio-runner/src/network.rs`, `Native::observe`: validate the exact fixed
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
4. In `studio-app/src/lib.rs`, `commit_durable`, inside the
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

The shared predicate implementation location is a Task6b code-review decision;
do not couple a normal product binary to xtask or introduce a configurable
production testing bypass. Topology/report predicates here provide the concrete
expected values. Task6b must bind the dynamic interface index and seal generation;
Task6a's pure plan checker only requires a nonzero index until the root journal
is available.

## Evidence status and remaining acceptance

Portable tests cover fixture predicates, independent ARP/TCP codec, capture
parsing/outcomes/timing, ownership-preserving cleanup decisions, stale leases,
exact result rows and refusal before history access. Native setup rollback/crash
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
