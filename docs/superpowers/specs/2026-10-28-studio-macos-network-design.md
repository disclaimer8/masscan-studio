# Studio: scanning home networks and owned servers on macOS

## Intent and scope

The user requested both home-network devices and their own servers, through
Wi-Fi/Ethernet on macOS. The existing Rust/Slint application, authenticated
privileged helper, persistence, TCP SYN engine and BPF adapter remain the product.
This is real TCP SYN scanning, not a TCP-connect replacement or Simulation.

The following are implementation choices, not additional user requirements:

- First release accepts IPv4 addresses, ranges and CIDRs, and TCP ports. It does
  not resolve server names, scan IPv6/UDP, or scan through tunnel/loopback links.
- One active scan uses one Ethernet-compatible interface and source IPv4. Route
  lookup selects the interface automatically; mixed-interface target sets are
  rejected with a useful error before packet transmission.
- At most 1,024 effective target addresses and 1,048,576 probes; all TCP ports
  1–65,535 are available, with at most 1,000 SYN packets/s;
  initial rate 100 packets/s. Existing Simulation/feth limits are unchanged.
- An explicit Start is required. Opening settings, checking a route, installing
  or authorizing the helper never sends ARP or TCP packets.
- Physical-network acceptance requires an explicitly supplied owned target and
  user-granted helper session. No live target is inferred from this design.

## User flow

New scan offers `Mac network · Wi-Fi / Ethernet` on macOS alongside the existing
feth and Simulation profiles. The user enters targets, ports, exclusions and
rate. The application shows the number of effective addresses and probes before
Start. CIDR expansion is bounded before allocation or per-target OS lookups.

Authorize opens the existing verified helper session without requiring a feth
stand for the physical profile. A read-only Check network action reports the
chosen interface, source address, direct/routed destination counts, and any
unsupported route. It does not claim to have resolved ARP or opened BPF.

After Start, the UI reports Preparing network while the helper resolves local
neighbours and gateway MACs. Stop remains responsive during preparation. After
preparation it reports the number of targets actually eligible for TCP probes,
and any addresses with no ARP answer as `not scanned: no neighbour response`.
These addresses are neither closed ports nor successfully scanned hosts.

Remote servers route through their gateway. Every on-link target uses its own
MAC, never a forced default-gateway MAC. Gateways are resolved once per distinct
next hop; all ARP replies are checked against the request, interface and source.
If a gateway cannot be resolved, preparation fails. If an on-link target cannot
be resolved, it is reported separately and excluded from the TCP plan. If none
remain, no engine is started and the result explains why no TCP scan ran.

Existing results, filters, host inspection, export, History and profiles work
with this backend. Persist unresolved-neighbour details with the scan so exports
and reopening History do not imply full target coverage.

Pause, Resume and Stop retain their existing meanings. A paused scan can resume
after restart only with the same job and verified frozen network plan. A changed
interface, source address/MAC, route or resolved destination MAC requires a new
scan. Previously unresolved targets never silently join a resumed scan.

## Architecture

### Reuse without modifying the other worktree

`feat/rmasscan-autodetect` at `e2a3352` contains route discovery and ARP code but
unfinished CLI/lab acceptance. Reuse only the `rmasscan-net` discovery, portable
route parser, OS observation and ARP modules with their tests. Record provenance
in the implementation commit. Do not merge the entire branch, change its files,
or claim its unfinished acceptance is complete. Keep current main dependencies.

### Immutable per-destination Ethernet delivery

The current `AdapterBinding` supplies one next-hop MAC. Extend `ReadyPlan` with an
optional complete, sorted per-destination MAC map, leaving the single-MAC API and
its golden output unchanged. The new constructor accepts only Ethernet, valid
unicast destination MACs and exactly the effective target IPs. The probe builder
selects Ethernet destination bytes from that immutable map; TCP sequence order,
cookies and IP/TCP checksums otherwise remain unchanged.

Engine identity includes a domain-separated, versioned encoding of the complete
map for routed plans. Existing single-MAC identity bytes and checkpoints remain
unchanged. Different destination MACs must produce different job digests.
Never report `Sent` or advance the cursor for a frame that was not sent.

### Physical route snapshot and neighbour preparation

A portable pure planner consumes a bounded target set with selector provenance,
`RouteTable` and `Interfaces`. Preserve explicit singleton addresses separately
from range/CIDR inputs. Apply user exclusions first; an explicit singleton that
remains and names this Mac or a forbidden endpoint is an error even if also
covered by a CIDR. Own addresses and network/broadcast endpoints included only
through ranges/CIDRs are excluded and disclosed. A home /24 containing the Mac
therefore works. Interface prefixes classify only locally connected subnets,
never arbitrary remote server addresses. Apply host/probe limits after these
read-only exclusions, before ARP; unresolved hosts do not relax admission limits. Inspect every effective target, not merely CIDR endpoints. Record
interface name/index, source IPv4/MAC and destination -> next-hop IPv4. Explicitly
handle local host addresses, multicast, unspecified, limited/directed broadcast,
and subnet network addresses using interface prefix information; /31 and /32
are handled according to their host semantics. Invalid explicit targets produce
errors; network/broadcast endpoints implied by a CIDR are excluded and disclosed.
Conflicting aliases/source addresses must not be guessed silently.

Add the missing prefix information to OS observations with synthetic tests. UI
observations may contain Darwin's masked MAC; only the root helper can produce
the final executable snapshot. Reject masked/zero/multicast source MACs there.

Preparation runs away from the IPC command loop. Batch bounded ARP discovery
over one short-lived BPF pair: at most three requests per distinct next hop,
at least one second apart, at most 100 ARP frames/s and a 35-second total
deadline. Run round-robin passes, with no second request until each unresolved
next hop has received its first, and no third until each has received its second.
An unresolved next hop receives three confirmed requests and at least one second
to answer after its last request. Only then classify it as no response. A global
deadline, uncertain send or inability to provide this response window aborts the
whole preparation; it is not a successful partial scan. Poll cancellation between sends/receives, with adapter I/O capped at
50 ms. Validate all input and resume provenance before opening a packet handle.
Check the route snapshot again after ARP and before starting the engine.

Route and interface observation APIs accept a cancellation callback and absolute
monotonic deadline. A read-only check and each full preparation snapshot have a
ten-second budget; the running guard uses its three-second budget. A Darwin
route lookup has an additional one-second absolute cap, including all foreign
replies and EINTR retries. Poll in at most 50 ms slices and check cancellation
before every retry. Never restart a deadline because a foreign message arrived.
Stop requests cancel both observation and ARP; all handles are closed before a
terminal cancellation acknowledgement. The UI remains responsive while workers
finish cancellation.

The running guard checks interface identity, source address/MAC and routes to
all targets. Use the existing one-second polling, three-second freshness and
five-second suspension rules; observations are cancellable. If complete
observation exceeds its budget, interrupt rather than accepting a partial
snapshot. Destination MACs are pinned for an attempt and re-resolved on Resume;
this does not assert continuous proof of remote-host identity.

### Protocol, persistence and checkpoint envelope

Add `Backend::MacNetwork` with a macOS-only release gate distinct from MacFeth.
Keep legacy job JSON readable. Separate job validation from constructing the
runtime adapter binding; the UI must not manufacture a usable physical binding.

Add job-specific read-only preflight commands/events. Network preparation emits
its immutable report through authenticated IPC before TCP starts. Persist this
report before acknowledging it; the helper waits for the acknowledgement. The
report contains original job identity, effective targets, unresolved targets,
routes, source identity and destination MAC map, with bounded lengths. Keep
`MAX_FRAME = 131072`. Encode the report/envelope as a versioned compact binary
blob, at most 24576 bytes, transported through the existing JSON byte-array
field. Use sorted fixed-width IPv4 entries and deduplicated next-hop/MAC tables;
store a 32-byte original-job digest, not duplicate Job strings. Limit interface
name to 63 UTF-8 bytes and use numeric reason tags rather than repeated prose.
The maximum outer JSON Envelope must be tested with worst-case byte values.
Validate both the actual Start frame size and the worst-case future preparation
report/checkpoint size before ARP, including all skipped-address records. This
keeps the maximum admitted job pausable. Oversize is an admission error, never a
late failure after SYNs were sent.

For MacNetwork only, persist a versioned checkpoint envelope containing that
frozen report and the unchanged engine checkpoint. `validate_checkpoint` and
`checkpoint_origin` dispatch by backend/envelope magic and reconstruct the exact
runtime plan. Verify original job, report targets/exclusions, scan/attempt IDs,
index and engine digest. The resumed helper independently verifies current OS
state and ARP; IPC data alone never authorizes a physical adapter binding.
The existing feth/Simulation checkpoint representation and validation remain.

Bump Studio IPC version when changing handshake/command semantics so an old
helper cannot interpret new messages. Update the helper installation normally;
never reuse a runner whose bundled hash differs.

## Failure behaviour and tests

- Malformed/oversized target sets fail before OS work; no ARP/TCP on invalid jobs.
- Split routes, VPN-only routes, own addresses, directed broadcast, masked MACs
  and contradictory source selection have explicit refusal tests.
- On-link A/B must emit different Ethernet destination MACs; routed C/D may
  share the gateway. A gateway failure does not become `closed` or `Completed`.
- Stop during ARP/preparation and during persistence acknowledgement prevents
  later engine startup. No orphan worker may transmit after its attempt ends.
- Network changes before first SYN, during a scan and before Resume interrupt
  or reject; saved rows are retained. No automatic restart after sleep/wake.
- Frozen checkpoint corruption, substituted job/route/map, stale attempt IDs,
  unavailable targets and frame-size overflow fail before packet transmission.
- All fake tests inject routes, neighbours, clock and adapter; no unit test opens
  real BPF. Existing three-OS suites and feth/Simulation regressions remain green.

## Acceptance and delivery

Deliver reviewed PRs for networking foundation and Studio integration. Keep the
physical profile gate closed in merged/distributed builds until the feature has
passed its documented acceptance criteria. Enable it on a clearly identified
unmerged candidate commit for acceptance; tests exercise that same production
path. No environment bypass exists. Merge/release that gate-enabling candidate
only after the required evidence is reviewed; otherwise retain the closed gate.

First use a sealed feth topology with multiple on-link peers and a routed
destination to prove Ethernet addressing, exclusions, cancellation, checkpoint
resume and independent packet counts. Then validate a user-supplied home-network
target and an owned remote server on the actual Mac; record interface type,
expected open/closed ports and any Wi-Fi/AP isolation limitations. No live test
targets or permissions are inferred from historical lab notes.

The final report separates fake tests, sealed-lab evidence and physical-network
evidence. Test or simulator success alone must never be called working physical
Wi-Fi/Ethernet support. Build/sign/hash the final package and use the existing
helper update flow when installation is requested.
