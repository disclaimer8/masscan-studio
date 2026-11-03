# Single-target acceptance: offline foundation

Branch: `acceptance/studio-single-target-policy`, based on fixture candidate
`634f46e`. This is an offline implementation record. The installed host/helper,
GUI execution gate and fixture acceptance are unchanged. No public/hotel scan,
new root permit, host replacement or physical capture has been performed.

## Implemented

- Exact public IPv4 intent, one to four sorted TCP ports, rate 1 and nonzero seed.
  Root observations determine the interface/source/MAC/single route. The permit
  fixes owner UID, immutable issuer host hash, selected helper hash, generation
  and lifetime. GUI inputs cannot supply these trusted fields.
- Fixed root namespace
  `/Library/PrivilegedHelperTools/MasscanStudio/single-target-v1`, strict owner,
  mode, ACL, symlink and hardlink checks, bounded reads and a directory lock.
  The initially considered `/private/var/run` was rejected because this Mac's
  ancestor is group writable. No permission relaxation was introduced.
- Durable exclusive-create claims, bound to the permit bytes, helper PID and
  current attempt. Claims survive process exits and cancellation. Revocation
  writes/syncs a tombstone before removing the active permit; generations cannot
  be recreated. Partial records remain fail closed for explicit recovery.
- A sticky session lease combines wall-clock validation with one monotonic
  deadline. Expiry, rollback, replacement and failed observations cannot revive
  that lease. Maintenance inspection can display expired records but cannot
  admit them for execution.
- Typed host `Capabilities`, `SingleTarget::CreatePermit`, `Inspect` and `Revoke`
  operations. New clients negotiate read-only support and reconnect only to the
  identical host/config before sending a new operation. Old hosts are retained.
  Create uses a five-minute lifetime and refuses an existing permit or fixture.
  Stage and fixture creation are blocked until permit cleanup. Stop cleans up
  its permit after active jobs have ended. Revoke has one control slot even when
  all eight helper slots are occupied; it grants no extra scanning capacity.

CLI surface in the *new, uninstalled* tooling:

```
work-session capabilities
work-session single-target create IP PORT[,PORT] SEED
work-session single-target inspect
work-session single-target revoke GENERATION
```

The immutable installed host cannot acquire these operations by staging another
executable. An explicitly reviewed host upgrade remains necessary. Its previous
PID 49278 was observed ready with zero active jobs after these offline checks.

## Validation

Local full Studio workspace: **363 passed, 0 failed, 2 ignored**. Clippy with
warnings denied and formatting checks passed. Focused tests were first observed
failing against stubs or permissive behavior, then passing with enforcement.
Coverage includes competing claims (exactly one of eight), reopen/reuse,
wrong current attempt, altered permit/claim, partial records, ACLs, links,
wrong owner/mode, oversized JSON, monotonic expiry, wall rollback, route binding,
old-host negotiation and revocation at helper capacity.

Independent read-only reviews found and prompted correction of the directory
choice, explicit current-attempt binding and revocation capacity. No remaining
Critical/Important findings were reported for the offline scope. Filesystem
behavior was tested in ordinary-user temporary directories through the same
methods; this is not native root-installation acceptance.

Local logs: `.superpowers/sdd/2026-11-03-single-target/`, particularly
`host-workspace.log`, `host-clippy-final.log`, `storage-final.log`,
`lease-red.log`, `lease-green.log`, `wire-red.log`, `wire-green.log`,
`host-red.log`, `host-final.log` and `revoke-red.log`.

## Remaining integration

Independent bounded physical capture and witness admission, the separate
permit-aware helper environment and attempt claim before ARP/TCP, the exact
application-side durable-report veto, package/CI checks, reviewed host upgrade,
and one explicitly permitted captured run remain outstanding. The current native
scanner still accepts only the sealed local fixture. Release distribution,
manual/native file-picker and broader network acceptance are not established.

## Offline packet-content verifier

The follow-on command `single-target-acceptance verify PERMIT.json REPORT.bin
CAPTURE.pcap STATS.json` reads bounded evidence without opening any adapter. It
requires complete classic Ethernet PCAP records and an exact recorded packet
count with no reported capture drops, a valid permit/report, observed next-hop
ARP resolution before TCP, exact permitted tuples/MACs, complete unique probe
order/cookies, and probe spacing of at least 950 ms (50 ms capture-timestamp
tolerance for the configured 1 pps). IPv4/TCP checksums, fragmentation, header
bounds, options and known TCP option lengths are checked independently of the
scanner's receive parser.

SYN-ACK/RST-ACK replies must correlate with prior probes; duplicate responses are
reported separately, conflicting states fail, and kernel resets require a prior
matching open reply. Silent ports are listed as unanswered and generate no
invented port-state row. This command proves packet-content consistency only: its
input files alone do not prove root provenance, capture readiness, a live grant,
GUI persistence or terminal/quiet windows. Those remain native integration work.

The full local workspace now has **370 passing tests, 0 failed, 2 ignored**. The
subsequent Clippy run and formatting check pass after test-style corrections.
Seven packet cases cover silence, real reply shapes/options, duplicate replies,
correlated resets, missing ARP, count/lifetime mismatch, reordered/duplicate/fast
or corrupted probes, early/foreign/fragmented replies, and capture loss. An
independent review caught malformed known TCP option lengths; the retained RED
regression and final GREEN tests establish the fix. Review approved this offline
scope with no remaining Critical/Important findings. Logs: `packet-red.log`,
`options-red.log`, `packet-final.log`, `witness-workspace.log` (tests passed;
initial lint errors retained) and `witness-clippy.log` (final lint pass).
