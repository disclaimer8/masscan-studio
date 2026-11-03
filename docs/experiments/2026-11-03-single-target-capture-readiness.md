# Single-target capture readiness: offline continuation

Branch `acceptance/studio-single-target-capture` follows the reviewed foundation
in draft PR #44. Its base `bb8f54c` records clean package/three-OS CI acceptance
at exact executable source `6a72a49`. The initial offline work changed no installed
executable; the packet-free follow-on below installed exact reviewed versions.

## Added and checked

`studio-platform::single_target` now exposes a capture witness and monotonic pin,
with fixed-name records in its existing private root namespace:

- `begin_capture` creates a one-use permit snapshot and a fresh private PCAP,
  refusing an already claimed permit or an existing capture. Partial failures
  preserve evidence and block reuse; an existing link cannot overwrite a target.
- `publish_capture` requires the exact installed issuer executable running as
  root, a still-valid exact permit, and a fresh correct PCAP header. The header is
  synced before the immutable readiness record is published. **Its caller must
  already own an opened capture handle. The API does not itself open one.**
- `live_capture` verifies the exact permit bytes, generation and capture process
  UID/PID/birth/executable/hash, a forty-second lifetime and no ended marker.
- `end_capture` durably invalidates readiness before capture closure. Cleanup can
  run after expiry without granting execution. `CapturePin` fixes one witness
  and one monotonic deadline; rollback, expiry, replacement or explicit failure
  permanently invalidates it.

Local `cargo xtask test`: **374 passed, 0 failed, 2 ignored**, then warnings-denied
Clippy and formatting passed. Four new tests cover identity/lifetime, immutable
monotonic pinning, private one-use files, publication refusal outside root,
claim-before-capture refusal, and non-overwriting symlink failure. Expected RED
failures preceded implementation. Independent read-only review reported no
Critical/Important finding for this offline scope.

Evidence: `.superpowers/sdd/2026-11-03-single-target/capture-red.log`,
`capture-pin-red.log`, `capture-final.log`, `capture-workspace.log`.

This establishes no successful root publication, real capture handle, root
producer, native dispatch or scanner enforcement. There is no new adapter open
or packet-producing entry point. The installed host remains `ae8b...`, PID 49278,
selected tool `89cf...`, helper `5a36...`; no root permission was relinquished.

## Concrete remaining sequence

1. Use the trusted host-config reader below for the authenticated owner UID.
2. Implement the fixed forty-second root capture child in the installed issuer
   executable. Open nonpromiscuous system libpcap with a filter restricted to the
   Mac's MAC address, scanner TCP source/destination port 40000 and its own ARP.
   Create/header-sync/publish only after the handle opens. End readiness on all
   exits and before closing the handle; retain partial evidence on failure.
   Save exact recorded count, drop statistics, timestamps, process identity and
   hashes. A process that survives a stalled worker must not renew readiness.
3. Add typed capture-start/export operations to the host. Keep capture capacity
   separate from its revocation control slot, and never accept arbitrary root
   paths, commands or interface overrides. Complete this protocol before any
   host replacement, so one reviewed OS authorization covers the whole upgrade.
4. Add the separate permit-aware helper environment. Choose it only from the
   exact canonical one-target job, with no fallback from a failed fixture gate.
   Bind the current attempt; check live capture then its pin on every admission;
   claim before possible ARP/TCP; invalidate the lease after any trusted-read
   error. Pin the observed source/interface/route and resolved next-hop MAC.
5. Extend only the exact application-side durable-report predicate and add a
   bounded GUI driver. Preserve persisted-report ACK ordering and zero-response
   results without inventing closed ports. Keep release/general scanning gated.
6. Review, test, package and CI the complete integrated candidate. Then perform
   the explicit reviewed host upgrade, recheck live target permission/DNS,
   create one fresh permit, and run one captured attempt. Verify root provenance,
   process cleanup, permit/attempt IDs, the terminal/quiet window, exact TCP
   probes and actual persisted rows together. No unattended retry or hotel
   device/gateway scan is authorized by this plan.

## Trusted host metadata reader

`work_session::host_config(uid)` reads only the fixed protected host namespace,
refuses owner UID zero, and uses bounded descriptor-based reads. It rejects
wrong owner/mode, links, ACLs, special files, oversized/unknown JSON fields and
file replacement during reading. The ordinary `connect` path now uses this
reader and retains its socket audit-peer and installed-executable verification.
The returned metadata alone is not proof of liveness or execution authority.

The new reader passed its filesystem regression after an observed RED failure.
A read-only Status request from the newly compiled, unenrolled tool reached the
retained host and was correctly refused with `Caller build is not authorized
for this working session`. The approved old client then still reported PID
49278 ready, active 0 and unchanged selected hashes. This verifies the real
namespace reader and expected caller refusal; it grants no new authority.

Logs: `config-red.log`, `config-final.log`, `config-live-refusal.log` and
`config-workspace.log` in the same local evidence directory.

After the reader refactor, the full local `cargo xtask test` finished with
**375 passed, 0 failed, 2 ignored**, warnings-denied Clippy and formatting passed.
Independent read-only review approved the reader while explicitly separating
trusted metadata from host liveness and execution authority.

## Clean package and retained-session acceptance

Exact executable source `be9e6976b868a3aef7a93b2aaf558781149a2fa4` passed
[Studio CI 41641067757](https://github.com/disclaimer8/masscan-studio/actions/runs/41641067757)
on macOS, Linux and Windows. Clean optimized package
`studio/dist/build-1793711083564/Masscan Studio.app` reports that source with
`dirty: false`. All manifest hashes and strict deep codesigning verified.

The retained maintenance host staged these exact immutable versions:

- GUI `709c8f8626c6ecf2d147cd378ecd33a9b53b49f2d1f91d2bf9dfc2af4c8df969`
- helper `4bb38ef5c7e27b06e16d5a819e4c21b480dfa110183f7d440cba3931b7bd0b90`

The reviewed local `verify-retained-session.py` pinned the clean source, all four
package binary hashes, exact Studio workflow and three successful OS jobs, and
the original host/PID/selected binaries before any staging. Packaged
`--smoke-work-session` then completed two actual authenticated helper connections
and Simulation Completed 8, Stopped 2, Completed 16. SQLite integrity passed,
with no checkpoints or network reports. Slint snapshots showed Ready/Lock and
Completed with 16 saved Simulation results. This is automated rendering and IPC
acceptance, not manual UI or native file-picker acceptance.

The original `89cf...` tool and `5a36...` helper selection was restored, with the
same `ae8b...` host PID 49278 and active count zero. The new immutable versions
and GUI caller authorization intentionally remain installed; original binaries
and both new binaries were independently hash/stat checked as root-owned 0755.
The installed helper also passed strict codesign verification. No new OS password
prompt or host replacement occurred. The single-target root namespace remains
absent. No permit creation, root capture publication, adapter access or scan was
performed by this test. Independent read-only review confirmed the bounded PASS
and found no cleanup issue.

Evidence: `capture-session.log`, `capture-session/{before,selected,after,ci,session,verified}.json`,
`capture-session/data/history.sqlite3` and its five Slint snapshots under
`.superpowers/sdd/2026-11-03-single-target/`.
