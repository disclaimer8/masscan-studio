# Single-target capture readiness: offline continuation

Branch `acceptance/studio-single-target-capture` follows the reviewed foundation
in draft PR #44. Its base `bb8f54c` records clean package/three-OS CI acceptance
at exact executable source `6a72a49`. No installed executable has been changed.

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

1. Add a bounded trusted host-config reader for an authenticated owner UID.
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
