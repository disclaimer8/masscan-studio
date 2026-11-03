# Single-target capture dispatch and evidence export

This follows recorder draft #46 (`03f64a1`). Host protocol version 2 explicitly
advertises capture support. Clients negotiate read-only capabilities before
reconnecting to an identical host configuration for Capture or ExportCapture.
Version 1/missing capability refuses without replacing or mutating the old host.

Capture uses the exact protected issuer executable and authenticated owner's
current permit generation. The child retains its own root/parent/permit/route
checks. Readiness is sent only after trusted `live_capture` checks, including
the kernel lease, and a match to this exact child PID. Capture has one separate
capacity reservation; a full ordinary-helper capacity plus capture still leaves
the dedicated revocation operation available. Staging and host stop remain
blocked while active work exists.

The supervisor owns and reaps only its child. It bounds startup, output and total
runtime (50 seconds, including the worker's forty-second recording and cleanup).
Client disconnect shortens cleanup to four seconds. A valid `S` stops the
recording; EOF or another byte is a failed run. Monitoring continues after `S`,
so a disappearing client cannot retain a stalled child until the longer deadline.
The client keeps its write side open after a valid stop. This was a concrete
review finding, corrected and covered by an ordinary `sleep` child regression.

`work-session single-target export GENERATION` sends a single JSON metadata line
followed by raw PCAP bytes on stdout. Root accepts no output path: only completed,
fixed-name private evidence belonging to the authenticated UID is eligible. It
rechecks the permit snapshot, matching ready/ended/result witnesses, actual
PCAP size and SHA-256 before streaming bounded frames. Expired or revoked
completed evidence remains exportable without granting execution.

`single-target-acceptance verify-evidence EXPORT.bin REPORT.bin` checks the
bounded metadata envelope, canonical permit binding, capture hash/size, success
status and measured counters, then runs the independent packet-content verifier.
It also rejects packets at or after the second following completion and SYNs
before the readiness second. Metadata timestamps have one-second resolution;
this is not subsecond admission or terminal quiet-window proof. Buffered
background traffic before publication is allowed. Offline content consistency
alone is not proof that the input came from root. A synthetic early-completion
case exposed this second review finding; its RED failure and GREEN fix are kept.

Validation: **397 passed, 0 failed, 2 ignored**, then warnings-denied Clippy and
formatting passed. Focused dispatch/envelope checks passed 13 tests, using only
private temporary files, synthetic packets and ordinary `cat`/`sleep` child
processes. Independent read-only review confirmed both Important findings fixed
and found no remaining Critical/Important issue in this scope.

Local evidence under `.superpowers/sdd/2026-11-03-single-target/`:
`capture-export-{red,green}.log`, `capture-host-{red,green}.log`,
`capture-host-tests.log`, `capture-window-{red,final}.log`,
`dispatch-workspace-reviewed.log`. Earlier interrupted/formatting-failed logs
are retained and superseded by the reviewed final run.

No root capture, new permit, host replacement, adapter opening or public scan
occurred. The retained administrative host remains available. Next: bind the
authenticated owner/current attempt to a distinct permit-aware scanner
environment, claim before ARP/TCP, enforce live capture and pinned route/MAC,
extend the exact durable-report predicate and add the bounded GUI driver.
Only the reviewed integrated candidate should trigger the single host upgrade.
