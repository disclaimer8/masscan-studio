# Single-target root recorder: source and offline acceptance

Branch `acceptance/studio-single-target-recorder` follows draft #45 at `511a414`.
The new `single-target-acceptance capture UID GENERATION` child requires root,
the exact installed issuer executable, a live matching parent host, trusted
fixed-namespace configuration and permit, and an independently observed exact
route before opening nonpromiscuous system libpcap. It accepts no interface,
filter or output-path override and transmits no packets. The retained host has
not been replaced and has no dispatch for this command.

Recording is bounded by a forty-second monotonic deadline, 1,024 frames and
16 MiB. The control pipe is nonblocking; only an explicit stop byte succeeds,
while EOF, invalid control, timeout, loss, malformed/truncated/backward frames
and write failure are errors. Stop invalidates readiness before draining the
bounded queue. The system BPF compiler/interpreter was exercised with synthetic
Ethernet frames without opening a device: own scanner TCP and own ARP matched;
foreign MACs and unrelated TCP ports did not.

Ready publication occurs only with the capture handle alive and its correct
PCAP header synced. A fixed private file holds a POSIX write lock owned by the
publisher process; the witness binds its device/inode. Readers use `F_GETLK`
and require the exact publisher PID, without acquiring a lock themselves.
This kernel lease is released unconditionally before statistics/handle closure,
even if publication or the durable ended marker fails. Same-process lease
queries refuse before opening another descriptor, because closing any descriptor
for that inode would release the process's POSIX locks.

Independent review identified the original marker-only cleanup gap. It was
corrected with this kernel lease and cross-process regressions demonstrating
refusal after release while the publisher remains alive and no ended marker
exists. Injected partial-publication/end failures also verify invalidation
ordering. Repeat read-only review found no remaining Critical/Important issue
in this source/offline scope.

Final root evidence has fixed names, private immutable records, a bounded
descriptor-based read of the actual PCAP, its SHA-256/size, counts, drop counters,
process/permit identity, elapsed time and an explicit failure field. Missing
statistics, drops, inconsistent counts and expired recording cannot be labeled
successful. Partial failures are retained; failed cleanup cannot manufacture a
successful completion record.

Validation: **391 passed, 0 failed, 2 ignored**, then warnings-denied Clippy and
formatting passed. Local logs under `.superpowers/sdd/2026-11-03-single-target/`:
`recorder-red.log`, `capture-completion-red.log`, `recorder-invalidation-red.log`,
`recorder-lease-final.log` (33 focused tests), `recorder-workspace-final.log`.

This is not native capture acceptance: no adapter was opened, no root permit or
capture record was created, no host replaced, and no public/hotel target scanned.
Typed host capture dispatch/export, hard child supervision, permit-aware scanner
admission, GUI integration and terminal/quiet-window proof remain the next work.
Keep draft and undistributed; preserve the current administrative session.
