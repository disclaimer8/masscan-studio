# Single-target GUI and independent result evidence

This follows runtime draft #48, `5eaaa4d1870531688b3392d6fd70cca27fe38645`.
Runtime CI 41654422870 passed on macOS, Windows and Linux. Its clean release
package is `studio/dist/build-1793716272908` (`dirty:false`); packaged GUI
Simulation completed eight endpoints and displayed eight saved results. This
packet-free package check did not install or replace the retained host.

The new `--smoke-single-target` driver uses the real GUI callbacks and Controller.
It requires a fresh history directory under canonical `STUDIO_SMOKE_OUT`, a
bounded `single-target-ticket.json`, a live typed host supporting capture, the
same unclaimed root permit returned by Inspect, the selected GUI/helper hashes,
and the installed root capture process. This ordinary-user ticket grants no
packet authority: the helper still consumes and revalidates the root claim.
The driver permits one Start, has a finite capture-relative deadline, and never
retries. Cancellation/failure/another terminal outcome fails the run.

Completion can correctly display zero replies. The driver records the actual
rendered model's IP/port/TCP state projection, final status and sent count,
screenshot, full clock samples, and the report/results reread from SQLite after
the Controller has joined. A same-count visible-state substitution is rejected.
It creates `gui-attempt.json` once; the external supervisor remains responsible
for checking process exit, package identity and the subsequent quiet interval.

Root capture now records precise opened/ready/stopped/closed stamps and an
independent clock sampler. All 50ms samples are validated before retaining a
bounded 500ms series, so a discarded sample cannot conceal a discontinuity.
Clock faults mark the capture unsuccessful. The conservative recording endpoint
is `stopped`, sampled before readiness invalidation and drain; `closed` is after
handle closure and cannot establish recording coverage until that time. The
optional timeline preserves earlier offline packet-only fixtures; GUI verification
requires it.

`single-target-acceptance verify-gui EXPORT.bin ATTEMPT.json HISTORY_DIR` checks
root export integrity, exact permit/nonce/capture PID, dense clock coverage,
readiness before Start and at least two seconds of recording after GUI/controller
join. Scanner SYN/ARP requests must lie strictly inside the unambiguous active
GUI window. Saved results must exactly match correlated responses before terminal
completion. Later responses are reported separately, and ambiguous completion
boundary responses fail. Silence never becomes a fabricated closed port.

The verifier independently reads SQLite with a read-only transaction and
parameterized queries, checking integrity, the sole exact scan/attempt/report,
Completed status, no resume checkpoint and the exact saved rows. It does not use
the application's migrating/open-for-write Store path. Offline content consistency
still cannot authenticate a copied file: orchestration must pin the actual
package, GUI PID/process incarnation, root peer and exported generation.

Validation results will be recorded after the final workspace run. Focused
checks use synthetic frames, real Slint models without a desktop, private SQLite
fixtures and clock records. They include silent success, correlated/late replies,
ambiguous timing, identity/count/result/clock/quiet-window substitutions, a
changed visible state with unchanged count, unchanged database bytes on read,
and rejection of an injected saved result. Independent source review found no
remaining Critical/Important findings in this scope.

No new permit, host upgrade, capture or public scan occurred. Next is a bounded
ordinary-user supervisor with pinned package/CI/provenance, one reviewed host
replacement, live target-permission/DNS checks, one captured GUI attempt and
owned-resource cleanup. Native acceptance remains unrun until those execute.
