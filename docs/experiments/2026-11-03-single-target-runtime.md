# Single-target runtime admission

This follows capture-dispatch draft #47 (`23d4979`). Its Studio CI run
41647558979 passed on macOS, Windows and Linux. The runtime candidate introduces
a distinct macOS environment selected only by a canonical public IPv4 job with
one to four explicit ports, rate one and a nonzero seed. Other jobs still pass
through the unchanged sealed-fixture predicate; fixture failure never retries
as a public-target job. The authenticated GUI account selects the permit owner.
Windows/Linux physical execution gates are unchanged.

The helper binds one fresh attempt after complete checkpoint validation, refuses
resume, verifies the protected host and installed helper hashes, and pins the
permit and live capture witness. It consumes a durable root claim before ARP.
Route/source/interface, resolved next-hop MAC, claim, capture and lifetime are
checked before TCP adapter use and by the existing network guard. The application
checks the actual persisted job/report bytes before emitting coverage and the
matching acknowledgment. This application-side predicate grants no permission.

Packet admission is checked at the actual send boundary. The existing ARP
resolver receives a callback that revalidates permission, capture, claim and the
outer deadline before/after each send, retry and receive. TCP uses a wrapper with
batch size one and a preopened transmission token, checked before every send and
WouldBlock retry. The token retains exact admitted record bytes and executable
hashes through its own descriptors; each send checks metadata/paths, immutable
directories, end/revocation markers, the kernel capture-lock owner, exact host and
capture process incarnations, wall-clock ordering and original monotonic expiry.
The fast path does not hash files, acquire locks, run commands or write records.
Late admission sends nothing; loss stays latched even if the source is restored.
Background observation continues to detect route changes.

Two contention fixes prevent legitimate concurrent work from being mistaken for
permission loss. Root store acquisition waits within the original finite budget.
Runner state acquisition waits for a retiring preflight worker. Read-only
preflight has an explicit observation method: cancellation of an old preflight
cannot invalidate an attempt that started before that worker resumed. Active
attempt observations retain sticky failure semantics. Admission failures remain
fatal in both paths. Independent review found and verified the ARP retry, first
TCP-send, and stale-preflight cancellation corrections; no Critical/Important
findings remain in the reviewed runtime scope.

Validation: **421 passed, 0 failed, 2 ignored**, then warnings-denied Clippy and
formatting passed. Focused tests
use synthetic adapters/the real resolver, private temporary files, process
identity queries, and real POSIX locks between ordinary test processes. They
cover before-first-send loss, loss after ARP/TCP, WouldBlock retry, restored-but-
invalid sessions, retained-descriptor substitution, bounded lock contention,
expiry/rollback, and preflight retirement scheduling. The composed token tests
construct a private fixture; they do not exercise production root token creation.

Local evidence is under `.superpowers/sdd/2026-11-03-single-target/`:
`runtime-arp-{red,green}.log`, `runtime-lock-{red,green}.log`,
`runtime-transmission-green.log`, `runtime-focused-final.log`, and
`runtime-workspace-final.log`. Earlier compilation/incomplete fixture failures
are retained; only final successful runs establish validation.

No new permit, privileged capture, host replacement or public scan was executed
for this change. The existing retained administrative host is unchanged. Next is
the bounded GUI driver and independent comparison of its saved results with
captured responses, including zero-response completion and terminal quiet time.
The integrated candidate still requires review, clean packaging, CI and one
reviewed host upgrade before native single-target acceptance. This remains draft
and undistributed.
