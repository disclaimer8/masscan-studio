# Work-session build updates and guard identity — 2026-10-31

The operator requested retained administrator access throughout development. The
first host retained access across clients but pinned one build, so rebuilding the
driver still required a new OS grant. Commit `6c0f875` adds explicit reviewed-build
staging; it also publishes the durable active scan/attempt identity at Started,
before Progress, to let the guard acceptance driver request its interruption.

`work-session stage TOOL RUNNER` is a software-maintenance capability: an approved
client may select reviewed executable code for privileged installation and use.
It is not a semantic verifier of arbitrary selected code. The host copies bounded
regular account-owned sources through no-follow descriptors into private root
storage, checks their requested hashes and signatures/system dependencies, then
publishes immutable versions. Existing verified installed versions are reused.
The tool/helper pair changes together after both installs succeed. Staging refuses
active work or an owned fixture. The host's identity stays fixed and previous
approved tool clients retain access. Fixture ownership uses the selected tool hash;
helper selection is rechecked after its lease reservation. See
[authorization guide](../../studio/AUTHORIZATION.md).

Validation: 329 local Studio tests passed, 0 failed, 2 ignored; Clippy and formatting
passed. New/resumed attempt identity, source ownership/type/link/size/hash rejection,
idle reservation, failed publication atomicity, selected caller acceptance, prior
caller retention and stale helper rejection have targeted regression coverage.
Scoped independent review found no Critical/Important issues. A minor follow-up
remains: copy/codesign/otool staging validation has no explicit wall-clock deadline.
Studio CI `41196748241` passed all three OS packages on `6c0f875`.

Engine CI `41196748208` failed its existing macOS
`would_block_unsent_backs_off_1ms_on_the_injected_clock` test: a concurrent fake RX
advanced the shared manual clock to a spurious 10,125 ms TX stall. Commit `51aef46`
is test-only: decouple RX from that clock and use zero RX drain time in the
TX-backoff-specific test. Runtime code is unchanged. All 32 lifecycle tests and 30
repetitions of the corrected test passed; scoped review found no issues.
Studio CI `41197077580` passed all three OS packages on `51aef46`. The engine
rerun `41197077592` also completed successfully on all three OSes.

Native activation completed that evening after one successful OS authorization.
The earlier unconfirmed prompt expired at 180 seconds and is retained in the logs.
Replacement archived the old PID 97855 host and started root host PID 49278. This
host is deliberately LEFT ACTIVE at the operator's request.

Actual staging passed: the unapproved new client was rejected before staging;
then both new hash versions were installed as root-owned immutable files, the
selected pair changed, and the new client was admitted. The original client
remained usable. Two separate authenticated root helpers (PID 49885 and 49992)
completed protocol 3 probes and exited with their IPC endpoints removed. The host
PID stayed49278, active 0 after each. Repeating the same stage was idempotent.
No authorization command or system prompt occurred during these operations.

Prepared package: `studio/dist/build-1793445885381/Masscan Studio.app`.
Tool SHA256 `ae8b058514f77783591c41995f4801ce3bff25373e78a81894879a2d223e0d8f`;
helper SHA256 `aa23da896185d7ef1773555fa41ed525c05325307aa03066c2a3fa0c05dc0bad`.
Additional copies with different ad-hoc signature identifiers, but identical
reviewed executable code, are prepared to verify actual new-hash installation:
tool `496ab1d8d2157d83e76b01ed9221d16541b808f2505d4b5fe8d337a4f4ef5c7a`,
helper `49346c47d533ece574328f26a8194465d1ef29be5bad52706de4ae31e068ede7`.
These copies were admitted and used for the native staging/probe checks above.
They exercise distinct hashes with unchanged code, not a new source-code revision.

A subsequent real code update was also installed without another authorization:
helper `237b228f48c127b577bb9b53f2ade469fdab57a754ecea6a9327fc74e8f241c8`,
from `studio/dist/build-1793472655892/Masscan Studio.app` at commit `1daad2e`.
The selected tool returned to the original `ae8b0585...` build, whose bytes were
unchanged. Helper PID 52472 passed another protocol 3 probe, exited cleanly and
removed its IPC endpoint. HostPID 49278 remained unchanged. This update fixes a
native guard/adapter-failure race documented in the network capture report.

Local scripts `check-work-session-stage.py` and `run-work-session-guard.py` under
`.superpowers/sdd/2026-10-28-studio-macos-network/` check pre-stage refusal, post-stage
caller transition, two independent helper leases, original client retention,
actual installed hashes and idempotence, then the fixed-feth guard lifecycle.
The native guard script checks successful CI admission first, exports its owned
run, tears down the fixture and deliberately retains the working host. Prior
failed guard evidence remains unchanged. No owned physical-target scan, final UI
acceptance, merge or general-network distribution is claimed.


## Final active state

Current selected tool:
`7f8d81538ea0a33b4b901d0fa22b416d37028cd80ddab7fe1b017ddfc48dc9cb`.
Current selected helper:
`237b228f48c127b577bb9b53f2ade469fdab57a754ecea6a9327fc74e8f241c8`.
Immutable host tool remains `ae8b058514f77783591c41995f4801ce3bff25373e78a81894879a2d223e0d8f`;
root PID 49278 is ready with active 0 and is intentionally NOT stopped.

The actual guard run `f7029a23f2ca04b9f2fe60eb095ef213` passed root and offline
packet/lifecycle verification (5 probes, 4 correlated replies; Interrupted, 4 durable
rows,no checkpoint). Export and fixture teardown succeeded, both feth interfaces
are absent. All evening updates and subsequent helper/fixture operations used the
retained session without another password. The previously approved tool clients
remain available for further Stage/status commands.

Final code5d29176 passed Studio CI41232753958 and engine CI41232754004 on all 3 OSes.
The helper-finish correction had331 local workspace tests passing; the subsequent
terminal-fixture predicate had95 affected tool tests passing. Clippy, formatting,
independent reviews and three packaged simulation smoke scenarios also passed.
Full native evidence and unchanged failed attempts are in the
[network capture report](2026-10-31-studio-macos-network-capture.md).
