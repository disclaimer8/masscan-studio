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
rerun `41197077592` passed the main test step on all three OSes and is still
finishing its additional laboratory/dependency checks at this checkpoint.

Native status at this checkpoint: the replacement OS prompt expired unconfirmed
at 180 seconds. The old host PID97855 remains active with zero jobs; both feth
interfaces are absent. No replacement, new-build staging or new guard pass is
claimed. The implementation requires one successful OS grant to replace the old
host, which has no staging operation; later staging uses that retained session.

Prepared package: `studio/dist/build-1793445885381/Masscan Studio.app`.
Tool SHA256 `ae8b058514f77783591c41995f4801ce3bff25373e78a81894879a2d223e0d8f`;
helper SHA256 `aa23da896185d7ef1773555fa41ed525c05325307aa03066c2a3fa0c05dc0bad`.
Additional copies with different ad-hoc signature identifiers, but identical
reviewed executable code, are prepared to verify actual new-hash installation:
tool `496ab1d8d2157d83e76b01ed9221d16541b808f2505d4b5fe8d337a4f4ef5c7a`,
helper `49346c47d533ece574328f26a8194465d1ef29be5bad52706de4ae31e068ede7`.
They have not yet been admitted to the running host.

Local scripts `check-work-session-stage.py` and `run-work-session-guard.py` under
`.superpowers/sdd/2026-10-28-studio-macos-network/` check pre-stage refusal, post-stage
caller transition, two independent helper leases, original client retention,
actual installed hashes and idempotence, then the fixed-feth guard lifecycle.
The native guard script checks successful CI admission first, exports its owned
run, tears down the fixture and deliberately retains the working host. Prior
failed guard evidence remains unchanged. No owned physical-target scan, final UI
acceptance, merge or general-network distribution is claimed.
