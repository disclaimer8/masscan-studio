# Studio: host actions and filtered export

Authorized by the user's next-stage instruction on 2026-10-26. Execute in
`masscan-studio-app`; Claude owns scanner algorithms/adapters/labs. Keep scanner
source at the current tested baseline and the raw gate closed.

## Deliverable

Manual hostname refresh, Nmap service inspection of one discovered real host,
visible progress/cancellation and durable evidence; CSV/JSON export of the current
filtered view in its displayed order. Simulation never triggers network actions.
The runner protocol and privileged executable do not gain DNS/Nmap/export APIs.

## Contracts

- Rust-only `studio-inspection` library plus an unprivileged DNS worker executable.
  macOS uses DNS-SD; Linux/Windows system resolver runs in a killable child.
  Four concurrent DNS queries, 3-second deadline, 512 distinct hosts per action,
  300-second cache; explicit refresh bypasses cache.
- External Nmap, no installer/bundling: IPv4 and only discovered open TCP ports,
  1–64 distinct ports, exclude 9100; original --unprivileged/-sT/-sV/--version-light
  CLI, 45s host timeout and 55s process deadline, bounded stdout/stderr, cancel/reap.
- XML at most 2 MiB, no entities/external resolution; allow harmless DOCTYPE,
  require exact host and successful finish, reject timeout/malformed output.
  Preserve service product/version/CPE/method/confidence as evidence, distinguish
  table guesses from probed services. DNS/hostnames never become shell fragments.
- Controller owns a bounded task queue; request generations and scan IDs prevent
  stale results overwriting a new selection/refresh. Closing Studio cancels work.
  Inspection errors affect inspection state, never interrupt a valid scan.
- SQLite additive migration stores host metadata and first-observation timestamps.
  Existing unknown timestamps remain unknown. Pending actions recover interrupted.
- Export visible rows only, same sorting/filter, CSV formula neutralization and
  quoting, JSON includes only inspection relevant to visible rows. Native save
  dialog, snapshot before asynchronous write, errors surfaced. No arbitrary CLI.

## Sequence and evidence

1. Test input/XML/export contracts RED, implement pure Rust library.
2. Implement bounded subprocesses and DNS worker, fake Rust child tests for
   deadline/cancel/overflow. Actual network test only against own loopback fixture.
3. Store migration and stale-request/controller tests; wire table/details/actions.
4. Native save dialog and export snapshots; test filters/order/host metadata.
5. Full Studio tests, build, UI smoke; cross-platform compile/tests where available.
6. Fresh review, fix important findings, record exact scope/hashes and commit.

This advances independent application work while scanner completion and live raw
acceptance remain with their existing gates. It does not declare engine release,
physical NIC support, or three-OS raw parity.
