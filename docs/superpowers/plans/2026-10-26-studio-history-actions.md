# Studio: saved scan management

User authorized continuing Studio after native profiles. Implements the remaining
history actions in the cross-platform spec §4 without touching rmasscan or labs.

## Contract

- Rename a saved scan; trimmed names have 1–128 characters, at most 512 bytes,
  no controls. Names need not be unique (different runs may share a name).
- Record UTC creation time for new scans; unknown old dates remain unknown.
- Repeat opens a draft with the exact original settings/seed, without starting
  or authorizing, resuming a checkpoint, or altering the original. Archived
  backend is not executable. The user explicitly checks and starts the draft.
- Delete requires confirmation naming the captured scan. Remove only that scan,
  its results, host details and checkpoint atomically. Profiles stay untouched.
  Existing old metadata referring to the scan is removed if present; no importer.
- Active scans cannot be deleted/renamed; controller also refuses history edits
  while any scan is active. Stale IDs and write failures are visible and leave
  the controller usable. UI selection changes cannot retarget confirmation.
- After deletion select the next available scan, or clear results/host state and
  disable Resume/host actions. Cancel pending inspection and ignore late replies.

## Tasks

1. Store APIs `rename_scan`/`delete_scan`, creation time; regression tests for
   atomic deletion, active/stale refusal, rollback, profiles/other scans intact.
2. Controller `RenameScan`/`DeleteScan`, result updates and selection refresh;
   test without a runner, active simulation refusal, late host completion.
3. History panel: rename, explicit repeat/settings, confirmed delete. Keep
   existing UI theme/style. Repeat never sends Start/Resume. Test draft behavior.
4. Full `cargo xtask test`, package and UI smoke, fresh whole-branch review,
   documentation, three-OS CI and merge after green checks.

## Review focus

Selection/confirmation races; FK cleanup and transaction rollback; late DNS/Nmap
replies after deletion; no automatic scan from Repeat; surviving checkpoint on
rename; active state and stale ID refusal independent of UI controls. Engine,
raw gate, root installation and live labs are out of scope.
