# Studio: retire Swift import and add native scan profiles

User correction, 2026-10-26: Swift is retired permanently; import is not a product
requirement. This supersedes the import task/old spec requirements. Work from main
000c489 in the existing Studio worktree. Claude owns rmasscan and the live labs.

1. Remove the Swift parser/import APIs, commands, chooser/report and imported-profile
   flow. Existing schema-v3 files must open without deleting saved scans or metadata.
   Keep only read compatibility for archived data; never execute archived checkpoints.
2. Native profiles on all platforms: create, load into settings, update and delete.
   Persist exact Job including seed as text; validate via Job::prepare. A profile is
   a template, never a checkpoint/attempt. Loading/saving never starts a scan or
   authorizes a runner. Default decision: at most 100 profiles, names 1–128 Unicode
   characters (<=512 bytes), trimmed and case-insensitively unique.
3. Schema v4 adds profiles after a consistent backup and transactional migration.
   Update/delete require an existing ID. Conflicts and invalid input leave existing
   records unchanged. Delete affects only the profile, never scan history.
4. UI: profile selector, explicit Load, editable name, Save new, Update loaded,
   confirmed Delete. Async result feedback in settings; refresh cannot silently
   overwrite the current draft. All controls work without elevated privileges.
5. RED/GREEN store/controller tests, v3 history preservation, removal guards,
   Mac packaged UI verification, full tests/clippy/fmt, fresh review, 3-OS CI.
   Do not load the busy home lab with builds during Claude's measurements.

No new external scanner, Swift dependency, raw gate change or engine changes.
