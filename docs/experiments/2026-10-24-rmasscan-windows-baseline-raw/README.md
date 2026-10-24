# Windows baseline raw evidence

## Removed interpreter-dependent tools

The repository allows no Python (CI guard `.github/workflows/no-python.yml`, `scripts/no-python.sh`). The files below invoked an interpreter and were deleted; the evidence data in this directory is unchanged. Each file is recoverable from git: `git show 5bcf8d5:docs/experiments/<path> | shasum -a 256` must print the recorded sha256. The corresponding lines were removed from `MANIFEST.sha256` (their hashes are recorded here instead).

| Path (under `docs/experiments/`) | Last commit containing it | Last changed in | sha256 |
|---|---|---|---|
| `2026-10-24-rmasscan-windows-baseline-raw/after-update-findalldevs.ps1` | `5bcf8d5` | `1c5366a` | `f84c9bb43ee4571ee4cfe57f531c1e9bfdc6992f565ed8e700c52acbf914662a` |
| `2026-10-24-rmasscan-windows-baseline-raw/base.ps1` | `5bcf8d5` | `9541fb5` | `fc130c99dd0f6d3ad80f97cd4500227b6885540d05b7cae9a3a886a643825a0f` |
| `2026-10-24-rmasscan-windows-baseline-raw/fd.ps1` | `5bcf8d5` | `9541fb5` | `42b3b5ff072f430c394a4dc083c3c7ec4bd608a3398d7f721a83f9d986d56b14` |
