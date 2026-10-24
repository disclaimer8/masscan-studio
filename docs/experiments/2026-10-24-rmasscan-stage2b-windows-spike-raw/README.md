# Spike raw evidence (2B-Windows)

## Removed interpreter-dependent tools

The repository allows no Python (CI guard `.github/workflows/no-python.yml`, `scripts/no-python.sh`). The files below invoked an interpreter and were deleted; the evidence data in this directory is unchanged. Each file is recoverable from git: `git show 5bcf8d5:docs/experiments/<path> | shasum -a 256` must print the recorded sha256. The corresponding lines were removed from `MANIFEST.sha256` (their hashes are recorded here instead).

| Path (under `docs/experiments/`) | Last commit containing it | Last changed in | sha256 |
|---|---|---|---|
| `2026-10-24-rmasscan-stage2b-windows-spike-raw/tools/flood.py` | `5bcf8d5` | `260e2c5` | `38baeb338e8ef69a1580e05a30fd91a9c2e99c4b515219d25fb21dec2a0bb00f` |
| `2026-10-24-rmasscan-stage2b-windows-spike-raw/tools/orch.sh` | `5bcf8d5` | `260e2c5` | `ab9ecc737c6783067f89d3aa5e3f8c596cdb3c3738527a85f0579896ac5eb861` |
