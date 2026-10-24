# Linux acceptance raw evidence

## Removed interpreter-dependent tools

The repository allows no Python (CI guard `.github/workflows/no-python.yml`, `scripts/no-python.sh`). The files below invoked an interpreter and were deleted; the evidence data in this directory is unchanged. Each file is recoverable from git: `git show 5bcf8d5:docs/experiments/<path> | shasum -a 256` must print the recorded sha256. The corresponding lines were removed from `MANIFEST.sha256` (their hashes are recorded here instead).

| Path (under `docs/experiments/`) | Last commit containing it | Last changed in | sha256 |
|---|---|---|---|
| `2026-10-24-rmasscan-linux-acceptance-raw/linux_io-lab.sh` | `5bcf8d5` | `eb8812a` | `58ead8a064bb40278d7b68f2eda2aa23b283dde55e65e5a2b5ee0ba9c238d515` |
| `2026-10-24-rmasscan-linux-acceptance-raw/round1-27e3042/linux_io-lab.sh` | `5bcf8d5` | `8479ff2` | `56e0794c60684ea02724dc5fd9c27f6e5cba7b321a26ae670dff0c16911a85e0` |
