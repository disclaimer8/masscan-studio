
Binary hashes: `binary_sha256` and `offline_binary_sha256` identify the build artifacts
produced on the oracle host and are not reproducible (`__DATE__`/`__TIME__` are embedded by
print_version, main-conf.c:101). Provenance is the pinned git HEAD; the hash only ties the
fixtures to the exact binary that made them. Each manifest case has a `binary` field
(`pinned` or `offline-patched`) and all records share one key set (absent values are null).
