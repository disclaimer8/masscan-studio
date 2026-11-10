# Studio packages

Run these commands from `studio/`:

```sh
cargo xtask package --release
cargo xtask verify-package dist/build-<timestamp>
```

`build` and `package` remain aliases. Omitting `--release` produces a debug
package. Every build gets a fresh `dist/build-<timestamp>` directory. The release
profile optimizes the binaries; it does not enable publisher signing or submit
anything to an external service.

The manifest records the commit, dirty-worktree flag, Cargo.lock hash, platform,
architecture, application/IPC versions, enabled raw profiles, build profile,
signing status and SHA-256 for every regular file
in the finished package. On macOS this includes `Info.plist`, bundled SQLite when
needed, and `_CodeSignature/CodeResources`. The manifest excludes itself. Schema
version 2 uses sorted paths with `/` separators on every platform.

`verify-package` rejects changed, missing, extra or symlinked files and malformed
inventories. It enumerates files below the package directory; it never opens a
path supplied by the manifest. On macOS it also runs
`codesign --verify --deep --strict` for the application and returns failure if
that check fails. Older manifests with only selected binaries cannot establish
complete package coverage; rebuild those packages to use this command. A hash
manifest establishes consistency with the accompanying manifest, not publisher
authenticity or native scan acceptance.

## Platform contents

| Platform | Contents | Distribution status |
| --- | --- | --- |
| macOS | `Masscan Studio.app` with launcher, UI, runner, inspector and SQLite if required | Ad-hoc signed for local acceptance; not notarized |
| Windows | UI, runner, inspector, external `sqlite3.dll`, standalone `studio-tools.exe` | Unsigned directory bundle; release builds compile the tools with the release profile |
| Linux | UI, runner and inspector | Unsigned directory bundle; runtime system libraries remain prerequisites |

The Windows build requires `SQLITE3_LIB_DIR` pointing to the verified external
SQLite DLL/import library. See `scripts/windows-sqlite.ps1`. Building on one host
does not validate native installation, authorization or packet delivery on the
other platforms.

## Linux baseline release

From a clean repository root, with Docker available:

```sh
bash studio/scripts/package-linux-baseline.sh /tmp/studio-linux-release
```

The output directory must be new. The script clones the exact source commit and
builds with pinned Rust 1.99.1 and Ubuntu 24.04 images in neutral directories.
Compilation and simulation acceptance run as an ordinary container user. The
default limits are four CPUs, four Cargo jobs and 6 GiB of memory; the
`STUDIO_BUILD_CPUS`, `STUDIO_BUILD_JOBS` and `STUDIO_BUILD_MEMORY` environment
variables can override these limits.

The release gate verifies the complete package inventory, clean source
provenance, direct ELF GLIBC requirements at or below 2.39, runtime library
resolution, and the packaged UI's pause/resume and stop-race simulation smokes.
It scans uncompressed package contents and evidence with `rmasscan-lab
privacy-scan`, creates an archive with numeric neutral ownership, then extracts
and verifies that archive again. Artifacts are exported only after every gate
passes. The `Studio Linux release` workflow runs this same command.

To inspect an existing Linux package using GNU binutils:

```sh
cd studio
cargo xtask verify-linux-abi dist/build-<timestamp> --max-glibc 2.39
```

The JSON report covers direct executable GLIBC requirements. It does not
establish compatibility with every distribution or cover all transitive system
libraries. Ubuntu 24.04 simulation acceptance does not establish desktop polkit
interaction or native packet delivery.

## Source and privacy provenance

Release builds must use neutral physical paths for the checkout, Cargo cache,
Rust toolchain and build output. Rust debug and panic data, build scripts and
embedded environment strings can preserve source paths inside binaries.
Manifest verification alone does not detect these leaks. Scan the actual
uncompressed deliverable and publishable logs before archiving; inspect archive
metadata separately. `privacy-scan` does not decompress archives or decode
UTF-16 strings, so Windows packages also need a UTF-16 path check.

After a source-history rewrite, rebuild from the new commit. Historical
packages retain their original provenance; editing their manifest or renaming
them cannot establish that they were built from the rewritten commit.

## Public macOS distribution

Apple requires Developer ID signing, hardened runtime and secure timestamps for
notarization. The current package command deliberately records `signing: ad-hoc`
and `notarized: false`. Switching to an optimized profile does not satisfy these
requirements. See [Apple's notarization documentation](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

On 2026-11-10, read-only `security find-identity -v -p codesigning` found Apple
Development and iPhone Distribution identities, but no Developer ID Application
identity. `notarytool` and `stapler` are installed. The package command has no
notarization profile configuration, and no notary-specific environment variable
names were present in the read-only check. No keychain credentials were read,
so the presence of an independently stored notary profile remains unknown.

Before a public release, configure the Developer ID Application identity and a
notary credential profile, sign every nested executable/library and then the
application using hardened runtime and secure timestamps, verify the signature,
submit the archive, inspect Apple's result, staple the accepted ticket and test
Gatekeeper acceptance. The final manifest must be regenerated after signing and
stapling because those operations change the package. That distribution workflow
is not implemented or claimed as verified by the local package command.
