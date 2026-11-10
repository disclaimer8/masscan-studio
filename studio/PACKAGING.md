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
