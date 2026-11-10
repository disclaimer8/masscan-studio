#!/usr/bin/env bash
# Run only inside the baseline image. Application code and validation live in Rust.
set -euo pipefail
test "$(id -u)" != 0 || { echo 'Release acceptance must run as an ordinary user' >&2; exit 2; }
cp -R /checkout/. /src/
cd /src/studio
test "$(git rev-parse HEAD)" = "$STUDIO_SOURCE_COMMIT"
test -z "$(git status --porcelain)"
mkdir -p /out/evidence
export CARGO_TARGET_DIR=/build/studio
run_logged() {
    local name=$1
    shift
    "$@" > "/out/evidence/$name.log" 2>&1 || {
        cat "/out/evidence/$name.log" >&2
        return 1
    }
}

run_logged abi-tests cargo test --locked -p xtask linux_abi
run_logged package cargo xtask package --release
packages=(/src/studio/dist/build-*)
test "${#packages[@]}" = 1 && test -d "${packages[0]}"
package=${packages[0]}
tool=/build/studio/debug/xtask
run_logged verify-package "$tool" verify-package "$package"
"$tool" verify-package-privacy "$package" > /out/evidence/package-home-paths.json
jq -e --arg sha "$STUDIO_SOURCE_COMMIT" \
    '.source_commit == $sha and .dirty == false and .profile == "release" and .platform == "linux" and .arch == "x86_64"' \
    "$package/manifest.json" > /out/evidence/provenance.log
"$tool" verify-linux-abi "$package" --max-glibc 2.39 > /out/evidence/abi.json
if "$tool" verify-linux-abi "$package" --max-glibc 2.2 > /out/evidence/abi-rejected.json 2>/out/evidence/abi-rejected.log; then
    echo 'ABI floor negative check unexpectedly passed' >&2
    exit 1
fi
jq -e '.ok == false' /out/evidence/abi-rejected.json >/dev/null
for executable in studio-ui studio-runner studio-inspect; do
    ldd "$package/$executable" > "/out/evidence/$executable-libraries.log"
    if grep -F 'not found' "/out/evidence/$executable-libraries.log"; then exit 1; fi
done
{
    getconf GNU_LIBC_VERSION
    printf 'acceptance_uid=%s\n' "$(id -u)"
    rustc --version
    cargo --version
    dpkg-query -W libx11-6 libxcursor1 libxi6 libxkbcommon0 libsqlite3-0 libfontconfig1
} > /out/evidence/runtime.log
for smoke in pause stop-race; do
    run_logged "smoke-$smoke" env STUDIO_DATA_DIR="/tmp/studio-smoke-$smoke" \
        SLINT_BACKEND=winit-software WINIT_UNIX_BACKEND=x11 \
        timeout 60s xvfb-run -a "$package/studio-ui" "--smoke-$smoke"
done
run_logged privacy-tool env CARGO_TARGET_DIR=/build/engine \
    cargo build --locked --release --manifest-path /src/rmasscan/Cargo.toml -p rmasscan-lab
scanner=/build/engine/release/rmasscan-lab
cp -R "$package" /out/package
printf '%s\n' "$STUDIO_SOURCE_COMMIT" > /out/source-commit.txt
# Scan uncompressed bytes and logs; an archive scan cannot establish their privacy.
# The UI contains bare home-prefix literals for its own redaction function.
# The inventory-backed path audit above detects complete paths in UTF-8/UTF-16;
# the lab scan additionally checks capture/discovery content. Logs are checked
# with the stricter prefix rule below, after every evidence file has been written.
"$scanner" privacy-scan --dir /out > /out/evidence/privacy.log
tar --sort=name --owner=0 --group=0 --numeric-owner -czf /out/studio-linux-x86_64.tar.gz -C /out/package .
mkdir /tmp/studio-roundtrip
tar -xzf /out/studio-linux-x86_64.tar.gz --no-same-owner -C /tmp/studio-roundtrip
run_logged archive-verification "$tool" verify-package /tmp/studio-roundtrip
"$scanner" privacy-scan --dir /tmp/studio-roundtrip > /out/evidence/archive-privacy.log
"$tool" verify-package-privacy /tmp/studio-roundtrip > /out/evidence/archive-home-paths.json
tar --numeric-owner -tvzf /out/studio-linux-x86_64.tar.gz > /out/evidence/archive-members.log
cd /out
sha256sum studio-linux-x86_64.tar.gz > studio-linux-x86_64.tar.gz.sha256
"$scanner" privacy-scan --dir /out/evidence --forbid /Users/ --forbid /home/ --forbid '\Users\' --forbid '\\Users\\' > /tmp/final-evidence-privacy.log
cp /tmp/final-evidence-privacy.log /out/evidence/final-evidence-privacy.log
