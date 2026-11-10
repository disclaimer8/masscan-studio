#!/usr/bin/env bash
# Thin orchestration: build in a neutral Ubuntu 24.04 environment as an ordinary user.
set -euo pipefail

output=${1:?Usage: package-linux-baseline.sh NEW_OUTPUT_DIRECTORY}
test ! -e "$output" || { echo 'Output directory must not exist' >&2; exit 2; }
source_root=$(git rev-parse --show-toplevel)
test -z "$(git -C "$source_root" status --porcelain)" || { echo 'A clean checkout is required' >&2; exit 2; }
source_commit=$(git -C "$source_root" rev-parse HEAD)
scratch=$(mktemp -d /tmp/studio-linux-build.XXXXXX)
container="studio-linux-build-${scratch##*.}"
image="studio-linux-baseline:1.99.1-24.04"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# A normal shallow clone also handles a caller that uses a linked worktree.
# Remove the local origin path; it is unnecessary for building and must not enter evidence.
git clone --quiet --depth 1 --no-local --single-branch "$source_root" "$scratch/checkout"
test "$(git -C "$scratch/checkout" rev-parse HEAD)" = "$source_commit"
git -C "$scratch/checkout" remote remove origin

mkdir "$scratch/image"
cat > "$scratch/image/Dockerfile" <<'DOCKER'
FROM rust:1.99.1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS toolchain
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential pkg-config git ca-certificates libsqlite3-dev libfontconfig1-dev \
    libxkbcommon-dev libxkbcommon-x11-0 libxcb-xkb1 libwayland-dev libx11-xcb-dev \
    libxcursor1 libxi6 \
    libegl1-mesa-dev xvfb xauth binutils jq && rm -rf /var/lib/apt/lists/*
COPY --from=toolchain /usr/local/cargo /cargo
COPY --from=toolchain /usr/local/rustup /rustup
ENV CARGO_HOME=/cargo RUSTUP_HOME=/rustup PATH=/cargo/bin:$PATH CARGO_BUILD_JOBS=4
RUN useradd --uid 10001 --create-home --home-dir /tmp/studio-home builder && \
    mkdir /src /build /out && chown -R 10001:10001 /src /build /out /cargo /rustup
USER builder
WORKDIR /src
DOCKER

docker build --platform linux/amd64 -t "$image" "$scratch/image" > "$scratch/image-build.log" 2>&1 || {
    cat "$scratch/image-build.log" >&2
    exit 1
}
docker run --name "$container" --platform linux/amd64 --hostname studio-build \
    --cpus "${STUDIO_BUILD_CPUS:-4}" --memory "${STUDIO_BUILD_MEMORY:-6g}" \
    --mount "type=bind,source=$scratch/checkout,target=/checkout,readonly" \
    --env "STUDIO_SOURCE_COMMIT=$source_commit" \
    --env "CARGO_BUILD_JOBS=${STUDIO_BUILD_JOBS:-4}" \
    "$image" bash /checkout/studio/scripts/linux-release-entry.sh > "$scratch/release-build.log" 2>&1 || {
    # Keep failed diagnostics outside the publishable output for investigation.
    docker cp "$container:/out/evidence" "$scratch/failed-evidence" >/dev/null 2>&1 || true
    cat "$scratch/release-build.log" >&2
    printf 'Failed build diagnostics: %s\n' "$scratch" >&2
    exit 1
}
mkdir -p "$output"
docker cp "$container:/out/." "$output/"
printf 'Verified Linux release: %s\nSource: %s\n' "$output" "$source_commit"
