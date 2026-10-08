#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

build_version=$(cat VERSION)
if [[ ! "$build_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "VERSION must contain a numeric semantic version" >&2
  exit 1
fi
build_commit=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
if [[ ! "$build_commit" =~ ^([0-9a-f]{12}|unknown)$ ]]; then
  echo "Invalid build commit" >&2
  exit 1
fi
build_flags="-s -w -X main.version=$build_version -X main.commit=$build_commit"
mkdir -p build
case "${1:-}" in
  local)
    CGO_ENABLED=0 go build -trimpath -ldflags="$build_flags" -o build/adgh-cf .
    ;;
  linux)
    bash scripts/check-repo.sh
    release_stage=$(mktemp -d build/.release-XXXXXX)
    trap 'rm -rf "$release_stage"' EXIT
    mkdir -p build/release
    for arch in amd64 arm64; do
      package_dir="$release_stage/linux-$arch"
      mkdir -p "$package_dir/candidates" "build/linux-$arch"
      CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags="$build_flags" -o "$package_dir/adgh-cf" .
      cp "$package_dir/adgh-cf" "build/linux-$arch/adgh-cf"
      # Allowlist assets; never package a checkout, local config or state directory.
      cp README.md VERSION CHANGELOG.md .env.example config*.example.json "$package_dir/"
      if [[ -f LICENSE ]]; then cp LICENSE "$package_dir/"; fi
      cp candidates/cloudflare-ipv4.txt candidates/community-ipv4.txt "$package_dir/candidates/"
      mkdir -p "$package_dir/docs/releases" "$package_dir/deploy/systemd"
      cp docs/PLAN.md docs/STATUS.md docs/DEPLOY.md docs/RELEASING.md docs/SECURITY.md "$package_dir/docs/"
      cp "docs/releases/v$build_version.md" "$package_dir/docs/releases/"
      cp deploy/systemd/adgh-cf.service deploy/systemd/adgh-cf.timer "$package_dir/deploy/systemd/"
      package_name="adgh-cf-v$build_version-linux-$arch.tar.gz"
      COPYFILE_DISABLE=1 tar -czf "build/release/$package_name" -C "$package_dir" .
      # Keep previous local download paths usable; Release uses versioned names.
      cp "build/release/$package_name" "build/adgh-cf-linux-$arch.tar.gz"
    done
    (
      cd build/release
      packages=("adgh-cf-v$build_version-linux-amd64.tar.gz" "adgh-cf-v$build_version-linux-arm64.tar.gz")
      if command -v sha256sum >/dev/null; then
        sha256sum "${packages[@]}" > "adgh-cf-v$build_version-SHA256SUMS"
        sha256sum --check "adgh-cf-v$build_version-SHA256SUMS"
      else
        shasum -a 256 "${packages[@]}" > "adgh-cf-v$build_version-SHA256SUMS"
        shasum -a 256 --check "adgh-cf-v$build_version-SHA256SUMS"
      fi
    )
    ;;
  *) echo "Usage: bash scripts/build.sh <local|linux>" >&2; exit 1 ;;
esac
