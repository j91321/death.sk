#!/usr/bin/env bash
# Installs Dart Sass (required by the hugo-book theme's SCSS).
# Keep DART_SASS_VERSION in sync with .github/workflows/*.yml.
set -euo pipefail

DART_SASS_VERSION="${DART_SASS_VERSION:-1.99.0}"

case "$(uname -m)" in
  x86_64)  arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if command -v sass >/dev/null && [ "$(sass --version)" = "${DART_SASS_VERSION}" ]; then
  echo "Dart Sass ${DART_SASS_VERSION} already installed"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/dart-sass.tar.gz" \
  "https://github.com/sass/dart-sass/releases/download/${DART_SASS_VERSION}/dart-sass-${DART_SASS_VERSION}-linux-${arch}.tar.gz"

sudo rm -rf /usr/local/dart-sass
sudo tar -C /usr/local -xzf "$tmp/dart-sass.tar.gz"
sudo ln -sf /usr/local/dart-sass/sass /usr/local/bin/sass

echo "Dart Sass $(sass --version) installed"
