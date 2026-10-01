#!/usr/bin/env bash
set -euo pipefail
build="${1:-build}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
DESTDIR="$stage" meson install -C "$build"
binary="$(find "$stage" -type f -path '*/bin/nsdiff' -print -quit)"
[[ -n "$binary" ]]
"$binary" --version
for pattern in '*/man1/nsdiff.1*' '*/bash-completion/completions/nsdiff' '*/zsh/site-functions/_nsdiff' '*/fish/vendor_completions.d/nsdiff.fish'; do
  [[ -n "$(find "$stage" -type f -path "$pattern" -print -quit)" ]] || { echo "missing install file: $pattern"; exit 1; }
done
