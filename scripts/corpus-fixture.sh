#!/usr/bin/env bash
# Build one corpus case (tests/corpus/trees/<case>) into firmware images: usage corpus-fixture.sh CASE OUTDIR.
# NAME.ext4 dirs become NAME.img via mke2fs -d, NAME.erofs via mkfs.erofs. Used by the action self-test;
# tests/corpus.rs does the same with pinned timestamps for the precision gate.
set -euo pipefail
case_dir="$(cd "$(dirname "$0")/.." && pwd)/tests/corpus/trees/$1"
out=$2
mkdir -p "$out"
for d in "$case_dir"/*.ext4 "$case_dir"/*.erofs; do
  [ -d "$d" ] || continue
  name=$(basename "$d")
  stem=${name%.*}
  if [ "${name##*.}" = ext4 ]; then
    truncate -s 4M "$out/$stem.img"
    "${MKE2FS:-mke2fs}" -q -F -t ext4 -O ^has_journal -d "$d" "$out/$stem.img"
  else
    mkfs.erofs "$out/$stem.img" "$d" >/dev/null
  fi
done
for f in "$case_dir"/*; do
  if [ -f "$f" ] && [ "$(basename "$f")" != modes.txt ]; then cp "$f" "$out/"; fi
done
