#!/bin/sh
# Focused native build; one compiler, no daemon/network or shared build output.
set -eu
: "${TMPDIR:?set TMPDIR to an attested owned scratch directory}"
test -d "$TMPDIR"
scratch=$(mktemp -d "${TMPDIR:?}/sharding.XXXXXXXX")
trap 'rm -rf "${scratch:?}"' EXIT
trap 'exit 130' HUP INT TERM
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cc=${CC:-cc}
# pkg-config supplies the baseline's existing native YAML/system crypto flags.
# Intentional word splitting for compiler/pkg-config flags; paths stay quoted.
# The final compiler flag overrides recovery even when UBSAN_OPTIONS or caller
# sanitizer flags ask to continue after undefined behavior.
# shellcheck disable=SC2046,SC2086
"$cc" -std=c17 -O1 -g -Wall -Wextra -Wpedantic -Werror ${SHARD_SANITIZERS:-} \
    $(pkg-config --cflags yaml-0.1 openssl) -I "$root/src" \
    "$root/src/sharding/routing.c" "$root/src/value.c" \
    "$root/src/disk.c" "$root/src/retention_gate.c" "$root/src/disk_tree.c" "$root/src/disk_log.c" \
    "$root/src/disk_history.c" \
    "$root/tests/sharding_harness.c" -o "$scratch/route-plan" \
    $(pkg-config --libs yaml-0.1 openssl) -pthread -lm ${SHARD_SANITIZERS:-} \
    -fno-sanitize-recover=undefined
if [ "$#" -gt 0 ]; then
    "$scratch/route-plan" "$@"
else
    "$scratch/route-plan"
    mkdir "$scratch/native"
    "$scratch/route-plan" --store "$scratch/native" > "$scratch/before"
    "$scratch/route-plan" --reopen "$scratch/native" > "$scratch/after"
    cmp "$scratch/before" "$scratch/after"
    cat "$scratch/after"
fi
