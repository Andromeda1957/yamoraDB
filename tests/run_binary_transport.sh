#!/usr/bin/env bash
set -euo pipefail

# Validate the caller's attested disposable storage before creating any files.
: "${TMPDIR:?set TMPDIR to an isolated managed task directory}"
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
python3 - "$root/.." "$TMPDIR" <<'PYTHON'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from tools.shared.scratch import is_managed_path, storage_root
path = Path(sys.argv[2])
if not path.is_dir() or not is_managed_path(path) or path.resolve() == storage_root().resolve():
    raise SystemExit("TMPDIR must be an isolated managed task directory")
PYTHON
work=$(mktemp -d "${TMPDIR%/}/binary-transport.XXXXXXXX")
trap 'rm -rf -- "${work:?}"' EXIT
cc_binary=${CC:-cc}
flags=(-std=c17 -O1 -g -Wall -Wextra -Werror -I"$root/src")
codec="$root/src/transport/binary_frame.c"
harness="$root/tests/binary_transport_harness.c"

# Serial builds, no make job fan-out. Codec itself has no external dependencies.
"$cc_binary" "${flags[@]}" "$codec" "$harness" -o "$work/codec"
"$work/codec"
# UBSan reports must fail the gate, including under an inherited recovery option.
"$cc_binary" "${flags[@]}" -fsanitize=address,undefined -fno-sanitize-recover=undefined \
    -fno-omit-frame-pointer \
    "$codec" "$harness" -o "$work/sanitized"
"$work/sanitized"
# Use the daemon's complete source closure; root-only globs lose schema and
# consensus dependencies as native storage evolves. Exclude duplicate main/codec.
make --no-print-directory -s -C "$root" -f Makefile -f - binary-test-sources > "$work/sources" <<'MAKE'
binary-test-sources:
	@printf '%s\n' $(filter-out src/daemon.c src/transport/binary_frame.c,$(SOURCE))
MAKE
sources=()
while IFS= read -r source; do
    sources+=("$root/$source")
done < "$work/sources"
"$cc_binary" "${flags[@]}" -DYD_BINARY_WITH_STORAGE "$codec" "$harness" \
    "${sources[@]}" -pthread -lssl -lcrypto -lyaml -lm -o "$work/storage"
"$work/storage" storage
"$work/storage" large
