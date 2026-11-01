#!/bin/sh
set -eu
: "${TMPDIR:?owned disk-backed scratch is required}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
parent=$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from tools.ci.yamora_driver_ci.runner import scratch_parent; print(scratch_parent(sys.argv[2]))' "$root/.." "$TMPDIR")
scratch=$(mktemp -d "$parent/sharding-runtime.XXXXXXXX")
trap 'rm -rf "${scratch:?}"' EXIT
trap 'exit 130' HUP INT TERM
# Use the complete native library dependency graph, never a second storage
# implementation or the daemon/network service. Deduplicate parent build wiring.
python3 - "$root" "$scratch/runtime" <<'PY'
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

root, output = Path(sys.argv[1]), sys.argv[2]
makefile = (root / "Makefile").read_text().replace("\\\n", " ")
sources = re.search(r"^LIB_SOURCE := (.+)$", makefile, re.MULTILINE).group(1).split()
sources += [f"src/sharding/{name}.c" for name in
            ("routing", "control", "native", "router", "cursor", "aggregate")]
sources.append("tests/sharding/runtime_harness.c")
flags = shlex.split(os.environ.get("SHARD_SANITIZERS", ""))
subprocess.run([
    os.environ.get("CC", "cc"), "-std=c17", "-O1", "-g", "-Wall", "-Wextra",
    "-Wpedantic", "-Werror", *flags,
    *[str(root / source) for source in dict.fromkeys(sources)], "-o", output,
    "-lyaml", "-lssl", "-lcrypto", "-pthread", "-lm", *flags,
    "-fno-sanitize-recover=undefined",
], check=True)
PY
mkdir "$scratch/data"
"$scratch/runtime" "$scratch/data"
