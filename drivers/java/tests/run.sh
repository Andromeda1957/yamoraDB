#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -x "$1" ]; then
    echo "Required absolute native daemon path missing or not executable" >&2
    exit 2
fi
case "$1" in /*) ;; *) echo "Native daemon path must be absolute" >&2; exit 2 ;; esac

# One explicit javac invocation; no Maven, Gradle, package downloads or daemon build.
cd "$(dirname "$0")/.."
scratch_parent=${TMPDIR:-${ANDROMEDA_SCRATCH_DIRECTORY:?managed scratch is required when TMPDIR is unset}}
mkdir -p "$scratch_parent"
test_root=$(mktemp -d "${scratch_parent%/}/yamora-java-check-XXXXXXXX")
trap 'rm -rf "${test_root:?}"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# JVM temp files and native child processes must share this invocation's allocation.
TMPDIR=$test_root
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
export TMPDIR ASAN_OPTIONS UBSAN_OPTIONS
javac -J-XX:ActiveProcessorCount=2 -J-XX:-UsePerfData -J-Xmx384m -J-Djava.io.tmpdir="$test_root" --release 17 -Xlint:all -Werror -d "$test_root/classes" src/io/yamora/*.java tests/io/yamora/*.java conformance/HttpReplicaAdapter.java
java -XX:ActiveProcessorCount=2 -XX:-UsePerfData -Xmx384m -Djava.io.tmpdir="$test_root" -cp "$test_root/classes" io.yamora.DriverTests
java -XX:ActiveProcessorCount=2 -XX:-UsePerfData -Xmx384m -Djava.io.tmpdir="$test_root" -cp "$test_root/classes" io.yamora.ClusterTests "$@"
java -XX:ActiveProcessorCount=2 -XX:-UsePerfData -Xmx384m -Djava.io.tmpdir="$test_root" -cp "$test_root/classes" io.yamora.BinaryTests
java -XX:ActiveProcessorCount=2 -XX:-UsePerfData -Xmx384m -Djava.io.tmpdir="$test_root" -cp "$test_root/classes" io.yamora.NativeTests "$1"
java -XX:ActiveProcessorCount=2 -XX:-UsePerfData -Xmx384m -Djava.io.tmpdir="$test_root" -cp "$test_root/classes" io.yamora.BinaryNativeTests "$1"
java -XX:ActiveProcessorCount=2 -XX:-UsePerfData -Xmx384m -Djava.io.tmpdir="$test_root" -cp "$test_root/classes" HttpReplicaAdapterTests
