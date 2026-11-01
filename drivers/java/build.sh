#!/bin/sh
set -eu

# JDK-only local distribution. Never downloads tools or publishes artifacts.
if [ "$#" -ne 1 ]; then
    echo 'Usage: sh build.sh /absolute/output/directory' >&2
    exit 2
fi
case "$1" in /*) ;; *) echo 'Output directory must be absolute' >&2; exit 2 ;; esac
sdk=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
version=$(cat "$sdk/VERSION")
if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo 'VERSION must contain a numeric major.minor.patch version' >&2
    exit 2
fi
output=$1
mkdir -p "$output"
for name in "yamora-java-$version.jar" "yamora-java-$version-sources.jar"; do
    if [ -e "$output/$name" ]; then
        echo 'Refusing to overwrite an existing artifact; select a fresh output directory' >&2
        exit 2
    fi
done
: "${TMPDIR:?Set TMPDIR to an owned disk-backed scratch directory}"
work=$(mktemp -d "${TMPDIR%/}/yamora-java-package-XXXXXXXX")
trap 'rm -rf "${work:?}"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/classes/META-INF"
javac -J-XX:ActiveProcessorCount=2 -J-XX:-UsePerfData -J-Xmx384m \
    -J-Djava.io.tmpdir="$work" --release 17 -Xlint:all -Werror \
    -d "$work/classes" "$sdk"/src/io/yamora/*.java
cp "$sdk/LICENSE" "$work/classes/META-INF/LICENSE"
cat > "$work/MANIFEST.MF" <<EOF
Manifest-Version: 1.0
Implementation-Title: Yamora Java driver
Implementation-Version: $version
Automatic-Module-Name: io.yamora.driver

EOF
jar -J-XX:ActiveProcessorCount=2 -J-XX:-UsePerfData -J-Xmx384m -J-Djava.io.tmpdir="$work" \
    --create --file "$work/yamora-java-$version.jar" --manifest "$work/MANIFEST.MF" \
    -C "$work/classes" .
jar -J-XX:ActiveProcessorCount=2 -J-XX:-UsePerfData -J-Xmx384m -J-Djava.io.tmpdir="$work" \
    --create --file "$work/yamora-java-$version-sources.jar" --manifest "$work/MANIFEST.MF" \
    -C "$sdk/src" . -C "$sdk" LICENSE -C "$sdk" README.md -C "$sdk" examples
cp "$work/yamora-java-$version.jar" "$work/yamora-java-$version-sources.jar" "$output/"
printf '%s\n' "$output/yamora-java-$version.jar" "$output/yamora-java-$version-sources.jar"
