"""Compile behavioral mutants privately; infrastructure failures never prove a red.

Run with task-owned TMPDIR. This is an explicit qualification command in addition
to run.sh; it needs only the JDK, Python standard library and fixture OpenSSL.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
MUTANTS = (
    (
        "request identity",
        "if (!e.requestId().equals(m.requestId()) ||",
        "if (false ||",
        "wrong-id",
        "binary call accepted hostile behavior",
    ),
    (
        "receipt semantics",
        '!"stored".equals(value.get("status"))',
        "false",
        "bad-json",
        "binary call accepted hostile behavior",
    ),
    (
        "typed uncertainty",
        "throw new BinaryUncertainException(envelope, safe);",
        "throw safe;",
        "wrong-id",
        "uncertainty classification",
    ),
    (
        "GET source hash",
        "!sourceEtag(body, deadline, cancellation).equals(m.etag())",
        "false",
        "get-source-hash",
        "binary call accepted hostile behavior",
    ),
    (
        "PUT frozen source hash",
        "!sourceEtag(e.ownedSource(), deadline, cancellation).equals(m.etag())",
        "false",
        "put-source-hash",
        "binary call accepted hostile behavior",
    ),
)


def behavioral_red(result, assertion):
    output = result.stdout + result.stderr
    forbidden = (
        "Sanitizer",
        "runtime error:",
        "OutOfMemoryError",
        "Could not",
        "error:",
        "SSLHandshakeException",
        "hostile peer failed",
    )
    return (
        result.returncode == 1
        and output.count('Exception in thread "main" java.lang.AssertionError: ' + assertion) == 1
        and "\tat io.yamora.BinaryTests.fails(" in output
        and not any(marker in output for marker in forbidden)
        and "Suppressed:" not in output
    )


def compile_and_run(root, text, case, file="BinaryClient.java", group="hostile"):
    destination = root / "src" / "io" / "yamora" / file
    destination.write_text(text)
    classes = root / "classes"
    if classes.exists():
        shutil.rmtree(classes)
    sources = sorted(
        str(p) for name in ("src", "tests") for p in (root / name / "io" / "yamora").glob("*.java")
    )
    sources.append(str(SDK / "conformance/HttpReplicaAdapter.java"))
    options = [
        "-XX:ActiveProcessorCount=2",
        "-XX:-UsePerfData",
        "-Xmx384m",
        "-Djava.io.tmpdir=" + str(root),
    ]
    compile_result = subprocess.run(
        [
            "javac",
            *("-J" + option for option in options),
            "--release",
            "17",
            "-Xlint:all",
            "-Werror",
            "-d",
            str(classes),
            *sources,
        ],
        text=True,
        capture_output=True,
        timeout=45,
        check=False,
    )
    if compile_result.returncode:
        raise RuntimeError(
            "compiler/infrastructure failure is not red proof\n" + compile_result.stderr
        )
    return subprocess.run(
        [
            "java",
            *options,
            "-Dyamora.binary.group=" + group,
            "-Dyamora.binary.hostile=" + case,
            "-cp",
            str(classes),
            "io.yamora.BinaryTests",
        ],
        env={**os.environ, "TMPDIR": str(root)},
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def main():
    # Deliberately reject synthetic infrastructure, compiler and fatal sanitizer output.
    for code, output in (
        (-11, "SIGSEGV"),
        (1, "error: cannot compile"),
        (1, "AddressSanitizer"),
        (75, "unavailable"),
    ):
        diagnostic = 'Exception in thread "main" java.lang.AssertionError: binary call accepted hostile behavior\n\tat io.yamora.BinaryTests.fails(BinaryTests.java:1)\n'
        result = subprocess.CompletedProcess([], code, diagnostic, output)
        if behavioral_red(result, "binary call accepted hostile behavior"):
            raise AssertionError("oracle accepted infrastructure as behavioral red")
    source = (SDK / "src/io/yamora/BinaryClient.java").read_text()
    with tempfile.TemporaryDirectory(
        prefix="binary-mutants-", dir=os.environ["TMPDIR"]
    ) as directory:
        root = Path(directory)
        for name in ("src", "tests"):
            shutil.copytree(SDK / name / "io", root / name / "io")
        for name, old, new, case, assertion in MUTANTS:
            if source.count(old) != 1:
                raise AssertionError("mutant target changed: " + name)
            red = compile_and_run(root, source.replace(old, new), case)
            if not behavioral_red(red, assertion):
                raise AssertionError(
                    "mutant lacked the exact behavioral failure: "
                    + name
                    + "\n"
                    + red.stdout
                    + red.stderr
                )
            print("RED " + name + ": " + assertion, flush=True)
            green = compile_and_run(root, source, case)
            if green.returncode or "Java binary contracts passed:" not in green.stdout:
                raise AssertionError(
                    "restored test did not pass: " + name + "\n" + green.stdout + green.stderr
                )
            print("GREEN restored " + name, flush=True)
    print(
        f"{len(MUTANTS)} compiled mutants rejected; {len(MUTANTS)} restored passes; infrastructure oracle checks passed"
    )


if __name__ == "__main__":
    main()
