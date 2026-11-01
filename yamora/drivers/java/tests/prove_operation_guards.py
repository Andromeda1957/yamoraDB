"""Compile private operation guard mutants; only ordinary assertions prove red."""

import argparse
import os
import shutil
import tempfile
from pathlib import Path

from prove_binary_guards import SDK
from prove_binary_guards import compile_and_run

MUTANTS = (
    (
        "transaction count",
        "BinaryOperations.java",
        "entries.size() == count",
        "true",
        "transaction count mismatch accepted",
    ),
    (
        "request identity",
        "BinaryOperations.java",
        "op.requestId().equals(m.requestId()) &&",
        "true &&",
        "operation guard accepted id",
    ),
    (
        "finite/page mode",
        "BinaryMessageCodec.java",
        "if (mode > 1 ||",
        "if (mode > 2 ||",
        "operation guard accepted mode",
    ),
    (
        "completed cursor",
        "BinaryOperations.java",
        "return new Page(next, false);",
        "return new Page(tip, false);",
        "incomplete page advanced cursor",
    ),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard", choices=[row[0].replace(" ", "-") for row in MUTANTS])
    args = parser.parse_args()
    selected = [
        row for row in MUTANTS if args.guard is None or row[0].replace(" ", "-") == args.guard
    ]
    with tempfile.TemporaryDirectory(
        prefix="operation-mutants-", dir=os.environ["TMPDIR"]
    ) as folder:
        root = Path(folder)
        for name in ("src", "tests"):
            shutil.copytree(SDK / name / "io", root / name / "io")
        for name, file, before, after, assertion in selected:
            original = (SDK / "src/io/yamora" / file).read_text()
            if original.count(before) != 1:
                raise AssertionError("mutant anchor changed: " + name)
            red = compile_and_run(root, original.replace(before, after), "", file, "operations")
            output = red.stdout + red.stderr
            if (
                red.returncode != 1
                or 'Exception in thread "main" java.lang.AssertionError: ' + assertion + "\n"
                not in output
                or (
                    "\tat io.yamora.BinaryTests."
                    + ("operationsCount" if name == "transaction count" else "operations")
                    + "("
                )
                not in output
                or any(
                    marker in output
                    for marker in (
                        "Suppressed:",
                        "Sanitizer",
                        "runtime error:",
                        "OutOfMemory",
                        "error:",
                        "hostile peer failed",
                        "SSLHandshakeException",
                    )
                )
            ):
                raise AssertionError("ordinary behavioral red absent: " + name + "\n" + output)
            print("RED " + name + ": " + assertion, flush=True)
            green = compile_and_run(root, original, "", file, "operations")
            if green.returncode or "Java binary contracts passed:" not in green.stdout:
                raise AssertionError(
                    "restored green absent: " + name + "\n" + green.stdout + green.stderr
                )
            print("GREEN restored " + name, flush=True)
    print(str(len(selected)) + " compiled operation mutants rejected and restored", flush=True)


if __name__ == "__main__":
    main()
