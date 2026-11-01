"""Compile private C# mutants; only exact dispatched behavioral failures prove red."""

import argparse
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
MUTANTS = (
    (
        "frame magic",
        "BinaryWire.cs",
        '!header.AsSpan(0, 4).SequenceEqual("YMBF"u8) || ',
        "",
        "binary-hostile-frames",
        "REGRESSION frame-magic: accepted invalid reply after exactly one dispatch",
    ),
    (
        "envelope version",
        "BinaryWire.cs",
        "header[4] != 1 || ",
        "",
        "binary-hostile-frames",
        "REGRESSION frame-version: accepted invalid reply after exactly one dispatch",
    ),
    (
        "reserved flags",
        "BinaryWire.cs",
        "header[6] != 0 || header[7] != 0",
        "false",
        "binary-hostile-frames",
        "REGRESSION frame-flags: accepted invalid reply after exactly one dispatch",
    ),
    (
        "TLV uniqueness",
        "BinaryReply.cs",
        "id <= previous ||",
        "id < previous ||",
        "binary-hostile-frames",
        "REGRESSION frame-tlv-duplicate: accepted invalid reply after exactly one dispatch",
    ),
    (
        "TLV order",
        "BinaryReply.cs",
        "id <= previous ||",
        "id == previous ||",
        "binary-hostile-frames",
        "REGRESSION frame-tlv-order: accepted invalid reply after exactly one dispatch",
    ),
    (
        "request identity",
        "BinaryReply.cs",
        "requestId != envelope.RequestId ||",
        "false ||",
        "binary-hostile-receipts",
        "REGRESSION missing-id: accepted invalid reply after exactly one dispatch",
    ),
    (
        "frozen source hash",
        "BinaryReply.cs",
        "Hash(envelope.OwnedSource, call) != meta.ETag",
        "false",
        "binary-hostile-receipts",
        "REGRESSION source-hash-lie: accepted invalid reply after exactly one dispatch",
    ),
    (
        "create-only receipt status",
        "BinaryReply.cs",
        'envelope.IfNoneMatch == "*" ? status == 201',
        'envelope.IfNoneMatch == "*" ? status is 200 or 201',
        "binary-hostile-receipts",
        "REGRESSION put-status-create: accepted invalid reply after exactly one dispatch",
    ),
    (
        "immutable uncertainty",
        "BinaryClient.cs",
        "throw new BinaryUncertainException(envelope, safe);",
        "throw safe;",
        "binary-hostile-receipts",
        "REGRESSION typed-uncertainty-missing-id: lost original envelope after exactly one dispatch",
    ),
    (
        "final monotonic guard",
        "BinaryClient.cs",
        "call.Check(); return result;",
        "return result;",
        "binary-decode-deadlines",
        "REGRESSION guard-Yamora.BinaryReturn: accepted invalid reply after exactly one dispatch",
    ),
)


def behavioral_red(code, output, selector, assertion):
    forbidden = (
        "Sanitizer",
        "runtime error:",
        "TimeoutException",
        "TaskCanceledException",
        "OperationCanceledException",
        "OutOfMemory",
        "error CS",
        "Build FAILED",
        "SIGSEGV",
        "SIGABRT",
        "infrastructure",
        "fixture dispatch missing",
        "AggregateException",
        "AuthenticationException",
    )
    return (
        code == 1
        and f"FAIL {selector}: System.Exception: {assertion}\n" in output
        and output.count("FAIL ") == 1
        and "0/1 checks passed; native enabled: True" in output
        and not any(marker in output for marker in forbidden)
    )


def run(command, env, cwd, timeout=60):
    # Inherit the invoking runner's managed process group. A nested session can
    # escape its verified shutdown and leave compilers using deleted scratch.
    child = subprocess.run(
        command,
        env=env,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )
    return child.returncode, child.stdout


def owned_processes(root):
    prefix = os.fsencode(root)
    owned = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            state = (entry / "stat").read_bytes().rsplit(b")", 1)[1].split()[0]
            environment = (entry / "environ").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if state not in (b"Z", b"X", b"x") and any(
            item == b"TMPDIR=" + prefix or item.startswith(b"TMPDIR=" + prefix + b"/")
            for item in environment
        ):
            owned.append(int(entry.name))
    return owned


def stop_owned(root):
    # Only this private allocation's descendants carry its unique TMPDIR.
    # Preserve scratch if their shutdown cannot be established.
    for signum in (signal.SIGTERM, signal.SIGKILL):
        for pid in owned_processes(root):
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass
        until = time.monotonic() + 5
        while owned_processes(root) and time.monotonic() < until:
            time.sleep(0.02)
    if owned_processes(root):
        raise RuntimeError("owned processes remain; retaining mutant scratch " + str(root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operations", action="store_true")
    parser.add_argument("--dotnet", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    for path in (args.dotnet, args.binary):
        if not path.is_absolute() or not path.is_file():
            raise ValueError("absolute existing dotnet/native binary required")
    selected = (
        (
            (
                "transaction count",
                "BinaryOperationsCodec.cs",
                'Require(specification.RootElement.GetProperty("operations").GetArrayLength() == count);',
                "Require(true);",
                "binary-operation-count",
                "expected BinaryOperationException",
            ),
            (
                "operation ID",
                "BinaryOperationsCodec.cs",
                "Require(meta.RequestId == operation.RequestId &&",
                "Require(true &&",
                "binary-operations",
                "expected BinaryOperationException",
            ),
            (
                "operation mode",
                "BinaryReply.cs",
                "if (streaming > 1 ||",
                "if (streaming > 2 ||",
                "binary-operations",
                "expected BinaryOperationException",
            ),
            (
                "completed cursor",
                "BinaryOperationsCodec.cs",
                "return (next, false);",
                "return (tip, false);",
                "binary-operation-feeds",
                "feed used checkpoint instead of next_after",
            ),
        )
        if args.operations
        else MUTANTS
    )
    selector, assertion = selected[0][-2:]
    for code, suffix in (
        (-11, "SIGSEGV"),
        (-6, "SIGABRT"),
        (75, "unavailable"),
        (1, "error CS0001"),
        (1, "AddressSanitizer"),
        (1, "TimeoutException"),
        (1, "AuthenticationException"),
    ):
        synthetic = f"FAIL {selector}: System.Exception: {assertion}\n0/1 checks passed; native enabled: True\n{suffix}"
        if behavioral_red(code, synthetic, selector, assertion):
            raise AssertionError("oracle accepted infrastructure as red")
    root = Path(tempfile.mkdtemp(prefix="binary-mutants-", dir=os.environ["TMPDIR"]))
    try:
        shutil.copytree(
            SDK, root / "sdk", ignore=shutil.ignore_patterns("bin", "obj", "__pycache__")
        )
        env = {
            **os.environ,
            "TMPDIR": str(root),
            "DOTNET_CLI_HOME": str(root / "dotnet-home"),
            "NUGET_PACKAGES": str(root / "nuget"),
            "NUGET_HTTP_CACHE_PATH": str(root / "nuget-http"),
            "DOTNET_NOLOGO": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_PROCESSOR_COUNT": "2",
            "YAMORA_TEST_BINARY": str(args.binary),
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
        }
        build = [
            str(args.dotnet),
            "build",
            str(root / "sdk/tests/Tests.csproj"),
            "-c",
            "Release",
            "--disable-build-servers",
            "--artifacts-path",
            str(root / "artifacts"),
            "--configfile",
            str(root / "sdk/NuGet.Config"),
            "-m:2",
            "-p:UseSharedCompilation=false",
        ]

        def execute(case):
            code, output = run(build, env, root)
            if code or "Build succeeded." not in output:
                raise AssertionError("build failure cannot prove red\n" + output)
            return run(
                [str(args.dotnet), str(root / "artifacts/bin/Tests/release/Tests.dll"), case],
                env,
                root,
            )

        for name, file, old, new, case, assertion in selected:
            target = root / "sdk/Yamora" / file
            original = target.read_text()
            if original.count(old) != 1:
                raise AssertionError("mutant target changed: " + name)
            target.write_text(original.replace(old, new))
            code, output = execute(case)
            if not behavioral_red(code, output, case, assertion):
                raise AssertionError("precise behavioral red absent: " + name + "\n" + output)
            print("RED " + name + ": " + assertion, flush=True)
            target.write_text(original)
            code, output = execute(case)
            if code or f"PASS {case}\n1/1 checks passed; native enabled: True" not in output:
                raise AssertionError("restored green absent: " + name + "\n" + output)
            print("GREEN restored " + name, flush=True)
    finally:
        stop_owned(root)
        shutil.rmtree(root)
    print(
        f"{len(selected)} behavioral reds and restored greens; infrastructure oracle checks passed; scratch cleaned"
    )


if __name__ == "__main__":

    def interrupted(signum, frame):
        raise KeyboardInterrupt("mutant runner interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    main()
