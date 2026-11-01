"""Exact behavioral mutant qualification; compiler/infra failures never prove red."""

import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
TEST = "hostile_receipts_framing_ids_and_source_hash_are_uncertain"
MUTANTS = (
    (
        "src/binary_reply.rs",
        "m.id != e.request_id()",
        "false",
        "missing-id",
        "HOSTILE_REJECT:missing-id",
    ),
    (
        "src/binary_reply.rs",
        '|| (e.if_none_match() == Some("*") && m.status != 201)',
        "",
        "create-status",
        "HOSTILE_REJECT:create-status",
    ),
    (
        "src/binary_reply.rs",
        "|| (e.if_match().is_some() && m.status != 200)",
        "",
        "match-status",
        "HOSTILE_REJECT:match-status",
    ),
    (
        "src/binary_reply.rs",
        "|| Some(source_etag(e.source(), control)?) != m.etag",
        "",
        "bad-tag",
        "HOSTILE_REJECT:bad-tag",
    ),
    (
        "src/binary_reply.rs",
        "if Some(source_etag(&body, control)?) != m.etag",
        "if false",
        "eof",
        "HOSTILE_GET_REJECT:bad-tag",
    ),
    (
        "src/binary.rs",
        "envelope: uncertain.then(|| envelope.clone())",
        "envelope: { let _ = uncertain; None }",
        "wrong-id",
        "HOSTILE_UNCERTAIN:wrong-id",
    ),
)


def run(root, arguments, case):
    result = subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(root / "Cargo.toml"),
            "--offline",
            "--locked",
            "--test",
            "binary",
            "-j2",
            *arguments,
        ],
        env={**os.environ, "YAMORA_BINARY_CASE": case, "TMPDIR": str(root)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return result, result.stdout + result.stderr


def behavioral_red(code, output, assertion, dispatch):
    return (
        code == 101
        and assertion in output
        and dispatch in output
        and "test result: FAILED. 0 passed; 1 failed;" in output
        and not any(
            marker in output
            for marker in (
                "could not compile",
                "error[E",
                "Sanitizer",
                "runtime error:",
                "signal:",
                "fixture teardown failed",
                "fixture exited",
                "timeout",
                "dispatch observation missing",
            )
        )
    )


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
        if state in (b"Z", b"X", b"x"):
            continue
        if any(
            item == b"TMPDIR=" + prefix or item.startswith(b"TMPDIR=" + prefix + b"/")
            for item in environment
        ):
            owned.append(int(entry.name))
    return owned


def stop_owned(root):
    # Only processes launched with this unique private mutant TMPDIR are owned.
    # Normal runs are empty here. On any compiler/test/timeout failure, stop and
    # verify all remaining fixture/native descendants BEFORE deleting scratch.
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
    for code, diagnostic in (
        (-11, "signal: 11"),
        (101, "error[E01]"),
        (101, "AddressSanitizer"),
        (101, "fixture teardown failed"),
        (101, "timeout"),
    ):
        counterfeit = (
            "HOSTILE_REJECT:x DISPATCH_CONFIRMED:x test result: FAILED. 0 passed; 1 failed; "
            + diagnostic
        )
        assert not behavioral_red(code, counterfeit, "HOSTILE_REJECT:x", "DISPATCH_CONFIRMED:x")
    root = Path(tempfile.mkdtemp(prefix="rust-binary-mutants-", dir=os.environ["TMPDIR"]))
    try:
        for name in ("src", "tests"):
            shutil.copytree(SDK / name, root / name, ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(SDK / name, root / name)
        for path, old, new, case, assertion in MUTANTS:
            target = root / path
            original = target.read_text()
            assert original.count(old) == 1, (path, old)
            try:
                target.write_text(original.replace(old, new))
                compiled, output = run(root, ["--no-run"], case)
                if compiled.returncode:
                    raise AssertionError("compiler/infra failure is not red proof\n" + output)
                result, output = run(root, ["--", "--exact", TEST, "--nocapture"], case)
                dispatch = (
                    "DISPATCH_CONFIRMED:get-bad-tag"
                    if "GET_REJECT" in assertion
                    else "DISPATCH_CONFIRMED:" + case
                )
                if not behavioral_red(result.returncode, output, assertion, dispatch):
                    raise AssertionError("behavioral red absent\n" + output)
                print("RED confirmed: " + assertion, flush=True)
            finally:
                target.write_text(original)
            result, output = run(root, ["--", "--exact", TEST, "--nocapture"], case)
            if result.returncode or "test result: ok. 1 passed; 0 failed;" not in output:
                raise AssertionError("restored green absent\n" + output)
            print("GREEN restored: " + assertion, flush=True)
    finally:
        stop_owned(root)
        shutil.rmtree(root)
    print("all six binary guard mutants rejected with exact assertion and confirmed dispatch")


if __name__ == "__main__":
    main()
