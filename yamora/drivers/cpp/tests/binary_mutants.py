"""Precise SDK mutants must fail behavioral assertions after confirmed dispatch."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from tools.ci.yamora_driver_ci.runner import scratch_parent

SDK = Path(__file__).resolve().parents[1]


def command(args, *, env, timeout=120):
    result = subprocess.run(args, capture_output=True, env=env, timeout=timeout)
    if result.returncode or re.search(rb"Sanitizer|runtime error:", result.stderr):
        raise AssertionError(
            f"build/infrastructure is not mutation proof: {args}: {result.stdout!r} {result.stderr!r}"
        )


def configured_arguments(settings, source, build):
    result = [settings["cmake"], "-S", str(source), "-B", str(build), "-G", settings["generator"]]
    if settings["platform"]:
        result += ["-A", settings["platform"]]
    if settings["toolset"]:
        result += ["-T", settings["toolset"]]
    for name, item in settings["cache"].items():
        result.append(f"-D{name}:{item['type']}={item['value']}")
    return result


def verify_settings(settings, build):
    # The actual child cache is the build configuration contract; do not trust
    # the caller's CXX environment or merely echo the requested compiler/flags.
    actual = {}
    for line in (build / "CMakeCache.txt").read_text().splitlines():
        if (
            line
            and not line.startswith(("//", "#"))
            and "=" in line
            and ":" in line.split("=", 1)[0]
        ):
            name, value = line.split("=", 1)
            actual[name.split(":", 1)[0]] = value
    for name, item in settings["cache"].items():
        if actual.get(name) != item["value"]:
            raise AssertionError(
                f"mutant build setting changed: {name}: {actual.get(name)!r} != {item['value']!r}"
            )
    for name, expected in (
        ("CMAKE_GENERATOR", settings["generator"]),
        ("CMAKE_GENERATOR_PLATFORM", settings["platform"]),
        ("CMAKE_GENERATOR_TOOLSET", settings["toolset"]),
    ):
        if actual.get(name) != expected:
            raise AssertionError(f"mutant generator setting changed: {name}")
    evidence = {
        name: value
        for name, value in actual.items()
        if name == "CMAKE_CXX_COMPILER" or "FLAGS" in name and not name.endswith("-ADVANCED")
    }
    print(
        "Verified actual mutant build settings: "
        + json.dumps({"configuration": settings["configuration"], **evidence}, sort_keys=True),
        flush=True,
    )


def run(settings, operations=False):
    root = scratch_parent(os.environ["TMPDIR"])
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    with tempfile.TemporaryDirectory(prefix="cpp-binary-mutants-", dir=root) as folder:
        work = Path(folder)
        source = work / "sdk"
        shutil.copytree(SDK, source, ignore=shutil.ignore_patterns("__pycache__", "build"))
        build = work / "build"
        command(configured_arguments(settings, source, build), env=environment)
        verify_settings(settings, build)
        child_settings = json.loads(
            (build / f"binary-mutant-settings-{settings['configuration']}.json").read_text()
        )
        probe = child_settings["probe"]
        build_command = [
            settings["cmake"],
            "--build",
            str(build),
            "--target",
            "yamora_cpp_binary_probe",
            "-j2",
        ]
        if settings["configuration"]:
            build_command += ["--config", settings["configuration"]]
        command(build_command, env=environment)
        reply = source / "src/binary_reply.cpp"
        client = source / "src/binary.cpp"
        operation = source / "src/binary_operations.hpp"
        originals = {
            reply: reply.read_text(),
            client: client.read_text(),
            operation: operation.read_text(),
        }
        mutations = [
            (
                "GET source hash",
                reply,
                "require(source_etag(r.body, control) == r.etag);",
                "(void)source_etag(r.body, control);",
                "Hostile.test_source_hash",
                "behavioral rejection expected; dispatch=1",
            ),
            (
                "PUT frozen source hash",
                reply,
                "source_etag(source, control) == r.etag",
                "!source.empty()",
                "Hostile.test_put_source_hash",
                "behavioral rejection expected; dispatch=1",
            ),
            (
                "required ID presence",
                reply,
                "r.request_id == options.request_id &&",
                "true &&",
                "Hostile.test_request_id_presence",
                "behavioral rejection expected; dispatch=1",
            ),
            (
                "create-only status",
                reply,
                'if (options.if_none_match && *options.if_none_match == "*")\n      require(r.status == 201);',
                "/* deliberate create-status mutant */",
                "Hostile.test_put_status",
                "behavioral rejection expected; dispatch=1",
            ),
            (
                "final guard",
                client,
                "data->source,\n              control);\n    control.check();",
                "data->source,\n              control);\n    /* deliberate final-guard mutant */",
                "Hostile.test_final_deadline_and_cancellation_guard",
                "behavioral rejection expected; dispatch=1",
            ),
            (
                "admission before copy",
                client,
                "  Impl::Admission admission(*impl_, control);",
                "  /* deliberate late admission */",
                "Hostile.test_shared_admission_and_socket_cancellation",
                "admission copied waiting source; dispatch=4",
            ),
            (
                "uncertainty message allocation after dispatch",
                client,
                "throw *uncertainty;",
                "throw BinaryUncertainWriteError(envelope, uncertainty->kind(), uncertainty->status());",
                "Hostile.test_sustained_allocation_failure_keeps_snapshot",
                "allocation snapshot required; dispatch=1",
            ),
            (
                "conditional 304 status acceptance",
                reply,
                "(r.status == 200 || r.status == 304)",
                "(r.status == 200)",
                "Hostile.test_conditional_304",
                "conditional 304 success required; dispatch=1",
            ),
            (
                "conditional 304 exact ETag correlation",
                reply,
                'require(options.if_none_match &&\n              (*options.if_none_match == "*" ||\n               *options.if_none_match == "\\"" + r.etag + "\\""));',
                "require(true);",
                "Hostile.test_conditional_304",
                "behavioral rejection expected; dispatch=1",
            ),
        ]
        if operations:
            mutations = [
                (
                    "transaction count",
                    operation,
                    'require(json(source,control).get("operations").list().size()==count);',
                    "(void)json(source,control);",
                    "Operations.test_transaction_count_matches_json_specification",
                    "behavioral rejection expected; dispatch=1",
                ),
                (
                    "operation mode",
                    reply,
                    "mode <= 1 && (!mode ||",
                    "mode <= 2 && (mode != 1 ||",
                    "Operations.test_mutation_correlations_preserve_envelope",
                    "behavioral rejection expected; dispatch=1",
                ),
                (
                    "operation ID",
                    operation,
                    "require(r.request_id==options.request_id &&",
                    "require(options.request_id.has_value() &&",
                    "Operations.test_mutation_correlations_preserve_envelope",
                    "behavioral rejection expected; dispatch=1",
                ),
                (
                    "completed cursor",
                    operation,
                    "return {next,false};",
                    "return {tip,false};",
                    "Operations.test_feed_complete_page_cursor_and_partial_line",
                    "feed used checkpoint instead of next_after",
                ),
            ]
        for label, path, before, after, test, assertion in mutations:
            original = originals[path]
            if original.count(before) != (
                2 if label == "uncertainty message allocation after dispatch" else 1
            ):
                raise AssertionError(f"precise mutant anchor changed: {label}")
            broken = original.replace(before, after)
            if label == "admission before copy":
                broken = broken.replace(
                    "  const BinaryEnvelope envelope(data);",
                    "  Impl::Admission admission(*impl_, control);\n  const BinaryEnvelope envelope(data);",
                )
            path.write_text(broken)
            try:
                command(
                    build_command,
                    env=environment,
                )
                result = subprocess.run(
                    [
                        sys.executable,
                        str(source / "tests/test_binary.py"),
                        probe,
                        test,
                    ],
                    capture_output=True,
                    env=environment,
                    timeout=40,
                )
                output = result.stdout + result.stderr
                # A compiler error, signal, timeout, sanitizer or fixture failure
                # cannot stand in for the exact behavior under test.
                if (
                    result.returncode != 1
                    or assertion.encode() not in output
                    or b"Ran 1 test" not in output
                    or b"FAILED (failures=" not in output
                    or b"errors=" in output
                    or re.search(rb"Sanitizer|runtime error:|TimeoutExpired", output)
                ):
                    raise AssertionError(
                        f"mutant did not fail the behavioral oracle: {label}: {output!r}"
                    )
                print(f"RED {label}: {test}: {assertion}", flush=True)
            finally:
                path.write_text(original)
        command(
            build_command,
            env=environment,
        )
        for test in sorted({item[4] for item in mutations}):
            command(
                [
                    sys.executable,
                    str(source / "tests/test_binary.py"),
                    probe,
                    test,
                ],
                env=environment,
                timeout=40,
            )
            print(f"GREEN restored: {test}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--operations", action="store_true")
    args = parser.parse_args()
    run(json.loads(args.settings.read_text()), args.operations)
