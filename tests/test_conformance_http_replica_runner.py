"""Executable controls for evidence integrity and persistent v2 supervision."""

import contextlib
import copy
import io
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.ci.yamora_driver_ci.process import RunnerError
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace
from yamora.conformance import http_replica_contract as contract
from yamora.conformance import http_replica_runner as runner
from yamora.conformance.contract import ConformanceError
from yamora.conformance.contract import source_tag


def wire():
    source = contract.FIXTURES["value-b"]
    receipt = {
        "status": "stored",
        "collection": "manifests",
        "document": "counter",
        "etag": source_tag(source)[1:-1],
        "revision": "0000000000000021",
    }
    return {
        "status": 200,
        "body": contract.encode_line(receipt).rstrip(b"\n"),
        "etag": source_tag(source),
        "revision": receipt["revision"],
        "raw": b"complete native HTTP response",
        "completed_ns": 30,
        "request": {
            "request_id": "1" * 32,
            "method": "PATCH",
            "target": runner.TARGET,
            "body": b'{ "$inc" : { "n" : 1 } }',
            "if_match": source_tag(contract.FIXTURES["value-a"]),
            "if_none_match": None,
        },
    }


def attempt(original, sent=50, completed=60, socket=20001):
    return {
        **original["request"],
        "seed": 1,
        "arrived_ns": sent - 1,
        "sent_ns": sent,
        "completed_ns": completed,
        "native_local": ("127.0.0.1", socket),
        "response": {k: original[k] for k in ("status", "body", "etag", "revision", "raw")},
    }


class OrchestrationTests(unittest.TestCase):
    """Exercise runner orchestration without claiming synthetic SDK/native proof."""

    def scenario(self, *, marker=None, phase="health", witnessed=True, body_error=None):
        events, completed, sessions = [], [], []
        original = wire()
        command = runner._command(
            contract.CASE_REQUIREMENTS["R15"],
            {"source": {"etag": source_tag(contract.FIXTURES["value-a"])}},
            15,
        )
        original["request"]["request_id"] = command["request_id"]
        records = [attempt(original, 10, 30), attempt(original, 11, 31, 20002)]
        cluster = SimpleNamespace(env={})

        class Relay:
            def __init__(self, cluster):
                self.first_commit = threading.Event()
                self.first_commit.set()
                self.first_receipt = original
                self.first_source = (
                    {
                        "status": 200,
                        "body": contract.FIXTURES["value-b"],
                        "etag": original["etag"],
                        "revision": original["revision"],
                        "completed_ns": 35,
                    }
                    if witnessed
                    else None
                )
                self.initial, self.seeds, self.witness_ns = records, [], None
                self.lose_initial = True

            def __enter__(self):
                return self

            def __exit__(self, *args):
                events.append("relay-close")
                if marker is not None:
                    raise marker

            def arm(self, method, target, source, *, overlap=1, lose_initial=True):
                self.lose_initial = lose_initial

            def check(self):
                if marker is not None and phase == "health" and sessions:
                    raise marker
                if marker is not None and phase == "committed" and len(sessions) == 2:
                    raise marker

            def snapshot(self):
                return list(records)

            def assert_overlap(self):
                runner.assert_native_overlap(records[:2])

            def assert_receipts(self):
                pass

            def release_after_witness(self, source, identity, *, deliver=True):
                self.witness_ns = 40
                events.append("release")
                return {"revision": "0000000000000022"}

            def release_delivery(self):
                pass

        relay = Relay(cluster)

        class Adapter:
            def __init__(self, prefix, driver, root, env, check):
                self.root, self.check, self.history = root, check, []
                self.index = len(sessions)
                sessions.append(self)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                events.append(f"close-{self.index}")

            def begin(self, **fields):
                if phase == "health":
                    self.check()

            def finish(self):
                self.check()
                events.append(f"success-{self.index}")
                completed.append(self.index)
                observation = contract.empty_observation(1)
                receipt = contract.json_bytes(original["body"])
                observation["api"].update(
                    receipt=receipt, etag=receipt["etag"], revision=receipt["revision"]
                )
                self.history.append({"observation": observation})
                return observation

            def call(self, **fields):
                events.append("explicit-replay")
                records.append(attempt(original, 50, 60, 20003))
                return self.finish()

        def advance(*args):
            events.append("advance-c")
            if body_error is not None:
                raise body_error
            return "f" * 32, {"source": {"revision": "0000000000000022", "completed_ns": 40}}

        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            with (
                patch.object(runner, "HTTPSSeedRelay", return_value=relay),
                patch.object(runner, "AdapterSession", Adapter),
                patch.object(runner, "configuration"),
                patch.object(runner, "_advance", side_effect=advance),
                patch.object(runner, "_source"),
            ):
                result = runner.recovery_case(
                    cluster, [], "python", contract.CASE_REQUIREMENTS["R15"], root, command, 15
                )
        return events, relay, result

    def test_r15_initial_delivery_is_lossless(self):
        _, relay, _ = self.scenario()
        self.assertFalse(relay.lose_initial, "R15_LOSSLESS_INITIAL_DELIVERY")

    def test_r15_both_original_sdk_successes_precede_c_then_explicit_replay(self):
        events, _, _ = self.scenario()
        advance = events.index("advance-c")
        for index in (0, 1):
            self.assertLess(
                events.index(f"success-{index}"), advance, "R15_INITIAL_SDK_SUCCESS_BEFORE_C"
            )
        self.assertLess(advance, events.index("explicit-replay"))

    def test_live_identity_and_receipt_errors_are_behavioral_through_health_and_teardown(self):
        for phase in ("health", "committed", "close"):
            for marker in (
                "RETRY_REQUEST_ID",
                "RETRY_BODY",
                "RETRY_IF_MATCH",
                "RECEIPT_BODY",
                "RECEIPT_REVISION",
            ):
                with (
                    self.subTest(phase=phase, marker=marker),
                    self.assertRaisesRegex(runner.BehavioralFailure, "^" + marker + "$"),
                ):
                    self.scenario(marker=ConformanceError(marker), phase=phase)

    def test_unwitnessed_behavior_markers_remain_infrastructure(self):
        with self.assertRaisesRegex(ConformanceError, "^RETRY_BODY$"):
            self.scenario(marker=ConformanceError("RETRY_BODY"), witnessed=False)

    def test_setup_tls_framing_cleanup_and_unrelated_markers_stay_infrastructure(self):
        for error in (
            ConformanceError("RETRY_BEFORE_WITNESS"),
            ConformanceError("RECEIPT_IDENTITY"),
            ConformanceError("HTTP_FRAME_EXCESS"),
            RunnerError("NATIVE_SANITIZER_FAILURE"),
            RunnerError("RELAY_SHUTDOWN_UNVERIFIED"),
        ):
            with self.subTest(error=str(error)), self.assertRaises(type(error)) as caught:
                self.scenario(marker=error)
            self.assertIs(caught.exception, error)

    def test_body_infrastructure_failure_wins_over_saved_behavior_error_on_close(self):
        error = RunnerError("UNEXPECTED_TLS_FAILURE")
        with self.assertRaisesRegex(RunnerError, "UNEXPECTED_TLS_FAILURE"):
            self.scenario(marker=ConformanceError("RETRY_BODY"), phase="close", body_error=error)


class EvidenceTests(unittest.TestCase):
    def test_changed_id_bytes_and_conditions_rejected_at_named_assertion(self):
        original = wire()
        first = attempt(original, 20, 30)
        changes = {
            "request_id": "2" * 32,
            "body": b'{"$inc":{"n":2}}',
            "if_match": None,
            "if_none_match": "*",
            "method": "PUT",
            "target": runner.TARGET + "-other",
        }
        for field, changed in changes.items():
            with self.subTest(field=field):
                retry = attempt(original)
                retry[field] = changed
                with self.assertRaisesRegex(
                    runner.BehavioralFailure, "^RETRY_" + field.upper() + "$"
                ):
                    runner.verify_attempts([first, retry], original, 40)
        runner.verify_attempts([first, attempt(original)], original, 40)

    def test_changed_returned_native_receipt_rejected_field_by_field(self):
        original = wire()
        for field, changed in {
            "status": 201,
            "body": b"current receipt",
            "etag": '"' + "9" * 16 + '"',
            "revision": "9" * 16,
        }.items():
            with self.subTest(field=field):
                retry = attempt(original)
                retry["response"][field] = changed
                with self.assertRaisesRegex(
                    runner.BehavioralFailure, "^RECEIPT_" + field.upper() + "$"
                ):
                    runner.verify_attempts([attempt(original, 20, 30), retry], original, 40)

    def test_missing_witnesses_and_early_forwarding_are_infrastructure(self):
        original = wire()
        with self.assertRaisesRegex(RunnerError, "MISSING_ADVANCE_WITNESS"):
            runner.verify_attempts([attempt(original)], original, None)
        with self.assertRaisesRegex(RunnerError, "MISSING_ORIGINAL_RECEIPT"):
            runner.verify_attempts([attempt(original)], None, 40)
        with self.assertRaisesRegex(RunnerError, "MISSING_NATIVE_ATTEMPTS"):
            runner.verify_attempts([], original, 40)
        with self.assertRaisesRegex(RunnerError, "RETRY_BEFORE_WITNESS"):
            runner.verify_attempts(
                [attempt(original, 20, 30), attempt(original, 39, 60)], original, 40
            )
        missing = attempt(original)
        missing["completed_ns"] = None
        with self.assertRaisesRegex(RunnerError, "MISSING_NATIVE_COMPLETION"):
            runner.verify_attempts([attempt(original, 20, 30), missing], original, 40)

    def test_serialized_and_completed_buffer_overlap_rejected_at_native_overlap(self):
        original = wire()
        first = attempt(original, 10, 20)
        for second in (attempt(original, 21, 30, 20002), attempt(original, 20, 30, 20002)):
            with self.subTest(sent=second["sent_ns"]):
                # Held SDK delivery times cannot turn completed native I/O into overlap.
                first["delivered_ns"] = second["delivered_ns"] = 1000
                with self.assertRaisesRegex(ConformanceError, "^NATIVE_OVERLAP$"):
                    runner.verify_attempts([first, second], original, 40, 2)
        runner.verify_attempts(
            [attempt(original, 10, 30), attempt(original, 11, 31, 20002)], original, 40, 2
        )

    def test_overlap_requires_distinct_native_tls_sockets(self):
        original = wire()
        with self.assertRaisesRegex(ConformanceError, "^OVERLAP_SOCKETS$"):
            runner.verify_attempts(
                [attempt(original, 10, 30), attempt(original, 11, 31)], original, 40, 2
            )

    def test_first_typed_patch_encoding_is_baseline_without_input_whitespace_claim(self):
        command = runner._command(
            contract.CASE_REQUIREMENTS["R03"],
            {"source": {"etag": source_tag(contract.FIXTURES["value-a"])}},
            1,
        )
        actual = wire()["request"] | {"request_id": command["request_id"]}
        runner.validate_request(command, actual, None)
        with self.assertRaisesRegex(runner.BehavioralFailure, "ORIGINAL_PATCH"):
            runner.validate_request(command, actual | {"body": b'{"$inc":{"n":2}}'}, None)

    def test_current_receipt_substitution_rejected_even_when_internally_consistent(self):
        original = wire()
        observation = contract.empty_observation(1)
        receipt = contract.json_bytes(original["body"])
        observation["api"].update(
            receipt=receipt, etag=receipt["etag"], revision=receipt["revision"]
        )
        runner.compare_api("python", "PATCH", observation, None, original)
        current = dict(
            receipt,
            etag=source_tag(contract.FIXTURES["value-c"])[1:-1],
            revision="0000000000000022",
        )
        substituted = copy.deepcopy(observation)
        substituted["api"].update(
            receipt=current, etag=current["etag"], revision=current["revision"]
        )
        with self.assertRaisesRegex(runner.BehavioralFailure, "^API_ORIGINAL_RECEIPT$"):
            runner.compare_api("python", "PATCH", substituted, None, original)

    def test_api_raw_native_status_body_etag_revision_are_exact(self):
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            (root / "call-000001").mkdir()
            original = wire()
            path = root / "call-000001/body.bin"
            path.write_bytes(original["body"])
            observation = contract.empty_observation(1)
            observation["api"].update(
                status=200,
                body_file="call-000001/body.bin",
                etag=original["etag"],
                revision=original["revision"],
            )
            runner.compare_api("rust", "PATCH", observation, root, original)
            for field, value in {
                "status": 201,
                "etag": '"' + "9" * 16 + '"',
                "revision": "9" * 16,
            }.items():
                wrong = copy.deepcopy(observation)
                wrong["api"][field] = value
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(
                        runner.BehavioralFailure, "API_ORIGINAL_" + field.upper()
                    ),
                ):
                    runner.compare_api("rust", "PATCH", wrong, root, original)
            path.write_bytes(original["body"] + b" ")
            with self.assertRaisesRegex(runner.BehavioralFailure, "API_ORIGINAL_BODY"):
                runner.compare_api("rust", "PATCH", observation, root, original)

    def test_all_driver_cells_required_without_implicit_skips(self):
        with self.assertRaisesRegex(RunnerError, "MISSING_REQUIRED_ADAPTERS"):
            runner.select_adapters(None, {})
        with self.assertRaisesRegex(RunnerError, "MISSING_REQUIRED_ADAPTERS"):
            runner.select_adapters(["go"], {})
        with self.assertRaisesRegex(RunnerError, "DRIVER_SELECTION"):
            runner.select_adapters([], {})
        configured = {driver: [sys.executable] for driver in contract.DRIVERS}
        self.assertEqual(tuple(runner.select_adapters(None, configured)), contract.DRIVERS)

    def test_frozen_manifest_explicitly_contains_all_fifteen_cases(self):
        manifest = contract.load_manifest()
        self.assertEqual(
            [case["id"] for case in manifest["cases"]], [f"R{i:02d}" for i in range(1, 16)]
        )


ADAPTER = r"""
import json, os, sys, time
from pathlib import Path
from yamora.conformance import http_replica_contract as contract
mode = sys.argv[1]
root = Path(sys.argv[sys.argv.index('--root') + 1])
for line in sys.stdin.buffer:
    command = contract.parse_line(line)
    if mode == 'stall':
        time.sleep(60)
    if mode == 'compiler':
        print('compiler failed', file=sys.stderr)
        raise SystemExit(7)
    observation = contract.empty_observation(command['seq'], command['action'])
    if command['action'] == 'close':
        observation['outcome'] = 'closed'
    else:
        path = 'call-%06d/body.bin' % command['seq']
        (root / path).write_bytes(b'observed-source')
        observation['api']['body_file'] = path
    raw = contract.encode_line(observation)
    if mode == 'cr':
        raw = raw[:-1] + b'\r\n'
    if mode == 'float':
        raw = raw.replace(b'"elapsed_ns":0', b'"elapsed_ns":0.0')
    if mode == 'oversize':
        raw = b'x' * 16385
    if mode == 'duplicate':
        raw = raw.replace(b'"seq":', b'"seq":99,"seq":')
    if mode == 'invalid-utf8':
        raw = b'\xff\n'
    if mode == 'big-body':
        (root / observation['api']['body_file']).write_bytes(b'x' * 131073)
    if mode == 'sanitizer':
        print('AddressSanitizer: fatal', file=sys.stderr, flush=True)
    if mode == 'extra':
        raw += raw
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    if command['action'] == 'close':
        if mode == 'bad-close':
            raise SystemExit(8)
        if mode == 'hang-close':
            time.sleep(60)
        break
"""


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.manager = workspace(scratch_parent(os.environ["TMPDIR"]))
        self.root = self.manager.__enter__()
        self.addCleanup(self.manager.__exit__, None, None, None)
        self.script = self.root / "synthetic_adapter.py"
        self.script.write_text(ADAPTER)
        self.fields = {
            "method": "GET",
            "collection": "manifests",
            "document": "counter",
            "source_file": None,
            "request_id": None,
            "if_match": None,
            "if_none_match": None,
        }

    def session(self, mode="valid", check=lambda: None):
        return runner.AdapterSession(
            [sys.executable, str(self.script), mode], "python", self.root, dict(os.environ), check
        )

    def test_persistent_commands_and_verified_close_share_one_process(self):
        with self.session() as session:
            first = session.call(**self.fields)
            second = session.call(**self.fields)
            pid = session.child.pid
            self.assertEqual((first["seq"], second["seq"]), (1, 2))
            self.assertEqual(
                contract.read_file(self.root, second["api"]["body_file"]), b"observed-source"
            )
        self.assertEqual(session.child.pid, pid)
        self.assertEqual(session.child.returncode, 0)
        self.assertEqual(session.history[-1]["command"]["action"], "close")
        self.assertTrue(session.session.closed)

    def test_one_outstanding_command(self):
        with self.session() as session:
            session.begin(**self.fields)
            with self.assertRaisesRegex(RunnerError, "ONE_OUTSTANDING_COMMAND"):
                session.begin(**self.fields)
            session.finish()

    def test_strict_jsonl_cr_duplicate_float_and_output_bound(self):
        for mode, marker in (
            ("cr", "JSONL_FRAME"),
            ("duplicate", "JSON_DUPLICATE_KEY"),
            ("float", "JSON_TYPE"),
            ("oversize", "ADAPTER_STDOUT_BOUND"),
            ("extra", "JSONL_FRAME"),
            ("invalid-utf8", "JSON_INVALID"),
            ("big-body", "FILE_BOUND_TYPE"),
        ):
            with self.subTest(mode=mode):
                isolated = self.root / mode
                isolated.mkdir()
                with self.assertRaisesRegex((contract.ContractError, RunnerError), marker):
                    with runner.AdapterSession(
                        [sys.executable, str(self.script), mode],
                        "python",
                        isolated,
                        dict(os.environ),
                    ) as session:
                        session.call(**self.fields)

    def test_compiler_and_sanitizer_failures_are_infrastructure(self):
        for mode, marker in (
            ("compiler", "ADAPTER_PROCESS_FAILURE"),
            ("sanitizer", "ADAPTER_INFRASTRUCTURE_FAILURE"),
        ):
            with self.subTest(mode=mode):
                isolated = self.root / mode
                isolated.mkdir()
                with self.assertRaisesRegex(RunnerError, marker):
                    with runner.AdapterSession(
                        [sys.executable, str(self.script), mode],
                        "python",
                        isolated,
                        dict(os.environ),
                    ) as session:
                        session.call(**self.fields)
                self.assertIsNotNone(session.child.poll())

    def test_watchdog_is_infrastructure_and_stops_owned_child(self):
        with self.assertRaisesRegex(RunnerError, "ADAPTER_WATCHDOG"):
            with self.session("stall") as session:
                session.begin(**self.fields)
                session.deadline = time.monotonic() - 1
                session.finish()
        self.assertIsNotNone(session.child.poll())

    def test_close_requires_zero_exit_after_observation(self):
        with self.assertRaisesRegex(RunnerError, "ADAPTER_SHUTDOWN_STATUS|ADAPTER_PROCESS_FAILURE"):
            with self.session("bad-close") as session:
                session.call(**self.fields)
        self.assertIsNotNone(session.child.poll())

    def test_relay_infrastructure_error_is_not_swallowed(self):
        def broken():
            raise RunnerError("UNEXPECTED_TLS_FAILURE")

        with self.assertRaisesRegex(RunnerError, "UNEXPECTED_TLS_FAILURE"):
            with self.session(check=broken) as session:
                session.call(**self.fields)

    def test_unverified_sdk_budget_never_counts_as_behavioral_red(self):
        # A lying/misconfigured observer cannot certify the SDK's fixed budget.
        script = ADAPTER.replace(
            "observation = contract.empty_observation(command['seq'], command['action'])",
            "observation = contract.empty_observation(command['seq'], command['action']); observation['elapsed_ns'] = 16000000000",
        )
        self.script.write_text(script)
        with self.assertRaisesRegex(RunnerError, "SDK_LOGICAL_BUDGET"):
            with self.session() as session:
                session.call(**self.fields)


class ExecuteTests(unittest.TestCase):
    def test_cli_distinguishes_behavior_from_all_infrastructure_failures(self):
        arguments = ["http-replica", "--binary", sys.executable, "--sha256", "a" * 64]
        cases = (
            (runner.BehavioralFailure("API_ORIGINAL_RECEIPT"), 1, "BEHAVIORAL FAILURE"),
            (RunnerError("ADAPTER_WATCHDOG"), 2, "INFRASTRUCTURE FAILURE"),
            (contract.ContractError("MISSING_API_FIELD"), 2, "INFRASTRUCTURE FAILURE"),
            (KeyError("MISSING_NATIVE_EVIDENCE"), 2, "INFRASTRUCTURE FAILURE"),
            (ConnectionRefusedError("UNEXPECTED_LIVE_MEMBER_FAILURE"), 2, "INFRASTRUCTURE FAILURE"),
        )
        for error, status, marker in cases:
            output = io.StringIO()
            with (
                self.subTest(error=type(error).__name__),
                patch.object(sys, "argv", arguments),
                patch.object(runner, "execute", side_effect=error),
                contextlib.redirect_stderr(output),
            ):
                self.assertEqual(runner.main(), status)
            self.assertIn(marker, output.getvalue())

    def test_configuration_enforces_pem_and_token_bounds_before_launch(self):
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            certs = root / "certs"
            certs.mkdir()
            for name in ("ca.pem", "client.pem", "client.key"):
                (certs / name).write_bytes(b"x" * 16384)
            for name in ("read.token", "write.token"):
                (root / name).write_bytes(b"x" * 512)
            cluster = SimpleNamespace(root=root, certs=certs, leader=lambda: 0)
            relay = SimpleNamespace(
                seeds=[{"host": "127.0.0.1", "port": 19100 + i, "node": i} for i in (1, 2, 3)]
            )
            config = runner.configuration(root / "valid", cluster, relay)
            self.assertEqual(
                contract.load_config(root / "valid/config.json", root / "valid"), config
            )
            self.assertEqual(config["timeout_ms"], 15000)
            self.assertEqual(config["attempt_timeout_ms"], 3000)
            for name, directory, limit in (("ca.pem", certs, 16384), ("write.token", root, 512)):
                path = directory / name
                path.write_bytes(b"x" * (limit + 1))
                with (
                    self.subTest(name=name),
                    self.assertRaisesRegex(contract.ContractError, "FILE_BOUND_TYPE"),
                ):
                    runner.configuration(root / ("invalid-" + name), cluster, relay)
                path.write_bytes(b"x" * limit)

    def test_explicit_digest_and_missing_tool_fail_before_native_launch(self):
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            with self.assertRaisesRegex(RunnerError, "EXPLICIT_DAEMON_SHA256_REQUIRED"):
                runner.execute(sys.executable, root, selected=["python"])
            with self.assertRaisesRegex(RunnerError, "DAEMON_DIGEST"):
                runner.execute(sys.executable, root, selected=["python"], expected_digest="0" * 64)
            expected = runner.digest(Path(sys.executable))
            with self.assertRaisesRegex(RunnerError, "MISSING_ADAPTER_EXECUTABLE"):
                runner.execute(
                    sys.executable,
                    root,
                    selected=["python"],
                    configured={"python": [str(root / "nonexistent-compiler")]},
                    expected_digest=expected,
                )
            self.assertEqual(list(root.iterdir()), [])

    def test_missing_case_cannot_produce_success_and_caller_environment_unchanged(self):
        environment = {
            "PATH": os.defpath,
            "PYTHONPATH": str(Path(runner.__file__).resolve().parents[2]),
        }
        before = dict(environment)
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            with (
                patch.object(runner, "run_case", return_value={"case": "R01"}),
                self.assertRaisesRegex(RunnerError, "INCOMPLETE_DRIVER_CASES"),
            ):
                runner.execute(
                    sys.executable,
                    root,
                    selected=["python"],
                    configured={"python": [sys.executable]},
                    expected_digest=runner.digest(Path(sys.executable)),
                    environment=environment,
                )
            self.assertEqual(list(root.iterdir()), [])
        self.assertEqual(environment, before)


if __name__ == "__main__":
    unittest.main()
