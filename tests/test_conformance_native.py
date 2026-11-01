"""Mandatory real native profile and exact behavioral reds; no optional skips."""

import contextlib
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.ci.yamora_driver_ci.runner import environment as private_environment
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace
from yamora.conformance import contract
from yamora.conformance import runner
from yamora.conformance.tests.native import Native
from yamora.conformance.tests.relay import Relay
from yamora.tests.test_binary_client_mutants import qualified_red


class NativeConformanceTests(unittest.TestCase):
    def test_complete_explicit_python_profile_and_cleanup(self):
        binary = os.environ.get("YAMORA_TEST_BINARY")
        self.assertIsNotNone(binary, "YAMORA_TEST_BINARY required; conformance never skips/builds")
        scratch = scratch_parent(os.environ["TMPDIR"])
        before = set(scratch.iterdir())
        run_case = runner.run_case
        observed = []
        with workspace(scratch) as outer:
            environment = private_environment(outer, Path(binary), dict(os.environ))
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
            original = dict(environment)

            def private_call(native, *args, **kwargs):
                self.assertIs(kwargs["env"], native.env)
                for key in ("HOME", "PATH", "PYTHONPATH", "XDG_CACHE_HOME"):
                    self.assertEqual(native.env[key], original[key])
                observed.append(True)
                return run_case(native, *args, **kwargs)

            with patch.object(runner, "run_case", side_effect=private_call):
                result = runner.execute(
                    binary,
                    scratch,
                    ["python"],
                    expected_digest=os.environ.get("YAMORA_CONFORMANCE_SHA256"),
                    environment=environment,
                )
            self.assertEqual(environment, original)
        self.assertEqual(len(observed), len(contract.CASE_IDS))
        self.assertEqual(set(result["drivers"]), {"python"})
        self.assertEqual({row["case"] for row in result["drivers"]["python"]}, contract.CASE_IDS)
        self.assertEqual(set(scratch.iterdir()), before, "all own allocations/guards removed")

    def test_required_binary_and_missing_adapter_never_build_or_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "existing executable"):
                runner.execute(root / "missing", root, ["python"])
            with self.assertRaisesRegex(contract.ConformanceError, "missing adapters"):
                runner.execute(sys.executable, root)
            with self.assertRaisesRegex(contract.ConformanceError, "MISSING_ADAPTER_EXECUTABLE"):
                runner.execute(
                    sys.executable, root, ["python"], {"python": [str(root / "missing-tool")]}
                )
            self.assertEqual(list(root.iterdir()), [])


class ConformanceMutantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get("YAMORA_TEST_BINARY")
        if binary is None:
            raise AssertionError("YAMORA_TEST_BINARY required; native guard mutants never skip")
        cls.stack = contextlib.ExitStack()
        cls.addClassCleanup(cls.stack.close)
        cls.root = cls.stack.enter_context(workspace(scratch_parent(os.environ["TMPDIR"])))
        data = cls.root / "native"
        data.mkdir()
        cls.native = cls.stack.enter_context(
            Native(data, binary, os.environ.get("YAMORA_CONFORMANCE_SHA256"))
        )
        cls.inputs = cls.root / "inputs"
        package = cls.inputs / "yamora"
        package.mkdir(parents=True)
        source = Path(__file__).resolve().parents[1]
        for path in source.glob("*.py"):
            shutil.copyfile(path, package / path.name)
        shutil.copytree(
            source / "conformance",
            package / "conformance",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        cls.env = cls.native.env | {"PYTHONPATH": str(cls.inputs), "PYTHONSAFEPATH": "1"}
        cls.prefix = [sys.executable, "-P", "-m", "yamora.conformance.python_adapter"]
        cls.cases = {case["id"]: case for case in contract.load_manifest()["cases"]}
        cls.sequence = 100

    def execute_case(self, case_id, suffix):
        type(self).sequence += 1
        case = self.cases[case_id] | {"id": case_id + "-" + suffix + "-" + str(self.sequence)}
        self.last_root = self.root / case["id"]
        result = runner.run_case(
            self.native, self.prefix, "python", case, self.last_root, self.sequence, self.env
        )
        return result

    def red_then_green(
        self,
        filename,
        before,
        after,
        case_id,
        marker,
        api_value,
        *,
        expected_outcome="success",
        delayed_observer=False,
    ):
        path = self.inputs / "yamora" / filename
        original = path.read_text()
        prefix, boundary, operation = original.partition("    def operation(")
        self.assertEqual(prefix.count(before), 1, "exact bounded behavioral mutation")
        relays = []

        def relay(*args, **kwargs):
            instance = Relay(*args, **kwargs)
            if delayed_observer:
                original_observe = instance.observe

                def after_adapter_exit(downstream):
                    contract.require(instance.adapter_done.wait(5), "CONTROL_ADAPTER_EXIT")
                    instance.stop.wait(0.15)
                    contract.require(
                        time.monotonic() - instance.finished_at >= 0.1, "CONTROL_DELAY"
                    )
                    instance.released_after_adapter_exit = True
                    original_observe(downstream)

                instance.observe = after_adapter_exit
            relays.append(instance)
            return instance

        outer = self

        class Invariant(unittest.TestCase):
            def runTest(self):
                try:
                    outer.execute_case(case_id, "broken")
                except contract.ConformanceError as error:
                    if str(error) != marker:
                        raise
                    self.fail(marker)

        path.write_text(prefix.replace(before, after) + boundary + operation)
        try:
            result = unittest.TestResult()
            with patch.object(runner, "Relay", side_effect=relay):
                Invariant().run(result)
            actual = contract.json_bytes(contract.read_bytes(self.last_root / "adapter.out"))
            self.assertEqual(len(relays), 1, result.errors or result.failures)
            observed = relays[0]
            result.binary_request_confirmed = (
                len(observed.requests) == 1
                and observed.ready.is_set()
                and observed.observation is not None
            )
            result.binary_mutant_observed = actual["outcome"] == expected_outcome and api_value(
                actual, observed
            )
            self.assertTrue(qualified_red(result, marker), result.failures or result.errors)
            print(
                f"QUALIFIED RED {filename}:{case_id} {marker}; request/native witness and exact mutant result confirmed"
            )
        finally:
            path.write_text(original)
        self.execute_case(case_id, "restored")
        print(f"RESTORED GREEN {filename}:{case_id}")

    def test_sdk_request_id_guard_red_then_restored_green(self):
        self.red_then_green(
            "binary_reply.py",
            '    if response.request_id != envelope.request_id:\n        raise wire.WireError("response request ID mismatch")\n',
            "",
            "committed-wrong-id",
            "DISPATCHED_OUTCOME",
            lambda actual, relay: (
                actual["api"]["status"] == 201 and actual["api"]["request_id"] == "ff" * 16
            ),
        )

    def test_duplicate_connection_is_rejected_after_native_witness(self):
        before = "            channel.send(wire.END, 1)\n"
        self.red_then_green(
            "binary_client.py",
            before,
            before
            + "            cancel.wait(1)\n"
            + "            with socket.create_connection((self.config.host, self.config.port), timeout=0.2):\n"
            + "                pass\n",
            "committed-cancel",
            "NO_AUTOMATIC_REPLAY",
            lambda actual, relay: relay.connections == 2,
            expected_outcome="uncertain",
        )

    def test_same_connection_replay_is_rejected_after_native_witness(self):
        before = "            channel.send(wire.END, 1)\n"
        self.red_then_green(
            "binary_client.py",
            before,
            before
            + "            cancel.wait(1)\n"
            + "            connection.settimeout(0.2)\n"
            + "            connection.sendall(wire.frame(wire.REQUEST, 1, metadata)\n"
            + "                               + wire.frame(wire.DATA, 1, envelope.source)\n"
            + "                               + wire.frame(wire.END, 1))\n",
            "committed-cancel",
            "NO_AUTOMATIC_REPLAY",
            lambda actual, relay: getattr(relay, "request_count", 1) == 2,
            expected_outcome="uncertain",
        )

    def test_delayed_observer_drains_queued_reconnect_after_adapter_exit(self):
        before = "            channel.send(wire.END, 1)\n"
        self.red_then_green(
            "binary_client.py",
            before,
            before
            + "            cancel.wait(1)\n"
            + "            with socket.create_connection((self.config.host, self.config.port), timeout=0.2):\n"
            + "                pass\n",
            "committed-cancel",
            "NO_AUTOMATIC_REPLAY",
            lambda actual, relay: relay.connections == 2 and relay.released_after_adapter_exit,
            expected_outcome="uncertain",
            delayed_observer=True,
        )

    def test_delayed_observer_drains_queued_request_after_adapter_exit(self):
        before = "            channel.send(wire.END, 1)\n"
        self.red_then_green(
            "binary_client.py",
            before,
            before
            + "            cancel.wait(1)\n"
            + "            connection.settimeout(0.2)\n"
            + "            connection.sendall(wire.frame(wire.REQUEST, 1, metadata)\n"
            + "                               + wire.frame(wire.DATA, 1, envelope.source)\n"
            + "                               + wire.frame(wire.END, 1))\n",
            "committed-cancel",
            "NO_AUTOMATIC_REPLAY",
            lambda actual, relay: relay.request_count == 2 and relay.released_after_adapter_exit,
            expected_outcome="uncertain",
            delayed_observer=True,
        )

    def test_partial_extra_request_header_cannot_pass_no_replay(self):
        before = "            channel.send(wire.END, 1)\n"
        self.red_then_green(
            "binary_client.py",
            before,
            before
            + "            cancel.wait(1)\n"
            + "            connection.settimeout(0.2)\n"
            + "            connection.sendall(wire.frame(wire.REQUEST, 1, metadata)[:8])\n",
            "committed-cancel",
            "NO_AUTOMATIC_REPLAY",
            lambda actual, relay: (
                getattr(relay, "extra_bytes", 0) == 8 and relay.released_after_adapter_exit
            ),
            expected_outcome="uncertain",
            delayed_observer=True,
        )

    def test_partial_extra_control_payload_cannot_pass_no_replay(self):
        before = "            channel.send(wire.END, 1)\n"
        self.red_then_green(
            "binary_client.py",
            before,
            before
            + "            cancel.wait(1)\n"
            + "            connection.settimeout(0.2)\n"
            + "            connection.sendall(wire.frame(wire.PING, 0, b'abcdefgh')[:-4])\n",
            "committed-cancel",
            "NO_AUTOMATIC_REPLAY",
            lambda actual, relay: getattr(relay, "extra_bytes", 0) == 20,
            expected_outcome="uncertain",
        )

    def test_complete_original_cancel_and_ping_are_not_replays(self):
        path = self.inputs / "yamora/binary_client.py"
        original = path.read_text()
        before = "            channel.send(wire.END, 1)\n"
        prefix, operation = original.split("    def operation(", 1)
        self.assertEqual(prefix.count(before), 1)
        after = (
            before
            + "            cancel.wait(1)\n"
            + "            connection.settimeout(0.2)\n"
            + "            connection.sendall(wire.frame(wire.CANCEL, 1)\n"
            + "                               + wire.frame(wire.PING, 0, b'abcdefgh'))\n"
        )
        relays = []

        def relay(*args, **kwargs):
            instance = Relay(*args, **kwargs)
            relays.append(instance)
            return instance

        path.write_text(prefix.replace(before, after) + "    def operation(" + operation)
        try:
            with patch.object(runner, "Relay", side_effect=relay):
                self.execute_case("committed-cancel", "complete-controls")
            self.assertEqual(len(relays), 1)
            self.assertEqual(relays[0].request_count, 1)
            self.assertEqual(relays[0].connections, 1)
            self.assertEqual(getattr(relays[0], "extra_bytes", 0), 40)
            self.assertTrue(relays[0].quiesced)
        finally:
            path.write_text(original)

    def test_sdk_end_guard_red_then_restored_green(self):
        self.red_then_green(
            "binary_client.py",
            "        kind, stream, size = wire.decode_header(self.exact(16), self.max_frame)\n        return kind, stream, self.exact(size)\n",
            '        try:\n            kind, stream, size = wire.decode_header(self.exact(16), self.max_frame)\n            return kind, stream, self.exact(size)\n        except wire.WireError:\n            return wire.END, 1, b""\n',
            "committed-no-end",
            "DISPATCHED_OUTCOME",
            lambda actual, relay: (
                actual["api"]["status"] == 201
                and actual["api"]["request_id"] == relay.reply["request_id"]
            ),
        )

    def test_sdk_returned_byte_corruption_red_then_restored_green(self):
        self.red_then_green(
            "binary_client.py",
            "            return response\n",
            '            return replace(response, body=response.body[:-1] + b"x")\n',
            "source-exact",
            "API_SOURCE_BYTES",
            lambda actual, relay: (
                actual["api"]["status"] == 200
                and contract.output_bytes(self.last_root, actual["api"]["body_file"], "body.bin")
                == relay.reply["body"][:-1] + b"x"
            ),
        )

    def test_sdk_returned_etag_corruption_red_then_restored_green(self):
        self.red_then_green(
            "binary_client.py",
            "            return response\n",
            "            return replace(response, etag='\"0000000000000000\"')\n",
            "source-exact",
            "API_ETAG",
            lambda actual, relay: actual["api"]["etag"] == '"0000000000000000"',
        )

    def test_sdk_returned_status_corruption_red_then_restored_green(self):
        self.red_then_green(
            "binary_client.py",
            "            return response\n",
            "            return replace(response, status=200)\n",
            "create",
            "API_STATUS",
            lambda actual, relay: actual["api"]["status"] == 200 and relay.reply["status"] == 201,
        )

    def test_tls_setup_error_is_never_a_behavioral_red(self):
        path = self.inputs / "yamora/conformance/python_adapter.py"
        original = path.read_text()
        self.assertEqual(original.count("args.server_name,"), 1)
        path.write_text(original.replace("args.server_name,", '"wrong.invalid",'))
        outer = self

        class InvalidTLS(unittest.TestCase):
            def runTest(self):
                outer.execute_case("committed-no-end", "invalid-tls")

        try:
            result = unittest.TestResult()
            InvalidTLS().run(result)
            result.binary_request_confirmed = False
            result.binary_mutant_observed = False
            self.assertFalse(qualified_red(result, "DISPATCHED_OUTCOME"))
            self.assertEqual(len(result.errors), 1, result.failures)
            self.assertEqual(result.failures, [])
        finally:
            path.write_text(original)

    def test_outer_watchdog_is_a_failure_not_a_deadline_observation(self):
        prefix = [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "conformance/tests/stalled_adapter.py"),
        ]
        case = self.cases["read-deadline"] | {"id": "watchdog"}
        with patch.object(runner, "WATCHDOG_SECONDS", 0.1):
            with self.assertRaisesRegex(contract.ConformanceError, "OUTER_WATCHDOG_FAILURE"):
                runner.run_case(self.native, prefix, "python", case, self.root / "watchdog", 99)
