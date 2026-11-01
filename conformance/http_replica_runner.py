"""Qualify public HTTP replica SDKs using independent native receipt witnesses.

This sidecar deliberately leaves tool installation and CI selection to its caller.
Only completed, fully witnessed fifteen-case driver runs produce a result.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import json
import os
import shutil
import subprocess
import sys
import time
from builtins import BaseExceptionGroup
from pathlib import Path

from tools.ci.yamora_driver_ci.process import RunnerError
from tools.ci.yamora_driver_ci.runner import environment as private_environment
from tools.ci.yamora_driver_ci.runner import immutable_daemon
from tools.ci.yamora_driver_ci.runner import native_binary
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace

from . import http_replica_contract as contract
from .contract import ConformanceError
from .contract import adapter_environment
from .contract import resolution_environments
from .contract import source_tag
from .tests.http_replica_native import CLUSTER
from .tests.http_replica_native import NativeHTTPReplica
from .tests.http_replica_relay import IDENTITY
from .tests.http_replica_relay import MUTATIONS
from .tests.http_replica_relay import HTTPSSeedRelay
from .tests.http_replica_relay import assert_identity
from .tests.http_replica_relay import assert_native_overlap
from .tests.http_replica_relay import assert_receipt
from .tests.native import digest
from .tests.native import owned_process

TARGET = "/v1/collections/manifests/documents/counter"
SDK_ALLOWANCE_NS = 500_000_000


class BehavioralFailure(AssertionError):
    """Observed SDK/native behavior contradicted a fully instrumented case."""


def infrastructure(condition, marker):
    if not condition:
        raise RunnerError(marker)


def behavior(condition, marker):
    if not condition:
        raise BehavioralFailure(marker)


def _assert(assertion, *arguments):
    """Identity/receipt differences are behavioral only after evidence exists."""
    try:
        assertion(*arguments)
    except ConformanceError as error:
        raise BehavioralFailure(str(error)) from error


def _witnessed_relay_failure(relay, error):
    """Only the relay's exact identity/receipt assertions describe SDK behavior."""
    markers = {"RETRY_" + key.upper() for key in IDENTITY} | {
        "RECEIPT_" + key.upper() for key in ("status", "body", "etag", "revision")
    }
    original, source = relay.first_receipt, relay.first_source
    return (
        isinstance(error, ConformanceError)
        and str(error) in markers
        and original is not None
        and source is not None
        and type(original.get("completed_ns")) is int
        and original["completed_ns"] > 0
        and type(source.get("completed_ns")) is int
        and source["completed_ns"] > 0
        and 200 <= original["status"] < 300
        and source["revision"] == original["revision"]
    )


def _check_relay(relay):
    try:
        relay.check()
    except ConformanceError as error:
        if _witnessed_relay_failure(relay, error):
            raise BehavioralFailure(str(error)) from error
        raise


@contextlib.contextmanager
def _observed_relay(cluster):
    """Preserve classification when relay teardown rethrows its saved error.

    The existing relay context still owns shutdown. Cleanup/TLS/setup errors
    remain infrastructure, including when they precede a saved behavioral error.
    """
    relay = HTTPSSeedRelay(cluster)
    body_error = None
    try:
        with relay:
            try:
                yield relay
            except BaseException as error:
                body_error = error
                raise
    except ConformanceError as error:
        if _witnessed_relay_failure(relay, error):
            if (
                body_error is not None
                and not isinstance(body_error, BehavioralFailure)
                and not _witnessed_relay_failure(relay, body_error)
            ):
                raise body_error from error
            raise BehavioralFailure(str(error)) from error
        raise


def configuration(root, cluster, relay):
    """Create bounded private inputs; credentials never enter argv or evidence."""
    root.mkdir(mode=0o700)
    (root / "input").mkdir(mode=0o700)
    for name, data in contract.FIXTURES.items():
        (root / "input" / (name + ".bin")).write_bytes(data)
    (root / "input/increment.bin").write_bytes(b'{"$inc":{"n":1}}')
    (root / "input/changed.bin").write_bytes(
        contract.FIXTURES["value-a"] + contract.COLLISION_COMMENT
    )
    for name in ("ca.pem", "client.pem", "client.key"):
        (root / name).write_bytes(contract.read_file(cluster.certs, name, 16384))
    for name in ("read.token", "write.token"):
        (root / name).write_bytes(contract.read_file(cluster.root, name, 512))
    leader = cluster.leader() + 1
    config = {
        "schema": contract.CONFIG,
        "cluster_id": CLUSTER,
        "voters": 3,
        "seeds": sorted(relay.seeds, key=lambda seed: seed["node"] != leader),
        "tls": {"ca_file": "ca.pem", "cert_file": "client.pem", "key_file": "client.key"},
        "tokens": {"read_file": "read.token", "write_file": "write.token"},
        "timeout_ms": 15000,
        "attempt_timeout_ms": 3000,
    }
    contract.validate_config(config, root)
    (root / "config.json").write_bytes(contract.encode_line(config))
    for path in root.rglob("*"):
        if path.is_file():
            path.chmod(0o600)
    return config


class AdapterSession:
    """Persistent JSONL process, one pending command, independent outer watchdog.

    Disk-backed stdout/stderr and existing owned_process/workspace helpers retain
    the established process-group and cleanup guarantees. Pipe writes are also
    nonblocking, so a child that never reads cannot defeat the watchdog.
    """

    def __init__(self, prefix, driver, root, environment, check=lambda: None):
        self.prefix, self.root, self.environment = prefix, Path(root), environment
        self.session = contract.Session(driver, self.root)
        self.check = check
        self.stack = contextlib.ExitStack()
        self.offset, self.pending, self.history = 0, None, []

    def __enter__(self):
        try:
            self.output = self.root / "adapter.out"
            self.errors = self.root / "adapter.err"
            output = self.stack.enter_context(self.output.open("wb"))
            errors = self.stack.enter_context(self.errors.open("wb"))
            self.child = self.stack.enter_context(
                owned_process(
                    [
                        *self.prefix,
                        "--config",
                        str(self.root / "config.json"),
                        "--root",
                        str(self.root),
                    ],
                    stdin=subprocess.PIPE,
                    stdout=output,
                    stderr=errors,
                    cwd=Path(__file__).resolve().parents[2],
                    env=self.environment,
                )
            )
            self.stack.callback(self.child.stdin.close)
            os.set_blocking(self.child.stdin.fileno(), False)
            return self
        except BaseException:
            self.stack.close()
            raise

    def _health(self):
        self.check()
        infrastructure(self.errors.stat().st_size <= 16384, "ADAPTER_STDERR_BOUND")
        diagnostics = self.errors.read_bytes()
        infrastructure(
            not any(
                word in diagnostics for word in (b"Sanitizer", b"runtime error:", b"Traceback")
            ),
            "ADAPTER_INFRASTRUCTURE_FAILURE",
        )
        infrastructure(
            self.output.stat().st_size - self.offset <= contract.LIMITS["line_bytes"],
            "ADAPTER_STDOUT_BOUND",
        )

    def begin(self, action="call", **fields):
        infrastructure(self.pending is None, "ONE_OUTSTANDING_COMMAND")
        self._health()
        infrastructure(self.output.stat().st_size == self.offset, "UNSOLICITED_OBSERVATION")
        command = {
            "schema": contract.COMMAND,
            "seq": self.session.sequence + 1,
            "action": action,
            **fields,
        }
        self.session.command(command)
        (self.root / f"call-{command['seq']:06d}").mkdir(mode=0o700)
        self.pending = command
        self.unsent = contract.encode_line(command)
        self.deadline = time.monotonic() + contract.LIMITS["watchdog_ms"] / 1000
        self.pump()
        return command

    def pump(self):
        if self.pending is None:
            raise RunnerError("NO_PENDING_COMMAND")
        self._health()
        infrastructure(time.monotonic() < self.deadline, "ADAPTER_WATCHDOG")
        if self.unsent:
            try:
                count = os.write(self.child.stdin.fileno(), self.unsent)
                self.unsent = self.unsent[count:]
            except BlockingIOError:
                pass
            except BrokenPipeError as error:
                raise RunnerError("ADAPTER_PROCESS_FAILURE") from error
        infrastructure(
            self.child.poll() is None
            or self.pending["action"] == "close"
            and self.child.returncode == 0,
            "ADAPTER_PROCESS_FAILURE",
        )
        with self.output.open("rb") as stream:
            stream.seek(self.offset)
            raw = stream.read(contract.LIMITS["line_bytes"] + 1)
        return raw

    def finish(self):
        while True:
            raw = self.pump()
            if b"\n" in raw:
                infrastructure(not self.unsent, "OBSERVATION_BEFORE_COMMAND")
                observation = self.session.observe(contract.parse_line(raw))
                infrastructure(
                    observation["elapsed_ns"] <= 15_000_000_000 + SDK_ALLOWANCE_NS,
                    "SDK_LOGICAL_BUDGET",
                )
                files = {}
                for item, key in (
                    (observation["api"], "body_file"),
                    (observation["envelope"], "body_file"),
                ):
                    if item is not None and item[key] is not None:
                        files[item[key]] = contract.read_file(self.root, item[key])
                self.history.append(
                    {
                        "command": copy.deepcopy(self.pending),
                        "observation": observation,
                        "files": files,
                    }
                )
                self.offset += len(raw)
                self.pending = None
                return observation
            time.sleep(0.005)

    def call(self, **fields):
        self.begin(**fields)
        return self.finish()

    def recover(self, handle):
        self.begin("recover", handle=handle)
        return self.finish()

    def close(self):
        self.begin("close")
        self.finish()
        self.child.stdin.close()
        deadline = time.monotonic() + 5
        while self.child.poll() is None:
            self._health()
            infrastructure(time.monotonic() < deadline, "ADAPTER_SHUTDOWN_TIMEOUT")
            time.sleep(0.005)
        self._health()
        infrastructure(self.child.returncode == 0, "ADAPTER_SHUTDOWN_STATUS")
        infrastructure(self.output.stat().st_size == self.offset, "EXTRA_CLOSE_OUTPUT")

    def __exit__(self, kind, value, traceback):
        try:
            if kind is None and not self.session.closed:
                self.close()
        finally:
            self.stack.close()


def compare_api(driver, method, observation, root, original):
    behavior(observation["outcome"] == "success", "API_ORIGINAL_RECEIPT_SUCCESS")
    api = observation["api"]
    available = contract.exposure(driver, method, observation["action"])
    for key in ("receipt", "status", "body_file", "etag", "revision"):
        if key not in available:
            continue
        if key == "body_file":
            behavior(contract.read_file(root, api[key]) == original["body"], "API_ORIGINAL_BODY")
        elif key == "receipt":
            wanted = contract.json_bytes(original["body"], contract.LIMITS["source_bytes"])
            if driver == "go":
                wanted = {k: wanted[k] for k in ("status", "etag", "revision")}
            behavior(api[key] == wanted, "API_ORIGINAL_RECEIPT")
        elif key == "etag":
            quoted = driver == "rust" or driver == "csharp" and observation["action"] == "recover"
            wanted = original[key]
            if wanted is not None and not quoted:
                wanted = wanted[1:-1]
            behavior(api[key] == wanted, "API_ORIGINAL_ETAG")
        else:
            behavior(api[key] == original[key], "API_ORIGINAL_" + key.upper())


def validate_request(command, request, root):
    """PATCH encoding is SDK-owned: its first actual emitted bytes are baseline."""
    for key, wanted in {
        "method": command["method"],
        "target": f"/v1/collections/{command['collection']}/documents/{command['document']}",
        "if_match": command["if_match"],
        "if_none_match": command["if_none_match"],
    }.items():
        behavior(request[key] == wanted, "ORIGINAL_" + key.upper())
    behavior(contract.request_id(request["request_id"]), "ORIGINAL_REQUEST_ID")
    if command["request_id"] is not None:
        behavior(request["request_id"] == command["request_id"], "ORIGINAL_REQUEST_ID")
    if command["method"] == "PATCH":
        behavior(
            contract.is_patch(
                contract.json_bytes(request["body"], contract.LIMITS["source_bytes"])
            ),
            "ORIGINAL_PATCH",
        )
    else:
        expected = (
            b""
            if command["source_file"] is None
            else contract.read_file(root, command["source_file"])
        )
        behavior(request["body"] == expected, "ORIGINAL_BODY")


def verify_attempts(records, original, witness_ns, initial_count=1):
    infrastructure(type(witness_ns) is int and witness_ns > 0, "MISSING_ADVANCE_WITNESS")
    infrastructure(
        original is not None and original.get("request") is not None,
        "MISSING_ORIGINAL_RECEIPT",
    )
    mutations = [record for record in records if record["method"] in MUTATIONS]
    infrastructure(len(mutations) >= initial_count, "MISSING_NATIVE_ATTEMPTS")
    if initial_count == 2:
        assert_native_overlap(mutations[:2])
    for index, record in enumerate(mutations):
        _assert(assert_identity, original["request"], record)
        if index >= initial_count and record["sent_ns"] is not None:
            infrastructure(record["sent_ns"] > witness_ns, "RETRY_BEFORE_WITNESS")
        reply = record["response"]
        if reply is not None and 200 <= reply["status"] < 300:
            infrastructure(record["completed_ns"] is not None, "MISSING_NATIVE_COMPLETION")
            _assert(assert_receipt, original, reply)


def _committed(relay, sessions):
    while not relay.first_commit.is_set():
        _check_relay(relay)
        for session in sessions:
            raw = session.pump()
            infrastructure(
                b"\n" not in raw or relay.first_commit.is_set(), "MISSING_COMMIT_WITNESS"
            )
        time.sleep(0.005)
    _check_relay(relay)
    infrastructure(
        relay.first_receipt is not None and relay.first_source is not None, "MISSING_COMMIT_WITNESS"
    )


def _source(cluster, wanted, revision):
    response = cluster.request(cluster.leader(), "GET", TARGET)
    behavior(response["status"] == 200 and response["body"] == wanted, "CURRENT_SOURCE_C")
    behavior(response["etag"] == source_tag(wanted), "CURRENT_SOURCE_ETAG")
    behavior(response["revision"] == revision, "CURRENT_SOURCE_REVISION")
    return response


def _command(case, seed, number):
    return {
        "method": case["method"],
        "collection": "manifests",
        "document": "counter",
        "source_file": None if case["source"] is None else "input/" + case["source"] + ".bin",
        "request_id": None if case["request_id"] == "sdk" else f"{number * 16 + 2:032x}",
        "if_match": seed["source"]["etag"] if case["condition"] == "match-seed" else None,
        "if_none_match": "*" if case["condition"] == "create" else None,
    }


def _advance(cluster, case, number):
    identity = f"{number * 16 + 3:032x}"
    value = contract.fixture_bytes(case["advance"])
    witness = cluster.write_and_witness(
        cluster.leader(),
        "PUT",
        TARGET,
        value,
        {"X-Yamora-Request-Id": identity},
        source_after=value,
    )
    return identity, witness


def _collision(command, kind):
    changed = dict(command)
    if kind == "body-comment":
        changed["source_file"] = "input/changed.bin"
    elif kind == "target-counter-other":
        changed["document"] = "counter-other"
    elif kind == "method-delete-without-body":
        changed.update(method="DELETE", source_file=None)
    elif kind == "remove-if-match":
        changed["if_match"] = None
    elif kind == "remove-if-none-match":
        changed["if_none_match"] = None
    else:
        raise RunnerError("UNKNOWN_COLLISION")
    return changed


def _success(session, driver, command, original, handle=None):
    observation = session.recover(handle) if handle is not None else session.call(**command)
    compare_api(driver, command["method"], observation, session.root, original)
    return observation


def collision_case(cluster, prefix, driver, case, root, command, number, *, adapter_env=None):
    """Conflict requests must reach the native server through an unarmed relay."""
    with _observed_relay(cluster) as relay:
        configuration(root / "adapter", cluster, relay)
        with AdapterSession(
            prefix,
            driver,
            root / "adapter",
            cluster.env if adapter_env is None else adapter_env,
            lambda: _check_relay(relay),
        ) as session:
            first = session.call(**command)
            relay.check()
            initial = [r for r in relay.snapshot() if r["method"] in MUTATIONS]
            infrastructure(
                len(initial) == 1 and initial[0]["response"] is not None,
                "COLLISION_ORIGINAL_WITNESS",
            )
            original = dict(initial[0]["response"], request={k: initial[0][k] for k in IDENTITY})
            validate_request(command, original["request"], session.root)
            behavior(original["status"] == case["commit_status"], "ORIGINAL_NATIVE_STATUS")
            compare_api(driver, command["method"], first, session.root, original)
            # No retry was forwarded while this first source witness was absent.
            committed = cluster.request(cluster.leader(), "GET", TARGET)
            behavior(
                committed["status"] == 200
                and committed["body"] == contract.fixture_bytes(case["commit_source"])
                and committed["etag"] == source_tag(committed["body"]),
                "COMMITTED_SOURCE",
            )
            behavior(
                committed["etag"] == original["etag"]
                and committed["revision"] == original["revision"],
                "COMMITTED_SOURCE_IDENTITY",
            )
            _, advance = _advance(cluster, case, number)
            behavior(advance["source"]["revision"] != original["revision"], "ADVANCE_REVISION")
            witness_ns = advance["source"]["completed_ns"]
            changed = _collision(command, case["collision"])
            start = len(relay.snapshot())
            rejected = session.call(**changed)
            relay.check()
            behavior(
                rejected["outcome"] == "status" and rejected["api"]["status"] == 409,
                "COLLISION_API_409",
            )
            conflicts = [r for r in relay.snapshot()[start:] if r["method"] in MUTATIONS]
            infrastructure(bool(conflicts), "MISSING_COLLISION_WIRE")
            for record in conflicts:
                validate_request(changed, record, session.root)
                infrastructure(
                    record["sent_ns"] is not None and record["sent_ns"] > witness_ns,
                    "COLLISION_BEFORE_WITNESS",
                )
            behavior(
                any(
                    r["response"] is not None and r["response"]["status"] == 409 for r in conflicts
                ),
                "COLLISION_NATIVE_409",
            )
            _source(cluster, contract.FIXTURES["value-c"], advance["source"]["revision"])
            if changed["document"] != command["document"]:
                absent = cluster.request(
                    cluster.leader(), "GET", "/v1/collections/manifests/documents/counter-other"
                )
                behavior(absent["status"] == 404, "COLLISION_TARGET_UNCHANGED")
            start = len(relay.snapshot())
            _success(session, driver, command, original)
            replays = [r for r in relay.snapshot()[start:] if r["method"] in MUTATIONS]
            infrastructure(bool(replays), "MISSING_ORIGINAL_REPLAY")
            verify_attempts(replays, original, witness_ns, initial_count=0)
            behavior(
                any(
                    r["response"] is not None and 200 <= r["response"]["status"] < 300
                    for r in replays
                ),
                "ORIGINAL_REPLAY_NATIVE_SUCCESS",
            )
            _source(cluster, contract.FIXTURES["value-c"], advance["source"]["revision"])
        result = {
            "api": [session.history],
            "original_receipt": original,
            "seeds": relay.seeds,
        }
    # Include late completion evidence only after every relay worker has joined.
    verify_attempts(relay.snapshot()[start:], original, witness_ns, initial_count=0)
    _source(cluster, contract.FIXTURES["value-c"], advance["source"]["revision"])
    result["native_attempts"] = relay.snapshot()
    return result


def overlap_case(cluster, prefix, driver, case, root, command, number, *, adapter_env=None):
    """Deliver both original replies before C; replay the original receipt after C."""
    with _observed_relay(cluster) as relay, contextlib.ExitStack() as stack:
        relay.arm(
            case["method"],
            TARGET,
            contract.fixture_bytes(case["commit_source"]),
            overlap=2,
            lose_initial=False,
        )
        sessions = []
        for index in range(2):
            adapter_root = root / f"adapter-{index}"
            configuration(adapter_root, cluster, relay)
            sessions.append(
                stack.enter_context(
                    AdapterSession(
                        prefix,
                        driver,
                        adapter_root,
                        cluster.env if adapter_env is None else adapter_env,
                        lambda: _check_relay(relay),
                    )
                )
            )
        for session in sessions:
            session.begin(**command)
        _committed(relay, sessions)
        original = relay.first_receipt
        # The relay barrier and native timestamps prove overlap before delivery.
        # Invalid timing or missing sockets is an infrastructure experiment error.
        relay.assert_overlap()
        behavior(original["status"] == case["commit_status"], "ORIGINAL_NATIVE_STATUS")
        for session in sessions:
            validate_request(command, original["request"], session.root)
            observation = session.finish()
            compare_api(driver, command["method"], observation, session.root, original)
        initial = [record for record in relay.snapshot() if record["method"] in MUTATIONS]
        infrastructure(len(initial) == 2, "R15_UNEXPECTED_INITIAL_RETRY")
        _source(cluster, contract.fixture_bytes(case["commit_source"]), original["revision"])
        identity, advance = _advance(cluster, case, number)
        behavior(advance["source"]["revision"] != original["revision"], "ADVANCE_REVISION")
        advanced = relay.release_after_witness(contract.FIXTURES["value-c"], identity, deliver=True)
        start = len(relay.snapshot())
        _success(sessions[0], driver, command, original)
        replays = [record for record in relay.snapshot()[start:] if record["method"] in MUTATIONS]
        infrastructure(bool(replays), "MISSING_ORIGINAL_REPLAY")
        behavior(
            any(
                record["response"] is not None and 200 <= record["response"]["status"] < 300
                for record in replays
            ),
            "ORIGINAL_REPLAY_NATIVE_SUCCESS",
        )
        relay.assert_receipts()
        verify_attempts(relay.snapshot(), original, relay.witness_ns, initial_count=2)
        _source(cluster, contract.FIXTURES["value-c"], advanced["revision"])
        stack.close()
        result = {
            "api": [session.history for session in sessions],
            "original_receipt": original,
            "topology": {"kind": case["topology"]},
            "seeds": relay.seeds,
        }
    verify_attempts(relay.snapshot(), original, relay.witness_ns, initial_count=2)
    _source(cluster, contract.FIXTURES["value-c"], advanced["revision"])
    result["native_attempts"] = relay.snapshot()
    return result


def recovery_case(cluster, prefix, driver, case, root, command, number, *, adapter_env=None):
    if case["overlap"] == 2:
        return overlap_case(
            cluster, prefix, driver, case, root, command, number, adapter_env=adapter_env
        )
    with _observed_relay(cluster) as relay, contextlib.ExitStack() as stack:
        committed_source = (
            None if case["commit_source"] is None else contract.fixture_bytes(case["commit_source"])
        )
        relay.arm(case["method"], TARGET, committed_source, overlap=case["overlap"])
        sessions = []
        for index in range(case["overlap"]):
            adapter_root = root / f"adapter-{index}"
            configuration(adapter_root, cluster, relay)
            sessions.append(
                stack.enter_context(
                    AdapterSession(
                        prefix,
                        driver,
                        adapter_root,
                        cluster.env if adapter_env is None else adapter_env,
                        lambda: _check_relay(relay),
                    )
                )
            )
        for session in sessions:
            session.begin(**command)
        _committed(relay, sessions)
        original = relay.first_receipt
        for session in sessions:
            validate_request(command, original["request"], session.root)
        behavior(original["status"] == case["commit_status"], "ORIGINAL_NATIVE_STATUS")
        identity, advance = _advance(cluster, case, number)
        topology = {"kind": case["topology"]}
        if case["topology"] == "leader-crash":
            killed = cluster.kill_leader()
            elected = cluster.leader()
            infrastructure(elected != killed, "NEW_LEADER_WITNESS")
            topology.update(killed=killed, elected=elected)
        automatic = case["recovery"] == "automatic"
        advanced = relay.release_after_witness(
            contract.FIXTURES["value-c"], identity, deliver=automatic
        )
        observations = [session.finish() for session in sessions]
        for session, observation in zip(sessions, observations, strict=True):
            if automatic:
                compare_api(driver, command["method"], observation, session.root, original)
            else:
                behavior(observation["outcome"] == "uncertain", "PUBLIC_UNCERTAINTY_REQUIRED")
                behavior(
                    observation["sdk_request_id"] == original["request"]["request_id"],
                    "UNCERTAIN_NATIVE_REQUEST_ID",
                )
            if observation["envelope"] is not None:
                body_file = observation["envelope"]["body_file"]
                owned = b"" if body_file is None else contract.read_file(session.root, body_file)
                behavior(owned == original["request"]["body"], "ENVELOPE_FIRST_WIRE_BODY")
        if case["topology"] == "full-restart":
            paired = [(node["data"], node["journal"]) for node in cluster.nodes]
            processes = [node["process"].pid for node in cluster.nodes]
            topology["elected"] = cluster.restart_all()
            infrastructure(
                paired == [(node["data"], node["journal"]) for node in cluster.nodes],
                "PAIRED_ROOTS_CHANGED",
            )
            infrastructure(
                all(node["process"].pid not in processes for node in cluster.nodes),
                "FULL_RESTART_WITNESS",
            )
            topology["same_paired_roots"] = True
        relay.release_delivery()
        if case["topology"] == "quorum-loss-restore":
            holder = cluster.leader()
            for index in range(3):
                if index != holder:
                    cluster.stop(index)
            topology["isolated"] = holder
            start = len(relay.snapshot())
            failed = sessions[0].recover(observations[0]["recovery_handle"])
            behavior(failed["outcome"] != "success", "QUORUM_LOSS_RECOVERY_SUCCEEDED")
            traffic = relay.snapshot()[start:]
            infrastructure(bool(traffic), "QUORUM_RECOVERY_NOT_OBSERVED")
            dispatched = [r for r in traffic if r["method"] in MUTATIONS]
            behavior(
                not any(
                    r["response"] is not None and 200 <= r["response"]["status"] < 300
                    for r in dispatched
                ),
                "QUORUM_NATIVE_RECOVERY_SUCCEEDED",
            )
            topology["elected"] = cluster.restore_quorum()
        if not automatic:
            _success(sessions[0], driver, command, original, observations[0]["recovery_handle"])
        relay.assert_receipts()
        verify_attempts(relay.snapshot(), original, relay.witness_ns, case["overlap"])
        _source(cluster, contract.FIXTURES["value-c"], advanced["revision"])
        # Dispose SDKs before closing their relay or native fixture.
        stack.close()
        result = {
            "api": [session.history for session in sessions],
            "original_receipt": original,
            "topology": topology,
            "seeds": relay.seeds,
        }
    verify_attempts(relay.snapshot(), original, relay.witness_ns, case["overlap"])
    _source(cluster, contract.FIXTURES["value-c"], advanced["revision"])
    result["native_attempts"] = relay.snapshot()
    return result


def run_case(
    binary,
    expected_digest,
    environment,
    prefix,
    driver,
    case,
    root,
    number,
    *,
    adapter_overlay=None,
):
    root.mkdir(mode=0o700)
    native_root = root / "native"
    native_root.mkdir(mode=0o700)
    with NativeHTTPReplica(
        native_root, binary, expected_digest, environment=environment
    ) as cluster:
        seed = None
        if case["seed"] is not None:
            source = contract.fixture_bytes(case["seed"])
            seed = cluster.write_and_witness(
                cluster.leader(),
                "PUT",
                TARGET,
                source,
                {"X-Yamora-Request-Id": f"{number * 16 + 1:032x}", "If-None-Match": "*"},
                source_after=source,
            )
        else:
            absent = cluster.request(cluster.leader(), "GET", TARGET)
            infrastructure(absent["status"] == 404, "INITIAL_ABSENCE_WITNESS")
        command = _command(case, seed, number)
        implementation = collision_case if case["collision"] is not None else recovery_case
        if adapter_overlay:
            result = implementation(
                cluster,
                prefix,
                driver,
                case,
                root,
                command,
                number,
                adapter_env=adapter_environment(cluster.env, adapter_overlay),
            )
        else:
            result = implementation(cluster, prefix, driver, case, root, command, number)
        cluster.check_logs()
    # Shutdown and digest validation above must succeed before evidence is returned.
    return {"case": case["id"], **result, "source_witnesses": cluster.observations}


def select_adapters(selected, adapters):
    infrastructure(
        type(adapters) is dict and not set(adapters) - set(contract.DRIVERS), "ADAPTER_NAMES"
    )
    chosen = contract.DRIVERS if selected is None else tuple(selected)
    infrastructure(
        bool(chosen)
        and len(set(chosen)) == len(chosen)
        and not set(chosen) - set(contract.DRIVERS),
        "DRIVER_SELECTION",
    )
    configured = {
        "python": [sys.executable, "-P", "-m", f"{__package__}.python_http_replica_adapter"],
        **adapters,
    }
    infrastructure(not set(chosen) - set(configured), "MISSING_REQUIRED_ADAPTERS")
    for name in chosen:
        prefix = configured[name]
        infrastructure(
            type(prefix) is list
            and 1 <= len(prefix) <= 16
            and all(
                type(arg) is str and 0 < len(arg) <= 4096 and "\0" not in arg for arg in prefix
            ),
            "ADAPTER_ARGV",
        )
    return {name: configured[name] for name in chosen}


def execute(
    binary,
    scratch,
    *,
    selected=None,
    configured=None,
    environment=None,
    expected_digest=None,
    adapter_environments=None,
):
    binary = native_binary(str(binary))
    infrastructure(
        type(expected_digest) is str
        and len(expected_digest) == 64
        and all(c in "0123456789abcdef" for c in expected_digest),
        "EXPLICIT_DAEMON_SHA256_REQUIRED",
    )
    infrastructure(digest(binary) == expected_digest, "DAEMON_DIGEST")
    configured = select_adapters(selected, {} if configured is None else configured)
    resolutions = resolution_environments(configured, adapter_environments)
    manifest = contract.load_manifest()
    inherited = dict(os.environ if environment is None else environment)
    results = {}
    with immutable_daemon(binary):
        parent = scratch_parent(str(scratch))
        with workspace(parent) as root:
            env = private_environment(root, binary, inherited, jobs=1)
            env["TMPDIR"] = str(parent)
            env["PYTHONPATH"] = inherited.get(
                "PYTHONPATH", str(Path(__file__).resolve().parents[2])
            )
            for driver, prefix in configured.items():
                infrastructure(
                    shutil.which(
                        prefix[0],
                        path=adapter_environment(env, resolutions.get(driver)).get(
                            "PATH", os.defpath
                        ),
                    )
                    is not None,
                    "MISSING_ADAPTER_EXECUTABLE",
                )
            for driver, prefix in configured.items():
                driver_root = root / driver
                driver_root.mkdir(mode=0o700)
                results[driver] = [
                    run_case(
                        binary,
                        expected_digest,
                        env,
                        prefix,
                        driver,
                        case,
                        driver_root / case["id"],
                        index,
                        **(
                            {"adapter_overlay": resolutions[driver]}
                            if resolutions.get(driver)
                            else {}
                        ),
                    )
                    for index, case in enumerate(manifest["cases"], 1)
                ]
                infrastructure(
                    [result["case"] for result in results[driver]]
                    == list(contract.CASE_REQUIREMENTS),
                    "INCOMPLETE_DRIVER_CASES",
                )
        return {
            "schema": "yamora-conformance-result/2",
            "profile": contract.PROFILE,
            "daemon_sha256": expected_digest,
            "drivers": results,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--scratch-root", default=os.environ.get("TMPDIR"))
    parser.add_argument("--driver", action="append")
    parser.add_argument("--adapters-file")
    args = parser.parse_args()
    try:
        adapters = {}
        if args.adapters_file is not None:
            path = Path(args.adapters_file).absolute()
            adapters = contract.json_bytes(
                contract.read_file(path.parent, path.name, contract.LIMITS["line_bytes"])
            )
        result = execute(
            args.binary,
            args.scratch_root,
            selected=args.driver,
            configured=adapters,
            expected_digest=args.sha256,
        )
        print(
            json.dumps(
                {key: result[key] for key in ("schema", "profile", "daemon_sha256")}
                | {"passed": {driver: len(cases) for driver, cases in result["drivers"].items()}}
            )
        )
        return 0
    except BehavioralFailure as error:
        print(f"HTTP REPLICA BEHAVIORAL FAILURE: {error}", file=sys.stderr)
        return 1
    except (Exception, BaseExceptionGroup) as error:
        print(
            f"HTTP REPLICA INFRASTRUCTURE FAILURE: {type(error).__name__}: {error}", file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
