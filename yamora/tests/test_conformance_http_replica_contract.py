"""Reject weakened scenarios and dishonest v2 observations without a daemon."""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from yamora.conformance import contract as v1
from yamora.conformance import http_replica_contract as c

ID = "11" * 16
REV = "0123456789abcdef"
TAG = "edf51ae5732201b0"


def call(seq=1, method="PUT", **changes):
    value = {
        "schema": c.COMMAND,
        "seq": seq,
        "action": "call",
        "method": method,
        "collection": "manifests",
        "document": "counter",
        "source_file": "input/value-a.bin",
        "request_id": ID,
        "if_match": None,
        "if_none_match": None,
    }
    if method in ("GET", "DELETE"):
        value["source_file"] = None
    if method == "GET":
        value["request_id"] = None
    return value | changes


def recover(seq=2, handle="h1"):
    return {"schema": c.COMMAND, "seq": seq, "action": "recover", "handle": handle}


def receipt(**changes):
    return {
        "status": "stored",
        "collection": "manifests",
        "document": "counter",
        "etag": TAG,
        "revision": REV,
    } | changes


def config():
    return {
        "schema": c.CONFIG,
        "cluster_id": "01" * 16,
        "voters": 3,
        "seeds": [{"host": "127.0.0.1", "port": 19000 + i, "node": i} for i in (1, 2, 3)],
        "tls": {"ca_file": "ca.pem", "cert_file": "client.pem", "key_file": "client.key"},
        "tokens": {"read_file": "read.token", "write_file": "write.token"},
        "timeout_ms": 15000,
        "attempt_timeout_ms": 3000,
    }


def uncertain(driver="python", seq=1, **changes):
    value = c.empty_observation(seq)
    value.update(
        outcome="uncertain",
        error_kind="transport",
        sdk_request_id=ID,
        recovery_handle="h1",
        recovery_mode=c.recovery_mode(driver),
    )
    if driver in c.ENVELOPE_DRIVERS:
        value["envelope"] = {
            "method": "PUT",
            "path": "/v1/collections/manifests/documents/counter",
            "if_match": None,
            "if_none_match": None,
            "request_id": ID,
            "body_file": f"call-{seq:06d}/envelope.bin",
        }
    return value | changes


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "input").mkdir()
        (self.root / "input/value-a.bin").write_bytes(b"# receipt\r\nn: 0 # keep\r\n")
        for seq in range(1, 5):
            (self.root / f"call-{seq:06d}").mkdir()

    def reject(self, marker, function, *args, **kwargs):
        with self.assertRaisesRegex(c.ContractError, "^" + marker + "$"):
            function(*args, **kwargs)

    def test_frozen_profile_has_fifteen_required_scenarios_and_v1_still_has_twenty_two(self):
        manifest = c.load_manifest()
        self.assertEqual(manifest["profile"], "http-replica-receipt")
        self.assertEqual(
            [row["id"] for row in manifest["cases"]], [f"R{i:02d}" for i in range(1, 16)]
        )
        self.assertEqual(manifest["cases"][11]["topology"], "leader-crash")
        self.assertEqual(manifest["cases"][12]["topology"], "full-restart")
        self.assertEqual(manifest["cases"][13]["topology"], "quorum-loss-restore")
        self.assertEqual(manifest["cases"][14]["overlap"], 2)
        self.assertEqual(v1.load_manifest()["profile"], "binary-document-standalone")
        self.assertEqual(len(v1.load_manifest()["cases"]), 22)

    def test_harmless_get_cannot_replace_required_case(self):
        value = c.load_manifest()
        value["cases"][12]["method"] = "GET"
        self.reject("FROZEN_CASE_SEMANTICS", c.validate_manifest, value)

    def test_each_case_rejects_weakening_each_bound_dimension(self):
        value = c.load_manifest()
        for i, row in enumerate(value["cases"]):
            for field in (
                "method",
                "seed",
                "source",
                "condition",
                "request_id",
                "commit_source",
                "commit_status",
                "fault",
                "advance",
                "topology",
                "recovery",
                "collision",
                "overlap",
            ):
                changed = copy.deepcopy(value)
                changed["cases"][i][field] = "weakened"
                with self.subTest(case=row["id"], field=field):
                    self.reject("FROZEN_CASE_SEMANTICS", c.validate_manifest, changed)

    def test_manifest_rejects_missing_duplicate_reordered_unknown_cases_and_extra_keys(self):
        value = c.load_manifest()
        variants = [
            value["cases"][:-1],
            value["cases"][:-1] + [value["cases"][0]],
            list(reversed(value["cases"])),
        ]
        for cases in variants:
            self.reject("FROZEN_CASE_SET", c.validate_manifest, value | {"cases": cases})
        for change, marker in (
            ({"schema": v1.SCHEMA}, "MANIFEST_VERSION"),
            ({"extra": 0}, "MANIFEST_KEYS"),
            ({"evidence": {}}, "FROZEN_EVIDENCE"),
        ):
            self.reject(marker, c.validate_manifest, value | change)
        for field, content in value["limits"].items():
            self.reject(
                "FROZEN_LIMITS",
                c.validate_manifest,
                value | {"limits": value["limits"] | {field: content + 1}},
            )
        for field in value["evidence"]:
            self.reject(
                "FROZEN_EVIDENCE",
                c.validate_manifest,
                value | {"evidence": value["evidence"] | {field: False}},
            )
        self.assertEqual(
            c.validate_manifest(value | {"limits": dict(reversed(list(value["limits"].items())))}),
            value,
        )

    def test_fixture_rewrite_rejects_even_matching_metadata(self):
        root = self.root / "profile"
        shutil.copytree(c.ROOT, root)
        changed = b"# receipt\nn: 0 # keep\n"
        (root / "fixtures/value-a.yaml").write_bytes(changed)
        value = c.load_manifest()
        value["fixtures"]["value-a"] = {"length": len(changed), "etag": c.source_tag(changed)}
        self.reject("FROZEN_FIXTURE_BYTES", c.validate_manifest, value, root)

    def test_fixture_bytes_cannot_be_normalized(self):
        root = self.root / "profile"
        shutil.copytree(c.ROOT, root)
        (root / "fixtures/value-a.yaml").write_bytes(b"# receipt\nn: 0 # keep\n")
        self.reject("FROZEN_FIXTURE_BYTES", c.fixture_bytes, "value-a", root)

    def test_literal_fixture_identity_and_independent_hashes(self):
        for name, n, tag in (
            ("value-a", 0, '"edf51ae5732201b0"'),
            ("value-b", 1, '"0846faf69c1bf449"'),
            ("value-c", 9, '"ad087d13ee536641"'),
        ):
            data = c.fixture_bytes(name)
            self.assertEqual(data, f"# receipt\r\nn: {n} # keep\r\n".encode())
            self.assertEqual(len(data), 24)
            self.assertEqual(c.source_tag(data), tag)
        self.reject("FIXTURE_NAME", c.fixture_bytes, "../value-a")

    def test_jsonl_is_bounded_strict_and_has_no_surrogate_escape(self):
        self.assertEqual(c.parse_line(c.encode_line(call())), call())
        for raw in (
            b'{"a":1,"a":2}\n',
            b'{"n":NaN}\n',
            b'{"n":1.0}\n',
            b'{"a":"\\ud800"}\n',
            b'{"\\ud800":1}\n',
            b"\xff\n",
            b"[]\n[]\n",
            b"{}\r\n",
            b"{}",
            b" " * 16384 + b"\n",
            b"[" * 14 + b"0" + b"]" * 14 + b"\n",
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(c.ContractError):
                c.parse_line(raw)
        self.assertEqual(c.parse_line(b'"' + b"a" * 16381 + b'"\n'), "a" * 16381)

    def test_config_binds_private_endpoints_id_files_and_budgets(self):
        value = config()
        self.assertIs(c.validate_config(value), value)
        for change, marker in (
            ({"cluster_id": "0" * 32}, "CONFIG_IDENTITY"),
            ({"voters": True}, "CONFIG_VOTERS"),
            ({"timeout_ms": 15001}, "CONFIG_BUDGET"),
            ({"tls": value["tls"] | {"key_file": "../../secret"}}, "CONFIG_TLS_FILES"),
            ({"extra": 0}, "CONFIG_KEYS"),
        ):
            self.reject(marker, c.validate_config, value | change)
        for field, bad, marker in (
            ("host", "localhost", "CONFIG_SEED_HOST"),
            ("host", "https://127.0.0.1", "CONFIG_SEED_HOST"),
            ("port", 8000, "CONFIG_SEED_PORT"),
            ("port", True, "CONFIG_SEED_PORT"),
            ("node", True, "CONFIG_SEED_NODE"),
            ("port", 19002, "CONFIG_SEED_PORT"),
            ("node", 2, "CONFIG_SEED_NODE"),
        ):
            changed = copy.deepcopy(value)
            changed["seeds"][0][field] = bad
            self.reject(marker, c.validate_config, changed)
        for name in ("ca.pem", "client.pem", "client.key", "read.token", "write.token"):
            (self.root / name).write_bytes(b"synthetic")
        (self.root / "config.json").write_bytes(c.encode_line(value))
        self.assertEqual(c.load_config(self.root / "config.json", self.root), value)
        self.reject("CONFIG_PATH", c.load_config, self.root / "other.json", self.root)

    def test_command_source_cannot_escape_fixed_slot(self):
        self.reject("COMMAND_SOURCE", c.validate_command, call(source_file="../secret"))

    def test_commands_reject_wrong_identity_ids_conditions_and_opaque_metadata(self):
        c.validate_command(call(), self.root)
        for change, marker in (
            ({"collection": "../secret"}, "COMMAND_IDENTITY"),
            ({"document": "Counter"}, "COMMAND_IDENTITY"),
            ({"collection": "yamldb-system"}, "COMMAND_RESERVED"),
            ({"request_id": "0" * 32}, "COMMAND_REQUEST_ID"),
            ({"request_id": "A" * 32}, "COMMAND_REQUEST_ID"),
            ({"if_match": TAG}, "COMMAND_IF_MATCH"),
            ({"if_match": ""}, "COMMAND_IF_MATCH"),
            ({"if_none_match": ""}, "COMMAND_IF_NONE_MATCH"),
            ({"if_match": '"' + TAG + '"', "if_none_match": "*"}, "COMMAND_CONDITIONS"),
            ({"operation_file": "opaque.json"}, "COMMAND_KEYS"),
            ({"seq": True}, "COMMAND_SEQUENCE"),
        ):
            self.reject(marker, c.validate_command, call(**change))
        self.reject("COMMAND_READ_OPTIONS", c.validate_command, call(method="GET", request_id=ID))
        self.reject(
            "COMMAND_IF_NONE_MATCH", c.validate_command, call(method="PATCH", if_none_match="*")
        )
        self.reject(
            "COMMAND_SOURCE",
            c.validate_command,
            call(method="DELETE", source_file="input/value-a.bin"),
        )
        self.reject("RECOVERY_HANDLE", c.validate_command, recover(handle="../h1"))

    def test_source_files_are_regular_nofollow_bounded_and_patch_is_exact_typed_value(self):
        file = self.root / "input/value-a.bin"
        for data, marker in (
            (b"", "COMMAND_EMPTY_SOURCE"),
            (b"\xff", "COMMAND_UTF8"),
            (b"x" * 131073, "FILE_BOUND_TYPE"),
        ):
            file.write_bytes(data)
            self.reject(marker, c.validate_command, call(), self.root)
        for data in (
            b'{"$inc":{"n":true}}',
            b'{"$inc":{"n":2}}',
            b'{"$inc":{"n":1,"n":1}}',
            b'{"$inc":{"n":1},"extra":1}',
        ):
            file.write_bytes(data)
            with self.assertRaises(c.ContractError):
                c.validate_command(call(method="PATCH"), self.root)
        file.write_bytes(b'{ "$inc": { "n": 1 } }')
        c.validate_command(call(method="PATCH"), self.root)
        file.unlink()
        file.symlink_to(self.root / "outside")
        (self.root / "outside").write_bytes(b"source")
        self.reject("FILE_PATH", c.validate_command, call(), self.root)
        file.unlink()
        (self.root / "input").rmdir()
        (self.root / "input").symlink_to(self.root)
        self.reject("FILE_PATH", c.read_file, self.root, "input/outside")

    def test_go_receipt_cannot_contradict_exposed_revision(self):
        value = c.empty_observation(1)
        value["api"].update(
            etag=TAG,
            revision=REV,
            receipt={"status": "stored", "etag": TAG, "revision": "0000000000000000"},
        )
        self.reject("API_RECEIPT_CONTRADICTION", c.validate_observation, value, "go", call())

    def test_all_nine_success_exposures_are_actual_public_fields(self):
        for driver in c.DRIVERS:
            for method in ("GET", "PUT", "PATCH", "DELETE"):
                with self.subTest(driver=driver, method=method):
                    command = call(method=method)
                    fields = c.exposure(driver, method)
                    value = c.empty_observation(1)
                    data = receipt()
                    for field in fields:
                        value["api"][field] = {
                            "status": 200 if method != "DELETE" else 204,
                            "body_file": "call-000001/body.bin",
                            "etag": '"' + TAG + '"'
                            if driver == "rust" and method != "GET"
                            else TAG,
                            "revision": REV,
                            "receipt": (
                                {key: data[key] for key in ("status", "etag", "revision")}
                                if driver == "go"
                                else data
                            ),
                        }[field]
                    body = (
                        b"# receipt\r\nn: 0 # keep\r\n"
                        if method == "GET"
                        else b""
                        if method == "DELETE"
                        else json.dumps(data).encode()
                    )
                    (self.root / "call-000001/body.bin").write_bytes(body)
                    c.validate_observation(value, driver, command, self.root)
        self.assertEqual(c.exposure("python", "GET"), {"body_file"})
        self.assertEqual(c.exposure("go", "DELETE"), set())
        self.assertNotIn("status", c.exposure("node", "PUT"))
        self.assertEqual(c.exposure("csharp", "PUT"), {"etag", "revision"})

    def test_impossible_fields_and_contradictory_raw_receipts_fail(self):
        value = c.empty_observation(1)
        value["api"].update(status=201, etag=TAG, revision=REV, receipt=receipt())
        self.reject("FABRICATED_API_FIELD", c.validate_observation, value, "node", call())
        value["api"].update(status=200, body_file="call-000001/body.bin", receipt=None)
        (self.root / "call-000001/body.bin").write_bytes(
            json.dumps(receipt(revision="0" * 16)).encode()
        )
        self.reject(
            "API_RAW_RECEIPT_CONTRADICTION", c.validate_observation, value, "cpp", call(), self.root
        )
        value = c.empty_observation(1)
        value["api"].update(
            status=200, body_file="call-000001/body.bin", etag='"' + TAG + '"', revision=REV
        )
        self.reject(
            "API_SUCCESS_STATUS",
            c.validate_observation,
            value,
            "rust",
            call(if_none_match="*"),
            self.root,
        )

    def test_status_error_and_close_require_consistent_outcomes(self):
        value = c.empty_observation(1)
        value.update(outcome="status", error_kind="status")
        value["api"]["status"] = 409
        c.validate_observation(value, "python", call())
        self.reject(
            "API_ERROR_STATUS",
            c.validate_observation,
            value | {"api": value["api"] | {"status": 200}},
            "python",
            call(),
        )
        self.reject(
            "OBSERVATION_ERROR_KIND",
            c.validate_observation,
            value | {"error_kind": "deadline"},
            "python",
            call(),
        )
        close = {"schema": c.COMMAND, "seq": 1, "action": "close"}
        closed = c.empty_observation(1, "close") | {"outcome": "closed"}
        c.validate_observation(closed, "go", close)
        self.reject(
            "CLOSE_OBSERVATION", c.validate_observation, closed | {"elapsed_ns": 1}, "go", close
        )
        for change in (
            {"seq": 2},
            {"outcome": []},
            {"elapsed_ns": 25000000000},
            {"error_kind": []},
        ):
            with self.assertRaises(c.ContractError):
                c.validate_observation(value | change, "python", call())

    def test_java_protocol_error_preserves_its_public_received_http_status(self):
        value = c.empty_observation(1)
        value.update(outcome="protocol", error_kind="protocol")
        value["api"]["status"] = 200
        try:
            c.validate_observation(value, "java", call(method="GET"))
        except c.ContractError as error:
            self.fail(f"JAVA_PUBLIC_PROTOCOL_STATUS: {error}")
        for driver in c.DRIVERS:
            if driver != "java":
                self.reject(
                    "API_ERROR_STATUS",
                    c.validate_observation,
                    value,
                    driver,
                    call(method="GET"),
                )
        for kind in ("transport", "deadline", "cancelled"):
            self.reject(
                "API_ERROR_STATUS",
                c.validate_observation,
                value | {"outcome": kind, "error_kind": kind},
                "java",
                call(method="GET"),
            )

    def test_uncertainty_ids_modes_envelopes_are_not_reconstructed(self):
        for driver in c.DRIVERS:
            with self.subTest(driver=driver):
                value = uncertain(driver)
                (self.root / "call-000001/envelope.bin").write_bytes(c.FIXTURES["value-a"])
                c.validate_observation(value, driver, call(), self.root)
                self.reject(
                    "UNCERTAIN_ORIGINAL_ID",
                    c.validate_observation,
                    value | {"sdk_request_id": "22" * 16},
                    driver,
                    call(),
                    self.root,
                )
                self.reject(
                    "RECOVERY_MODE",
                    c.validate_observation,
                    value | {"recovery_mode": "invented"},
                    driver,
                    call(),
                    self.root,
                )
                changed = copy.deepcopy(value)
                changed["envelope"] = (
                    None if driver in c.ENVELOPE_DRIVERS else uncertain("rust")["envelope"]
                )
                self.reject(
                    "SDK_ENVELOPE_EXPOSURE",
                    c.validate_observation,
                    changed,
                    driver,
                    call(),
                    self.root,
                )

    def test_real_envelope_fields_files_and_original_snapshot_are_bound(self):
        value = uncertain("rust")
        (self.root / "call-000001/envelope.bin").write_bytes(c.FIXTURES["value-a"])
        for field, wrong, marker in (
            ("path", "/v1/collections/manifests/documents/other", "ENVELOPE_IDENTITY"),
            ("method", "GET", "ENVELOPE_IDENTITY"),
            ("if_match", '"' + TAG + '"', "ENVELOPE_CONDITIONS"),
            ("body_file", "../envelope.bin", "OUTPUT_PATH"),
        ):
            changed = copy.deepcopy(value)
            changed["envelope"][field] = wrong
            self.reject(marker, c.validate_observation, changed, "rust", call(), self.root)
        session = c.Session("rust", self.root)
        session.command(call())
        (self.root / "input/value-a.bin").write_bytes(c.FIXTURES["value-c"])
        session.observe(value)
        self.assertEqual(session.handles["h1"][1], c.FIXTURES["value-a"])

    def test_session_sequences_unknown_handles_and_generated_id_recovery(self):
        session = c.Session("python")
        self.reject("SESSION_SEQUENCE", session.command, call(seq=2))
        self.reject("UNKNOWN_RECOVERY_HANDLE", session.command, recover(seq=1))
        session.command(call(request_id=None))
        self.reject("SESSION_STATE", session.command, call())
        session.observe(uncertain())
        session.command(recover())
        wrong = uncertain(seq=2, action="recover", sdk_request_id="22" * 16)
        self.reject("UNCERTAIN_ORIGINAL_ID", session.observe, wrong)
        value = c.empty_observation(2, "recover")
        value.update(recovery_handle="h1", recovery_mode="caller-reissue")
        value["api"].update(etag=TAG, revision=REV, receipt=receipt())
        session.observe(value)
        session.command({"schema": c.COMMAND, "seq": 3, "action": "close"})
        session.observe(c.empty_observation(3, "close") | {"outcome": "closed"})
        self.reject("SESSION_STATE", session.command, call(seq=4))

    def test_csharp_recovery_exposes_raw_receipt_but_ordinary_mutation_does_not(self):
        command = recover()
        value = c.empty_observation(2, "recover")
        value.update(recovery_mode="sdk-envelope", recovery_handle="h1")
        value["api"].update(
            status=201, body_file="call-000002/body.bin", etag='"' + TAG + '"', revision=REV
        )
        (self.root / "call-000002/body.bin").write_bytes(json.dumps(receipt()).encode())
        c.validate_observation(value, "csharp", command, self.root, original=call())
        self.reject(
            "FABRICATED_API_FIELD",
            c.validate_observation,
            value | {"seq": 1, "action": "call", "recovery_mode": None, "recovery_handle": None},
            "csharp",
            call(),
        )
        deletion = call(method="DELETE")
        uncertain_delete = uncertain("csharp")
        uncertain_delete["envelope"].update(method="DELETE", body_file=None)
        c.validate_observation(uncertain_delete, "csharp", deletion, self.root)

    def test_handles_are_ordered_bounded_and_retained_after_success(self):
        session = c.Session("python")
        for seq in range(1, 17):
            session.command(call(seq=seq))
            value = uncertain(seq=seq, recovery_handle=f"h{seq}")
            if seq == 1:
                self.reject("HANDLE_ALLOCATION", session.observe, value | {"recovery_handle": "h2"})
            session.observe(value)
        session.command(recover(seq=17))
        value = c.empty_observation(17, "recover")
        value.update(recovery_handle="h1", recovery_mode="caller-reissue")
        value["api"].update(etag=TAG, revision=REV, receipt=receipt())
        session.observe(value)
        self.assertEqual(len(session.handles), 16)
        session.command(call(seq=18))
        self.reject("HANDLE_BOUND", session.observe, uncertain(seq=18, recovery_handle="h16"))
        for bad in ("h0", "h17", "h01", "../h1"):
            self.reject("RECOVERY_HANDLE", c.validate_command, recover(handle=bad))

    def test_command_ceiling_includes_close_and_output_files_are_bounded(self):
        session = c.Session("python")
        for seq in range(1, 64):
            session.command(call(seq=seq, method="GET"))
            value = c.empty_observation(seq)
            value["api"]["body_file"] = f"call-{seq:06d}/body.bin"
            session.observe(value)
        close = {"schema": c.COMMAND, "seq": 64, "action": "close"}
        session.command(close)
        session.observe(c.empty_observation(64, "close") | {"outcome": "closed"})
        self.reject("COMMAND_SEQUENCE", c.validate_command, call(seq=65))
        value = c.empty_observation(1)
        value["api"].update(body_file="call-000001/body.bin", etag=TAG, revision=REV)
        path = self.root / "call-000001/body.bin"
        path.write_bytes(b"x" * (c.LIMITS["source_bytes"] + 1))
        self.reject(
            "FILE_BOUND_TYPE", c.validate_observation, value, "go", call(method="GET"), self.root
        )
        path.write_bytes(c.FIXTURES["value-c"])
        self.reject(
            "API_SOURCE_ETAG_CONTRADICTION",
            c.validate_observation,
            value,
            "go",
            call(method="GET"),
            self.root,
        )


class BehavioralMutants(unittest.TestCase):
    def test_targeted_validator_mutants_have_named_red_then_restored_green(self):
        targets = (
            ("FROZEN_CASE_SEMANTICS", "test_harmless_get_cannot_replace_required_case"),
            ("FROZEN_FIXTURE_BYTES", "test_fixture_bytes_cannot_be_normalized"),
            ("COMMAND_SOURCE", "test_command_source_cannot_escape_fixed_slot"),
            ("API_RECEIPT_CONTRADICTION", "test_go_receipt_cannot_contradict_exposed_revision"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "yamora"
            (package / "tests").mkdir(parents=True)
            (package / "conformance").mkdir()
            for path in (
                package / "__init__.py",
                package / "tests/__init__.py",
                package / "conformance/__init__.py",
            ):
                path.write_text("")
            module = package / "conformance/http_replica_contract.py"
            source = Path(c.__file__).read_text()
            shutil.copyfile(Path(v1.__file__), package / "conformance/contract.py")
            shutil.copyfile(
                Path(__file__), package / "tests/test_conformance_http_replica_contract.py"
            )
            shutil.copytree(c.ROOT, package / "conformance/v2/http-replica-receipt")
            shutil.copytree(Path(v1.__file__).parent / "v1", package / "conformance/v1")
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root))

            def run(test):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-P",
                        "-m",
                        "unittest",
                        "yamora.tests.test_conformance_http_replica_contract.ContractTests." + test,
                    ],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    timeout=20,
                )
                output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
                # An incomplete process, import error, setup error or timeout is
                # never accepted as a validator mutation's behavioral red.
                self.assertIn("Ran 1 test", output)
                self.assertNotIn("ERROR:", output)
                self.assertNotIn("Sanitizer", output)
                return result.returncode, output

            for marker, test in targets:
                with self.subTest(marker=marker):
                    module.write_text(source)
                    self.assertEqual(run(test)[0], 0)
                    broken = source.replace(
                        "if not condition:", f'if not condition and marker != "{marker}":', 1
                    )
                    self.assertNotEqual(broken, source)
                    module.write_text(broken)
                    status, output = run(test)
                    self.assertEqual(status, 1, output)
                    self.assertIn("FAILED (failures=1)", output)
                    self.assertIn("ContractError not raised", output)
                    module.write_text(source)
                    self.assertEqual(run(test)[0], 0)


if __name__ == "__main__":
    unittest.main()
