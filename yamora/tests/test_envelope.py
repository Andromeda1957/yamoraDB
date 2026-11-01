"""Native envelope/key-provider behavioral checks using private synthetic data.

Default builds use fatal ASan/UBSan. ENVELOPE_SANITIZER=none selects normal C.
No real credentials, cloud services or owner storage are used.
"""

import hashlib
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from yamora.tests.envelope_provider_fixture import certificate
from yamora.tests.envelope_provider_fixture import service


class EnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = os.environ.get("TMPDIR")
        if not scratch or not Path(scratch).is_dir():
            raise RuntimeError("an existing owned disk-backed TMPDIR is required")
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.yamora = Path(__file__).resolve().parents[1]
        cls.binary = cls.build("envelope-harness")
        cls.ca, cls.key = certificate(cls.root)
        cls.wrong_ca, _ = certificate(cls.root, "untrusted")

    @classmethod
    def build(cls, name, envelope=None, provider=None):
        binary = cls.root / name
        command = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-pthread",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
        ]
        sanitizer = os.environ.get("ENVELOPE_SANITIZER", "address,undefined")
        if sanitizer != "none":
            command.append("-fsanitize=" + sanitizer)
        command += [
            "-I" + str(cls.yamora / "src"),
            "-I" + str(cls.yamora / "src/security"),
            str(cls.yamora / "tests/envelope_harness.c"),
            str(envelope or cls.yamora / "src/security/envelope.c"),
            str(provider or cls.yamora / "src/security/key_provider.c"),
            str(cls.yamora / "src/security/oidc_json.c"),
        ]
        for wrapped in (
            "RAND_bytes",
            "RAND_priv_bytes",
            "EVP_CIPHER_CTX_new",
            "EVP_EncryptInit_ex",
            "EVP_DecryptFinal_ex",
            "OPENSSL_cleanse",
            "free",
        ):
            command.append("-Wl,--wrap=" + wrapped)
        flags = subprocess.run(
            ["pkg-config", "--cflags", "--libs", "openssl"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout
        command += shlex.split(flags) + ["-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if compiled.returncode:
            raise RuntimeError("native envelope compilation failed:\n" + compiled.stderr)
        return binary

    def invoke(self, *arguments, binary=None, expected=0):
        result = subprocess.run(
            [str(binary or self.binary), *map(str, arguments)],
            env=dict(
                os.environ,
                # Deliberate guard mutants exit at REQUIRE before cleanup;
                # baseline and provider checks always retain leak detection.
                ASAN_OPTIONS=f"detect_leaks={int(expected == 0)}:halt_on_error=1",
                UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
            ),
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn("Sanitizer", result.stderr)
        self.assertNotIn("runtime error:", result.stderr)
        return result

    def test_exact_yaml_key_loss_rotation_backup_recovery(self):
        self.invoke("lifecycle")

    def test_metadata_identity_generation_tamper_truncation_and_crypto_failures(self):
        self.invoke("guards")

    def test_bounded_configuration_parsing_and_cleared_failure_outputs(self):
        self.invoke("bounds")

    def test_persisted_backup_restores_with_original_key_in_new_process(self):
        original = self.root / "original-envelope"
        backup = self.root / "backup-envelope"
        self.invoke("archive", "write", original)
        shutil.copyfile(original, backup)
        self.assertNotIn(b"# authored comment", backup.read_bytes())
        self.assertNotIn(b"exact bytes", backup.read_bytes())
        self.invoke("archive", "missing", backup)
        self.invoke("archive", "wrong", backup)
        self.invoke("archive", "restore", backup)
        wire = backup.read_bytes()
        key_length = int.from_bytes(wire[36:38], "big")
        wrapped_length = int.from_bytes(wire[38:40], "big")
        metadata = bytearray(wire[:128])
        metadata[38:40] = b"\0\0"
        key_id = wire[128 : 128 + key_length]
        context = hashlib.sha256(metadata + key_id).digest()
        start = 128 + key_length
        wrapped = wire[start : start + wrapped_length]
        dek = AESGCM(bytes([0xC7]) * 32).decrypt(wrapped[:12], wrapped[12:], context)
        start += wrapped_length
        plaintext = AESGCM(dek).decrypt(wire[88:100], wire[start:], wire[:start])
        self.assertEqual(
            plaintext,
            "# authored comment\nname: 'café'\nnumber: 01\nbody: |\n  exact bytes\n".encode(),
        )

    def test_real_tls_kms_and_vault_protocol_calls(self):
        for kind in ("aws", "vault"):
            with self.subTest(kind=kind), service(self.ca, self.key, kind) as fixture:
                port, calls, problems = fixture
                self.invoke("provider", kind, port, self.ca, "okay")
                self.assertGreaterEqual(sum(op == "encrypt" for op, _ in calls), 2)
                self.assertGreaterEqual(sum(op == "decrypt" for op, _ in calls), 4)
                self.assertGreaterEqual(len({digest for _, digest in calls}), 3)
                self.assertEqual(problems, [])

    def test_provider_permission_availability_redirect_and_parser_errors(self):
        shared = (
            "denied",
            "unavailable",
            "redirect",
            "oversize",
            "malformed",
            "duplicate",
            "missing",
            "base64",
            "errors",
        )
        for kind in ("aws", "vault"):
            specific = ("key-id", "algorithm") if kind == "aws" else ("version", "cipher-version")
            for failure in shared + specific:
                with (
                    self.subTest(kind=kind, failure=failure),
                    service(self.ca, self.key, kind, failure) as fixture,
                ):
                    port, calls, problems = fixture
                    self.invoke("provider", kind, port, self.ca, "deny")
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(problems, [])

    def test_vault_write_version_rotation_preserves_historical_decrypt(self):
        with service(self.ca, self.key, "vault") as fixture:
            port, calls, problems = fixture
            self.invoke("provider", "vault", port, self.ca, "history")
            self.assertGreaterEqual(sum(op == "encrypt" for op, _ in calls), 2)
            self.assertEqual(problems, [])

    def test_unwrap_failures_and_wrong_plaintext_keys_never_escape(self):
        for kind in ("aws", "vault"):
            for failure in (
                "decrypt-denied",
                "decrypt-malformed",
                "decrypt-wrong-key",
                "decrypt-short-key",
                "decrypt-base64",
                "decrypt-missing",
            ):
                with (
                    self.subTest(kind=kind, failure=failure),
                    service(self.ca, self.key, kind, failure) as fixture,
                ):
                    port, calls, problems = fixture
                    self.invoke("provider", kind, port, self.ca, "unwrap-deny")
                    self.assertEqual([op for op, _ in calls], ["encrypt", "decrypt"])
                    self.assertEqual(problems, [])

    def test_untrusted_tls_peer_is_terminal(self):
        for kind in ("aws", "vault"):
            with self.subTest(kind=kind), service(self.ca, self.key, kind) as fixture:
                port, calls, problems = fixture
                self.invoke("provider", kind, port, self.wrong_ca, "deny")
                self.assertEqual(calls, [])
                self.assertEqual(problems, [])

    def test_cancellation_boundary_and_pending_network_callback_cancellation(self):
        self.invoke("cancel-contract")
        for kind in ("aws", "vault"):
            with self.subTest(kind=kind), service(self.ca, self.key, kind) as fixture:
                port, calls, problems = fixture
                self.invoke("provider-cancel", kind, port, self.ca)
                self.assertGreaterEqual(len(calls), 4)
                self.assertEqual(problems, [])

    def test_cancellation_guard_mutation_fails_and_restored_contract_passes(self):
        marker = "return false; /* caller must own the cancellation boundary */"
        paths = {}
        for name in ("envelope", "key_provider"):
            source = (self.yamora / f"src/security/{name}.c").read_text()
            self.assertEqual(source.count(marker), 1)
            path = self.root / f"cancellation-mutant-{name}.c"
            path.write_text(source.replace(marker, "return true;"))
            paths[name] = path
        binary = self.build(
            "cancellation-mutant", envelope=paths["envelope"], provider=paths["key_provider"]
        )
        result = self.invoke("cancel-contract", binary=binary, expected=1)
        self.assertIn("contract failure", result.stderr)
        self.invoke("cancel-contract")

    def test_guard_mutations_fail_then_restored_native_passes(self):
        source = (self.yamora / "src/security/envelope.c").read_text()
        changes = (
            ("get(wire + 24, 8) != expected->generation", "false"),
            ("memcmp(wire + 56, expected->object_id, 32)", "false"),
            (
                "if (EVP_DecryptFinal_ex(ctx, plaintext + plain_len, &final) != 1)",
                "if (false)",
            ),
            ("OPENSSL_cleanse(bytes, length ? length : 1);", "(void)length;"),
        )
        for index, (before, after) in enumerate(changes):
            with self.subTest(guard=index):
                self.assertEqual(source.count(before), 1)
                path = self.root / ("mutant-" + str(index) + ".c")
                path.write_text(source.replace(before, after))
                binary = self.build("mutant-" + str(index), envelope=path)
                result = self.invoke("guards", binary=binary, expected=1)
                self.assertIn("contract failure", result.stderr)
        self.invoke("guards")

    def test_provider_binding_mutations_fail_then_restored_services_pass(self):
        source = (self.yamora / "src/security/key_provider.c").read_text()
        guards = (
            ("aws", "key-id", '!equals(yd_oidc_json_get(root, "KeyId"), id)'),
            (
                "vault",
                "version",
                '!version_number(yd_oidc_json_get(data, "key_version"), provider->version)',
            ),
        )
        for kind, failure, guard in guards:
            with self.subTest(kind=kind):
                self.assertEqual(source.count(guard), 1)
                path = self.root / ("provider-mutant-" + kind + ".c")
                path.write_text(source.replace(guard, f"({guard} && false)"))
                binary = self.build("provider-mutant-" + kind, provider=path)
                with service(self.ca, self.key, kind, failure) as fixture:
                    port, _, problems = fixture
                    result = self.invoke(
                        "provider", kind, port, self.ca, "deny", binary=binary, expected=1
                    )
                    self.assertIn("contract failure", result.stderr)
                    self.assertEqual(problems, [])
                with service(self.ca, self.key, kind, failure) as fixture:
                    port, _, problems = fixture
                    self.invoke("provider", kind, port, self.ca, "deny")
                    self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
