"""TCP binary server steps against independently verified Python stdlib clients.

BINARY_TLS_SANITIZER=address,undefined or thread instruments the harness and TLS.
Thread mode also requires BINARY_TLS_OPENSSL, a read-only, fully TSan-instrumented
OpenSSL prefix. No sanitizer suppression or recover mode is used.
"""

import concurrent.futures
import contextlib
import os
import queue
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tools.shared.scratch import storage_root
from yamora.tests import test_tls_revocation as revocation

TEST_MODULE = "yamora.tests.test_binary_tls"

READY, WANT_READ, WANT_WRITE, EOF, ERROR = range(5)


class BinaryTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the project's ephemeral PKI generator, including real revoked,
        # wrong-purpose and foreign identities, without inheriting its tests.
        cls.pki = type("BinaryPKI", (revocation.NativeTlsRevocationTests,), {})
        cls.addClassCleanup(cls.pki.doClassCleanups)
        cls.pki.setUpClass()
        cls.fixtures = cls.pki.fixtures
        cls.binary = cls.fixtures / "binary-tls-harness"
        repo = Path(__file__).resolve().parents[2]
        sanitizer = os.environ.get("BINARY_TLS_SANITIZER", "")
        compiler = "clang" if sanitizer else "cc"
        command = [
            compiler,
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-pthread",
            "-I",
            str(repo / "yamora/src"),
            "-I",
            str(repo / "yamora/src/transport"),
        ]
        if sanitizer:
            command += [
                f"-fsanitize={sanitizer}",
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
            ]
        prefix = os.environ.get("BINARY_TLS_OPENSSL")
        if sanitizer == "thread" and not prefix:
            raise RuntimeError("Thread qualification requires fully instrumented OpenSSL")
        if prefix:
            command += ["-I", str(Path(prefix) / "include")]
        command += [
            str(repo / "yamora/tests/binary_tls_harness.c"),
            os.environ.get("BINARY_TLS_SOURCE", str(repo / "yamora/src/transport/tls.c")),
        ]
        for name in (
            "malloc",
            "calloc",
            "SSL_new",
            "SSL_CTX_free",
            "SSL_set_fd",
            "SSL_read_ex",
            "SSL_write_ex",
            "SSL_get_error",
            "poll",
            "pthread_mutex_lock",
        ):
            command += [f"-Wl,--wrap={name}"]
        command += (
            [str(Path(prefix) / "libssl.a"), str(Path(prefix) / "libcrypto.a"), "-ldl"]
            if prefix
            else ["-lssl", "-lcrypto"]
        )
        command += shlex.split(os.environ.get("BINARY_TLS_EXTRA_FLAGS", ""))
        command += ["-o", str(cls.binary)]
        compiled = subprocess.run(command, capture_output=True, timeout=90)
        if compiled.returncode:
            raise RuntimeError(compiled.stderr.decode())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=storage_root())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cert, self.key, self.crl = [
            self.root / s for s in ("server.pem", "server.key", "active.crl")
        ]
        self.rotate("server")
        shutil.copyfile(self.fixtures / "clear.crl", self.crl)
        self.events = queue.Queue()
        self.saved = []

    def rotate(self, name):
        shutil.copyfile(self.fixtures / f"{name}.pem", self.cert)
        shutil.copyfile(self.fixtures / f"{name}.key", self.key)
        self.key.chmod(0o600)

    def arguments(self, mode="echo", *, mtls=False, crl=False, timeout=1500):
        return [
            str(self.binary),
            mode,
            str(self.cert),
            str(self.key),
            str(self.fixtures / "trusted.pem") if mtls else "-",
            str(self.crl) if crl else "-",
            str(timeout),
        ]

    def start(self, mode="echo", **options):
        process = subprocess.Popen(
            self.arguments(mode, **options),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.process = process

        def collect():
            for line in process.stdout:
                self.events.put(line.strip())
            self.events.put("EXIT")

        reader = threading.Thread(target=collect)
        reader.start()

        def cleanup():
            try:
                if process.poll() is None:
                    process.stdin.write("quit\n")
                    process.stdin.flush()
                process.wait(timeout=15)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=5)
            finally:
                reader.join(timeout=5)
                error = process.stderr.read()
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()
            self.assertEqual(process.returncode, 0, error)

        self.addCleanup(cleanup)
        event = self.event("PORT")
        self.port = int(event.split()[1])
        return process

    def event(self, prefix, timeout=10):
        for i, line in enumerate(self.saved):
            if line.startswith(prefix + " ") or line == prefix:
                return self.saved.pop(i)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            line = self.events.get(timeout=max(0.01, end - time.monotonic()))
            if line.startswith(prefix + " ") or line == prefix:
                return line
            if line == "EXIT":
                self.fail(f"Harness exited while waiting for {prefix}: {self.saved}")
            self.saved.append(line)
        self.fail(f"Missing harness event {prefix}")

    def command(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self.event({"reload": "RELOADED", "free": "FREED"}.get(command, command))

    def context(self, *, protocols=("yamora-binary/1",), identity=None, tls12=False, ca="trusted"):
        context = ssl.create_default_context(cafile=str(self.fixtures / f"{ca}.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_2 if tls12 else ssl.TLSVersion.TLSv1_3
        if tls12:
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        if protocols:
            context.set_alpn_protocols(list(protocols))
        if identity:
            context.load_cert_chain(
                self.fixtures / f"{identity}.pem", self.fixtures / f"{identity}.key"
            )
        return context

    @contextlib.contextmanager
    def connect(self, **options):
        with socket.create_connection(("127.0.0.1", self.port), timeout=4) as raw:
            with self.context(**options).wrap_socket(
                raw, server_hostname="server.test", suppress_ragged_eofs=False
            ) as connection:
                yield connection

    def receive(self, connection, size):
        result = bytearray()
        while len(result) < size:
            part = connection.recv(size - len(result))
            self.assertTrue(part)
            result.extend(part)
        return bytes(result)

    def echo(self, c, data=b"# exact YAML\r\nvalue: yes\r\n"):
        c.sendall(data)
        self.assertEqual(self.receive(c, len(data)), data)

    def done(self, number=0):
        return [int(s) for s in self.event(f"DONE {number}").split()[2:]]

    def test_begin_failures_ownership_sticky_validation_and_expired_handshake(self):
        result = subprocess.run(self.arguments("selftest"), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"SELFTEST OK\n")

    def test_invalid_identity_ca_and_crl_configuration_refuses_initial_context(self):
        for options, target in (
            ({}, self.key),
            ({"mtls": True}, self.fixtures / "trusted.pem"),
            ({"mtls": True, "crl": True}, self.crl),
        ):
            with self.subTest(target=target.name):
                # Do not mutate the shared PKI fixture: use a private CA path.
                arguments = self.arguments(**options)
                if target == self.fixtures / "trusted.pem":
                    target = self.root / "invalid-ca.pem"
                    arguments[4] = str(target)
                original = target.read_bytes() if target.exists() else None
                try:
                    target.write_text("invalid PEM")
                    result = subprocess.run(arguments, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, b"REJECTED\n")
                finally:
                    if original is not None:
                        target.write_bytes(original)
        result = subprocess.run(self.arguments(crl=True), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr)  # CRL without a CA.

    def test_invalid_io_arguments_and_expired_io_are_sticky_and_clear_outputs(self):
        self.start("validate")
        for i in range(8):
            with self.connect() as c:
                c.sendall(bytes([i]))
                self.assertEqual(self.done(i)[:2], [ERROR, 1])

    def test_http_legacy_no_alpn_compatibility(self):
        self.start("http")
        with self.connect(protocols=()) as c:
            self.assertIsNone(c.selected_alpn_protocol())
            self.echo(c)
        self.assertEqual(self.event("HANDSHAKE 0"), f"HANDSHAKE 0 {READY}")

    def test_tls13_exact_alpn_and_source_bytes(self):
        self.start()
        with self.connect(protocols=("http/1.1", "yamora-binary/1", "yamora-raft/1")) as c:
            self.assertEqual(c.version(), "TLSv1.3")
            self.assertEqual(c.selected_alpn_protocol(), "yamora-binary/1")
            self.echo(c)
        self.assertEqual(self.event("HANDSHAKE 0"), f"HANDSHAKE 0 {READY}")

    def test_missing_wrong_http_and_raft_alpn_rejected(self):
        self.start()
        for i, protocols in enumerate(
            ((), ("wrong",), ("http/1.1",), ("yamora-raft/1",), ("yamora-binary/10",))
        ):
            with self.subTest(protocols=protocols):
                with self.assertRaises((ssl.SSLError, OSError)):
                    with self.connect(protocols=protocols) as c:
                        self.echo(c)
                self.assertEqual(self.event(f"HANDSHAKE {i}"), f"HANDSHAKE {i} {ERROR}")

    def test_tls12_and_plaintext_rejected(self):
        self.start(timeout=250)
        with self.assertRaises((ssl.SSLError, OSError)):
            with self.connect(tls12=True):
                pass
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as c:
            c.sendall(b"GET / HTTP/1.1\r\n\r\n")
            with contextlib.suppress(ConnectionResetError):
                self.assertEqual(c.recv(1024), b"")
        for i in range(2):
            self.assertEqual(self.event(f"HANDSHAKE {i}"), f"HANDSHAKE {i} {ERROR}")

    def test_mtls_optional_ca_and_http_certificate_purpose(self):
        self.start(mtls=True)
        with self.connect(identity="client") as c:
            self.echo(c)
        for i, identity in enumerate(
            (None, "foreign-client", "expired-client", "wrong-purpose"), start=1
        ):
            with self.subTest(identity=identity):
                with self.assertRaises((ssl.SSLError, OSError)):
                    with self.connect(identity=identity) as c:
                        self.echo(c)
                self.assertEqual(self.event(f"HANDSHAKE {i}"), f"HANDSHAKE {i} {ERROR}")

    def test_server_identity_verified_by_python(self):
        self.start()
        with self.assertRaises(ssl.SSLCertVerificationError):
            with self.connect(ca="foreign"):
                pass

    def test_revoked_client_and_crl_reload_retains_old_session(self):
        self.start(mtls=True, crl=True)
        with self.connect(identity="revoked-client") as old:
            self.echo(old)
            shutil.copyfile(self.fixtures / "revoked.crl", self.crl)
            self.command("reload")
            self.echo(old)
            with self.assertRaises((ssl.SSLError, OSError)):
                with self.connect(identity="revoked-client") as c:
                    self.echo(c)
            with self.connect(identity="client") as c:
                self.echo(c)
            self.crl.write_text("invalid CRL")
            self.process.stdin.write("reload\n")
            self.process.stdin.flush()
            self.event("RETAINED")
            self.echo(old)

    def test_context_rotation_invalid_retention_and_profile_free(self):
        self.start()
        with self.connect() as old:
            self.echo(old)
            cert = old.getpeercert(binary_form=True)
            self.rotate("revoked-server")
            self.command("reload")
            with self.connect() as current:
                new_cert = current.getpeercert(binary_form=True)
                self.assertNotEqual(new_cert, cert)
                self.echo(current)
                self.key.write_text("broken key")
                self.process.stdin.write("reload\n")
                self.process.stdin.flush()
                self.event("RETAINED")
                with self.connect() as retained:
                    self.assertEqual(retained.getpeercert(binary_form=True), new_cert)
                    self.echo(retained)
                self.command("free")
                self.echo(current)
                self.echo(old)

    def test_stalled_handshake_and_read_expire_without_internal_wait(self):
        self.start(timeout=200)
        with socket.create_connection(("127.0.0.1", self.port), timeout=2):
            self.assertEqual(self.event("HANDSHAKE 0"), f"HANDSHAKE 0 {ERROR}")
            self.assertEqual(self.done()[1], 1)
        with self.connect() as c:
            self.assertEqual(self.event("HANDSHAKE 1"), f"HANDSHAKE 1 {READY}")
            self.assertEqual(self.done(1)[:2], [ERROR, 1])
            with contextlib.suppress(ssl.SSLError, OSError):
                c.recv(1)

    def test_second_request_gets_fresh_explicit_write_deadline(self):
        self.start(timeout=2000)
        with self.connect() as c:
            self.echo(c, b"first")
            time.sleep(0.4)  # Deliberately beyond the first 200 ms response deadline.
            self.echo(c, b"second after old deadline")

    def test_pending_ssl_read_bytes_do_not_require_socket_readability(self):
        self.start("pending")
        with self.connect() as c:
            self.echo(c, bytes(range(128)))

    def test_clean_close_notify_is_distinct_from_truncation(self):
        self.start()
        with self.connect() as c:
            self.echo(c)
            with contextlib.suppress(ssl.SSLEOFError):
                c.unwrap()
        self.assertEqual(self.done()[:2], [EOF, 0])
        with self.connect() as c:
            self.echo(c)
        self.assertEqual(self.done(1)[:2], [ERROR, 1])

    def test_actual_partial_writes_want_write_and_slow_reader_progress(self):
        self.start("write", timeout=8000)
        with self.connect() as c:
            time.sleep(0.15)
            received = self.receive(c, 4 * 1024 * 1024)
            self.assertEqual(received, (bytes(i % 251 for i in range(65536)) * 64))
        result, failed, total, _, want_write, partials = self.done()
        self.assertEqual((result, failed, total), (READY, 0, 4 * 1024 * 1024))
        self.assertGreater(want_write, 0)
        self.assertGreater(partials, 0)

    def test_stalled_slow_reader_write_expires_and_does_not_replay(self):
        self.start("write", timeout=250)
        with self.connect():
            result, failed, total, _, want_write, _ = self.done()
            self.assertEqual((result, failed), (ERROR, 1))
            self.assertLess(total, 4 * 1024 * 1024)
            self.assertGreater(want_write, 0)

    def test_forced_short_positive_writes_resume_only_remaining_bytes(self):
        self.start("short")
        with self.connect() as c:
            self.assertEqual(self.receive(c, 1000), bytes(i % 251 for i in range(1000)))
        self.assertEqual(self.done()[2], 1000)

    def test_opposite_direction_wants_and_exact_ssl_retry_bytes(self):
        self.start("opposite")
        with self.connect() as c:
            self.assertEqual(self.receive(c, 16), b"immutable retry\0")
        self.assertEqual(self.done()[:2], [READY, 0])

    def retry_rejected(self, mode):
        self.start(mode)
        with self.connect():
            self.assertEqual(self.done()[:2], [ERROR, 1])

    def test_pending_write_rejects_changed_pointer(self):
        self.retry_rejected("retry-pointer")

    def test_pending_write_rejects_changed_length(self):
        self.retry_rejected("retry-length")

    def test_pending_write_rejects_mutated_bytes(self):
        self.retry_rejected("retry-bytes")

    def test_pending_write_rejects_interleaved_read(self):
        self.retry_rejected("retry-read")

    def test_pending_write_allocation_failure_is_terminal(self):
        self.retry_rejected("alloc-write")

    def test_write_clean_shutdown_clears_pending_state(self):
        self.start("write-eof")
        with self.connect():
            self.assertEqual(self.done()[:2], [EOF, 0])

    def test_write_syscall_error_is_terminal(self):
        self.start("write-error")
        with self.connect():
            self.assertEqual(self.done()[:2], [ERROR, 1])

    def test_guard_mutants_reject_alpn_deadline_retry_and_fd_regressions(self):
        source = Path(__file__).resolve().parents[1] / "src/transport/tls.c"
        original = source.read_text()
        variants = (
            (
                "missing-alpn",
                'if (size != 15 || memcmp(protocol, "yamora-binary/1", 15))',
                'if (false && (size != 15 || memcmp(protocol, "yamora-binary/1", 15)))',
                "test_missing_wrong_http_and_raft_alpn_rejected",
            ),
            (
                "expired-deadline",
                "if (!deadline || current >= deadline)",
                "if (!deadline)",
                "test_begin_failures_ownership_sticky_validation_and_expired_handshake",
            ),
            (
                "retry-buffer",
                "if (buffer != state->pending_buffer || size != state->pending_size ||",
                "unsigned char *moved = malloc(size); assert(moved); "
                "memcpy(moved, state->pending_copy, size); free(state->pending_copy); "
                "state->pending_copy = moved;\n"
                "        if (buffer != state->pending_buffer || size != state->pending_size ||",
                "test_opposite_direction_wants_and_exact_ssl_retry_bytes",
            ),
            (
                "fd-ownership",
                "free(connection->binary_state);",
                "close(connection->fd); free(connection->binary_state);",
                "test_begin_failures_ownership_sticky_validation_and_expired_handshake",
            ),
            (
                "stale-deadline",
                "    size_t sent = 0;\n    ERR_clear_error();\n    errno = 0;",
                "    if (!connection->write_deadline) connection->write_deadline = deadline;\n"
                "    if (now() >= connection->write_deadline) return step_fail(connection, ETIMEDOUT);\n"
                "    size_t sent = 0;\n    ERR_clear_error();\n    errno = 0;",
                "test_second_request_gets_fresh_explicit_write_deadline",
            ),
        )
        for name, old, new, test in variants:
            with self.subTest(mutant=name):
                self.assertEqual(original.count(old), 1)
                mutant = self.root / f"{name}.c"
                mutant.write_text(
                    original.replace(
                        '#include "tls.h"', '#include "tls.h"\n#include <assert.h>'
                    ).replace(old, new)
                )
                environment = dict(os.environ, BINARY_TLS_SOURCE=str(mutant))
                completed = subprocess.run(
                    [sys.executable, "-m", "unittest", f"{TEST_MODULE}.BinaryTlsTests.{test}"],
                    env=environment,
                    capture_output=True,
                    timeout=45,
                )
                self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn(b"FAIL", completed.stderr)
                self.assertNotIn(
                    b"ERROR: setUpClass", completed.stderr
                )  # Must compile, then fail behavior.

    def test_concurrent_context_reload_and_serialized_connection_io(self):
        self.start(timeout=5000)
        barrier = threading.Barrier(5)

        def client():
            with self.connect(identity="client") as c:
                barrier.wait(timeout=5)
                for _ in range(30):
                    self.echo(c, b"concurrent reload source\r\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as threads:
            futures = [threads.submit(client) for _ in range(4)]
            barrier.wait(timeout=5)
            for _ in range(25):
                self.command("reload")
            for future in futures:
                future.result(timeout=10)
        # Additional connection churn while established I/O/reloads run. The
        # main-thread dispatch serializes these begins against publication;
        # the coordinated native test below proves begin/reload overlap.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as threads:

            def late_clients():
                for _ in range(8):
                    with self.connect() as c:
                        self.echo(c)

            future = threads.submit(late_clients)
            for _ in range(15):
                self.command("reload")
            future.result(timeout=10)

    def test_native_begin_reload_overlap_retains_acquired_context(self):
        self.start("overlap", timeout=5000)
        original = ssl.PEM_cert_to_DER_cert(self.cert.read_text())
        self.rotate("revoked-server")
        replacement = ssl.PEM_cert_to_DER_cert(self.cert.read_text())
        self.assertNotEqual(original, replacement)
        # The native acquisition pauses before SSL_new while holding the old
        # profile context's mutex. A separate reload thread must contend, then
        # replace/release that context before this begin finishes SSL_set_fd.
        with self.connect() as acquired:
            self.assertEqual(self.event("OVERLAP"), "OVERLAP 1 1 1 1 1")
            self.assertEqual(acquired.getpeercert(binary_form=True), original)
            self.echo(acquired)
            with self.connect() as current:
                self.assertEqual(current.getpeercert(binary_form=True), replacement)
                self.echo(current)
                self.command("free")
                self.echo(acquired, b"acquired reference survives replacement/free")
                self.echo(current, b"replacement reference survives profile free")

    def test_native_overlap_guard_rejects_serialized_begin_reload(self):
        environment = dict(os.environ)
        environment["BINARY_TLS_EXTRA_FLAGS"] = (
            environment.get("BINARY_TLS_EXTRA_FLAGS", "") + " -DYD_TEST_SERIALIZE_OVERLAP"
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                f"{TEST_MODULE}.BinaryTlsTests.test_native_begin_reload_overlap_retains_acquired_context",
            ],
            env=environment,
            capture_output=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn(
            b"OVERLAP FAILED: reload did not contend while begin held context lock",
            completed.stderr,
        )
        self.assertIn(b"Ran 1 test", completed.stderr)
        self.assertNotIn(b"ERROR: setUpClass", completed.stderr)


if __name__ == "__main__":
    unittest.main()
