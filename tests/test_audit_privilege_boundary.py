"""Real distinct-UID DAC and native helper/daemon qualification.

The fixed launcher supplies isolated UID0 setup with only SETUID/SETGID. Every
helper, daemon and signalling/cleanup worker drops to its actual unprivileged
UID before exercising native storage, IPC and TLS requests.
"""

import errno
import hashlib
import http.client
import json
import os
import re
import select
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

WORKER = Path(__file__).with_name("audit_privilege_worker.py")
NATIVE_GATE_CODE = """    const char *gate = getenv("YAMORA_TEST_JOB_GATE");
    if (gate) {
        FILE *entered = fopen(gate, "w");
        if (!entered || fclose(entered)) abort();
        for (unsigned attempt = 0; attempt < 2000; attempt++) {
            FILE *held = fopen(gate, "r");
            if (!held) break;
            fclose(held);
            struct timespec interval = {.tv_nsec = 10000000};
            nanosleep(&interval, NULL);
        }
    }
"""


def drop_identity(uid):
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)


@unittest.skipUnless(
    os.environ.get("ANDROMEDA_AUDIT_FIXTURE") == "1",
    "requires the fixed managed audit UID launcher; qualification is opt-in",
)
class AuditPrivilegeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.getresuid(), (0, 0, 0), "TRUSTED_LAUNCHER_UID_REQUIRED")
        fields = dict(
            line.split(":", 1)
            for line in Path("/proc/self/status").read_text().splitlines()
            if ":" in line
        )
        self.assertEqual(int(fields["CapEff"].strip(), 16), (1 << 6) | (1 << 7))
        self.assertEqual(fields["NoNewPrivs"].strip(), "1")
        Path(os.environ["TMPDIR"]).chmod(0o755)
        self.allocation = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"], prefix="dac-")
        self.root = Path(self.allocation.name)
        self.root.chmod(0o1777)
        self.private = self.root / "helper"
        self.address = "yamora-audit-" + uuid.uuid4().hex
        self.children = []
        self.servers = []
        self.addCleanup(self.cleanup)

    def spawn(self, uid, *arguments, server=False):
        process = subprocess.Popen(
            ["/usr/bin/python3", str(WORKER), *arguments],
            preexec_fn=lambda: drop_identity(uid),
            stdin=subprocess.PIPE if server else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        process.fixture_uid = uid
        self.children.append(process)
        return process

    def run_role(self, uid, *arguments):
        process = self.spawn(uid, *arguments)
        out, error = process.communicate(timeout=8)
        self.assertEqual(process.returncode, 0, error)
        self.assertLessEqual(len(out), 16384)
        value = json.loads(out)
        if "identity" in value:
            self.assert_identity(value["identity"], uid)
        return value

    def assert_identity(self, value, uid):
        self.assertEqual(value["uid"], [uid] * 3)
        self.assertEqual(value["gid"], [uid] * 3)
        self.assertEqual(value["caps"], dict.fromkeys(("CapEff", "CapPrm", "CapInh", "CapAmb"), 0))
        self.assertEqual(value["no_new_privs"], 1)

    def start_helper(self, control="none"):
        process = self.spawn(1001, "helper", str(self.private), self.address, control, server=True)
        self.servers.append(process)
        self.assertTrue(select.select([process.stdout], [], [], 8)[0], "HELPER_READY_DEADLINE")
        line = process.stdout.readline(16385)
        if not line:
            _out, error = process.communicate(timeout=8)
            self.fail("HELPER_FAILED_BEFORE_READY: " + error)
        evidence = json.loads(line)
        self.assert_identity(evidence["ready"], 1001)
        return process, evidence

    def stop_helper(self, process):
        if process.stdin:
            process.stdin.close()
            process.stdin = None
        _out, error = process.communicate(timeout=8)
        self.assertEqual(process.returncode, 0, error)

    def reset_fixture(self):
        for process in self.servers:
            if process.poll() is None:
                self.stop_helper(process)
        for path in (self.private, self.root / "displaced-helper"):
            self.run_role(1001, "cleanup", str(path))

    def cleanup(self):
        try:
            self.reset_fixture()
        finally:
            self.allocation.cleanup()
        self.assertTrue(
            all(process.poll() is not None for process in self.children),
            "FIXTURE_LEFT_CHILD_PROCESS",
        )
        self.assertFalse(self.root.exists(), "FIXTURE_LEFT_PRIVATE_FILES")

    def check_boundary(self, control="none"):
        helper, evidence = self.start_helper(control)
        self.assertEqual(evidence["sequence"], 0)
        writer = self.run_role(1000, "exchange", self.address, "APPEND")
        self.assertEqual(writer["reply"], "ACK:1", "AUTHORIZED_EXCHANGE_REQUIRED")
        self.assertNotEqual(writer["identity"]["pid"], evidence["ready"]["pid"])
        attacks = self.run_role(1000, "attacks", str(self.private))["attempts"]
        labels = {
            "key_read": "DAEMON_READ_KEY_MUST_BE_DENIED",
            "anchor_replace": "ANCHOR_REPLACE_MUST_BE_DENIED",
        }
        self.assertEqual(len(attacks), 11)
        first = ("key_read", "anchor_write", "anchor_replace")
        for name in (*first, *(name for name in attacks if name not in first)):
            result = attacks[name]
            self.assertIn(
                result,
                (errno.EACCES, errno.EPERM),
                labels.get(name, name.upper() + "_MUST_BE_DENIED"),
            )
        denied = self.run_role(1002, "exchange", self.address, "APPEND")
        self.assertEqual(denied["reply"], "DENIED", "UNAUTHORIZED_UID_MUST_BE_DENIED")
        for malformed in ("INVALID", "X" * 128):
            refused = self.run_role(1000, "exchange", self.address, malformed)
            self.assertEqual(refused["reply"], "REFUSED")
        current = self.run_role(1000, "exchange", self.address, "READ")
        self.assertEqual(current["reply"], "ACK:1", "DENIAL_CHANGED_ANCHOR")
        self.run_role(1001, "crash", str(helper.pid))
        _out, error = helper.communicate(timeout=8)
        self.assertEqual(helper.returncode, -9, error)
        restarted, evidence = self.start_helper()
        self.assertEqual(evidence["sequence"], 1, "DURABLE_ANCHOR_LOST_ON_RESTART")
        self.assertEqual(self.run_role(1000, "exchange", self.address, "APPEND")["reply"], "ACK:2")
        self.stop_helper(restarted)

    def test_real_dac_exchange_restart_and_cleanup(self):
        self.check_boundary()

    def test_readable_key_control_is_detected(self):
        with self.assertRaisesRegex(AssertionError, "DAEMON_READ_KEY_MUST_BE_DENIED"):
            self.check_boundary("readable-key")
        self.reset_fixture()
        self.check_boundary()

    def test_replaceable_anchor_control_is_detected(self):
        with self.assertRaisesRegex(AssertionError, "ANCHOR_REPLACE_MUST_BE_DENIED"):
            self.check_boundary("replaceable-anchor")
        self.reset_fixture()
        self.check_boundary()

    def test_peer_uid_bypass_control_is_detected(self):
        with self.assertRaisesRegex(AssertionError, "UNAUTHORIZED_UID_MUST_BE_DENIED"):
            self.check_boundary("peer-uid-bypass")
        self.reset_fixture()
        self.check_boundary()


@unittest.skipUnless(
    os.environ.get("ANDROMEDA_AUDIT_FIXTURE") == "1",
    "requires the fixed managed audit UID launcher; qualification is opt-in",
)
class NativeAuditPrivilegeBoundaryTests(unittest.TestCase):
    """Same real DAC fixture, replacing the synthetic sink with native storage."""

    sanitize = True

    spawn = AuditPrivilegeBoundaryTests.spawn
    run_role = AuditPrivilegeBoundaryTests.run_role
    assert_identity = AuditPrivilegeBoundaryTests.assert_identity
    cleanup = AuditPrivilegeBoundaryTests.cleanup
    reset_fixture = AuditPrivilegeBoundaryTests.reset_fixture
    stop_helper = AuditPrivilegeBoundaryTests.stop_helper

    @classmethod
    def setUpClass(cls):
        from yamora.tests.audit_native_support import build_client
        from yamora.tests.audit_native_support import build_helper

        cls.build_allocation = tempfile.TemporaryDirectory(
            dir=os.environ["TMPDIR"], prefix="native-"
        )
        cls.addClassCleanup(cls.build_allocation.cleanup)
        cls.build = Path(cls.build_allocation.name)
        cls.build.chmod(0o755)
        cls.helper_binary = build_helper(cls.build, sanitize=cls.sanitize)
        cls.client_binary = build_client(cls.build, sanitize=cls.sanitize)

    def setUp(self):
        AuditPrivilegeBoundaryTests.setUp(self)
        self.run_role(1001, "prepare-native", str(self.private))
        self.native_helpers = []
        self.addCleanup(self.native_cleanup)

    def native_cleanup(self):
        for process in self.native_helpers:
            if process.poll() is None:
                self.run_role(process.fixture_uid, "terminate-native", str(process.pid))
            out, error = process.communicate(timeout=8)
            self.assertEqual(error, "", out + error)
        for process in tuple(self.children):
            if process.poll() is None:
                try:
                    process.communicate(input="\n" if process.stdin else None, timeout=8)
                except subprocess.TimeoutExpired:
                    self.run_role(process.fixture_uid, "terminate-native", str(process.pid))
                    process.communicate(timeout=8)
        self.run_role(1001, "cleanup", str(self.root / "public"))

    def native_helper(self, mode="create", binary=None):
        socket_path = self.root / "public/audit.sock"
        process = self.spawn(
            1001,
            "native-exec",
            str(binary or self.helper_binary),
            "--key-file",
            str(self.private / "key"),
            "--key-id",
            "11" * 16,
            "--audit-dir",
            str(self.private / "log"),
            "--anchor-dir",
            str(self.private / "anchors"),
            "--socket",
            str(socket_path),
            "--daemon-uid",
            "1000",
            "--mode",
            mode,
            "--segment-records",
            str(getattr(self, "segment_records", 64)),
            "--segments",
            "3",
            "--max-bytes",
            "196608",
            "--pending",
            "8",
        )
        self.native_helpers.append(process)
        self.assertTrue(select.select([process.stdout], [], [], 8)[0])
        self.assert_identity(json.loads(process.stdout.readline())["identity"], 1001)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                out, error = process.communicate()
                self.fail(f"NATIVE_HELPER_START:{process.returncode}:{out}:{error}")
            if socket_path.exists():
                # resume may replace the old socket after a crash; a successful
                # native client HELLO supplies the actual readiness proof.
                probe = self.native_client("finish")
                if probe == "FINISH:1\n":
                    return process
            time.sleep(0.02)
        self.fail("NATIVE_HELPER_READY_DEADLINE")

    def native_client(self, mode="finish", uid=1000):
        process = self.spawn(
            uid,
            "native-exec",
            str(self.client_binary),
            str(self.root / "public/audit.sock"),
            "1001",
            mode,
        )
        out, error = process.communicate(timeout=8)
        self.assertEqual(process.returncode, 0, out + error)
        self.assertEqual(error, "")
        evidence, result = out.split("\n", 1)
        self.assert_identity(json.loads(evidence)["identity"], uid)
        return result

    def sequence(self):
        return self.run_role(1001, "native-sequence", str(self.private))["sequence"]

    def native_dac(self):
        attempts = self.run_role(1000, "native-attacks", str(self.private))["attempts"]
        self.assertEqual(len(attempts), 11)
        for name, result in attempts.items():
            self.assertIn(
                result, (errno.EACCES, errno.EPERM), f"NATIVE_{name.upper()}_MUST_BE_DENIED"
            )

    def test_native_helper_exchange_dac_unknown_and_restart(self):
        helper = self.native_helper()
        self.assertEqual(self.sequence(), 3)
        self.native_dac()
        self.assertEqual(
            self.native_client(uid=1002), "DENIED\n", "NATIVE_UNAUTHORIZED_UID_MUST_BE_DENIED"
        )
        self.assertEqual(self.native_client(), "FINISH:1\n")
        before = self.sequence()
        self.assertEqual(self.native_client("abandon"), "INTENT\n")
        deadline = time.monotonic() + 3
        while self.sequence() != before + 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.sequence(), before + 2, "NATIVE_DISCONNECT_UNKNOWN_NOT_ANCHORED")
        self.run_role(1001, "terminate-native", str(helper.pid))
        out, error = helper.communicate(timeout=8)
        self.assertEqual((helper.returncode, out, error), (0, "", ""))
        restarted = self.native_helper("resume")
        self.assertEqual(self.sequence(), before + 4)
        self.native_dac()
        self.run_role(1001, "terminate-native", str(restarted.pid))

    def test_native_crash_reconciles_anchored_intent_and_old_session_cannot_finish(self):
        helper = self.native_helper()
        client = self.spawn(
            1000,
            "native-exec",
            str(self.client_binary),
            str(self.root / "public/audit.sock"),
            "1001",
            "hold",
            server=True,
        )
        self.assertTrue(select.select([client.stdout], [], [], 8)[0])
        self.assert_identity(json.loads(client.stdout.readline())["identity"], 1000)
        self.assertEqual(client.stdout.readline(), "INTENT\n")
        before = self.sequence()
        self.run_role(1001, "crash", str(helper.pid))
        out, error = helper.communicate(timeout=8)
        self.assertEqual((helper.returncode, out, error), (-9, "", ""))
        restarted = self.native_helper("resume")
        self.assertEqual(self.sequence(), before + 3, "NATIVE_PENDING_RESTART_MUST_APPEND_UNKNOWN")
        out, error = client.communicate(input="\n", timeout=8)
        self.assertEqual((client.returncode, out, error), (0, "FINISH:-3\n", ""))
        self.assertEqual(self.native_client(), "FINISH:1\n")
        self.run_role(1001, "terminate-native", str(restarted.pid))

    def test_native_malformed_handles_capacity_idle_and_lost_replies(self):
        helper = self.native_helper()
        before = self.sequence()
        for mode in ("malformed", "truncated", "oversized", "handles", "lost-begin", "lost-finish"):
            with self.subTest(mode=mode):
                self.assertEqual(
                    self.run_role(1000, "native-ipc", str(self.root / "public/audit.sock"), mode)[
                        "verified"
                    ],
                    mode,
                )
        deadline = time.monotonic() + 3
        while self.sequence() != before + 6 and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.sequence(), before + 6)
        self.assertEqual(self.native_client("capacity"), "CAPACITY_OK\n")
        for mode in ("constructor", "fork"):
            with self.subTest(mode=mode):
                self.assertEqual(self.native_client(mode), "FINISH:1\n")
        self.assertEqual(
            self.native_client("idle"), "FINISH:1\n", "AUTHENTICATED_IDLE_SESSION_MUST_SURVIVE"
        )
        self.run_role(1001, "terminate-native", str(helper.pid))

    def test_native_anchor_namespace_failure_blocks_ack_and_new_dispatch(self):
        helper = self.native_helper()
        before = self.sequence()
        self.run_role(1001, "native-contaminate", str(self.private))
        self.assertEqual(self.native_client(), "BEGIN:-3\n", "UNANCHORED_INTENT_MUST_NOT_ACK")
        self.assertEqual(self.native_client(), "DENIED\n", "POISONED_HELPER_MUST_NOT_ADMIT")
        self.assertEqual(self.sequence(), before)
        self.run_role(1001, "terminate-native", str(helper.pid))

    def lock_case(self, binary, expected):
        path = str(self.root / "public/audit.sock")
        helper = self.spawn(1001, "silent-helper", path, server=True)
        self.native_helpers.append(helper)
        self.assertTrue(select.select([helper.stdout], [], [], 8)[0])
        self.assert_identity(json.loads(helper.stdout.readline())["identity"], 1001)
        client = self.spawn(1000, "native-exec", str(binary), path, "1001", "lock", server=True)
        self.assertTrue(select.select([client.stdout], [], [], 8)[0])
        self.assert_identity(json.loads(client.stdout.readline())["identity"], 1000)
        self.assertTrue(select.select([helper.stdout], [], [], 8)[0])
        self.assertEqual(json.loads(helper.stdout.readline()), {"waiting": True})
        out, error = client.communicate(input="\n", timeout=8)
        if expected:
            self.assertEqual((client.returncode, out, error), (0, "LOCK_OK\n", ""))
        else:
            self.assertEqual(
                (client.returncode, out, error), (2, "", "ASSERTION:AUDIT_MUTEX_DEADLINE\n")
            )
        out, error = helper.communicate(timeout=8)
        self.assertEqual((helper.returncode, out, error), (0, "", ""))

    def test_client_mutex_obeys_original_deadline_red_then_green(self):
        from yamora.tests.audit_native_support import SECURITY
        from yamora.tests.audit_native_support import build_client

        self.lock_case(self.client_binary, True)
        source = (SECURITY / "audit_client.c").read_text()
        before = "pthread_mutex_clocklock(&c->mutex, CLOCK_MONOTONIC, &end)"
        self.assertEqual(source.count(before), 1)
        mutant = self.build / "client-mutant.c"
        mutant.write_text(source.replace(before, "((void)end, pthread_mutex_lock(&c->mutex))"))
        directory = self.build / "mutant"
        directory.mkdir(mode=0o755)
        binary = build_client(directory, client_source=mutant)
        self.lock_case(binary, False)
        self.lock_case(self.client_binary, True)

    def test_native_peer_guard_mutant_then_restored_boundary(self):
        from yamora.tests.audit_native_support import SECURITY
        from yamora.tests.audit_native_support import build_helper

        helper = self.native_helper()
        self.assertEqual(self.native_client(uid=1002), "DENIED\n")
        self.run_role(1001, "terminate-native", str(helper.pid))

        helper.communicate(timeout=8)
        source = (SECURITY / "audit_helper.c").read_text()
        before = "peer.uid == o->daemon_uid"
        self.assertEqual(source.count(before), 1)
        mutant = self.build / "helper-mutant.c"
        mutant.write_text(source.replace(before, "true"))
        directory = self.build / "helper-mutant"
        directory.mkdir(mode=0o755)
        binary = build_helper(directory, helper_source=mutant)
        helper = self.native_helper("resume", binary)
        with self.assertRaisesRegex(AssertionError, "NATIVE_PEER_UID_BOUNDARY"):
            self.assertEqual(self.native_client(uid=1002), "DENIED\n", "NATIVE_PEER_UID_BOUNDARY")
        self.run_role(1001, "terminate-native", str(helper.pid))
        helper.communicate(timeout=8)
        helper = self.native_helper("resume")
        self.assertEqual(self.native_client(uid=1002), "DENIED\n")
        self.run_role(1001, "terminate-native", str(helper.pid))

    def test_late_ack_cannot_grant_dispatch_red_then_green(self):
        from yamora.tests.audit_native_support import SECURITY
        from yamora.tests.audit_native_support import build_client

        helper = self.native_helper()
        self.assertEqual(self.native_client("late"), "LATE_OK\n")
        source = (SECURITY / "audit_client.c").read_text()
        guard = "if (!now || now >= deadline) return YD_AUDIT_UNCERTAIN;"
        self.assertEqual(source.count(guard), 1)
        mutant = self.build / "client-late-mutant.c"
        mutant.write_text(source.replace(guard, "/* deliberately allow a late acknowledgement */"))
        directory = self.build / "late-mutant"
        directory.mkdir(mode=0o755)
        binary = build_client(directory, sanitize=self.sanitize, client_source=mutant)
        process = self.spawn(
            1000, "native-exec", str(binary), str(self.root / "public/audit.sock"), "1001", "late"
        )
        out, error = process.communicate(timeout=8)
        evidence, result = out.split("\n", 1)
        self.assert_identity(json.loads(evidence)["identity"], 1000)
        self.assertEqual(
            (process.returncode, result, error),
            (2, "", "ASSERTION:AUDIT_LATE_ACK_MUST_NOT_DISPATCH\n"),
        )
        self.assertEqual(self.native_client("late"), "LATE_OK\n")
        self.run_role(1001, "terminate-native", str(helper.pid))


@unittest.skipUnless(
    os.environ.get("ANDROMEDA_AUDIT_FIXTURE") == "1",
    "requires the fixed managed audit UID launcher; qualification is opt-in",
)
class NormalNativeAuditPrivilegeBoundaryTests(NativeAuditPrivilegeBoundaryTests):
    """Run the same privilege/recovery acceptance without instrumentation."""

    sanitize = False


@unittest.skipUnless(
    os.environ.get("ANDROMEDA_AUDIT_FIXTURE") == "1",
    "requires the fixed managed audit UID launcher",
)
class NativeAuditedDaemonTests(unittest.TestCase):
    """Actual TLS HTTP/binary daemon UID1000 with native helper UID1001."""

    sanitize = True
    spawn = AuditPrivilegeBoundaryTests.spawn
    run_role = AuditPrivilegeBoundaryTests.run_role
    assert_identity = AuditPrivilegeBoundaryTests.assert_identity
    cleanup = AuditPrivilegeBoundaryTests.cleanup
    reset_fixture = AuditPrivilegeBoundaryTests.reset_fixture
    stop_helper = AuditPrivilegeBoundaryTests.stop_helper
    native_cleanup = NativeAuditPrivilegeBoundaryTests.native_cleanup
    native_helper = NativeAuditPrivilegeBoundaryTests.native_helper
    native_client = NativeAuditPrivilegeBoundaryTests.native_client
    sequence = NativeAuditPrivilegeBoundaryTests.sequence

    @classmethod
    def setUpClass(cls):
        NativeAuditPrivilegeBoundaryTests.setUpClass.__func__(cls)
        from yamora.tests.audit_native_support import build_daemon

        cls.native_objects = cls.build / "daemon-objects"
        cls.daemon_binary = build_daemon(
            cls.build, sanitize=cls.sanitize, object_directory=cls.native_objects
        )

    def setUp(self):
        NativeAuditPrivilegeBoundaryTests.setUp(self)
        self.daemons = []
        self.addCleanup(self.cleanup_daemons)
        self.daemon_root = self.root / "daemon"
        evidence = self.run_role(1000, "prepare-daemon", str(self.daemon_root))
        self.certificate = evidence["certificate"]
        self.tls_context = ssl.create_default_context(cadata=evidence["certificate"])
        self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.tls_context.maximum_version = ssl.TLSVersion.TLSv1_3
        initialize = self.spawn(
            1000,
            "native-exec",
            str(self.daemon_binary),
            "--data-dir",
            str(self.daemon_root / "data"),
            "--init-disk",
            "--validate-only",
        )
        out, error = initialize.communicate(timeout=15)
        self.assertEqual(initialize.returncode, 0, out + error)
        self.assertEqual(error, "")

    def cleanup_daemons(self):
        for process in self.daemons:
            if process.poll() is None:
                self.run_role(1000, "terminate-native", str(process.pid))
            out, error = process.communicate(timeout=12)
            self.assertNotIn("Sanitizer", error, out + error)
        self.run_role(1000, "cleanup", str(self.daemon_root))

    def start_daemon(
        self,
        *,
        socket_path=None,
        expect_ready=True,
        binary=None,
        data=None,
        extra=(),
        gate=None,
        pending=False,
    ):
        process = self.spawn(
            1000,
            *(("native-gated-exec", str(gate)) if gate else ("native-exec",)),
            str(binary or self.daemon_binary),
            "--data-dir",
            str(data or self.daemon_root / "data"),
            "--port",
            "0",
            "--workers",
            "2",
            "--binary-port",
            "0",
            "--io-timeout-ms",
            "2000",
            "--auth-token-file",
            str(self.daemon_root / "read"),
            "--write-auth-token-file",
            str(self.daemon_root / "write"),
            "--tls-cert-file",
            str(self.daemon_root / "cert.pem"),
            "--tls-key-file",
            str(self.daemon_root / "key.pem"),
            "--audit-socket",
            str(socket_path or self.root / "public/audit.sock"),
            "--audit-helper-uid",
            "1001",
            *extra,
        )
        self.daemons.append(process)
        if pending:
            return process
        if not expect_ready:
            out, error = process.communicate(timeout=8)
            self.assertNotEqual(process.returncode, 0)
            self.assertNotIn("listening on", out)
            self.assertNotIn("Sanitizer", error)
            return process
        return self.wait_daemon(process)

    def wait_daemon(self, process):
        deadline, ports, pending = time.monotonic() + 12, {}, b""
        while len(ports) != 2:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, "AUDITED_DAEMON_START_DEADLINE")
            self.assertTrue(select.select([process.stdout], [], [], remaining)[0])
            part = os.read(process.stdout.fileno(), 4096)
            if not part:
                out, error = process.communicate(timeout=5)
                self.fail(f"AUDITED_DAEMON_START:{process.returncode}:{out}:{error}")
            pending += part
            self.assertLessEqual(len(pending), 8192)
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if line.startswith(b"{"):
                    self.assert_identity(json.loads(line)["identity"], 1000)
                match = re.search(rb"^(yamora|binary) listening on 127\.0\.0\.1:(\d+)", line)
                if match:
                    ports[match[1].decode()] = int(match[2])
        return process, ports["yamora"], ports["binary"]

    def binary_context(self):
        # WireClient selects binary ALPN on its supplied context. Keep that
        # context separate from subsequent HTTPS exchanges in the same test.
        context = ssl.create_default_context(cadata=self.certificate)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        return context

    def request(self, port, method, target, body=None, *, token=None, headers=None):
        connection = http.client.HTTPSConnection(
            "localhost", port, context=self.tls_context, timeout=5
        )
        try:
            connection.request(
                method,
                target,
                body,
                {
                    "Authorization": "Bearer " + (token or ("r" if method == "GET" else "w") * 64),
                    "Content-Type": "application/yaml",
                    **(headers or {}),
                },
            )
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def records(self, *forbidden):
        # The helper-UID inspector fails on any forbidden value in the log.
        values = [value.hex() for value in forbidden]
        return self.run_role(1001, "native-inspect", str(self.private), *values)["records"]

    def runtime_access_sequence(self, port):
        """One management sequence; returns its records and every credential used."""
        role, principal = "audit-readers", "audit-app"
        supplied = "runtime-audit-supplied-principal-token-0001"
        target = "/v1/collections/people/documents/audited"
        self.assertIn(self.request(port, "PUT", target, b"name: audited\n")[0], (200, 201))
        before = self.sequence()

        def manage(method, path, value=None, token="w" * 64):
            body = None if value is None else json.dumps(value).encode()
            headers = {"Content-Type": "application/json"}
            status, reply = self.request(port, method, path, body, token=token, headers=headers)
            return status, json.loads(reply) if reply else None

        role_path = "/v1/access/roles/" + role
        principal_path = "/v1/access/principals/" + principal
        self.assertEqual(manage("PUT", role_path, {"read": ["people"], "write": []})[0], 201)
        created = manage("PUT", principal_path, {"roles": [role], "token": supplied})
        self.assertEqual(created[0], 201, created)
        self.assertEqual(self.request(port, "GET", target, token=supplied)[0], 200)
        rotated = manage("POST", principal_path + "/rotate", {"generate_token": True})
        self.assertEqual(rotated[0], 200, rotated)
        generated = rotated[1]["token"]
        self.assertEqual(self.request(port, "GET", target, token=generated)[0], 200)
        denied = manage(
            "PUT", "/v1/access/roles/intruders", {"read": ["people"], "write": []}, "r" * 64
        )
        self.assertEqual(denied[0], 403)
        self.assertEqual(manage("GET", "/v1/access")[0], 200)
        self.assertEqual(manage("DELETE", principal_path)[0], 200)
        self.assertEqual(manage("DELETE", role_path)[0], 200)
        secrets = []
        for token in (supplied, generated):
            secrets.append(token.encode())
            digest = hashlib.sha256(b"yamora-runtime-access-token-v1\0" + token.encode())
            secrets += [digest.digest(), digest.hexdigest().encode()]
        records = [r for r in self.records(*secrets) if r["sequence"] >= before]
        return records, role, principal

    def assert_runtime_access_audit(self, records, role, principal):
        finishes = [r for r in records if r["kind"] == 3]
        intents = {r["sequence"]: r for r in records if r["kind"] == 2}
        for operation, subject, status in (
            (15, role, 201),
            (17, principal, 201),
            (18, principal, 200),
            (19, principal, 200),
            (16, role, 200),
        ):
            matches = [
                r
                for r in finishes
                if (r["operation"], r["subject"], r["status"]) == (operation, subject, status)
            ]
            self.assertEqual(len(matches), 1, "ACCESS_AUDIT_EVENT_NAMES_ITS_SUBJECT")
            finish = matches[0]
            self.assertEqual((finish["authentication"], finish["actor"]), (2, ""))
            self.assertEqual(finish["outcome"], 2)
            intent = intents[finish["intent"]]
            self.assertEqual((intent["operation"], intent["subject"]), (operation, subject))
        # Listings, refusals and principal requests carry no subject.
        self.assertTrue(
            any(
                r["operation"] == 2 and r["status"] == 200 and r["authentication"] == 2
                for r in finishes
            )
        )
        self.assertTrue(any(r["operation"] == 14 and r["status"] == 403 for r in finishes))
        reads = [r for r in finishes if r["authentication"] == 3 and r["actor"] == principal]
        self.assertEqual(len(reads), 2)
        for r in records:
            if r["operation"] not in range(15, 20):
                self.assertEqual(r["subject"], "")

    def test_runtime_access_changes_audit_their_subject_red_then_restored(self):
        from yamora.tests.audit_native_support import ROOT
        from yamora.tests.audit_native_support import build_daemon

        source = (ROOT / "src/daemon.c").read_text()
        naming = (
            "event.operation = yd_access_admin_audit(request->method, request->target, "
            "event.subject);"
        )
        self.assertEqual(source.count(naming), 1)
        mutant_source = self.build / "daemon-access-audit-mutant.c"
        mutant_source.write_text(source.replace(naming, "(void)0;"))
        mutant = build_daemon(
            self.build / "access-audit-mutant",
            sanitize=self.sanitize,
            daemon_source=mutant_source,
            object_directory=self.native_objects,
        )
        self.native_helper()
        for label, binary in (("broken", mutant), ("restored", None)):
            with self.subTest(profile=label):
                process, port, _binary = self.start_daemon(
                    binary=binary, extra=("--runtime-access",)
                )
                records = self.runtime_access_sequence(port)
                if label == "broken":
                    with self.assertRaisesRegex(
                        AssertionError, "ACCESS_AUDIT_EVENT_NAMES_ITS_SUBJECT"
                    ):
                        self.assert_runtime_access_audit(*records)
                else:
                    self.assert_runtime_access_audit(*records)
                self.run_role(1000, "terminate-native", str(process.pid))
                out, error = process.communicate(timeout=12)
                self.assertEqual(process.returncode, 0, out + error)

    def test_real_http_binary_denial_publication_and_redaction(self):
        from yamora.tests.binary_runtime_support import GET
        from yamora.tests.binary_runtime_support import PUT
        from yamora.tests.binary_runtime_support import WireClient

        self.native_helper()
        process, port, binary_port = self.start_daemon()
        target = "/v1/collections/people/documents/alice"
        source = b"name: Alice\nsecret: private-field-value\n"
        before = self.sequence()
        self.assertIn(self.request(port, "PUT", target, source)[0], (200, 201))
        self.assertEqual(self.sequence(), before + 2, "DURABLE_AUDIT_BEFORE_HTTP_ACK")
        self.assertEqual(self.request(port, "GET", target), (200, source))
        self.assertEqual(
            self.request(port, "PUT", target, b"name: denied\n", token="x" * 64)[0], 401
        )
        context = ssl.create_default_context()
        context.load_verify_locations(
            cadata=self.run_role(1000, "daemon-certificate", str(self.daemon_root))["certificate"]
        )
        with WireClient(binary_port, context) as wire:
            self.assertEqual(wire.request(GET, target, token="r" * 64).body, source)
            denied = wire.request(PUT, target, b"name: denied\n", token="x" * 64)
            self.assertEqual(denied.status, 401)
            self.assertEqual(wire.request(GET, target, token="r" * 64).body, source)
        records = self.records()
        finishes = [r for r in records if r["kind"] == 3]
        self.assertTrue(
            any(r["operation"] == 6 and r["outcome"] == 2 and r["has_revision"] for r in finishes)
        )
        self.assertTrue(
            any(r["operation"] == 14 and r["outcome"] == 1 and r["status"] == 401 for r in finishes)
        )
        self.run_role(1000, "terminate-native", str(process.pid))
        out, error = process.communicate(timeout=12)
        self.assertEqual(process.returncode, 0, out + error)

    def test_audit_begin_guard_mutant_red_then_restored(self):
        from yamora.tests.audit_native_support import ROOT
        from yamora.tests.audit_native_support import build_daemon

        source = (ROOT / "src/daemon.c").read_text()
        guard = "if (!audit_begin_request(server, &request, status != 0)) {"
        self.assertEqual(source.count(guard), 1)
        mutant_source = self.build / "daemon-guard-mutant.c"
        mutant_source.write_text(source.replace(guard, "if (false) {"))
        mutant = build_daemon(
            self.build / "mutant-daemon",
            sanitize=self.sanitize,
            daemon_source=mutant_source,
            object_directory=self.native_objects,
        )
        helper = self.native_helper()
        process, port, _binary = self.start_daemon(binary=mutant)
        target = "/v1/collections/people/documents/control"
        self.assertIn(self.request(port, "PUT", target, b"name: control\n")[0], (200, 201))
        self.run_role(1001, "terminate-native", str(helper.pid))
        helper.communicate(timeout=8)
        with self.assertRaisesRegex(AssertionError, "AUDIT_BEGIN_GUARD_REQUIRED"):
            self.assertEqual(
                self.request(port, "PUT", target, b"name: bypass\n")[0],
                503,
                "AUDIT_BEGIN_GUARD_REQUIRED",
            )
        self.run_role(1000, "terminate-native", str(process.pid))
        process.communicate(timeout=12)
        self.native_helper(mode="resume")
        _restored, port, _binary = self.start_daemon()
        self.assertEqual(self.request(port, "GET", target), (200, b"name: bypass\n"))
        current_helper = self.native_helpers[-1]
        self.run_role(1001, "terminate-native", str(current_helper.pid))
        current_helper.communicate(timeout=8)
        self.assertEqual(self.request(port, "PUT", target, b"name: denied\n")[0], 503)

    def test_missing_helper_refuses_before_listener(self):
        self.start_daemon(socket_path=self.root / "public/missing.sock", expect_ready=False)

    def test_binary_startup_gate_red_then_restored(self):
        from yamora.tests.audit_native_support import ROOT
        from yamora.tests.audit_native_support import build_daemon
        from yamora.tests.binary_runtime_support import GET
        from yamora.tests.binary_runtime_support import WireClient

        source = (ROOT / "src/daemon.c").read_text()
        marker = (
            "    /* All listener/worker constructors completed; final audited admission follows. */"
        )
        guard = "if (!atomic_load_explicit(&server->dispatch_ready, memory_order_acquire)) {"
        self.assertEqual(source.count(marker), 1)
        self.assertEqual(source.count(guard), 1)
        gated_source = source.replace(marker, NATIVE_GATE_CODE + marker)
        candidates = {}
        for label, candidate in (
            ("broken", gated_source.replace(guard, "if (false) {")),
            ("restored", gated_source),
        ):
            path = self.build / ("startup-" + label + ".c")
            path.write_text(candidate)
            candidates[label] = build_daemon(
                self.build / ("startup-" + label),
                sanitize=self.sanitize,
                daemon_source=path,
                object_directory=self.native_objects,
            )
        self.native_helper()
        seed, port, _binary = self.start_daemon()
        target = "/v1/collections/people/documents/startup"
        body = b"name: stable\n"
        self.assertEqual(self.request(port, "PUT", target, body)[0], 201)
        self.run_role(1000, "terminate-native", str(seed.pid))
        _out, error = seed.communicate(timeout=12)
        self.assertEqual((seed.returncode, error), (0, ""))
        for label, binary in candidates.items():
            with self.subTest(profile=label):
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    binary_port = reservation.getsockname()[1]
                gate = self.daemon_root / ("startup-gate-" + label)
                self.addCleanup(self.run_role, 1000, "release-job-gate", str(gate))
                process = self.start_daemon(
                    binary=binary,
                    gate=gate,
                    pending=True,
                    extra=("--binary-port", str(binary_port), "--io-timeout-ms", "10000"),
                )
                deadline = time.monotonic() + 5
                while not self.run_role(1000, "job-gate-state", str(gate))["entered"]:
                    self.assertLess(
                        time.monotonic(), deadline, "STARTUP_MUST_REACH_REAL_LISTENER_GATE"
                    )
                    time.sleep(0.01)
                with WireClient(binary_port, self.binary_context()) as wire:
                    if label == "broken":
                        early = wire.request(GET, target, token="r" * 64)
                        self.assertEqual(
                            (early.status, early.body),
                            (200, body),
                            "BROKEN_GATE_MUST_RELEASE_SEEDED_SOURCE",
                        )
                        with self.assertRaisesRegex(AssertionError, "BINARY_STARTUP_GATE_REQUIRED"):
                            self.assertEqual(
                                early.status,
                                503,
                                "BINARY_STARTUP_GATE_REQUIRED",
                            )
                    else:
                        self.assertEqual(
                            wire.request(GET, target, token="r" * 64).status,
                            503,
                            "BINARY_STARTUP_GATE_REQUIRED",
                        )
                    self.run_role(1000, "release-job-gate", str(gate))
                    self.wait_daemon(process)
                    reply = wire.request(GET, target, token="r" * 64)
                    self.assertEqual((reply.status, reply.body), (200, body))
                self.run_role(1000, "terminate-native", str(process.pid))
                _out, error = process.communicate(timeout=12)
                self.assertEqual((process.returncode, error), (0, ""))

    def test_helper_loss_blocks_new_dispatch(self):
        helper = self.native_helper()
        _process, port, _binary_port = self.start_daemon()
        target = "/v1/collections/people/documents/alice"
        self.assertIn(self.request(port, "PUT", target, b"name: original\n")[0], (200, 201))
        self.run_role(1001, "terminate-native", str(helper.pid))
        _out, error = helper.communicate(timeout=8)
        self.assertEqual(error, "")
        self.assertEqual(self.request(port, "PUT", target, b"name: forbidden\n")[0], 503)
        self.assertEqual(self.request(port, "GET", target)[0], 503)

    def test_receipt_replay_requires_current_auth_and_live_helper(self):
        data = self.daemon_root / "schema-data"
        self.run_role(1000, "native-directory", str(data))
        initialize = self.spawn(
            1000,
            "native-exec",
            str(self.daemon_binary),
            "--data-dir",
            str(data),
            "--init-disk",
            "--schema-policies",
            "--validate-only",
        )
        out, error = initialize.communicate(timeout=15)
        self.assertEqual(initialize.returncode, 0, out + error)
        helper = self.native_helper()
        _process, port, _binary = self.start_daemon(data=data, extra=("--schema-policies",))
        target = "/v1/schema-policies/people"
        source = b"type: object\nproperties: {name: {type: string}}\n"
        headers = {"X-Yamora-Request-Id": "12" * 16, "If-None-Match": "*"}
        first = self.request(port, "PUT", target, source, headers=headers)
        self.assertEqual(first[0], 201, first)
        later = self.request(
            port, "PUT", "/v1/collections/people/documents/later", b"name: later\n"
        )
        self.assertEqual(later[0], 201, later)
        self.assertEqual(self.request(port, "PUT", target, source, headers=headers), first)
        self.assertEqual(
            self.request(port, "PUT", target, source, headers=headers, token="x" * 64)[0], 403
        )
        self.assertEqual(self.request(port, "PUT", target, source, headers=headers), first)
        self.run_role(1001, "terminate-native", str(helper.pid))
        helper.communicate(timeout=8)
        self.assertEqual(self.request(port, "PUT", target, source, headers=headers)[0], 503)

    def test_detached_index_job_finishes_original_intent_and_session_keeps_identity(self):
        from yamora.tests.audit_native_support import ROOT
        from yamora.tests.audit_native_support import build_daemon
        from yamora.tests.binary_runtime_support import GET
        from yamora.tests.binary_runtime_support import WireClient

        source = (ROOT / "src/disk_index_jobs.c").read_text()
        before_call = "    bool valid = yd_disk_indexes_online_from("
        self.assertEqual(source.count(before_call), 1)
        gated_source = self.build / "gated-index-jobs.c"
        gated_source.write_text(source.replace(before_call, NATIVE_GATE_CODE + before_call))
        gated = build_daemon(
            self.build / "gated",
            sanitize=self.sanitize,
            object_directory=self.native_objects,
            source_overrides={"src/disk_index_jobs.c": gated_source},
        )
        gate = self.daemon_root / "job-gate"
        self.addCleanup(self.run_role, 1000, "release-job-gate", str(gate))
        self.native_helper()
        _process, port, binary_port = self.start_daemon(
            binary=gated, gate=gate, extra=("--io-timeout-ms", "10000")
        )
        target = "/v1/collections/people/documents/alice"
        source = b"name: Alice\n"
        self.assertEqual(self.request(port, "PUT", target, source)[0], 201)
        with WireClient(binary_port, self.binary_context()) as wire:
            self.assertEqual(wire.request(GET, target, token="r" * 64).body, source)
            before = self.sequence()
            status, body = self.request(port, "POST", "/v1/index-builds", b'{"indexes": []}')
            self.assertEqual(status, 202, body)
            job = json.loads(body)
            # request() closes the originating HTTPS connection immediately.
            deadline = time.monotonic() + 5
            while not self.run_role(1000, "job-gate-state", str(gate))["entered"]:
                self.assertLess(time.monotonic(), deadline, "JOB_MUST_REACH_REAL_WORKER_GATE")
                time.sleep(0.01)
            intents = [r for r in self.records() if r["sequence"] > before and r["kind"] == 2]
            self.assertEqual(len(intents), 1, intents)
            self.assertFalse(
                any(
                    r["kind"] == 3 and r["intent"] == intents[0]["sequence"] for r in self.records()
                )
            )
            self.assertEqual(wire.request(GET, target, token="x" * 64).status, 401)
            self.assertEqual(wire.request(GET, target, token="r" * 64).body, source)
            status, running_job = self.request(port, "GET", "/v1/index-builds/" + job["id"])
            self.assertEqual(status, 200, running_job)
            self.assertEqual(json.loads(running_job)["status"], "running")
            self.run_role(1000, "release-job-gate", str(gate))
            deadline = time.monotonic() + 8
            while True:
                status, body = self.request(port, "GET", "/v1/index-builds/" + job["id"])
                self.assertEqual(status, 200, body)
                done = json.loads(body)
                if done["status"] != "running":
                    break
                self.assertLess(time.monotonic(), deadline, "AUDITED_JOB_TERMINAL_DEADLINE")
                time.sleep(0.01)
            self.assertEqual(done["status"], "succeeded", done)
            finishes = [
                r
                for r in self.records()
                if r["kind"] == 3 and r["intent"] == intents[0]["sequence"]
            ]
            self.assertEqual(len(finishes), 1, finishes)
            self.assertEqual(finishes[0]["outcome"], 2)
            self.assertEqual(finishes[0]["status"], 0)
            self.assertTrue(finishes[0]["has_revision"])
            self.assertEqual(finishes[0]["revision"], done["revision"])
            self.assertEqual(wire.request(GET, target, token="x" * 64).status, 401)
            self.assertEqual(wire.request(GET, target, token="r" * 64).body, source)

    def test_segment_rotation_and_exhaustion_never_bypass_audit(self):
        self.segment_records = 18
        self.native_helper()
        _process, port, _binary = self.start_daemon()
        target = "/v1/collections/people/documents/alice"
        self.assertEqual(self.request(port, "PUT", target, b"name: retained\n")[0], 201)
        successful = 0
        for _ in range(30):
            status, body = self.request(port, "GET", target)
            if status == 503:
                break
            self.assertEqual((status, body), (200, b"name: retained\n"))
            successful += 1
        else:
            self.fail("AUDIT_CAPACITY_MUST_STOP_DISPATCH")
        self.assertGreater(successful, 6, "ROTATED_SEGMENT_MUST_ACCEPT_OPERATIONS")
        records = self.records()
        self.assertEqual({r["segment"] for r in records}, {1, 2, 3})
        self.assertEqual(self.request(port, "PUT", target, b"name: forbidden\n")[0], 503)
        self.assertEqual(self.records(), records, "CAPACITY_FAILURE_MUST_PRESERVE_ANCHORED_CHAIN")

    def test_failed_listener_startup_never_records_service_success(self):
        self.native_helper()
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            self.start_daemon(expect_ready=False, extra=("--port", str(occupied.getsockname()[1])))
        finishes = [r for r in self.records() if r["kind"] == 3 and r["operation"] == 12]
        self.assertEqual(len(finishes), 1, finishes)
        if finishes[0]["outcome"] == 2:
            print("OBSERVED_FALSE_STARTUP_SUCCESS_AFTER_LISTENER_FAILURE", flush=True)
        self.assertEqual(finishes[0]["outcome"], 3, "FAILED_STARTUP_MUST_NOT_RECORD_SUCCESS")

    def test_encrypted_publication_failure_preserves_ciphertext_and_audit_truth(self):
        self.native_helper()
        self.run_role(1000, "prepare-encrypted-daemon", str(self.daemon_root))
        _process, port, _binary = self.start_daemon(
            data=self.daemon_root / "encrypted",
            extra=("--encrypted-storage-file", str(self.daemon_root / "encrypted.json")),
        )
        target = "/v1/collections/people/documents/alice"
        source = b"name: Alice\nsecret: private-field-value\n"
        self.assertEqual(self.request(port, "PUT", target, source)[0], 201)
        self.assertEqual(self.request(port, "GET", target), (200, source))
        state = self.run_role(1000, "encrypted-state", str(self.daemon_root))["ciphertext"]
        before = self.sequence()
        self.run_role(1000, "poison-encrypted-publication", str(self.daemon_root))
        self.assertGreaterEqual(self.request(port, "PUT", target, b"name: failed\n")[0], 500)
        finishes = [r for r in self.records() if r["kind"] == 3 and r["sequence"] > before]
        self.assertEqual(len(finishes), 1, finishes)
        self.assertEqual(finishes[0]["outcome"], 4)
        self.assertFalse(finishes[0]["has_revision"])
        self.assertEqual(self.request(port, "GET", target), (200, source))
        self.assertEqual(
            self.run_role(1000, "encrypted-state", str(self.daemon_root))["ciphertext"], state
        )

    def test_helper_loss_blocks_otherwise_healthy_encrypted_publication(self):
        helper = self.native_helper()
        self.run_role(1000, "prepare-encrypted-daemon", str(self.daemon_root))
        _process, port, _binary = self.start_daemon(
            data=self.daemon_root / "encrypted",
            extra=("--encrypted-storage-file", str(self.daemon_root / "encrypted.json")),
        )
        target = "/v1/collections/people/documents/alice"
        self.assertEqual(self.request(port, "PUT", target, b"name: healthy\n")[0], 201)
        state = self.run_role(1000, "encrypted-state", str(self.daemon_root))["ciphertext"]
        self.run_role(1001, "terminate-native", str(helper.pid))
        helper.communicate(timeout=8)
        self.assertEqual(self.request(port, "PUT", target, b"name: unaudited\n")[0], 503)
        self.assertEqual(
            self.run_role(1000, "encrypted-state", str(self.daemon_root))["ciphertext"], state
        )


@unittest.skipUnless(
    os.environ.get("ANDROMEDA_AUDIT_FIXTURE") == "1",
    "requires the fixed managed audit UID launcher",
)
class NormalNativeAuditedDaemonTests(NativeAuditedDaemonTests):
    """Qualify the same actual daemon/helper acceptance without sanitizers."""

    sanitize = False
