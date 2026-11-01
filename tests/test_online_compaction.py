"""Online compaction and in-place format upgrade through the real daemon.

A single standalone server reclaims deleted and replaced space while it keeps
serving reads and writes, without a stopped writer or a separate root.
"""

import contextlib
import http.client
import io
import json
import os
import re
import signal
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root
from yamora import yamoractl

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build")) / "yamora"
NATIVE = ".yamora-disk"
STAGE = ".yamora-compact-"
PAGE = 4096
LIVE = 100
CHURN = 200
WRITES = 1500
# Writes made after the writer sees the switch: they prove the compacted file
# serves writes, and the bound keeps its growth below the reclaimed space.
AFTER_SWITCH = 8


def crc32c(data):
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def relabel(root, fmt):
    """Rewrite both superblocks as an older format with valid checksums."""
    path = Path(root) / NATIVE
    data = bytearray(path.read_bytes())
    for slot in range(2):
        start = slot * PAGE
        data[start + 7] = ord(str(fmt))
        struct.pack_into("<I", data, start + PAGE - 4, crc32c(data[start : start + PAGE - 4]))
    path.write_bytes(bytes(data))


def formats(root):
    data = (Path(root) / NATIVE).read_bytes()[: 2 * PAGE]
    return [chr(data[slot * PAGE + 7]) for slot in range(2)]


def source(number, version):
    # The feed window keeps the source of every put it covers. Documents this
    # small keep that retained part well below the superseded pages, so each
    # compaction must at least halve the file.
    pad = "".join(chr(97 + (number + i) % 26) for i in range(60 + (number * 37) % 120))
    return f"# authored d-{number} v{version}\r\nvalue: {number} # inline\npad: {pad}\n"


class OnlineCompactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="online-compaction-", dir=runtime_root()
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.read = self.root / "read"
        self.write = self.root / "write"
        self.read.write_text("test-read-credential-for-online-compaction")
        self.write.write_text("test-write-credential-for-online-compaction")
        self.read.chmod(0o600)
        self.write.chmod(0o600)
        self.processes = []
        self.addCleanup(self.stop_all)

    def stop_all(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=30)
            process.stdout.close()
            process.stderr.close()

    def initialize(self, name="data"):
        seed = self.root / (name + "-seed")
        (seed / "items").mkdir(parents=True)
        (seed / "items" / "seed.yaml").write_bytes(b"# seed\nvalue: -1\n")
        data = self.root / name
        data.mkdir(mode=0o700)
        result = self.daemon_run(
            "--data-dir", data, "--init-disk", "--import-yaml", seed, "--validate-only"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return data

    def daemon_run(self, *arguments, binary=BINARY):
        return subprocess.run(
            [str(binary), *map(str, arguments)], capture_output=True, text=True, timeout=120
        )

    def start(self, data, *extra, binary=BINARY, write=True, environment=None):
        command = [
            str(binary),
            "--data-dir",
            str(data),
            "--port",
            "0",
            "--cache-bytes",
            "262144",
            "--auth-token-file",
            str(self.read),
            *(["--write-auth-token-file", str(self.write)] if write else []),
            *map(str, extra),
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, **(environment or {})),
        )
        self.processes.append(process)
        line = process.stdout.readline()
        match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
        self.assertIsNotNone(match, line if line else process.stderr.read())
        self.port = int(match.group(1))
        return process

    def stop(self, process):
        process.terminate()
        process.wait(timeout=30)
        stderr = process.stderr.read()
        self.assertEqual(process.returncode, 0, stderr)
        return stderr

    def request(self, path, body=None, *, method="GET", token="read", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        sent = {"Content-Type": "application/yaml", **(headers or {})}
        if token:
            sent["Authorization"] = "Bearer " + getattr(self, token).read_text()
        payload = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
        connection.request(method, path, body=payload, headers=sent)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def transaction(self, operations):
        status, _, body = self.request(
            "/v1/transactions", {"operations": operations}, method="POST", token="write"
        )
        self.assertEqual(status, 200, body)

    def churn(self, rounds, live=LIVE, churn=CHURN):
        for version in range(rounds):
            for start in range(0, live + churn, 50):
                self.transaction(
                    [
                        {"collection": "items", "document": f"d-{n}", "put": source(n, version)}
                        for n in range(start, min(start + 50, live + churn))
                    ]
                )
            for start in range(live, live + churn, 50):
                self.transaction(
                    [
                        {"collection": "items", "document": f"d-{n}", "delete": True}
                        for n in range(start, start + 50)
                    ]
                )

    def survivors(self, version, live=LIVE):
        for number in range(live):
            status, _, body = self.request(f"/v1/collections/items/documents/d-{number}")
            self.assertEqual(status, 200, number)
            self.assertEqual(body.decode(), source(number, version), number)
        for number in range(live, live + CHURN, 23):
            status, _, _ = self.request(f"/v1/collections/items/documents/d-{number}")
            self.assertEqual(status, 404, number)

    def feed(self, after):
        status, _, body = self.request(f"/v1/changes?after={after}&limit=30")
        self.assertEqual(status, 200, body)
        page = json.loads(body)
        return page["transactions"], page["next_after"]

    def status(self):
        status, _, body = self.request("/v1/storage/compaction")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def wait_finished(self, *, automatic=False, runs=1, seconds=180):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            current = self.status()
            if current["runs"] >= runs and current["state"] != "running":
                return current
            time.sleep(0.2)
        self.fail(f"compaction did not finish: {current}")

    def native_size(self, data):
        return (Path(data) / NATIVE).stat().st_size

    def test_operator_compaction_shrinks_file_while_serving_reads_and_writes(self):
        data = self.initialize()
        self.start(data)
        status, _, body = self.request("/v1/changes")
        start = json.loads(body)["next_after"]
        self.churn(6)
        before = self.native_size(data)
        retained, _ = self.feed(start)
        self.assertEqual(len(retained), 30)
        failures, writes, stop = [], {}, threading.Event()

        def switched():
            # A run reaches "cleaning" only after the switch, then "done".
            code, _, body = self.request("/v1/storage/compaction")
            if code != 200:
                failures.append(("status", code))
                return True
            return json.loads(body)["phase"] in ("cleaning", "done")

        def writer():
            # The cap keeps every commit of the test inside the 4,096-commit
            # feed window, so the retained frames compared below never rotate.
            # Checking the phase before each write leaves at most one write in
            # flight at the switch, however late the main thread observes it.
            number, after_switch = 0, None
            while not stop.is_set():
                if after_switch is None and switched():
                    after_switch = 0
                if number >= WRITES or after_switch == AFTER_SWITCH:
                    stop.wait(0.01)
                    continue
                if after_switch is not None:
                    after_switch += 1
                slot = number % 32
                text = f"# concurrent\nslot: {slot}\nround: {number}\n"
                code, _, _ = self.request(
                    f"/v1/collections/live/documents/w-{slot}",
                    text.encode(),
                    method="PUT",
                    token="write",
                )
                if code not in (200, 201):
                    failures.append(("put", code))
                writes[slot] = text
                if number % 4 == 3:
                    gone = (slot + 5) % 32
                    if gone in writes:
                        code, _, _ = self.request(
                            f"/v1/collections/live/documents/w-{gone}",
                            method="DELETE",
                            token="write",
                        )
                        if code not in (200, 204):
                            failures.append(("delete", code))
                        writes.pop(gone)
                number += 1

        def reader():
            number = 0
            while not stop.is_set():
                code, _, body = self.request(f"/v1/collections/items/documents/d-{number % LIVE}")
                if code != 200 or body.decode() != source(number % LIVE, 5):
                    failures.append(("get", code))
                number += 1

        threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
        for thread in threads:
            thread.start()
        try:
            time.sleep(0.2)
            code, _, body = self.request("/v1/storage/compaction", method="POST", token="write")
            self.assertEqual(code, 202, body)
            self.assertIn(json.loads(body)["state"], ("running", "succeeded"))
            finished = self.wait_finished()
            time.sleep(0.2)
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=60)
        self.assertEqual(failures, [])
        self.assertEqual(finished["state"], "succeeded", finished)
        self.assertGreater(finished["reclaimed_bytes"], 0)
        self.assertEqual(finished["error"], "")
        # The writer appended to both files during the run and keeps its
        # commits in the feed window, so the file halves at the switch and
        # still ends below its size before the run.
        self.assertLess(finished["size_after"] * 2, finished["size_before"], finished)
        after = self.native_size(data)
        self.assertLess(after, before, (before, after))
        self.assertEqual(self.status()["file_bytes"], after)
        self.assertEqual([name for name in os.listdir(data) if name.startswith(STAGE)], [])
        self.survivors(5)
        for slot in range(32):
            code, _, body = self.request(f"/v1/collections/live/documents/w-{slot}")
            if slot in writes:
                self.assertEqual((code, body.decode()), (200, writes[slot]))
            else:
                self.assertEqual(code, 404)
        self.assertEqual(self.feed(start)[0], retained)
        code, _, body = self.request("/v1/stats")
        stats = json.loads(body)
        self.assertEqual(stats["compaction_state"], "succeeded")
        self.assertEqual(stats["compaction_runs"], 1)
        self.assertEqual(stats["compaction_reclaimed_bytes"], finished["total_reclaimed_bytes"])
        self.assertEqual(stats["file_bytes"], after)
        # Yamoractl drives the same surface; space freed again is reused.
        self.churn(6)
        grown = self.native_size(data)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = yamoractl.main(
                [
                    "--port",
                    str(self.port),
                    "--timeout",
                    "30",
                    "--auth-token-file",
                    str(self.read),
                    "--write-auth-token-file",
                    str(self.write),
                    "compact",
                    "--wait",
                ]
            )
        self.assertEqual(code, 0)
        reported = json.loads(output.getvalue().strip().splitlines()[-1])
        self.assertEqual((reported["state"], reported["runs"]), ("succeeded", 2))
        # Most of the growth since the first run is reclaimed. The feed window
        # still keeps the sources of both rounds of churn, so garbage, not the
        # file, is what must not accumulate.
        compacted = self.native_size(data)
        self.assertGreaterEqual(
            (grown - compacted) * 5, (grown - after) * 2, (after, grown, compacted)
        )
        self.assertLess(grown, before * 2)
        process = self.processes[-1]
        self.stop(process)
        self.start(data)
        self.survivors(5)
        self.assertEqual(self.feed(start)[0], retained)
        code, _, _ = self.request(
            "/v1/collections/items/documents/after",
            b"after: restart\n",
            method="PUT",
            token="write",
        )
        self.assertEqual(code, 201)

    def test_automatic_policy_compacts_a_growing_file(self):
        data = self.initialize()
        self.start(
            data,
            "--auto-compact",
            "--auto-compact-min-bytes",
            "65536",
            "--auto-compact-interval-seconds",
            "1",
        )
        self.churn(4)
        finished = self.wait_finished(seconds=240)
        self.assertEqual(finished["state"], "succeeded", finished)
        self.assertTrue(finished["automatic"])
        self.assertGreater(finished["total_reclaimed_bytes"], 0)
        self.survivors(3)

    def test_storage_controls_require_admin_credentials_and_exact_requests(self):
        data = self.initialize()
        self.start(data)
        path = "/v1/storage/compaction"
        self.assertEqual(self.request(path, token=None)[0], 401)
        self.assertEqual(self.request(path, method="POST", token=None)[0], 401)
        self.assertEqual(self.request(path, method="POST", token="read")[0], 403)
        self.assertEqual(self.request(path, method="DELETE", token="read")[0], 403)
        self.assertEqual(self.request("/v1/storage/upgrade", method="POST", token="read")[0], 403)
        self.assertEqual(self.status()["state"], "idle")
        code, headers, _ = self.request(path, method="PUT", token="write")
        self.assertEqual((code, headers.get("Allow")), (405, "GET, HEAD, POST, DELETE"))
        code, headers, _ = self.request("/v1/storage/upgrade", method="GET", token="write")
        self.assertEqual((code, headers.get("Allow")), (405, "POST"))
        self.assertEqual(self.request("/v1/storage/other", token="write")[0], 404)
        for body, extra in ((b'{"force":true}', {}), (b"[]", {}), (b"", {"If-Match": '"x"'})):
            code, _, reply = self.request(path, body, method="POST", token="write", headers=extra)
            self.assertEqual(code, 400, reply)
            self.assertEqual(json.loads(reply)["error"], "invalid_storage_control")
        self.assertEqual(self.status()["runs"], 0)
        code, _, body = self.request(path, method="DELETE", token="write")
        self.assertEqual((code, json.loads(body)), (200, {"cancelled": False}))
        code, _, body = self.request("/v1/storage/upgrade", b"{}", method="POST", token="write")
        self.assertEqual(code, 200, body)
        self.assertEqual(json.loads(body)["upgraded"], False)
        process = self.processes[-1]
        self.stop(process)
        # A read-only server exposes no maintenance surface.
        self.start(data, write=False)
        code, _, body = self.request(path)
        self.assertEqual(
            (code, json.loads(body)["error"]), (409, "storage_maintenance_unavailable")
        )
        self.assertEqual(self.request(path, method="POST", token="read")[0], 405)
        code, _, body = self.request("/v1/stats")
        self.assertEqual(json.loads(body)["compaction_state"], "unavailable")

    def test_killed_compaction_is_recovered_on_restart(self):
        value = os.environ.get("YAMORA_SCHEMA_TEST_BINARY", "")
        fault = Path(value)
        if not value or not fault.is_absolute() or not os.access(fault, os.X_OK):
            raise AssertionError("YAMORA_SCHEMA_TEST_BINARY must be the built fault daemon")
        for stage in (3, 5):
            with self.subTest(stage=stage):
                data = self.initialize(f"data-{stage}")
                process = self.start(
                    data, binary=fault, environment={"YAMORA_COMPACT_KILL_AT": str(stage)}
                )
                self.churn(3)
                before = self.native_size(data)
                code, _, _ = self.request("/v1/storage/compaction", method="POST", token="write")
                self.assertEqual(code, 202)
                process.wait(timeout=120)
                self.assertEqual(process.returncode, -signal.SIGKILL)
                leftovers = [name for name in os.listdir(data) if name.startswith(STAGE)]
                self.assertEqual(len(leftovers), 1)
                if stage == 5:
                    self.assertLess(self.native_size(data) * 2, before)
                else:
                    self.assertEqual(self.native_size(data), before)
                restarted = self.start(data)
                self.survivors(2)
                self.assertEqual([n for n in os.listdir(data) if n.startswith(STAGE)], [])
                self.assertIn("removed 1 interrupted online compaction stage", self.stop(restarted))

    def test_format2_upgrade_in_place_then_writes(self):
        data = self.root / "v2"
        data.mkdir(mode=0o700)
        header = bytearray(PAGE)
        header[:8] = b"YAMDIS02"
        struct.pack_into("<QQQ", header, 8, 1, 0, 8192)
        struct.pack_into("<I", header, PAGE - 4, crc32c(header[: PAGE - 4]))
        native = data / NATIVE
        native.write_bytes(bytes(header + header))
        native.chmod(0o600)
        before = native.read_bytes()
        refused = self.daemon_run(
            "--data-dir",
            data,
            "--port",
            "0",
            "--auth-token-file",
            self.read,
            "--write-auth-token-file",
            self.write,
        )
        self.assertEqual(refused.returncode, 1)
        self.assertIn("--upgrade-format", refused.stderr)
        self.assertIn("copy migration", refused.stderr)
        self.assertEqual(native.read_bytes(), before)
        result = self.daemon_run("--data-dir", data, "--upgrade-format", "--validate-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(
            {key: report[key] for key in ("status", "from", "to", "resumed")},
            {"status": "upgraded", "from": 2, "to": 5, "resumed": False},
        )
        self.assertEqual(formats(data), ["5", "5"])
        again = self.daemon_run("--data-dir", data, "--upgrade-format", "--validate-only")
        self.assertEqual(json.loads(again.stdout)["status"], "current")
        self.start(data)
        code, _, _ = self.request(
            "/v1/collections/items/documents/one", b"# kept\none: 1\n", method="PUT", token="write"
        )
        self.assertEqual(code, 201)

    def test_unsupported_upgrade_input_is_refused_unchanged(self):
        data = self.initialize()
        relabel(data, 4)
        native = data / NATIVE
        native.chmod(0o640)
        before = native.read_bytes()
        result = self.daemon_run("--data-dir", data, "--upgrade-format", "--validate-only")
        self.assertEqual(result.returncode, 1)
        self.assertIn("private native file", result.stderr)
        self.assertEqual(native.read_bytes(), before)
        native.chmod(0o600)
        self.assertEqual(
            self.daemon_run("--upgrade-format", "--data-dir", data).returncode, 2
        )  # serving requires the write credential
        self.assertEqual(native.read_bytes(), before)

    def test_served_format4_store_upgrades_live_then_compacts(self):
        data = self.initialize()
        relabel(data, 4)
        self.start(data)
        self.churn(2)
        code, _, body = self.request("/v1/storage/compaction", method="POST", token="write")
        self.assertEqual((code, json.loads(body)["error"]), (409, "compaction_unsupported"))
        self.assertFalse(self.status()["supported"])
        code, _, body = self.request("/v1/storage/upgrade", method="POST", token="write")
        self.assertEqual(code, 200, body)
        upgraded = json.loads(body)
        self.assertEqual((upgraded["upgraded"], upgraded["from"], upgraded["to"]), (True, 4, 5))
        self.assertEqual(formats(data), ["5", "5"])
        self.assertTrue(self.status()["supported"])
        code, _, body = self.request("/v1/storage/compaction", method="POST", token="write")
        self.assertEqual(code, 202, body)
        self.assertEqual(self.wait_finished()["state"], "succeeded")
        self.survivors(1)
        large = b"text: " + b"x" * (300 * 1024) + b"\n"
        code, _, body = self.request(
            "/v1/collections/items/documents/large", large, method="PUT", token="write"
        )
        self.assertEqual(code, 201, body)


if __name__ == "__main__":
    unittest.main()
