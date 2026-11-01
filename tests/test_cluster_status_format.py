"""Maximum counter widths must fit the actual public diagnostic response."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ClusterStatusFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "status"
        result = subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=undefined",
                "-ffunction-sections",
                "-fdata-sections",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "tests/cluster_status_format.c"),
                *[
                    str(ROOT / "src" / source)
                    for source in (
                        "security/access.c",
                        "security/field_response.c",
                        "security/audit_dispatch.c",
                        "security/audit_client.c",
                        "security/audit_helper_codec.c",
                        "security/audit_codec.c",
                        "value.c",
                    )
                ],
                "-Wl,--gc-sections",
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            timeout=120,
        )
        if result.returncode:
            raise AssertionError(result.stderr.decode())

    def response(self, *arguments):
        result = subprocess.run([str(self.binary), *arguments], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        headers, body = result.stdout.split(b"\r\n\r\n", 1)
        self.assertTrue(headers.startswith(b"HTTP/1.1 200 "), result.stdout)
        length = next(
            line.split(b": ", 1)[1]
            for line in headers.split(b"\r\n")
            if line.startswith(b"Content-Length:")
        )
        self.assertEqual(int(length), len(body))
        return json.loads(body), len(body)

    def test_detailed_maximum_width_counters_serialize_without_truncation(self):
        status, length = self.response()
        self.assertLess(length, 4096)
        self.assertEqual(status["applied"], 2**64 - 1)
        self.assertEqual(status["compaction"]["candidate_bytes"], 2**64 - 1)
        app = status["application_compaction"]
        for key in (
            "attempted",
            "reconciled",
            "publications",
            "retired",
            "source_bytes",
            "saved_bytes",
            "retained_bytes",
            "reserved_bytes",
            "image_high_water",
            "archive_high_water",
            "restore_high_water",
        ):
            self.assertEqual(app[key], 2**64 - 1, key)
        self.assertEqual(app["capacity"], 32)
        self.assertEqual(app["stop"], 5)

    def test_advisory_status_keeps_its_small_public_shape(self):
        status, length = self.response("advisory")
        self.assertEqual(set(status), {"node", "leader", "term", "role"})
        self.assertEqual(status["term"], 2**64 - 1)
        self.assertLess(length, 256)
