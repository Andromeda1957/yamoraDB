"""Native response-hash suppression; caller identity/daemon hooks are separate."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class FieldResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = os.environ.get("TMPDIR")
        if not scratch or not Path(scratch).is_dir():
            raise RuntimeError("an existing owned disk-backed TMPDIR is required")
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.binary = cls.root / "field-response"
        command = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
        ]
        sanitizer = os.environ.get("FIELD_RESPONSE_SANITIZER", "address,undefined")
        if sanitizer:
            command.append("-fsanitize=" + sanitizer)
        command += [
            str(ROOT / "tests/field_response_harness.c"),
            os.environ.get("FIELD_RESPONSE_SOURCE", str(ROOT / "src/security/field_response.c")),
            str(ROOT / "src/value.c"),
            str(ROOT / "src/transport/binary_message.c"),
            "-I",
            str(ROOT / "src/security"),
            "-Wl,--wrap=malloc",
            "-Wl,--wrap=calloc",
            "-Wl,--wrap=realloc",
            "-Wl,--wrap=strdup",
            "-Wl,--wrap=yd_json_sized",
            "-lyaml",
            "-lm",
            "-o",
            str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def invoke(self, mode, body=b"", fault=""):
        path = self.root / "body"
        path.write_bytes(body)
        result = subprocess.run(
            [str(self.binary), mode, str(path), fault],
            capture_output=True,
            env=dict(
                os.environ,
                ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:abort_on_error=1",
                UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
            ),
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertNotIn(b"Sanitizer", result.stderr)
        return result.stdout

    def test_root_fingerprints_removed_nested_user_values_preserved(self):
        value = {
            "revision": "HIDDEN_HASH",
            "etag": "HIDDEN_HASH",
            "documents": [
                {
                    "id": "one",
                    "value": {"revision": "authored", "etag": "user-value", "name": "public"},
                }
            ],
            "matched": 1,
            "next_after": None,
        }
        output = self.invoke("json", json.dumps(value).encode())
        status, body = output.split(b"\n", 1)
        self.assertEqual(status, b"OK 0")
        value.pop("revision")
        value.pop("etag")
        self.assertEqual(json.loads(body), value)
        self.assertNotIn(b"HIDDEN_HASH", body)
        self.assertEqual(
            json.loads(self.invoke("json", b'[{"revision":"user"}]').split(b"\n", 1)[1]),
            [{"revision": "user"}],
        )
        self.assertEqual(
            json.loads(self.invoke("json", b'{"revision":"x","etag":"y"}').split(b"\n", 1)[1]), {}
        )

    def test_source_bytes_identical_and_failures_clear_owned_body(self):
        for source in (
            b"# authored\r\nrevision: 'private' # unchanged\r\netag: hi\r\n",
            b'{"revision":"authored","etag":"authored"}\n',
        ):
            self.assertEqual(self.invoke("source", source), b"OK 1\n" + source)
        self.assertEqual(self.invoke("json", b""), b"OK 0\n")
        for body in (
            b'{"revision":',
            b'{"revision":"x","revision":"y"}',
            b"true",
            b"revision: x\n",
        ):
            self.assertEqual(self.invoke("json", body), b"FAIL 0\n")
        for fault in ("allocate", "serialize", "oversize"):
            self.assertEqual(
                self.invoke("json", b'{"revision":"HIDDEN_HASH","ok":true}', fault), b"FAIL 0\n"
            )
        self.assertEqual(self.invoke("unknown", b"private source"), b"FAIL 0\n")

    def test_strict_header_suppression_and_malformed_blocks_clear(self):
        source = b'Allow: GET, HEAD\r\neTaG: "HIDDEN_HASH"\r\nX-YAMLDB-REVISION: HIDDEN_HASH\r\nRetry-After: 1\r\n'
        self.assertEqual(
            self.invoke("headers", source), b"OK\nAllow: GET, HEAD\r\nRetry-After: 1\r\n"
        )
        self.assertEqual(self.invoke("headers", b"ETag: x\r\nETag: y\r\n"), b"OK\n")
        self.assertEqual(self.invoke("headers", b""), b"OK\n")
        for bad in (
            b"Allow: GET\n",
            b"ETag : x\r\n",
            b" ETag: x\r\n",
            b"ETag: x\r\n folded\r\n",
            b"ETag: x\r\nBad: \x01\r\n",
            b"ETag: x\r\n\r\n",
            b"bad\r\n",
            b"ETag: x",
        ):
            with self.subTest(bad=bad):
                self.assertEqual(self.invoke("headers", bad), b"FAIL\n")
        self.assertEqual(self.invoke("headers-unterminated", b"ETag: x\r\n"), b"FAIL\n")

    def test_actual_binary_encode_decode_has_no_content_metadata(self):
        self.assertEqual(
            self.invoke("binary"),
            b"".join(
                f"0000000000000000 0 1 7 {status} 2 2\n".encode() for status in (200, 403, 503)
            ),
        )
