"""Vector catalogs against the last native library built without them.

Vector support stores no new on-disk format version. Compatibility instead
rests on the catalog: the pre-vector loader rejects any index ``type`` other
than ``text``, so an older binary must refuse a store whose catalog holds a
vector index instead of misreading its postings as ordinary entries. A catalog
without vector indexes must stay byte-for-byte readable by both binaries.

The old side is the real library at the commit before vector support,
extracted with ``git archive`` and linked to a small request harness.
"""

import io
import json
import os
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root
from yamora.tests import test_disk_api as disk_api
from yamora.tests import test_document_api as api

ROOT = Path(__file__).resolve().parents[1]
# Last commit before native vector indexes; its loader rejects unknown types.
PRE_VECTOR_COMMIT = "a62e760d6"

HARNESS = r"""#include "disk.h"
#include "disk_api.h"
#include "disk_bulk.h"
#include <stdio.h>
#include <string.h>

/* old-reader DIR validate | old-reader DIR read|write METHOD TARGET BODY|- */
int main(int argc, char **argv) {
    if (argc != 3 && argc != 6) return 3;
    char error[256] = {0};
    bool writable = !strcmp(argv[2], "write");
    YDDisk *disk = yd_disk_open(argv[1], writable, 32768, error, sizeof(error));
    if (!disk) {
        printf("OPEN_REFUSED %s\n", error);
        return 0;
    }
    if (argc == 3) {
        YDDiskView view = yd_disk_view(disk);
        if (yd_disk_validate(disk, &view, error, sizeof(error))) puts("VALID");
        else printf("INVALID %s\n", error);
        yd_disk_close(disk);
        return 0;
    }
    YDDiskAPI api;
    if (!yd_disk_api_init(&api, disk, false)) {
        yd_disk_close(disk);
        return 4;
    }
    const char *body = strcmp(argv[5], "-") ? argv[5] : NULL;
    YDDiskReply reply = yd_disk_api_request(&api, argv[3], argv[4], (const unsigned char *)body,
                                            body ? strlen(body) : 0, NULL, NULL, false);
    printf("%d %s\n%.*s", reply.status, reply.revision, (int)reply.length,
           reply.body ? reply.body : "");
    yd_disk_reply_free(&reply);
    yd_disk_api_destroy(&api);
    yd_disk_close(disk);
    return 0;
}
"""

VECTOR = {
    "collection": "items",
    "name": "embedding",
    "fields": ["embedding"],
    "type": "vector",
    "dimensions": 3,
    "metric": "dot",
    "ann": {"type": "lsh", "tables": 2, "bits": 4},
}
PLAIN = [
    {"collection": "items", "name": "by-n", "fields": ["n"]},
    {"collection": "items", "name": "words", "fields": ["title"], "type": "text"},
]
DOCUMENTS = {
    "a": "n: 1\ntitle: first light\nembedding: [1, 0, 0]\n",
    "b": "n: 2\ntitle: second light\nembedding: [0, 2, 0]\n",
    "c": "n: 3\ntitle: third\nembedding: [0.5, 0.5, 3]\n",
}
QUERY = json.dumps({"filter": {"n": {"$gte": 2}}, "sort": {"n": "ascending"}})


class PreVectorBinaryCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not api.BINARY.is_file():
            raise AssertionError(f"native daemon missing: {api.BINARY}")
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root(), prefix="vector-compat-")
        cls.addClassCleanup(cls.allocation.cleanup)
        build = Path(cls.allocation.name)
        archive = subprocess.run(
            ["git", "archive", PRE_VECTOR_COMMIT, "yamora/src", "yamora/Makefile"],
            cwd=ROOT.parent,
            capture_output=True,
            timeout=60,
            check=True,
        )
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tree:
            for member in tree:
                if not member.isfile():
                    continue
                relative = Path(member.name)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or relative.parts[0] != "yamora"
                    or relative.parts[1] not in ("src", "Makefile")
                ):
                    raise AssertionError("archived native source escaped its owned allocation")
                path = build / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(tree.extractfile(member).read())
        old = build / "yamora"
        if (old / "src/vector.c").exists():
            raise AssertionError("pre-vector commit already contains vector support")
        sources = subprocess.run(
            ["make", "-s", "--no-print-directory", "-f", "-", "sources"],
            cwd=old,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        harness = build / "old_reader.c"
        harness.write_text(HARNESS)
        cls.old = build / "old-reader"
        compiled = subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=all",
                "-fsanitize=address,undefined",
                "-I",
                str(old / "src"),
                str(harness),
                *[str(old / name) for name in shlex.split(sources.stdout)],
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-o",
                str(cls.old),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )
        if compiled.returncode:
            raise AssertionError(
                "Compiler/infra failure is not behavioral red:\n" + compiled.stderr
            )

    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.store = self.server.data.with_name(self.server.data.name + "-disk")
        for name, source in DOCUMENTS.items():
            status, _, body = self.server.request(
                f"/v1/collections/items/documents/{name}",
                raw=source.encode(),
                method="PUT",
                write=True,
            )
            self.assertIn(status, (200, 201), body)

    def catalog(self, definitions):
        status, _, body = self.server.request(
            "/v1/indexes", {"indexes": definitions}, method="PUT", write=True
        )
        self.assertEqual(status, 200, body)

    def new_state(self):
        """What the current binary serves: catalog bytes, revision, query page."""
        status, headers, indexes = self.server.request("/v1/indexes", method="GET")
        self.assertEqual(status, 200, indexes)
        status, _, page = self.server.request("/v1/query/items", raw=QUERY.encode())
        self.assertEqual(status, 200, page)
        return indexes, headers["X-YamlDB-Revision"], page

    def stop(self):
        process = self.server.processes[-1]
        process.terminate()
        self.assertEqual(process.wait(timeout=20), 0)

    def restart(self):
        validated = subprocess.run(
            [str(api.BINARY), "--data-dir", str(self.store), "--validate-only"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.server.port = self.server.start(self.store)

    def old_binary(self, *arguments):
        result = subprocess.run(
            [str(self.old), str(self.store), *arguments],
            capture_output=True,
            text=True,
            timeout=60,
            env={
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("OPEN_REFUSED", result.stdout)
        return result.stdout

    def old_request(self, mode, method, target, body="-"):
        head, _, payload = self.old_binary(mode, method, target, body).partition("\n")
        status, _, revision = head.partition(" ")
        return int(status), revision, payload.encode()

    def test_pre_vector_binary_refuses_a_vector_catalog_instead_of_misreading_it(self):
        self.catalog([*PLAIN, VECTOR])
        indexes, revision, page = self.new_state()
        status, _, body = self.server.request(
            "/v1/vector-search/items", {"index": "embedding", "vector": [0, 0, 1], "k": 2}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual([row["id"] for row in json.loads(body)["documents"]], ["c", "a"])
        self.stop()

        # Validation, catalog reads, indexed queries and writes all refuse.
        verdict = self.old_binary("validate")
        self.assertTrue(verdict.startswith("INVALID"), verdict)
        status, _, body = self.old_request("read", "GET", "/v1/indexes")
        self.assertEqual(status, 503, body)
        self.assertIn(b"invalid_indexes", body)
        status, _, body = self.old_request("read", "POST", "/v1/query/items", QUERY)
        self.assertGreaterEqual(status, 400, body)
        self.assertNotIn(b'"documents"', body)
        status, _, body = self.old_request(
            "write", "PUT", "/v1/collections/items/documents/d", "n: 4\nembedding: [9, 9, 9]\n"
        )
        self.assertGreaterEqual(status, 400, body)
        # Even dropping the vector index needs the current binary.
        status, _, body = self.old_request(
            "write", "PUT", "/v1/indexes", json.dumps({"indexes": PLAIN})
        )
        self.assertGreaterEqual(status, 400, body)
        self.assertEqual(self.old_binary("validate"), verdict)

        # Nothing the old binary attempted reached the store.
        self.restart()
        self.assertEqual(self.new_state(), (indexes, revision, page))
        status, _, body = self.server.request("/v1/collections/items/documents/d", method="GET")
        self.assertEqual(status, 404, body)

    def test_catalog_without_vector_indexes_reads_identically_in_both_binaries(self):
        self.catalog(PLAIN)
        indexes, revision, page = self.new_state()
        self.stop()

        self.assertEqual(self.old_binary("validate"), "VALID\n")
        self.assertEqual(self.old_request("read", "GET", "/v1/indexes"), (200, revision, indexes))
        self.assertEqual(
            self.old_request("read", "POST", "/v1/query/items", QUERY), (200, revision, page)
        )
        # The old binary maintains the same catalog, and the new one accepts it.
        status, written, body = self.old_request(
            "write", "PUT", "/v1/collections/items/documents/d", "n: 4\ntitle: fourth light\n"
        )
        self.assertIn(status, (200, 201), body)
        self.assertNotEqual(written, revision)
        self.assertEqual(self.old_binary("validate"), "VALID\n")

        self.restart()
        current, now, rows = self.new_state()
        # The catalog body embeds the store revision, which the write moved.
        self.assertEqual(now, written)
        self.assertEqual(json.loads(current), {**json.loads(indexes), "revision": written})
        self.assertEqual([row["id"] for row in json.loads(rows)["documents"]], ["b", "c", "d"])
        status, _, body = self.server.request(
            "/v1/search/items", {"index": "words", "text": "light"}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            sorted(row["id"] for row in json.loads(body)["documents"]), ["a", "b", "d"]
        )


if __name__ == "__main__":
    unittest.main()
