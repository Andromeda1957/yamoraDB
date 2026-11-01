"""Native aggregations read one immutable generation with bounded reducer state."""

import concurrent.futures
import itertools
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from yamora.client import YamoraClient
from yamora.client import YamoraClientError
from yamora.tests import test_disk_api as disk_api
from yamora.tests.native_build import library_sources
from yamora.tests.test_document_api import BINARY

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_BYTES = 8192
SPILLED_GROUPS = 100000
SANITIZER_ENVIRONMENT = {
    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}


def documents_bytes(body):
    """The exact encoded documents array of one aggregate envelope."""
    text = body if isinstance(body, bytes) else body.encode()
    prefix = b'{"documents":'
    if not text.startswith(prefix):
        raise AssertionError(text[:200])
    return text[len(prefix) : text.index(b',"revision":')]


def spill_descriptors(pid, directory):
    """Descriptors the process holds on files inside the spill directory."""
    base = str(directory) + "/"
    found = []
    try:
        names = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return found
    for name in names:
        try:
            if os.readlink(f"/proc/{pid}/fd/{name}").startswith(base):
                found.append(f"/proc/{pid}/fd/{name}")
        except OSError:
            continue
    return found


def write_items(data, count):
    """2000 wide distinct keys overflow a 64 KiB aggregation memory limit."""
    items = data / "items"
    items.mkdir(parents=True)
    for i in range(count):
        (items / f"i{i:04d}.yaml").write_text(
            f"key: k{i:04d}-{'x' * 32}\nparity: {i % 2}\nv: {i}\nf: {i * 0.25 + 0.001!r}\n"
        )
    return data


def harness_command(output, *defines):
    return [
        os.environ.get("CC", "cc"),
        "-std=c17",
        "-O1",
        "-g",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-fsanitize=address,undefined",
        # Small native bounds reach the candidate fallbacks and the
        # spilled-group ceiling without millions of documents.
        f"-DYD_AGGREGATE_CANDIDATE_BYTES={CANDIDATE_BYTES}",
        f"-DYD_AGGREGATE_SPILLED_GROUPS={SPILLED_GROUPS}",
        *defines,
        str(ROOT / "tests/aggregate_harness.c"),
        *library_sources(),
        "-pthread",
        "-lyaml",
        "-lm",
        "-lcrypto",
        "-o",
        str(output),
    ]


class StreamingAggregateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "aggregate"
        # The second build takes the named-file fallback that filesystems
        # without O_TMPFILE use.
        cls.named_binary = Path(temporary.name) / "aggregate-named"
        builds = [
            subprocess.Popen(
                harness_command(output, *defines),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for output, defines in (
                (cls.binary, ()),
                (cls.named_binary, ("-DYD_AGGREGATE_SPILL_NAMED_FILES",)),
            )
        ]
        for build in builds:
            _, stderr = build.communicate(timeout=900)
            if build.returncode:
                raise AssertionError(stderr.decode(errors="replace"))

    def reduce(self, pipeline, *, count=1000000, groups=32, width=0):
        return subprocess.run(
            [
                str(self.binary),
                json.dumps(pipeline),
                str(count),
                str(groups),
                str(width),
            ],
            capture_output=True,
            text=True,
            timeout=90,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )

    def spill(
        self,
        pipeline,
        *,
        count,
        groups,
        width=0,
        memory=65536,
        max_bytes=0,
        total=0,
        request=0,
        hold=0,
        configured=True,
        binary=None,
    ):
        """Reduce with disk use allowed; return (result, facts parsed from stderr)."""
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root).resolve() / "spill"
            directory.mkdir(mode=0o700)
            result = subprocess.run(
                [
                    str(binary or self.binary),
                    "--spill",
                    str(directory) if configured else "-",
                    str(total),
                    str(request),
                    str(memory),
                    str(max_bytes),
                    str(hold),
                    json.dumps(pipeline),
                    str(count),
                    str(groups),
                    str(width),
                ],
                capture_output=True,
                text=True,
                timeout=300,
                env={**os.environ, **SANITIZER_ENVIRONMENT},
            )
            left = sorted(path.name for path in directory.iterdir())
        facts = {"left": left}
        for line in result.stderr.splitlines():
            if line.startswith("explain="):
                facts["explain"] = json.loads(line[len("explain=") :])
            elif line.startswith(("spill_files=", "closed_files=")):
                for item in line.split():
                    name, value = item.split("=")
                    facts[name] = int(value)
        return result, facts

    def test_spilled_reducers_equal_memory_results_and_seal_every_block(self):
        group = {
            "$group": {
                "_id": "$key",
                "n": {"$sum": 1},
                "total": {"$sum": "$fraction"},
                "avg": {"$avg": "$value"},
                "low": {"$min": "$value"},
                "high": {"$max": "$fraction"},
            }
        }
        cases = (
            ([group, {"$sort": {"total": -1}}, {"$limit": 40}], 20000, 5000),
            ([group, {"$match": {"n": 4}}, {"$sort": {"high": 1}}, {"$skip": 3}], 20000, 5000),
            (
                [
                    {
                        "$group": {
                            "_id": {"k": "$key", "odd": "$missing"},
                            "s": {"$sum": "$fraction"},
                        }
                    },
                    {"$sort": {"s": 1}},
                    {"$limit": 25},
                ],
                20000,
                3000,
            ),
            (
                [
                    {"$set": {"copy": "$fraction"}},
                    {"$match": {"value": {"$gte": 100}}},
                    {"$sort": {"copy": -1}},
                    {"$skip": 5},
                    {"$limit": 40},
                ],
                6000,
                6000,
            ),
            (
                [
                    {"$sort": {"fraction": -1}},
                    {
                        "$group": {
                            "_id": "$key",
                            "s": {"$sum": "$fraction"},
                            "top": {"$max": "$value"},
                        }
                    },
                    {"$sort": {"s": 1}},
                    {"$limit": 30},
                ],
                20000,
                4000,
            ),
            (
                [
                    {
                        "$facet": {
                            "a": [group, {"$sort": {"total": -1}}, {"$limit": 5}],
                            "b": [
                                {
                                    "$facet": {
                                        "c": [{"$count": "n"}],
                                        "d": [
                                            {"$group": {"_id": "$key", "n": {"$sum": 1}}},
                                            {"$group": {"_id": "$n", "groups": {"$sum": 1}}},
                                        ],
                                    }
                                }
                            ],
                        }
                    }
                ],
                20000,
                5000,
            ),
        )
        # The 64 KiB limit is already exceeded before the first group, so every
        # input is replayed from disk. Under 1 MiB about 1,500 live groups freeze
        # mid-stream and their saved states merge with the inputs that follow.
        for (pipeline, count, groups), limit in itertools.product(cases, (65536, 1 << 20)):
            with self.subTest(pipeline=pipeline, limit=limit):
                memory = self.reduce(pipeline, count=count, groups=groups, width=24)
                self.assertEqual(memory.returncode, 0, memory.stderr)
                spilled, facts = self.spill(
                    pipeline, count=count, groups=groups, width=24, memory=limit
                )
                self.assertEqual(spilled.returncode, 0, spilled.stderr)
                self.assertEqual(spilled.stdout, memory.stdout)
                self.assertTrue(facts["explain"]["spill"])
                self.assertGreaterEqual(facts["explain"]["spill_runs"], 2)
                self.assertEqual(facts["spill_files"], 1)
                self.assertEqual(
                    (facts["plaintext"], facts["exposed"], facts["entries"]), (0, 0, 0)
                )
                self.assertEqual(
                    (facts["closed_files"], facts["in_use"], facts["left"]), (0, 0, [])
                )

    def test_named_spill_fallback_unlinks_each_private_file_before_writing(self):
        pipeline = [
            {"$group": {"_id": "$key", "s": {"$sum": "$fraction"}, "n": {"$sum": 1}}},
            {"$sort": {"s": -1}},
            {"$limit": 20},
        ]
        memory = self.reduce(pipeline, count=20000, groups=5000, width=24)
        self.assertEqual(memory.returncode, 0, memory.stderr)
        spilled, facts = self.spill(
            pipeline, count=20000, groups=5000, width=24, binary=self.named_binary
        )
        self.assertEqual(spilled.returncode, 0, spilled.stderr)
        self.assertEqual(spilled.stdout, memory.stdout)
        self.assertTrue(facts["explain"]["spill"])
        self.assertEqual(facts["spill_files"], 1)
        self.assertEqual((facts["plaintext"], facts["exposed"], facts["entries"]), (0, 0, 0))
        self.assertEqual((facts["closed_files"], facts["in_use"], facts["left"]), (0, 0, []))

    def test_spill_raises_group_count_to_its_documented_ceiling_for_many_and_large_keys(self):
        histogram = [
            {"$group": {"_id": "$key", "n": {"$sum": 1}}},
            {"$group": {"_id": "$n", "groups": {"$sum": 1}}},
        ]
        memory = self.reduce(histogram, count=70000, groups=70000)
        self.assertEqual(memory.returncode, 2)
        self.assertIn("group/state limit", memory.stderr)
        spilled, facts = self.spill(histogram, count=70000, groups=70000)
        self.assertEqual(spilled.returncode, 0, spilled.stderr)
        self.assertEqual(json.loads(spilled.stdout), [{"_id": 1, "groups": 70000}])
        self.assertEqual(facts["explain"]["spilled_row_limit"], SPILLED_GROUPS)
        # Under the largest memory limit the 65,536-group bound alone starts the spill.
        roomy, facts = self.spill(histogram, count=70000, groups=70000, memory=48 << 20)
        self.assertEqual(roomy.returncode, 0, roomy.stderr)
        self.assertEqual(roomy.stdout, spilled.stdout)
        self.assertTrue(facts["explain"]["spill"])
        over, _ = self.spill(histogram, count=SPILLED_GROUPS + 1, groups=SPILLED_GROUPS + 1)
        self.assertEqual((over.returncode, over.stdout), (2, ""))
        self.assertIn("spilled group limit exceeded", over.stderr)
        large = [{"$group": {"_id": "$key", "n": {"$sum": 1}}}, {"$count": "groups"}]
        memory = self.reduce(large, count=1700, groups=1700, width=40000)
        self.assertEqual(memory.returncode, 2)
        self.assertIn("64 MiB", memory.stderr)
        spilled, facts = self.spill(large, count=1700, groups=1700, width=40000, memory=4 << 20)
        self.assertEqual(spilled.returncode, 0, spilled.stderr)
        self.assertEqual(json.loads(spilled.stdout), [{"groups": 1700}])
        self.assertEqual(facts["plaintext"], 0)

    def test_spill_byte_caps_and_unconfigured_servers_fail_closed(self):
        pipeline = [{"$group": {"_id": "$key", "n": {"$sum": 1}}}]
        for options, expected in (
            ({"max_bytes": 65536}, "aggregate spill exceeds the request limit"),
            ({"request": 65536}, "aggregate spill exceeds the request limit"),
            ({"request": 65536, "max_bytes": 65537}, "maxSpillBytes exceeds the server request"),
            (
                {"total": 1 << 20, "request": 1 << 20, "hold": 1000000},
                "aggregate spill exceeds the server limit",
            ),
            ({"configured": False}, "aggregate disk use is not enabled on this server"),
        ):
            with self.subTest(options=options):
                result, facts = self.spill(pipeline, count=20000, groups=5000, width=24, **options)
                self.assertEqual((result.returncode, result.stdout), (2, ""))
                self.assertIn(expected, result.stderr)
                if options.get("configured", True):
                    self.assertEqual((facts["closed_files"], facts["in_use"]), (0, 0))
                self.assertEqual(facts["left"], [])
        result, facts = self.spill(pipeline, count=20000, groups=5000, width=24, max_bytes=1 << 26)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(facts["explain"]["spill_request_limit"], 1 << 26)
        self.assertLessEqual(facts["explain"]["spill_bytes"], 1 << 26)

    def test_index_input_matches_unindexed_scan_through_every_planner_path(self):
        def stage(pipeline):
            return {"pipeline": pipeline, "explain": True}

        sums = {"$group": {"_id": "$group", "s": {"$sum": "$fraction"}, "n": {"$sum": 1}}}
        cases = (
            # pipeline, plan, index, order, fallback, examined
            (
                [{"$match": {"number": {"$lt": 100}}}, sums],
                ("index", "number", "document-id", None, 100),
            ),
            (
                [{"$match": {"rank": {"$lt": 200}}}, {"$set": {"copy": "$fraction"}}],
                ("index", "rank", "document-id", None, 200),
            ),
            (
                [{"$match": {"rank": {"$gte": 300}}}, sums],
                ("scan", None, "document-id", "candidate-limit", 1024),
            ),
            (
                [{"$match": {"number": {"$gte": 200}}}, sums],
                ("index", "number", "document-id", None, 824),
            ),
            (
                [{"$match": {"tags": "a"}}, {"$count": "n"}],
                ("index", "tags", "document-id", None, 1024),
            ),
            (
                [{"$match": {"group": 3}}, {"$sort": {"number": -1}}, sums],
                ("index", "group", "document-id", None, None),
            ),
            (
                [{"$sort": {"number": 1}}, {"$set": {"n": "$number"}}, {"$limit": 5}],
                ("index", "number", "index", None, 1024),
            ),
            (
                [
                    {"$match": {"group": {"$gte": 2}}},
                    {"$sort": {"group": 1}},
                    {"$set": {"x": "$number"}},
                    {"$limit": 300},
                ],
                ("index", "group", "index", None, None),
            ),
            (
                [{"$sort": {"group": 1}}, {"$set": {"x": "$number"}}, {"$limit": 10}],
                ("index", "group", "index", None, 1024),
            ),
            (
                [{"$sort": {"rank": -1}}, {"$set": {"r": "$rank"}}, {"$limit": 3}],
                ("scan", None, "document-id", None, 1024),
            ),
            (
                [
                    {"$match": {"number": {"$lt": 50}}},
                    {
                        "$facet": {
                            "a": [{"$facet": {"b": [{"$count": "n"}]}}],
                            "c": [{"$group": {"_id": {"g": "$group"}, "n": {"$sum": 1}}}],
                        }
                    },
                ],
                ("index", "number", "document-id", None, 50),
            ),
        )
        requests = [stage(pipeline) for pipeline, _ in cases]
        with tempfile.TemporaryDirectory() as root:
            for name in ("indexed", "plain"):
                (Path(root) / name).mkdir(mode=0o700)
            result = subprocess.run(
                [str(self.binary), "--index-input", root, json.dumps(requests)],
                capture_output=True,
                timeout=300,
                env={**os.environ, **SANITIZER_ENVIRONMENT},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 2 * len(cases))
        for index, (pipeline, (plan, name, order, fallback, examined)) in enumerate(cases):
            with self.subTest(pipeline=pipeline):
                indexed, plain = lines[2 * index], lines[2 * index + 1]
                self.assertFalse(indexed.startswith(b"ERROR"), indexed)
                self.assertFalse(plain.startswith(b"ERROR"), plain)
                self.assertEqual(documents_bytes(indexed), documents_bytes(plain))
                indexed, plain = json.loads(indexed), json.loads(plain)
                self.assertEqual(plain["documents_examined"], 1024)
                self.assertEqual(plain["explain"]["input"]["plan"], "scan")
                found = indexed["explain"]["input"]
                self.assertEqual(
                    (found["plan"], found["index"], found["order"], found["fallback"]),
                    (plan, name, order, fallback),
                )
                if examined is not None:
                    self.assertEqual(indexed["documents_examined"], examined)
                elif plan == "index":
                    self.assertLess(indexed["documents_examined"], 1024)
                self.assertEqual(
                    indexed["explain"]["scan"],
                    "index-order" if order == "index" else "primary-id-order",
                )

    def test_million_documents_stream_into_small_state_with_exact_reductions(self):
        result = self.reduce(
            [
                {
                    "$group": {
                        "_id": "$key",
                        "n": {"$sum": 1},
                        "total": {"$sum": "$value"},
                        "avg": {"$avg": "$value"},
                        "min": {"$min": "$value"},
                        "max": {"$max": "$value"},
                    }
                }
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 32)
        for key, row in enumerate(rows):
            self.assertEqual(
                row,
                {
                    "_id": key,
                    "n": 31250,
                    "total": 31250 * key + 32 * (31249 * 31250 // 2),
                    "avg": key + 32 * 31249 / 2,
                    "min": key,
                    "max": key + 32 * 31249,
                },
            )
        self.assertEqual(sum(row["total"] for row in rows), 499999500000)
        state = int(result.stderr.split("state_bytes=")[1].splitlines()[0])
        self.assertLess(state, 128 * 1024)

    def test_primary_reference_to_another_collection_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), "--corrupt", root], capture_output=True, text=True, timeout=30
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_groups_shared_facet_memory_and_output_limits_fail_without_partial_results(self):
        group = {"$group": {"_id": "$key", "n": {"$sum": 1}}}
        for pipeline, count, groups, width, expected in (
            ([group], 65537, 65537, 0, "group/state limit"),
            ([{"$facet": {"one": [group], "two": [group]}}], 1000, 1000, 40000, "64 MiB"),
            ([group], 500, 500, 40000, "16 MiB"),
            # Nested facets draw on the same request budget as their parents.
            (
                [
                    {
                        "$facet": {
                            "outer": [
                                {"$facet": {"inner": [{"$facet": {"deep": [group]}}], "x": [group]}}
                            ],
                        }
                    }
                ],
                1000,
                1000,
                40000,
                "64 MiB",
            ),
        ):
            with self.subTest(expected=expected):
                result = self.reduce(pipeline, count=count, groups=groups, width=width)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(expected, result.stderr)


class DiskAggregateTests(unittest.TestCase):
    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )

    def aggregate(self, pipeline, *, collection="people", revision=None):
        request = {"pipeline": pipeline}
        if revision is not None:
            request["revision"] = revision
        status, headers, body = self.server.request(f"/v1/aggregate/{collection}", request)
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        self.assertEqual(result["revision"], headers["X-YamlDB-Revision"])
        return result

    def add_carol(self):
        self.client.put("people", "carol", b"name: Carol\ncountry: US\nrating: 2800\n")

    def spill_daemon(self, directory=None):
        """A second daemon over 2000 items with a private spill directory."""
        root = self.server.root.resolve()
        if directory is None:
            directory = root / "spill"
            directory.mkdir(mode=0o700)
        data = root / "spill-data"
        if not data.exists():
            write_items(data, 2000)
        port = self.server.start(
            data,
            "--aggregate-spill-directory",
            str(directory),
            "--aggregate-memory-limit",
            "65536",
        )
        return port, directory

    def daemon_exit(self, *extra):
        data = self.server.root / "small-data"
        data.mkdir(exist_ok=True)
        result = subprocess.run(
            [
                str(BINARY),
                "--data-dir",
                str(data),
                "--port",
                "0",
                "--auth-token-file",
                str(self.server.read),
                "--write-auth-token-file",
                str(self.server.write),
                *extra,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotIn("listening", result.stdout)
        return result.returncode, result.stderr

    def test_disk_use_options_are_validated_first_and_need_a_configured_server(self):
        pipeline = [{"$group": {"_id": "$country", "n": {"$sum": 1}}}]

        def status(**options):
            body = {"pipeline": pipeline, **options}
            return self.server.request("/v1/aggregate/people", body)[0]

        self.assertEqual(status(allowDiskUse=False), 200)
        for options in (
            {"allowDiskUse": True},
            {"allowDiskUse": "true"},
            {"allowDiskUse": 1},
            {"maxSpillBytes": 65536},
            {"allowDiskUse": False, "maxSpillBytes": 65536},
            # Options are checked before the pinned revision, which is stale here.
            {"allowDiskUse": "yes", "revision": "0000000000000000"},
        ):
            with self.subTest(options=options):
                self.assertEqual(status(**options), 400)
        self.assertEqual(status(revision="0000000000000000"), 412)
        with self.assertRaises(YamoraClientError):
            self.client.aggregate("people", pipeline, allow_disk_use=True)

    def test_spilled_http_aggregation_matches_memory_and_enforces_request_caps(self):
        port, directory = self.spill_daemon()

        def run(pipeline, **options):
            body = {"pipeline": pipeline, **options}
            return self.server.request("/v1/aggregate/items", body, port=port)

        group = [
            {
                "$group": {
                    "_id": {"k": "$key", "p": "$parity"},
                    "n": {"$sum": 1},
                    "s": {"$sum": "$f"},
                }
            },
            {"$sort": {"s": -1}},
            {"$limit": 40},
        ]
        for pipeline in (
            group,
            [{"$sort": {"f": -1}}, {"$set": {"g": "$v"}}, {"$limit": 25}],
            [
                {"$group": {"_id": "$key", "v": {"$max": "$v"}}},
                {"$group": {"_id": None, "groups": {"$sum": 1}, "top": {"$max": "$v"}}},
            ],
        ):
            with self.subTest(pipeline=pipeline):
                status, _, memory = run(pipeline)
                self.assertEqual(status, 200, memory)
                status, _, spilled = run(pipeline, allowDiskUse=True, explain=True)
                self.assertEqual(status, 200, spilled)
                self.assertEqual(documents_bytes(spilled), documents_bytes(memory))
                explain = json.loads(spilled)["explain"]
                self.assertTrue(explain["spill"])
                self.assertGreater(explain["spill_bytes"], 0)
        status, _, body = run(group, allowDiskUse=True, maxSpillBytes=1 << 26)
        self.assertEqual(status, 200, body)
        self.assertEqual(documents_bytes(body), documents_bytes(run(group)[2]))
        for options in (
            {"allowDiskUse": True, "maxSpillBytes": 65536},
            {"allowDiskUse": True, "maxSpillBytes": 1 << 40},
            {"allowDiskUse": True, "maxSpillBytes": 0},
            {"allowDiskUse": True, "maxSpillBytes": True},
            {"allowDiskUse": True, "maxSpillBytes": 65536.5},
        ):
            with self.subTest(options=options):
                self.assertEqual(run(group, **options)[0], 400)
        self.assertEqual(list(directory.iterdir()), [])

    def test_spill_directory_startup_sweeps_only_owned_spill_files_and_refuses_unsafe_options(
        self,
    ):
        root = self.server.root.resolve()
        directory = root / "swept"
        directory.mkdir(mode=0o700)
        prefix = ".yamora-spill-"
        (directory / (prefix + "0123456789abcdef" * 2)).write_bytes(b"left by a crash")
        kept = [
            prefix + "0123456789abcdef" * 2 + "0",
            prefix + "0123456789ABCDEF" * 2,
            prefix + "f" * 31,
            "notes.txt",
        ]
        for name in kept:
            (directory / name).write_bytes(b"not a spill file")
        outside = root / "outside"
        outside.write_text("keep")
        (directory / (prefix + "a" * 32)).symlink_to(outside)
        (directory / (prefix + "b" * 32)).mkdir()
        self.spill_daemon(directory)
        self.assertEqual(
            sorted(path.name for path in directory.iterdir()),
            sorted([*kept, prefix + "a" * 32, prefix + "b" * 32]),
        )
        self.assertEqual(outside.read_text(), "keep")
        linked = root / "linked"
        linked.symlink_to(directory)
        shared = root / "shared"
        shared.mkdir()
        shared.chmod(0o755)
        for extra, code, message in (
            (("--aggregate-spill-directory", str(linked)), 1, "symbolic link"),
            (("--aggregate-spill-directory", str(shared)), 1, "mode 0700"),
            (("--aggregate-spill-directory", "swept"), 1, "absolute path"),
            (("--aggregate-spill-directory", str(root / "missing")), 1, "unavailable"),
            (("--aggregate-spill-limit", "1048576"), 1, "require --aggregate-spill-directory"),
            (
                (
                    "--aggregate-spill-directory",
                    str(directory),
                    "--aggregate-spill-limit",
                    "65536",
                    "--aggregate-spill-request-limit",
                    "131072",
                ),
                1,
                "request limit within the server limit",
            ),
            (("--aggregate-memory-limit", "1024"), 2, "--aggregate-memory-limit"),
            (("--aggregate-spill-limit", "12x"), 2, "--aggregate-spill-limit"),
            (
                (
                    "--aggregate-spill-directory",
                    str(directory),
                    "--aggregate-spill-directory",
                    str(directory),
                ),
                2,
                "--aggregate-spill-directory",
            ),
            (("--aggregate-spill-directory",), 2, "--aggregate-spill-directory"),
        ):
            with self.subTest(extra=extra):
                status, stderr = self.daemon_exit(*extra)
                self.assertEqual(status, code, stderr)
                self.assertIn(message, stderr)

    def test_killed_spilling_daemon_leaves_no_file_and_restarts_cleanly(self):
        port, directory = self.spill_daemon()
        process = self.server.processes[-1]
        pipeline = [{"$group": {"_id": "$key", "n": {"$sum": 1}}}, {"$count": "groups"}]
        request = {"pipeline": pipeline, "allowDiskUse": True}
        stop = threading.Event()

        def load():
            while not stop.is_set():
                try:
                    self.server.request("/v1/aggregate/items", request, port=port)
                except OSError:
                    return

        worker = threading.Thread(target=load, daemon=True)
        worker.start()
        try:
            deadline = time.monotonic() + 120
            while not spill_descriptors(process.pid, directory):
                self.assertLess(time.monotonic(), deadline, "no spill file was observed")
                time.sleep(0.001)
            process.kill()
            process.wait(timeout=30)
        finally:
            stop.set()
            worker.join(timeout=30)
        self.server.processes.remove(process)
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(list(directory.iterdir()), [])
        port, _ = self.spill_daemon(directory)
        status, _, body = self.server.request("/v1/aggregate/items", request, port=port)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["documents"], [{"groups": 2000}])
        self.assertEqual(list(directory.iterdir()), [])

    def test_index_backed_input_matches_unindexed_results_and_keeps_revision_pins(self):
        data = self.server.root / "index-data"
        items = data / "items"
        items.mkdir(parents=True)
        for i in range(300):
            (items / f"d{i:03d}.yaml").write_text(
                f"number: {i}\nrank: {(i * 37) % 300}\ngroup: {i % 7}\nf: {i * 0.1 + 0.001!r}\n"
            )
        port = self.server.start(data)

        def run(pipeline, expected=200, **options):
            body = {"pipeline": pipeline, "explain": True, **options}
            status, _, result = self.server.request("/v1/aggregate/items", body, port=port)
            self.assertEqual(status, expected, result)
            return result

        sums = {"$group": {"_id": "$group", "s": {"$sum": "$f"}, "n": {"$sum": 1}}}
        cases = (
            ([{"$match": {"number": {"$gte": 250}}}, sums], "document-id", 50),
            (
                [
                    {"$match": {"rank": {"$lt": 40}}},
                    {"$sort": {"f": -1}},
                    {"$set": {"r": "$rank"}},
                    {"$limit": 10},
                ],
                "document-id",
                40,
            ),
            ([{"$sort": {"number": 1}}, {"$set": {"n": "$number"}}, {"$limit": 5}], "index", 300),
            (
                [{"$match": {"group": 3, "number": {"$lt": 100}}}, {"$count": "n"}],
                "document-id",
                100,
            ),
        )
        before = [run(pipeline) for pipeline, _, _ in cases]
        client = YamoraClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )
        client.create_index("items", "number", ["number"])
        client.create_index("items", "rank", ["rank"])
        for (pipeline, order, examined), old in zip(cases, before, strict=True):
            with self.subTest(pipeline=pipeline):
                new = run(pipeline)
                self.assertEqual(documents_bytes(new), documents_bytes(old))
                old, new = json.loads(old), json.loads(new)
                self.assertEqual(old["documents_examined"], 300)
                self.assertEqual(old["explain"]["input"]["plan"], "scan")
                self.assertEqual(new["explain"]["input"]["plan"], "index")
                self.assertEqual(new["explain"]["input"]["order"], order)
                self.assertEqual(new["documents_examined"], examined)
        revision = client.snapshot_revision()
        run(cases[0][0], revision=revision)
        client.put("items", "d999", b"number: 999\n")
        run(cases[0][0], 412, revision=revision)

    def test_structured_group_keys_order_by_declared_fields_and_coalesce_numbers_and_nulls(self):
        for name, body in {
            "a": b"ns: x\nkind: 1\nv: 1\n",
            "b": b"ns: x\nkind: 1.0\nv: 2\n",
            "c": b"ns: a\nv: 4\n",
            "d": b"ns: a\nkind: null\nv: 8\n",
            "e": b"kind: 2\nv: 16\n",
        }.items():
            self.client.put("keyed", name, body)
        self.client.put("listed", "a", b"kind: [1]\n")

        def rows(key):
            result = self.aggregate(
                [{"$group": {"_id": key, "s": {"$sum": "$v"}}}], collection="keyed"
            )
            return [(list(row["_id"].items()), row["s"]) for row in result["documents"]]

        self.assertEqual(
            rows({"ns": "$ns", "kind": "$kind"}),
            [
                ([("ns", None), ("kind", 2)], 16),
                ([("ns", "a"), ("kind", None)], 12),
                ([("ns", "x"), ("kind", 1)], 3),
            ],
        )
        self.assertEqual(
            rows({"z": "$kind", "a": "$ns"}),
            [
                ([("z", None), ("a", "a")], 12),
                ([("z", 1), ("a", "x")], 3),
                ([("z", 2), ("a", None)], 16),
            ],
        )
        for collection, key in (
            ("keyed", {"a": "$ns", "$b": "$kind"}),
            ("keyed", {f"f{i}": "$ns" for i in range(33)}),
            ("listed", {"k": "$kind"}),
        ):
            with self.subTest(key=key):
                status, _, _ = self.server.request(
                    f"/v1/aggregate/{collection}",
                    {"pipeline": [{"$group": {"_id": key, "n": {"$sum": 1}}}]},
                )
                self.assertEqual(status, 400)

    def test_nested_facets_are_bounded_by_depth_and_shared_stage_budget(self):
        self.add_carol()

        def nest(depth, inner):
            for level in range(depth):
                inner = [{"$facet": {f"l{level}": inner}}]
            return inner

        count = [{"$count": "n"}]
        expected = [{"n": 3}]
        for level in range(4):
            expected = [{f"l{level}": expected}]
        result = self.aggregate(nest(4, count))
        self.assertEqual(result["documents"], expected)
        self.assertEqual(result["documents_examined"], 3)
        branch = [{"$match": {"rating": {"$gte": 0}}}] * 30 + count
        two = self.aggregate([{"$facet": {"a": branch, "b": branch}}])
        self.assertEqual(two["documents"], [{"a": [{"n": 3}], "b": [{"n": 3}]}])
        lookup = {
            "$lookup": {"from": "people", "localField": "name", "foreignField": "name", "as": "x"}
        }
        for pipeline in (
            nest(5, count),
            [{"$facet": {"a": branch, "b": branch, "c": branch}}],
            nest(1, [lookup]),
            nest(3, [lookup]),
        ):
            with self.subTest(pipeline=pipeline):
                status, _, _ = self.server.request("/v1/aggregate/people", {"pipeline": pipeline})
                self.assertEqual(status, 400)

    def test_python_method_empty_input_and_post_reducer_stage_order(self):
        before = self.server.change_page()["next_after"]
        source = self.client.get("people", "alice")
        result = self.client.aggregate(
            "people",
            [
                {"$group": {"_id": "$country", "total": {"$sum": "$rating"}}},
                {"$sort": {"total": -1}},
                {"$limit": 1},
                {"$match": {"_id": "US"}},
            ],
        )
        self.assertEqual(result["documents"], [])
        for reducer in ({"$group": {"_id": None, "n": {"$sum": 1}}}, {"$count": "n"}):
            self.assertEqual(self.client.aggregate("absent", [reducer])["documents"], [])
        self.assertEqual(self.client.get("people", "alice"), source)
        self.assertEqual(self.server.change_page()["next_after"], before)
        for pipeline in (
            # One input sort may precede the reducer; a second may not.
            [{"$sort": {"a": 1}}, {"$sort": {"b": 1}}, {"$count": "n"}],
            [{"$limit": 1}, {"$count": "n"}],
            [{"$match": {}}],
            [{"$group": {"_id": "$$ROOT"}}],
            [{"$facet": {"a": [{"$unknown": {}}]}}],
        ):
            with self.subTest(pipeline=pipeline):
                self.assertEqual(
                    self.server.request("/v1/aggregate/absent", {"pipeline": pipeline})[0], 400
                )

    def test_exact_integer_sum_promotion_and_scalar_extrema(self):
        self.client.put("amounts", "a", b"v: 9007199254740993\ns: alpha\n")
        self.client.put("amounts", "b", b"v: 2\ns: omega\n")
        result = self.aggregate(
            [
                {
                    "$group": {
                        "_id": None,
                        "total": {"$sum": "$v"},
                        "lo": {"$min": "$s"},
                        "hi": {"$max": "$s"},
                        "empty": {"$avg": "$missing"},
                    }
                }
            ],
            collection="amounts",
        )
        self.assertEqual(
            result["documents"],
            [
                {
                    "_id": None,
                    "total": 9007199254740995,
                    "lo": "alpha",
                    "hi": "omega",
                    "empty": None,
                }
            ],
        )
        self.client.put("amounts", "a", b"v: 9223372036854775807\n")
        total = self.aggregate(
            [{"$group": {"_id": None, "total": {"$sum": "$v"}}}], collection="amounts"
        )["documents"][0]["total"]
        self.assertIsInstance(total, float)
        self.assertGreater(total, 9e18)

    def test_custom_bucket_output_half_open_boundaries_and_protocol_rejection(self):
        result = self.aggregate(
            [
                {
                    "$bucket": {
                        "groupBy": "$rating",
                        "boundaries": [2400, 2600, 2800],
                        "output": {"sum": {"$sum": "$rating"}},
                    }
                }
            ]
        )
        self.assertEqual(
            result["documents"], [{"_id": 2400, "sum": 2400}, {"_id": 2600, "sum": 2600}]
        )
        for options in (
            {"default": 2000},
            {"boundaries": [0, "other"]},
            {"unknown": True},
        ):
            spec = {"groupBy": "$rating", "boundaries": [0, 2500], **options}
            self.assertEqual(
                self.server.request("/v1/aggregate/people", {"pipeline": [{"$bucket": spec}]})[0],
                400,
            )
        for request, headers in (
            ({"pipeline": [{"$count": "n"}], "unexpected": True}, {}),
            ({"pipeline": [{"$count": "n"}], "revision": "bad"}, {}),
            ({"pipeline": [{"$count": "n"}]}, {"If-Match": '"0000000000000000"'}),
        ):
            self.assertEqual(
                self.server.request("/v1/aggregate/people", request, headers=headers)[0], 400
            )

    def test_group_reductions_filter_sort_and_limit_use_read_credential(self):
        self.add_carol()
        result = self.aggregate(
            [
                {"$match": {"rating": {"$gte": 2000}}},
                {
                    "$group": {
                        "_id": "$country",
                        "count": {"$sum": 1},
                        "total": {"$sum": "$rating"},
                        "average": {"$avg": "$rating"},
                        "low": {"$min": "$rating"},
                        "high": {"$max": "$rating"},
                    }
                },
                {"$sort": {"total": -1}},
                {"$limit": 1},
            ]
        )
        self.assertEqual(
            result["documents"],
            [
                {
                    "_id": "US",
                    "count": 2,
                    "total": 5200,
                    "average": 2600,
                    "low": 2400,
                    "high": 2800,
                },
            ],
        )
        self.assertEqual(result["documents_examined"], 3)

    def test_bucket_boundaries_and_default_are_explicit(self):
        self.add_carol()
        result = self.aggregate(
            [
                {
                    "$bucket": {
                        "groupBy": "$rating",
                        "boundaries": [0, 2500, 2700],
                        "default": "other",
                    }
                },
            ]
        )
        self.assertEqual(
            result["documents"],
            [
                {"_id": 0, "count": 1},
                {"_id": 2500, "count": 1},
                {"_id": "other", "count": 1},
            ],
        )
        status, _, _ = self.server.request(
            "/v1/aggregate/people",
            {
                "pipeline": [
                    {"$bucket": {"groupBy": "$rating", "boundaries": [0, 2500]}},
                ]
            },
        )
        self.assertEqual(status, 400)

    def test_facets_share_input_and_have_independent_reducers(self):
        self.add_carol()
        result = self.aggregate(
            [
                {
                    "$facet": {
                        "countries": [
                            {"$group": {"_id": "$country", "n": {"$sum": 1}}},
                            {"$sort": {"_id": 1}},
                        ],
                        "high": [{"$match": {"rating": {"$gte": 2500}}}, {"$count": "players"}],
                        "empty": [{"$match": {"rating": {"$gt": 9999}}}, {"$count": "players"}],
                    }
                }
            ]
        )
        self.assertEqual(
            result["documents"],
            [
                {
                    "countries": [{"_id": "GB", "n": 1}, {"_id": "US", "n": 2}],
                    "high": [{"players": 2}],
                    "empty": [],
                }
            ],
        )
        self.assertEqual(result["documents_examined"], 3)

    def test_numeric_keys_coalesce_and_missing_numeric_inputs_are_ignored(self):
        for name, body in {
            "a": b"key: 1\nvalue: 2\n",
            "b": b"key: 1.0\nvalue: 4\n",
            "c": b"key: null\nvalue: text\n",
            "d": b"unrelated: true\n",
        }.items():
            self.client.put("values", name, body)
        result = self.aggregate(
            [
                {
                    "$group": {
                        "_id": "$key",
                        "sum": {"$sum": "$value"},
                        "avg": {"$avg": "$value"},
                        "n": {"$sum": 1},
                    }
                }
            ],
            collection="values",
        )
        self.assertEqual(
            result["documents"],
            [
                {"_id": None, "sum": 0, "avg": None, "n": 2},
                {"_id": 1, "sum": 6, "avg": 3, "n": 2},
            ],
        )

    def test_rejects_unknown_stages_accumulators_invalid_bounds_and_stale_revision(self):
        for pipeline in (
            [{"$unknown": {}}],
            [{"$group": {"_id": None, "v": {"$unknown": 1}}}],
            [{"$bucket": {"groupBy": "$rating", "boundaries": [2, 1]}}],
            [{"$group": {"n": {"$sum": 1}}}],
            [{"$facet": {"nested": [{"$facet": {}}]}}],
        ):
            with self.subTest(pipeline=pipeline):
                status, _, _ = self.server.request("/v1/aggregate/people", {"pipeline": pipeline})
                self.assertEqual(status, 400)
        previous = self.client.snapshot_revision()
        self.add_carol()
        status, _, _ = self.server.request(
            "/v1/aggregate/people",
            {
                "pipeline": [{"$count": "players"}],
                "revision": previous,
            },
        )
        self.assertEqual(status, 412)
        status, _, _ = self.server.request(
            "/v1/aggregate/people", {"pipeline": [{"$count": "n"}]}, headers={"Authorization": ""}
        )
        self.assertEqual(status, 401)

    def test_concurrent_transactions_never_produce_mixed_aggregate(self):
        def write():
            for _ in range(12):
                self.client.transaction(
                    [
                        {
                            "collection": "people",
                            "document": "alice",
                            "patch": {"$inc": {"rating": 1}},
                        },
                        {
                            "collection": "people",
                            "document": "bob",
                            "patch": {"$inc": {"rating": -1}},
                        },
                    ]
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            writer = workers.submit(write)
            for _ in range(18):
                result = self.aggregate([{"$group": {"_id": None, "total": {"$sum": "$rating"}}}])
                self.assertEqual(result["documents"], [{"_id": None, "total": 5000}])
            writer.result(timeout=20)
