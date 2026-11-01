"""Native deny-by-default field masks; no daemon enforcement claims.

FIELD_POLICY_SANITIZER defaults to fatal address/undefined sanitizers. Sources
can be overridden for deliberate guard-mutation red/green qualification.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rule(*, collection="records", documents=None, read=None, write=None):
    return {
        "collection": collection,
        "documents": ["*"] if documents is None else documents,
        "read": ["*"] if read is None else read,
        "write": ["*"] if write is None else write,
    }


class FieldPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = os.environ.get("TMPDIR")
        if not scratch or not Path(scratch).is_dir():
            raise RuntimeError("an existing owned disk-backed TMPDIR is required")
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.binary = cls.root / "field-policy"
        command = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
        ]
        sanitizer = os.environ.get("FIELD_POLICY_SANITIZER", "address,undefined")
        if sanitizer:
            command.append("-fsanitize=" + sanitizer)
        command += [
            str(ROOT / "tests/field_policy_harness.c"),
            os.environ.get("FIELD_POLICY_SOURCE", str(ROOT / "src/security/field_policy.c")),
            os.environ.get(
                "FIELD_POLICY_QUERY_SOURCE", str(ROOT / "src/security/field_policy_query.c")
            ),
            *[
                str(ROOT / "src" / source)
                for source in (
                    "value.c",
                    "query.c",
                    "query_regex.c",
                    "text.c",
                    "geo.c",
                    "aggregate.c",
                    "aggregate_keys.c",
                    "aggregate_spill.c",
                    "patch.c",
                    "snapshot.c",
                )
            ],
            "-I",
            str(ROOT / "src/security"),
            "-Wl,--gc-sections",
            "-Wl,--wrap=malloc",
            "-Wl,--wrap=calloc",
            "-Wl,--wrap=realloc",
            "-Wl,--wrap=strdup",
            "-lyaml",
            "-lcrypto",
            "-lm",
            "-pthread",
            "-o",
            str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def invoke(self, mode, policy, *args, request=None, source=None, allocation_failure=False):
        policy_file = self.root / "policy.yaml"
        policy_file.write_text(json.dumps(policy))
        command = [str(self.binary), mode, str(policy_file), *args]
        if request is not None:
            request_file = self.root / "request.yaml"
            request_file.write_text(json.dumps(request))
            command.append(str(request_file))
        if source is not None:
            source_file = self.root / "source.yaml"
            source_file.write_text(source)
            command.append(str(source_file))
        env = dict(
            os.environ,
            ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:abort_on_error=1",
            UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
        )
        if allocation_failure:
            env["FIELD_POLICY_ALLOC_FAIL"] = str(int(allocation_failure))
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Sanitizer", result.stderr)
        return result.stdout

    def allows(self, policy, path, *, document="public-one", write=False, collection="records"):
        return self.invoke(
            "allows", policy, collection, document, path, "write" if write else "read"
        ).strip()

    def test_document_selectors_and_subtree_boundaries(self):
        policy = [rule(documents=["public-*", "exact"], read=["profile.name"], write=["title"])]
        self.assertEqual(self.allows(policy, "profile.name"), "ALLOW")
        self.assertEqual(self.allows(policy, "profile.name.child", document="exact"), "ALLOW")
        for path, document, collection in (
            ("profile", "public-one", "records"),
            ("profile.names", "public-one", "records"),
            ("profile.secret", "public-one", "records"),
            ("profile.name", "private-one", "records"),
            ("profile.name", "public-one", "other"),
            ("profile.name", "-", "records"),
            ("", "public-one", "records"),
            ("title", "public-one", "records"),
        ):
            with self.subTest(path=path, document=document, collection=collection):
                self.assertEqual(
                    self.allows(policy, path, document=document, collection=collection), "DENY"
                )
        self.assertEqual(self.allows(policy, "title", write=True), "ALLOW")
        self.assertEqual(self.allows(policy, "profile.name", write=True), "DENY")

    def test_empty_missing_malformed_and_allocation_failure_deny(self):
        self.assertEqual(self.invoke("load", []).strip(), "ALLOW")
        self.assertEqual(self.allows([], "title"), "DENY")
        self.assertEqual(self.allows(None, "title"), "DENY")
        self.assertEqual(self.invoke("load", [rule()], allocation_failure=True).strip(), "DENY")
        bad = [
            None,
            {},
            [dict(rule(), unknown=True)],
            [rule(documents=[])],
            [rule(documents=["**"])],
            [rule(documents=["../outside"])],
            [rule(documents=["EXACT"])],
            [rule(documents=["same", "same"])],
            [rule(read=["x", "x"])],
            [rule(read=["x..y"])],
            [rule(read=["x.*"])],
            [rule(read=["x.$secret"])],
            [rule(read=["x/y"])],
            [rule(read=["x\\y"])],
            [rule(read=["x "])],
            [rule(read=["x" * 257])],
            [rule(collection="yamldb-system")],
            [rule()] * 65,
            [rule(read=[str(i) for i in range(65)])],
            [rule(documents=["x" * 129])],
        ]
        for policy in bad:
            with self.subTest(policy=policy):
                self.assertEqual(self.invoke("load", policy).strip(), "DENY")
        for path in ("bad..path", "$secret", "a/b", "a\\b", "a.*", "a" * 257):
            self.assertEqual(self.allows([rule()], path), "DENY")

    def test_exact_limits_and_partial_constructor_allocation_failures(self):
        self.assertEqual(self.invoke("load", [rule()] * 64).strip(), "ALLOW")
        self.assertEqual(self.invoke("load", [rule(read=["x" * 256])]).strip(), "ALLOW")
        self.assertEqual(self.invoke("load", [rule(documents=["x" * 128 + "*"])]).strip(), "ALLOW")
        self.assertEqual(
            self.invoke("load", [rule(read=[str(i) for i in range(64)])]).strip(), "ALLOW"
        )
        for failure in range(1, 25):
            with self.subTest(failure=failure):
                self.assertEqual(
                    self.invoke("load", [rule()], allocation_failure=failure).strip(), "DENY"
                )

    def test_writes_do_not_grant_replacement_or_array_sibling_mutation(self):
        policy = [
            rule(read=["title", "counter", "items"], write=["title", "counter", "items.0.name"])
        ]
        self.assertEqual(self.allows(policy, "title", write=True), "ALLOW")
        self.assertEqual(self.allows(policy, "", write=True), "DENY")
        self.assertEqual(self.allows([rule()], "", write=True), "ALLOW")
        self.assertEqual(
            self.invoke(
                "patch", policy, "records", "doc", request={"$set": {"title": "new"}}
            ).strip(),
            "ALLOW",
        )
        for ops in (
            {"$set": {"hidden": "x"}},
            {"$set": {"title": "x", "hidden": "x"}},
            {"$unset": {"items.0": True}},
            {"$set": {"items.0.name": "x"}},
            {"$rename": {"title": "hidden"}},
            {},
        ):
            with self.subTest(ops=ops):
                self.assertEqual(
                    self.invoke("patch", policy, "records", "doc", request=ops).strip(), "DENY"
                )
        self.assertEqual(
            self.invoke(
                "patch",
                [rule(read=["items"], write=["items"])],
                "records",
                "doc",
                request={"$unset": {"items.0": True}},
            ).strip(),
            "ALLOW",
        )
        for op in ("$inc", "$push", "$pull"):
            self.assertEqual(
                self.invoke(
                    "patch",
                    [rule(read=[], write=["counter"])],
                    "records",
                    "doc",
                    request={op: {"counter": 1}},
                ).strip(),
                "DENY",
            )
        self.assertEqual(
            self.invoke(
                "patch", policy, "records", "doc", request={"$inc": {"counter": 1}}
            ).strip(),
            "ALLOW",
        )

    def test_new_update_operators_need_the_authority_their_effect_requires(self):
        policy = [
            rule(
                read=["counter", "tags", "old"],
                write=["counter", "tags", "old", "new", "created"],
            )
        ]

        def patch(ops, rules=policy, document="doc"):
            return self.invoke("patch", rules, "records", document, request=ops).strip()

        for ops in (
            {"$addToSet": {"tags": "x"}},
            {"$addToSet": {"tags": {"$each": ["a", "b"]}}},
            {"$min": {"counter": 1}},
            {"$max": {"counter": 1}},
            {"$mul": {"counter": 2}},
            {"$setOnInsert": {"created": True}},
            {"$rename": {"old": "new"}},
        ):
            with self.subTest(ops=ops):
                self.assertEqual(patch(ops), "ALLOW")
        write_only = [rule(read=[], write=["counter", "created"])]
        for op in ("$addToSet", "$min", "$max", "$mul"):
            with self.subTest(op=op):
                self.assertEqual(patch({op: {"counter": 1}}, write_only), "DENY")
        self.assertEqual(patch({"$setOnInsert": {"created": 1}}, write_only), "ALLOW")
        for ops in (
            {"$rename": {"new": "old"}},
            {"$rename": {"old": "hidden"}},
            {"$rename": {"old": 1}},
            {"$setOnInsert": {"hidden": 1}},
            {"$bogus": {"counter": 1}},
        ):
            with self.subTest(ops=ops):
                self.assertEqual(patch(ops), "DENY")
        self.assertEqual(
            patch({"$rename": {"old": "new"}}, [rule(read=["old"], write=["new"])]), "DENY"
        )
        # A filter update checks its operations collection-wide.
        self.assertEqual(patch({"$inc": {"counter": 1}}, document="-"), "ALLOW")
        self.assertEqual(
            patch({"$inc": {"counter": 1}}, [rule(documents=["public-*"])], document="-"), "DENY"
        )

    def test_dotted_filters_need_read_over_their_possible_sequence_fan_out(self):
        narrow = [rule(read=["title", "profile.name", "items.0"], write=[])]

        def query(filter, rules=narrow):
            request = {"filter": filter, "count_only": True}
            return self.invoke("query", rules, "records", "-", request=request).strip()

        for filter in (
            {"title": "x"},
            {"items.0": "x"},
            {"items.0.name": "x"},
            {"items.0.7.name": "x"},
        ):
            with self.subTest(filter=filter):
                self.assertEqual(query(filter), "ALLOW")
        # profile may be a sequence whose element names the grant never covered.
        for filter in (
            {"profile.name": "Sam"},
            {"items.name": "x"},
            {"$and": [{"title": "x"}, {"profile.name": {"$exists": True}}]},
        ):
            with self.subTest(filter=filter):
                self.assertEqual(query(filter), "DENY")
        self.assertEqual(query({"profile.name": "Sam"}, [rule(read=["profile"])]), "ALLOW")

    def test_allowed_patch_preserves_exact_hidden_source(self):
        source = "# authored comment\ntitle: old # keep me\nsecret: 'PRIVATE' # preserve exactly\n"
        output = self.invoke(
            "patch",
            [rule(read=["title"], write=["title"])],
            "records",
            "doc",
            request={"$set": {"title": "new"}},
            source=source,
        )
        self.assertEqual(
            output,
            "ALLOW\n# authored comment\ntitle: \"new\" # keep me\nsecret: 'PRIVATE' # preserve exactly\n",
        )

    def test_queries_authorize_all_dependencies_before_empty_or_false_input(self):
        policy = [rule(read=["title", "profile.name"], write=[])]
        good = {
            "filter": {"title": "public"},
            "sort": {"profile.name": "asc"},
            "projection": ["title"],
        }
        output = self.invoke(
            "query",
            policy,
            "records",
            "-",
            request=good,
            source="title: public\nprofile: {name: Sam, secret: PRIVATE}\nsecret: PRIVATE\n",
        )
        self.assertEqual(output, 'ALLOW\n{"title":"public"}\n')
        for spec in (
            {"filter": {"secret": {"$exists": True}}, "projection": ["title"]},
            {
                "filter": {"$or": [{"title": "public"}, {"secret": "PRIVATE"}]},
                "projection": ["title"],
            },
            {"filter": {"$not": {"secret": "x"}}, "count_only": True},
            {"filter": {"secret": {"$elemMatch": {"child": 1}}}, "count_only": True},
            {"sort": {"secret": 1}, "projection": ["title"]},
            {"projection": ["profile"]},
            {"projection": ["secret"]},
            {},
            {"projection": ["title"], "explain": True},
            {"projection": ["title"], "filter": {"title": {"$unknown": 1}}},
            {"projection": ["title"], "unknown": True},
        ):
            with self.subTest(spec=spec):
                self.assertEqual(
                    self.invoke("query", policy, "records", "-", request=spec).strip(), "DENY"
                )
        self.assertEqual(
            self.invoke("query", policy, "records", "-", request={"count_only": True}).strip(),
            "ALLOW",
        )
        self.assertEqual(
            self.invoke(
                "query", [rule(read=[], write=["*"])], "records", "-", request={"count_only": True}
            ).strip(),
            "DENY",
        )

    def test_document_masks_cannot_enumerate_via_counts_pages_or_empty_projection(self):
        policy = [rule(documents=["public-*"], read=["title"], write=[])]
        for spec in (
            {"count_only": True},
            {"projection": []},
            {"projection": ["title"]},
            {"after": "private-doc", "projection": ["title"]},
        ):
            self.assertEqual(
                self.invoke("query", policy, "records", "-", request=spec).strip(), "DENY"
            )
        self.assertEqual(
            self.invoke(
                "query", policy, "records", "public-one", request={"projection": ["title"]}
            ).strip(),
            "ALLOW",
        )
        self.assertEqual(
            self.invoke(
                "query", policy, "records", "private-one", request={"projection": ["title"]}
            ).strip(),
            "DENY",
        )
        self.assertEqual(
            self.invoke(
                "query",
                policy,
                "records",
                "public-one",
                request={"after": "public-two", "projection": ["title"]},
            ).strip(),
            "DENY",
        )
        self.assertEqual(
            self.invoke(
                "query",
                [rule(documents=["public-one"])],
                "records",
                "public-one",
                request={"explain": True},
            ).strip(),
            "DENY",
        )

    def test_aggregation_validates_every_foreign_dependency_and_native_stage(self):
        pipeline = [
            {
                "$lookup": {
                    "from": "foreign",
                    "localField": "key",
                    "foreignField": "key",
                    "as": "joined",
                }
            },
            {"$project": ["joined"]},
        ]
        full = [rule(), rule(collection="foreign")]
        self.assertEqual(
            self.invoke("aggregate", full, "records", request=pipeline).strip(), "ALLOW"
        )
        for policy in (
            [rule()],
            [rule(read=["title"]), rule(collection="foreign")],
            [rule(), rule(collection="foreign", read=["key"])],
            [rule(), rule(collection="foreign", documents=["public-*"])],
        ):
            self.assertEqual(
                self.invoke("aggregate", policy, "records", request=pipeline).strip(), "DENY"
            )
        for pipeline in ([], [{"$bogus": {}}], [{"$count": 1}]):
            self.assertEqual(
                self.invoke("aggregate", full, "records", request=pipeline).strip(), "DENY"
            )
        self.assertEqual(
            self.invoke("aggregate", [rule()], "records", request=[{"$count": "total"}]).strip(),
            "ALLOW",
        )

    def test_search_feed_export_and_replication_require_whole_collection_authority(self):
        full = [rule()]
        for policy in (full, [rule(read=["title"])], [rule(documents=["public-*"])], []):
            expected = "ALLOW" if policy == full else "DENY"
            self.assertEqual(self.invoke("search", policy, "records").strip(), expected)
            self.assertEqual(self.invoke("stream", policy, "records", "read").strip(), expected)
        self.assertEqual(
            self.invoke("stream", [rule(write=["title"])], "records", "write").strip(), "DENY"
        )
        self.assertEqual(self.invoke("stream", full, "other", "read").strip(), "DENY")
        self.assertEqual(self.invoke("stream", full, "records", "write").strip(), "ALLOW")
