"""Durable profile selection, original-source identity and final-value admission."""

import hashlib
import json
import unittest

from yamora.tests.test_schema_policy_api import SchemaHarnessSupport
from yamora.tests.test_schema_policy_api import command

JSON_PROFILE = "yamora-json-schema-2020-12-v1"
OPENAPI_PROFILE = "yamora-openapi-3.1-schema-v1"
CRD_PROFILE = "yamora-crd-v1-schema-v1"
SCHEMA = {
    "type": "object",
    "properties": {"value": {"type": ["integer", "null"]}},
    "required": ["value"],
    "additionalProperties": False,
}


def envelope(profile, schema=SCHEMA):
    if profile == JSON_PROFILE:
        return {"profile": profile, "schema": schema}
    if profile == OPENAPI_PROFILE:
        return {
            "profile": profile,
            "name": "Record",
            "document": {
                "openapi": "3.1.0",
                "info": {"title": "fixture", "version": "1"},
                "paths": {},
                "components": {"schemas": {"Record": schema}},
            },
        }
    return {
        "profile": profile,
        "version": "v1",
        "document": {
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "spec": {"versions": [{"name": "v1", "schema": {"openAPIV3Schema": schema}}]},
        },
    }


class SchemaPolicyProfileTests(SchemaHarnessSupport, unittest.TestCase):
    def roundtrip(self, profile):
        source = json.dumps(envelope(profile), ensure_ascii=True, indent=2) + "\n"
        self.create(source)
        read = self.call("GET")
        value = json.loads(read["body"])
        self.assertEqual(value["profile"], profile)
        self.assertEqual(value["source"], source)
        self.assertEqual(value["source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        good, bad, absent = self.api(
            command("PUT", "/v1/collections/allowed/documents/good", "value: 1.0\n"),
            command("PUT", "/v1/collections/allowed/documents/bad", "value: wrong\n"),
            command("GET", "/v1/collections/allowed/documents/bad"),
        )
        self.assertEqual(good["status"], 201, good)
        self.assertEqual(bad["status"], 422, bad)
        self.assertEqual(absent["status"], 404, absent)
        self.assertEqual(bad["view"], good["view"])
        self.assertEqual(absent["view"], good["view"])

    def test_json_profile_roundtrip_and_admission(self):
        self.roundtrip(JSON_PROFILE)

    def test_openapi_component_roundtrip_and_admission(self):
        self.roundtrip(OPENAPI_PROFILE)

    def test_crd_version_roundtrip_and_admission(self):
        self.roundtrip(CRD_PROFILE)

    def test_unsupported_semantics_and_selectors_leave_root_unchanged(self):
        before = self.call("GET")["view"]
        cases = [
            {"profile": "unknown", "schema": True},
            envelope(JSON_PROFILE, {"$ref": "https://example.invalid/schema"}),
            envelope(JSON_PROFILE, {"pattern": "a+"}),
            {**envelope(OPENAPI_PROFILE), "name": "missing"},
            {**envelope(CRD_PROFILE), "version": "missing"},
            {**envelope(JSON_PROFILE), "extra": True},
        ]
        cases[3]["document"]["openapi"] = "3.0.3"
        for case in cases:
            with self.subTest(case=case):
                reply = self.call(
                    "PUT", body=json.dumps(case), if_none_match="*", request_id=self.next_id()
                )
                self.assertIn(reply["status"], (400, 422), reply)
                self.assertEqual(reply["view"], before)

    def test_profile_replacement_preserves_old_receipt_and_v1_identity(self):
        source = json.dumps(envelope(JSON_PROFILE, True))
        identity = self.next_id()
        request = command("PUT", body=source, if_none_match="*", request_id=identity)
        original = self.api(request)[0]
        self.assertEqual(original["status"], 201, original)
        current = self.call(
            "PUT", body="type: integer\n", if_match=self.etag(original), request_id=self.next_id()
        )
        self.assertEqual(current["status"], 200, current)
        self.assertEqual(json.loads(self.call("GET")["body"])["profile"], "yamora-shape-v1")
        self.same_reply(original, self.api(request)[0])

    def test_json_profile_patch_and_transaction_reject_before_any_effects(self):
        self.create(json.dumps(envelope(JSON_PROFILE)))
        target = "/v1/collections/allowed/documents/original"
        original = self.call("PUT", target, "value: 1.0\n")
        self.assertEqual(original["status"], 201, original)
        patch = self.call("PATCH", target, json.dumps({"$set": {"value": "wrong"}}))
        self.assertEqual(patch["status"], 422, patch)
        transaction = self.call(
            "POST",
            "/v1/transactions",
            json.dumps(
                {
                    "operations": [
                        {"collection": "allowed", "document": "new", "put": "value: 2\n"},
                        {"collection": "allowed", "document": "original", "put": "value: wrong\n"},
                    ]
                }
            ),
        )
        self.assertEqual(transaction["status"], 422, transaction)
        self.assertEqual(transaction["view"], original["view"])
        self.assertEqual(patch["view"], original["view"])
        self.assertEqual(self.call("GET", target)["body"], b"value: 1.0\n")
        self.assertEqual(self.call("GET", "/v1/collections/allowed/documents/new")["status"], 404)

    def test_new_profile_activation_scans_preexisting_documents_atomically(self):
        original = self.call("PUT", "/v1/collections/allowed/documents/bad", "value: wrong\n")
        self.assertEqual(original["status"], 201, original)
        rejected = self.call(
            "PUT",
            body=json.dumps(envelope(JSON_PROFILE)),
            if_none_match="*",
            request_id=self.next_id(),
        )
        self.assertEqual(rejected["status"], 422, rejected)
        self.assertEqual(rejected["view"], original["view"])
        self.assertEqual(self.call("GET")["status"], 404)


if __name__ == "__main__":
    unittest.main()
